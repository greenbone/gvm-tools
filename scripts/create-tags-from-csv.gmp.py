# SPDX-FileCopyrightText: 2024 Martin Boller
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

# Run with gvm-script --gmp-username admin-user --gmp-password password socket create-tags-from-csv.gmp.py hostname-server tags.csv

import csv
import sys
import time
from argparse import ArgumentParser, Namespace, RawTextHelpFormatter
from pathlib import Path

from gvm.errors import GvmResponseError
from gvm.protocols.gmp import Gmp
from gvmtools.helper import error_and_exit

HELP_TEXT = (
    "This script pulls tagname, hostnames/IP addresses, and credentials "
    "from a csv file and creates a tag for each row. \n\n"
    "csv file to contain name of tag, ips, and up to 4 credentials previously created \n"
    "name,ip-addresses,credential1,credential2,credential3,credential4"
)


def check_args(args):
    len_args = len(args.script) - 1
    if len_args != 1:
        message = """
        This script pulls tag names from a csv file and creates a tag \
for each row.
        One parameter after the script name is required.

        1. <tags_csvfile>  -- text file containing tagname and hostnames or IP-addresses

        Example:
            $ gvm-script --gmp-username name --gmp-password pass \
ssh --hostname <gsm> scripts/create_tags_from_csv.gmp <tags_csvfile>
        """
        print(message)
        sys.exit()


def parse_args(args: Namespace) -> Namespace:  # pylint: disable=unused-argument
    """Parsing args ..."""

    parser = ArgumentParser(
        prefix_chars="+",
        add_help=False,
        formatter_class=RawTextHelpFormatter,
        description=HELP_TEXT,
    )

    parser.add_argument(
        "+h",
        "++help",
        action="help",
        help="Show this help message and exit.",
    )

    parser.add_argument(
        "tags_csv_file",
        type=str,
        help=("File containing host names / IPs"),
    )

    script_args, _ = parser.parse_known_args(args)
    return script_args


def config_id(
    gmp: Gmp,
    config_name: str,
):
    response_xml = gmp.get_scan_configs(
        filter_string="rows=-1, name= " + config_name
    )
    scan_configs_xml = response_xml.xpath("config")
    config_id = ""

    for scan_config in scan_configs_xml:
        config_id = scan_config.get("id")
    return config_id


def alert_id(
    gmp: Gmp,
    alert_name: str,
):
    response_xml = gmp.get_alerts(filter_string="rows=-1, name=" + alert_name)
    alerts_xml = response_xml.xpath("alert")
    alert_id = ""

    for alert in alerts_xml:
        alert_id = alert.get("id")
    return alert_id


def credential_id(
    gmp: Gmp,
    credName: str,
):
    response_xml = gmp.get_credentials(
        filter_string="rows=-1, name=" + credName
    )
    credentials_xml = response_xml.xpath("credential")
    cred_id = ""

    for credential in credentials_xml:
        cred_id = credential.get("id")
    return cred_id


def target_id(
    gmp: Gmp,
    targetName: str,
):
    response_xml = gmp.get_targets(filter_string="rows=-1, name=" + targetName)
    targets_xml = response_xml.xpath("target")
    target_id = ""

    for target in targets_xml:
        target_id = target.get("id")
    return target_id


def task_id(
    gmp: Gmp,
    taskName: str,
):
    response_xml = gmp.get_tasks(filter_string="rows=-1, name=" + taskName)
    tasks_xml = response_xml.xpath("task")
    task_id = ""

    for task in tasks_xml:
        task_id = task.get("id")
    return task_id


def tag_id(
    gmp: Gmp,
    tagName: str,
):
    response_xml = gmp.get_tags(filter_string="rows=-1, name=" + tagName)
    tags_xml = response_xml.xpath("tag")
    tag_id = ""

    for tag in tags_xml:
        tag_id = tag.get("id")
    return tag_id


def scanner_id(
    gmp: Gmp,
    scanner_name: str,
):
    response_xml = gmp.get_scanners(
        filter_string="rows=-1, name=" + scanner_name
    )
    scanners_xml = response_xml.xpath("scanner")
    scanner_id = ""

    for scanner in scanners_xml:
        scanner_id = scanner.get("id")
    return scanner_id


def schedule_id(
    gmp: Gmp,
    schedule_name: str,
):
    response_xml = gmp.get_schedules(
        filter_string="rows=-1, name=" + schedule_name
    )
    schedules_xml = response_xml.xpath("schedule")
    schedule_id = ""

    for schedule in schedules_xml:
        schedule_id = schedule.get("id")
    return schedule_id


def create_tags(
    gmp: Gmp,
    tag_csv_file: Path,
):
    try:
        numbertags = 0
        with open(tag_csv_file, encoding="utf-8") as csvFile:
            content = csv.reader(csvFile, delimiter=",")  # read the data
            for row in content:  # loop through each row
                if len(row) == 0:
                    continue
                tagType = row[0]
                tagName = row[1]
                tagDescription = row[2]
                tagNameFull = tagName + ":" + tagDescription + ":" + tagType
                if tag_id(gmp, tagNameFull):
                    print(f"Tag: {tagNameFull} already exist")
                    continue
                # Up to ten resources (rows 3 - 12)
                tagResources = []
                if tagType.upper() == "FAIL!":
                    print("Failed!")
                elif tagType.upper() == "ALERT":
                    getUUID = alert_id
                    resource_type = gmp.types.EntityType.ALERT
                elif tagType.upper() == "CONFIG":
                    getUUID = config_id
                    resource_type = gmp.types.EntityType.SCAN_CONFIG
                elif tagType.upper() == "CREDENTIAL":
                    getUUID = credential_id
                    resource_type = gmp.types.EntityType.CREDENTIAL
                elif tagType.upper() == "REPORT":
                    filter = "~" + tagName
                    resource_type = gmp.types.EntityType.REPORT
                elif tagType.upper() == "SCANNER":
                    getUUID = scanner_id
                    resource_type = gmp.types.EntityType.SCANNER
                elif tagType.upper() == "SCHEDULE":
                    getUUID = schedule_id
                    resource_type = gmp.types.EntityType.SCHEDULE
                elif tagType.upper() == "TARGET":
                    getUUID = target_id
                    resource_type = gmp.types.EntityType.TARGET
                elif tagType.upper() == "TASK":
                    getUUID = task_id
                    resource_type = gmp.types.EntityType.TASK
                else:
                    print(
                        "Only alert, config, credential, report, scanner, schedule, target, and task supported"
                    )
                    exit()

                if len(row[3]) >= 1:
                    tagResource = getUUID(gmp, row[3])
                    tagResources.append(tagResource)
                if len(row[4]) >= 1:
                    tagResource = getUUID(gmp, row[4])
                    tagResources.append(tagResource)
                if len(row[5]) >= 1:
                    tagResource = getUUID(gmp, row[5])
                    tagResources.append(tagResource)
                if len(row[6]) >= 1:
                    tagResource = getUUID(gmp, row[6])
                    tagResources.append(tagResource)
                if len(row[7]) >= 1:
                    tagResource = getUUID(gmp, row[7])
                    tagResources.append(tagResource)
                if len(row[8]) >= 1:
                    tagResource = getUUID(gmp, row[8])
                    tagResources.append(tagResource)
                if len(row[9]) >= 1:
                    tagResource = getUUID(gmp, row[9])
                    tagResources.append(tagResource)
                    tagResource = getUUID(gmp, row[10])
                if len(row[10]) >= 1:
                    tagResources.append(tagResource)
                if len(row[11]) >= 1:
                    tagResource = getUUID(gmp, row[11])
                    tagResources.append(tagResource)
                if len(row[12]) >= 1:
                    tagResource = getUUID(gmp, row[12])
                    tagResources.append(tagResource)
                comment = f"Created: {time.strftime('%Y/%m/%d-%H:%M:%S')}"

                if tagType.upper() == "REPORT":
                    try:
                        print("Creating tag: " + tagNameFull)
                        gmp.create_tag(
                            name=tagNameFull,
                            comment=comment,
                            value=tagName,
                            resource_type=resource_type,
                            resource_filter=filter,
                        )
                        numbertags = numbertags + 1
                    except GvmResponseError as gvmerr:
                        print(f"{gvmerr=}, name: {tagNameFull}")
                        pass
                else:
                    try:
                        print("Creating tag: " + tagNameFull)
                        gmp.create_tag(
                            name=tagNameFull,
                            comment=comment,
                            value=tagName,
                            resource_type=resource_type,
                            resource_ids=tagResources,
                        )
                        numbertags = numbertags + 1
                    except GvmResponseError as gvmerr:
                        print(f"{gvmerr=}, name: {tagNameFull}")
                        pass
        csvFile.close()  # close the csv file
    except IOError as e:
        error_and_exit(f"Failed to read tag_csv_file: {str(e)} (exit)")

    if len(row) == 0:
        error_and_exit("tag file is empty (exit)")

    return numbertags


def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=undefined-variable
    if args.script:
        args = args.script[1:]

    parsed_args = parse_args(args=args)

    print("Creating tags.\n")

    numbertags = create_tags(
        gmp,
        parsed_args.tags_csv_file,
    )

    numbertags = str(numbertags)
    print("    [" + numbertags + "] tag(s) created!\n")


if __name__ == "__gmp__":
    main(gmp, args)
