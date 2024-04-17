# -*- coding: utf-8 -*-
#
# Loosely based on Greenbone sample scripts
# As provided by Greenbone in the gvm-tools repo
#
# Martin Boller
#
# SPDX-License-Identifier: GPL-3.0-or-later
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# Run with gvm-script --gmp-username admin-user --gmp-password password socket create-alerts-from-csv.gmp.py alerts.csv
#
#
# Information on Variables to be used in alerts: https://docs.greenbone.net/GSM-Manual/gos-22.04/en/scanning.html#using-alerts
# Example script: https://forum.greenbone.net/t/working-example-of-creating-an-alert-using-script/7511/2

import sys
import time
import csv
import json

from argparse import ArgumentParser, Namespace, RawTextHelpFormatter
from pathlib import Path
from typing import List
from gvm.errors import GvmResponseError

from gvm.protocols.gmp import Gmp

from gvmtools.helper import error_and_exit

HELP_TEXT = (
    "This script pulls alert information "
    "from a csv file and creates a alert for each row. \n"
    "use the same alert names when creating tasks! \n\n"
    "Use example alerts.csv as a template \n\n"
    "It should be rather self explanatory."
)

def check_args(args):
    len_args = len(args.script) - 1
    if len_args != 2:
        message = """
        This script pulls alerts from a csv file and creates a \
alert for each row in the csv file.
        One parameter after the script name is required.

        1. <alerts_csvfile>  -- csv file containing names and secrets required for scan alerts

        Example:
            $ gvm-script --gmp-username name --gmp-password pass \
ssh --hostname <gsm> scripts/create_alerts_from_csv.gmp.py \
<alerts-csvfile>
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
        "alert_file",
        type=str,
        help=("CSV File containing alerts"),
    )
    script_args, _ = parser.parse_known_args(args)
    return script_args

def alert_id(
    gmp: Gmp,
    alert_name: str,
):
    response_xml = gmp.get_alerts(filter_string="rows=-1, name=" + alert_name)
    alerts_xml = response_xml.xpath("alert")
    alert_id = ""

    for alert in alerts_xml:
        name = "".join(alert.xpath("name/text()"))
        alert_id = alert.get("id")
    return alert_id

def credential_id(
    gmp: Gmp,
    credential_name: str,
):
    response_xml = gmp.get_credentials(filter_string="rows=-1, name=" + credential_name)
    credentials_xml = response_xml.xpath("credential")
    credential_id = ""

    for credential in credentials_xml:
        name = "".join(credential.xpath("name/text()"))
        credential_id = credential.get("id")
    return credential_id

def report_format_id(
    gmp: Gmp,
    report_format_name: str,
):
    response_xml = gmp.get_report_formats(details=True, filter_string="rows=-1, name=" + report_format_name)
    report_formats_xml = response_xml.xpath("report_format")
    report_format_id = ""

    for report_format in report_formats_xml:
        name = "".join(report_format.xpath("name/text()"))
        report_format_id = report_format.get("id")
    return report_format_id

def event_list(string):
    event_list = list(string.split(" "))
    return event_list
 

def create_alerts(   
    gmp: Gmp,
    alert_file: Path,
):
    try:
        numberalerts = 0
        with open(alert_file, encoding="utf-8") as csvFile:
            content = csv.reader(csvFile, delimiter=',')  #read the data
            for row in content:   #loop through each row
                if len(row) == 0:
                    continue
                alert_name = row[0]
                str_alert_type = row[1]
                strRow2 = row[2]
                strRow3 = row[3]
                strRow4 = row[4]
                strRow5 = row[5]
                strRow6 = row[6]
                report_format = report_format_id(gmp, row[7])
                event_data = row[8]

                comment = f"Created: {time.strftime('%Y/%m/%d-%H:%M:%S')}"
                alert_type=getattr(gmp.types.AlertMethod, str_alert_type)

                if alert_id(gmp, alert_name):
                    print(f"Alert: {alert_name} exist, not creating...")
                    continue
                
                if str_alert_type == "EMAIL":
                    sender_email = strRow2
                    recipient_email = strRow3
                    subject = strRow4
                    message = strRow5
                    notice_type = strRow6
                    try:
                        print("Creating alert: " + alert_name)
                        gmp.create_alert(
                            name=alert_name,
                            comment=comment,
                            event=gmp.types.AlertEvent.TASK_RUN_STATUS_CHANGED,
                            event_data={"status": event_data},
                            condition=gmp.types.AlertCondition.ALWAYS,
                            method=alert_type,
                            method_data={
                                "message": message,
                                "notice": notice_type,
                                "from_address": sender_email,
                                "subject": subject,
                                "notice_report_format": report_format,
                                "notice_attach_format": report_format,
                                "to_address": recipient_email,
                            },
                        )
                        numberalerts = numberalerts + 1
                    except GvmResponseError as gvmerr:
                        print(f"{gvmerr=}, name: {alert_name}")
                        pass 
                else:
                    smb_credential = credential_id(gmp, strRow2)
                    smb_share_path = strRow3
                    smb_report_name = strRow4
                    smb_folder = strRow5
                    smb_file_path = smb_folder + "/" + smb_report_name

                    try:
                        print("Creating alert: " + alert_name)
                        gmp.create_alert(
                        name=alert_name,
                        comment=comment,
                        event=gmp.types.AlertEvent.TASK_RUN_STATUS_CHANGED,
                        event_data={"status": event_data},
                        condition=gmp.types.AlertCondition.ALWAYS,
                        method=alert_type,
                        method_data={
                            "smb_credential": smb_credential,
                            "smb_share_path": smb_share_path,
                            "smb_report_format": report_format,
                            "smb_file_path": smb_file_path,
                        },
                        )
                        numberalerts = numberalerts + 1
                    except GvmResponseError as gvmerr:
                        print(f"{gvmerr=}, name: {alert_name}")
                        pass 
        csvFile.close()   #close the csv file

    except IOError as e:
        error_and_exit(f"Failed to read alert_file: {str(e)} (exit)")

    if len(row) == 0:
        error_and_exit("alerts file is empty (exit)")
    
    return numberalerts
    
def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=undefined-variable
    if args.script:
        args = args.script[1:]

    parsed_args = parse_args(args=args)

    print(
        "Creating alerts.\n"
    )

    numberalerts = create_alerts(
        gmp,
        parsed_args.alert_file,
    )

    numberalerts = str(numberalerts)
    print("    [" + numberalerts + "] alert(s) created!\n")


if __name__ == "__gmp__":
    main(gmp, args)
