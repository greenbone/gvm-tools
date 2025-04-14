# SPDX-FileCopyrightText: 2025 Martin Boller
#
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Loosely based on other greenbone scripts
#
# Run with: gvm-script --gmp-username admin-user --gmp-password password socket export-hosts-csv.gmp.py <csv file> days
# example: gvm-script --gmp-username admin --gmp-password top$ecret socket export-hosts-csv.gmp.py hosts.csv 2


import csv
import sys
from argparse import ArgumentParser, Namespace, RawTextHelpFormatter
from datetime import date, datetime, time, timedelta

from gvm.protocols.gmp import Gmp
from gvmtools.helper import error_and_exit

HELP_TEXT = (
    "This script generates a csv file with Operating System "
    "from Greenbone Vulnerability Manager.\n\n"
    "csv file will contain:\n"
    "IP Address, Hostname, MAC Address, Operating System, Last Seen, CVSS\n"
)


def check_args(args: Namespace) -> None:
    len_args = len(args.script) - 1
    if len_args < 2:
        message = """
        This script requests all hosts <days> prior to today and exports it as a csv file.
        It requires two parameter after the script name:
        1. filename -- name of the csv file of the report
        2. days     -- number of days before and until today to pull hosts information from
        
        Examples:
            $ gvm-script --gmp-username username --gmp-password password socket export-hosts-csv.gmp.py <csv_file> <days>
            $ gvm-script --gmp-username admin --gmp-password 0f6fa69b-32bb-453a-9aa4-b8c9e56b3d00 socket export-hosts-csv.gmp.py operatingsystems.csv 4
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
        "csv_filename",
        type=str,
        help=("CSV File containing credentials"),
    )

    parser.add_argument(
        "delta_days",
        type=int,
        help=("Number of days in the past to pull hosts information"),
    )

    script_args, _ = parser.parse_known_args(args)
    return script_args


def list_operating_systems(
    gmp: Gmp, from_date: date, to_date: date, csvfilename: str
) -> None:
    operating_system_filter = (
        f"rows=-1 "
        f"and modified>{from_date.isoformat()} "
        f"and modified<{to_date.isoformat()}"
    )

    os_info = []

    operating_systems_xml = gmp.get_operating_systems(
        filter_string=operating_system_filter
    )

    for operating_system in operating_systems_xml.xpath("asset"):
        # title will always be there
        os_title = operating_system.xpath("name/text()")[0]

        os_latest_severity = operating_system.xpath(
            "os/latest_severity/value/text()"
        )[0]

        os_host_count = operating_system.xpath("os/installs/text()")[0]

        os_info.append(
            [
                os_title,
                os_latest_severity,
                os_host_count,
            ]
        )

    # Write the list host_info to csv file
    writecsv(csvfilename, os_info)
    print(
        f"CSV file: {csvfilename}\n"
        f"From:     {from_date}\n"
        f"To:       {to_date}\n"
    )


def writecsv(csv_filename: str, hostinfo: list) -> None:
    field_names = [
        "IP Address",
        "Hostname",
        "MAC Address",
        "Operating System",
        "Last Seen",
        "CVSS",
    ]
    try:
        with open(csv_filename, "w") as csvfile:
            writer = csv.writer(csvfile, delimiter=",", quoting=csv.QUOTE_ALL)
            writer.writerow(field_names)
            writer.writerows(hostinfo)
            csvfile.close
    except IOError as e:
        error_and_exit(f"Failed to write csv file: {str(e)} (exit)")


def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=undefined-variable
    # argv[0] contains the csv file name
    check_args(args)
    if args.script:
        args = args.script[1:]
    parsed_args = parse_args(args=args)

    delta_days = parsed_args.delta_days
    # simply getting yesterday from midnight to now
    from_date = datetime.combine(datetime.today(), time.min) - timedelta(
        days=delta_days
    )
    to_date = datetime.now()
    # get the hosts
    list_operating_systems(gmp, from_date, to_date, parsed_args.csv_filename)


if __name__ == "__gmp__":
    main(gmp, args)
