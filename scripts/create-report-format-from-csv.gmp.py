# SPDX-FileCopyrightText: 2024 Martin Boller
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

# Run with gvm-script --gmp-username admin-user --gmp-password password socket create-report_formats-from-csv.gmp.py report_formats.csv

import csv
import sys
from argparse import ArgumentParser, Namespace, RawTextHelpFormatter
from pathlib import Path

from gvm.protocols.gmp import Gmp
from gvmtools.helper import error_and_exit

HELP_TEXT = (
    "This script pulls report-format information "
    "from a csv file and creates a report-format for each row. \n"
    "csv file may contain Name of target, Login, password, and ssh-key \n"
    "Name,Type,Login,Password,ssh-key \n\n"
    "Please note: SNMP and ESX not supported yet "
)


def check_args(args):
    len_args = len(args.script) - 1
    if len_args != 2:
        message = """
        This script pulls report-format data from a csv file and creates a \
report-format for each row in the csv file.
        One parameter after the script name is required.

        1. <report_formats_csvfile>  -- csv file containing names and secrets required for scan report_formats

        Example:
            $ gvm-script --gmp-username name --gmp-password pass \
ssh --hostname <gsm> scripts/create_report_formats_from_csv.gmp.py \
<report_formats-csvfile>
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
        "cred_file",
        type=str,
        help=("CSV File containing report_formats"),
    )
    script_args, _ = parser.parse_known_args(args)
    return script_args


def create_report_formats(
    gmp: Gmp,
    cred_file: Path,
):
    try:
        numberreport_formats = 0
        with open(cred_file, encoding="utf-8") as csvFile:
            content = csv.reader(csvFile, delimiter=",")  # read the data
            for row in content:  # loop through each row
                numberreport_formats = numberreport_formats + 1
                REPORT_FORMAT_XML_STRING = (
                    '<get_report_formats_response status="200" status_text="OK">'
                    '<report_format id="c4aa21e4-23e6-4064-ae49-c0d425738a98">'
                    "<name>CSV vulnscan.dk</name>"
                    "<term>name=CSV first=1 rows=10 sort=name</term>"
                    "<keywords>"
                    "<keyword>"
                    "<column>name</column>"
                    "<relation>=</relation>"
                    "<value>CSV</value>"
                    "</keyword>"
                    "<keyword>"
                    "<column>first</column>"
                    "<relation>=</relation>"
                    "<value>1</value>"
                    "</keyword>"
                    "<keyword>"
                    "<column>rows</column>"
                    "<relation>=</relation>"
                    "<value>10</value>"
                    "</keyword>"
                    "<keyword>"
                    "<column>sort</column>"
                    "<relation>=</relation>"
                    "<value>name</value>"
                    "</keyword>"
                    "</keywords>"
                    "<extension>csv</extension>"
                    "<content_type>text/csv</content_type>"
                    "<comment>vulnscan.dk CSV Report Format. Version 2023-03-31.</comment>"
                    "<summary>vulnscan.dk CSV Report Format</summary>"
                    "<description>Complete scan report in GMP XML format. Version 20200827.</description>"
                    "<predefined>1</predefined>"
                    "<configurable>0</configurable>"
                    "<trust>1<time>2024-03-30T18:24:54Z</time></trust>"
                    "<active>1</active>"
                    "<creation_time>2024-03-31T10:48:03Z</creation_time>"
                    "<modification_time>2024-03-31T10:48:03Z</modification_time>"
                    '<report_formats start="1" max="10000000"/>'
                    "<report_format_count>5<filtered>0</filtered><page>0</page></report_format_count>"
                    "</report_format>"
                    "</get_report_formats_response>"
                )

                gmp.import_report_format(REPORT_FORMAT_XML_STRING)

        csvFile.close()  # close the csv file

    except IOError as e:
        error_and_exit(f"Failed to read cred_file: {str(e)} (exit)")

    if len(row) == 0:
        error_and_exit("report_formats file is empty (exit)")

    return numberreport_formats


def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=undefined-variable
    if args.script:
        args = args.script[1:]

    parsed_args = parse_args(args=args)

    numberreport_formats = create_report_formats(
        gmp,
        parsed_args.cred_file,
    )

    numberreport_formats = str(numberreport_formats)
    print("   \n [" + numberreport_formats + "] report_format(s) created!\n")


if __name__ == "__gmp__":
    main(gmp, args)
