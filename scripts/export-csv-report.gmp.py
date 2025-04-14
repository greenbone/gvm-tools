# SPDX-FileCopyrightText: 2024 Martin Boller
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Based on the export-pdf-report script and modified to
# create csv and return more (all) details.

import sys
from argparse import Namespace
from base64 import b64decode
from pathlib import Path

from gvm.protocols.gmp import Gmp


def check_args(args):
    len_args = len(args.script) - 1
    if len_args < 1:
        message = """
        This script requests the given report and exports it as a csv
        file locally. It requires one parameter after the script name.

        1. <report_id>     -- ID of the report

        Optional a file name to save the csv in.

        Examples:
            $ gvm-script --gmp-username name --gmp-password pass \
ssh --hostname <gsm> scripts/export-csv-report.gmp.py <report_id> <csv_file>
            $ gvm-script --gmp-username admin --gmp-password '0f6fa69b-32bb-453a-9aa4-b8c9e56b3d00' socket export-csv-report.gmp.py b26229cd-94c8-44f8-9cb6-27486a3dedad ./test.csv
        """
        print(message)
        sys.exit()


def main(gmp: Gmp, args: Namespace) -> None:
    # check if report id and CSV filename are provided to the script
    # argv[0] contains the script name
    check_args(args)

    report_id = args.argv[1]
    if len(args.argv) == 3:
        csv_filename = args.argv[2] + ".csv"
    else:
        csv_filename = args.argv[1] + ".csv"

    csv_report_format_id = "c1645568-627a-11e3-a660-406186ea4fc5"

    response = gmp.get_report(
        report_id=report_id,
        report_format_id=csv_report_format_id,
        ignore_pagination=True,
        details=True,
    )

    report_element = response.find("report")
    # get the full content of the report element
    content = report_element.find("report_format").tail

    if not content:
        print(
            "Requested report is empty. Either the report does not contain any "
            " results or the necessary tools for creating the report are "
            "not installed.",
            file=sys.stderr,
        )
        sys.exit(1)

    # convert content to 8-bit ASCII bytes
    binary_base64_encoded_csv = content.encode("ascii")

    # decode base64
    binary_csv = b64decode(binary_base64_encoded_csv)

    # write to file and support ~ in filename path
    csv_path = Path(csv_filename).expanduser()

    csv_path.write_bytes(binary_csv)

    print("Done. CSV created: " + str(csv_path))


if __name__ == "__gmp__":
    main(gmp, args)
