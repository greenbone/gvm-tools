# -*- coding: utf-8 -*-
# Copyright (C) 2019-2021 Greenbone Networks GmbH
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

import sys

from base64 import b64decode
from pathlib import Path
from argparse import Namespace
from gvm.protocols.gmp import Gmp


def check_args(args):
    len_args = len(args.script) - 1
    if len_args < 1:
        message = """
        This script requests the given report and exports it as a pdf 
        file locally. It requires one parameters after the script name.

        1. <report_id>     -- ID of the report
        
        Optional a file name to save the pdf in.

        Example:
            $ gvm-script --gmp-username name --gmp-password pass \
ssh --hostname <gsm> scripts/export-pdf-report.gmp.py <report_id> <pdf_file>
        """
        print(message)
        sys.exit()


def main(gmp: Gmp, args: Namespace) -> None:
    # check if report id and PDF filename are provided to the script
    # argv[0] contains the script name
    check_args(args)

    report_id = args.argv[1]
    if len(args.argv) == 3:
        pdf_filename = args.argv[2]
    else:
        pdf_filename = args.argv[1] + ".pdf"

    pdf_report_format_id = "c402cc3e-b531-11e1-9163-406186ea4fc5"

    response = gmp.get_report(
        report_id=report_id, report_format_id=pdf_report_format_id
    )

    report_element = response.find("report")
    # get the full content of the report element
    content = report_element.find("report_format").tail

    if not content:
        print(
            'Requested report is empty. Either the report does not contain any '
            ' results or the necessary tools for creating the report are '
            'not installed.',
            file=sys.stderr,
        )
        sys.exit(1)

    # convert content to 8-bit ASCII bytes
    binary_base64_encoded_pdf = content.encode('ascii')

    # decode base64
    binary_pdf = b64decode(binary_base64_encoded_pdf)

    # write to file and support ~ in filename path
    pdf_path = Path(pdf_filename).expanduser()

    pdf_path.write_bytes(binary_pdf)

    print('Done. PDF created: ' + str(pdf_path))


if __name__ == '__gmp__':
    main(gmp, args)
