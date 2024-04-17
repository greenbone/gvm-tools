# -*- coding: utf-8 -*-
# 
# Based on the Greenbone export-xml-report script and modified to 
# return more (all) details.
# Martin Boller
#
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
#
# 2022-11-02 - Martin B
# Added ignore_pagination=True, details=True to get the full report
# 

import sys
from argparse import Namespace
from base64 import b64decode
from pathlib import Path

from gvm.protocols.gmp import Gmp

from gvm.xml import pretty_print

def check_args(args):
    len_args = len(args.script) - 1
    if len_args < 1:
        message = """
        This script requests the given report and exports it as a xml 
        file locally. It requires one parameters after the script name.

        1. <report_id>     -- ID of the report
        
        Optional a file name to save the xml in.

        Example:
            $ gvm-script --gmp-username name --gmp-password pass \
ssh --hostname <gsm> scripts/export-xml-report.gmp.py <report_id> <xml_file>
        """
        print(message)
        sys.exit()


def main(gmp: Gmp, args: Namespace) -> None:
    # check if report id and xml filename are provided to the script
    # argv[0] contains the script name
    check_args(args)

    report_id = args.argv[1]
    if len(args.argv) == 3:
        xml_filename = args.argv[2] + ".xml"
    else:
        xml_filename = args.argv[1] + ".xml"

    xml_report_format_id = "5057e5cc-b825-11e4-9d0e-28d24461215b"

    response = gmp.get_report(
        report_id=report_id, report_format_id=xml_report_format_id, ignore_pagination=True, details=True
    )

    report_element = response.find("report")
    data = pretty_print(report_element)
    # get the full content of the report element
    content = report_element.find("report_format").tail

    if not content:
        print(
            "Requested report is empty. Either the report does not contain any"
            " results or the necessary tools for creating the report are "
            "not installed.",
            file=sys.stderr,
        )
        sys.exit(1)

    # convert content to 8-bit ASCII bytes
    binary_base64_encoded_xml = content.encode("ascii")

    # decode base64
    binary_xml = b64decode(binary_base64_encoded_xml)

    # write to file and support ~ in filename path
    xml_path = Path(xml_filename).expanduser()

    xml_path.write_bytes(data)

    print("Done. xml created: " + str(xml_path))


if __name__ == "__gmp__":
    main(gmp, args)
