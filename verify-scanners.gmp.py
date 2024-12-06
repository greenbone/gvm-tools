# SPDX-FileCopyrightText: 2024 Martin Boller
#
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Run with gvm-script --gmp-username admin-user --gmp-password password socket list-scanners.gmp.py

from argparse import Namespace

from gvm.protocols.gmp import Gmp

from gvmtools.helper import Table

from gvm.xml import pretty_print

from gvm.errors import GvmResponseError

from gvmtools.helper import error_and_exit

from gvm.errors import GvmServerError

def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=unused-argument

    heading = ["#", "Name", "Id", "Host", "Version"]

    rows = []
    numberRows = 0

    print(
        "Verifying scanners.\n"
    )
    response_xml = gmp.get_scanners(filter_string="rows=-1")
    scanners_xml = response_xml.xpath("scanner")

    for scanner in scanners_xml:
        # Count number of reports
        numberRows = numberRows + 1
        # Cast/convert to text to show in list
        rowNumber = str(numberRows)
        name = "".join(scanner.xpath("name/text()"))
        scanner_id = scanner.get("id")
        host = "".join(scanner.xpath("host/text()"))
        if host == "":
            host = "local scanner"
        try:
            status_xml = gmp.verify_scanner(str(scanner_id))
            #pretty_print(status_xml)
            for scanner_status in status_xml:
                scanner_version = "".join(scanner_status.xpath("text()"))
        except GvmServerError as gvmerr:
            scanner_version= "*No Response*"
            pass 

        rows.append([rowNumber, name, scanner_id, host, scanner_version])

    print(Table(heading=heading, rows=rows))


if __name__ == "__gmp__":
    main(gmp, args)
