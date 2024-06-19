# SPDX-FileCopyrightText: 2024 Martin Boller
#
# SPDX-License-Identifier: GPL-3.0-or-later

from argparse import Namespace

from gvm.protocols.gmp import Gmp
from gvmtools.helper import Table


def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=unused-argument

    response_xml = gmp.get_report_formats(details=True, filter_string="rows=-1")
    report_formats_xml = response_xml.xpath("report_format")
    heading = ["#", "Name", "Id", "Summary"]
    rows = []
    numberRows = 0

    print("Listing report formats.\n")

    for report_format in report_formats_xml:
        # Count number of reports
        numberRows = numberRows + 1
        # Cast/convert to text to show in list
        rowNumber = str(numberRows)
        name = "".join(report_format.xpath("name/text()"))
        report_format_id = report_format.get("id")
        report_format_summary = "".join(report_format.xpath("summary/text()"))

        rows.append([rowNumber, name, report_format_id, report_format_summary])

    print(Table(heading=heading, rows=rows))


if __name__ == "__gmp__":
    main(gmp, args)
