# SPDX-FileCopyrightText: 2024 Martin Boller
#
# SPDX-License-Identifier: GPL-3.0-or-later

from argparse import Namespace

from gvm.protocols.gmp import Gmp
from gvmtools.helper import Table


def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=unused-argument

    response_xml = gmp.get_filters(filter_string="rows=-1")
    filters_xml = response_xml.xpath("filter")

    heading = ["#", "Name", "Id", "Modified", "Type", "Term"]

    rows = []
    numberRows = 0

    print("Listing filters.\n")

    for filter in filters_xml:
        # Count number of reports
        numberRows = numberRows + 1
        # Cast/convert to text to show in list
        rowNumber = str(numberRows)

        name = "".join(filter.xpath("name/text()"))
        modified = "".join(filter.xpath("modification_time/text()"))
        term = "".join(filter.xpath("term/text()"))
        type = "".join(filter.xpath("type/text()"))
        filter_id = filter.get("id")
        rows.append([rowNumber, name, filter_id, modified, type, term])

    print(Table(heading=heading, rows=rows))


if __name__ == "__gmp__":
    main(gmp, args)
