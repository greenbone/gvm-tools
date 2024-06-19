# SPDX-FileCopyrightText: 2024 Martin Boller
#
# SPDX-License-Identifier: GPL-3.0-or-later

from argparse import Namespace

from gvm.protocols.gmp import Gmp
from gvmtools.helper import Table


def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=unused-argument

    response_xml = gmp.get_tags(filter_string="rows=-1")
    tags_xml = response_xml.xpath("tag")

    heading = ["#", "Name", "Id", "Modified", "Value", "Type", "Count"]

    rows = []
    numberRows = 0

    print("Listing tags.\n")

    for tag in tags_xml:
        # Count number of reports
        numberRows = numberRows + 1
        # Cast/convert to text to show in list
        rowNumber = str(numberRows)

        name = "".join(tag.xpath("name/text()"))
        modified = "".join(tag.xpath("modification_time/text()"))
        value = "".join(tag.xpath("value/text()"))
        type = "".join(tag.xpath("resources/type/text()"))
        count = "".join(tag.xpath("resources/count/total/text()"))
        tag_id = tag.get("id")
        rows.append([rowNumber, name, tag_id, modified, value, type, count])

    print(Table(heading=heading, rows=rows))


if __name__ == "__gmp__":
    main(gmp, args)
