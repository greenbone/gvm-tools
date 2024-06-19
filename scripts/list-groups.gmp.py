# SPDX-FileCopyrightText: 2024 Martin Boller
#
# SPDX-License-Identifier: GPL-3.0-or-later

from argparse import Namespace

from gvm.protocols.gmp import Gmp
from gvmtools.helper import Table


def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=unused-argument

    response_xml = gmp.get_groups(filter_string="rows=-1")
    groups_xml = response_xml.xpath("group")

    heading = ["#", "Name", "Id", "Members"]

    rows = []
    numberRows = 0

    print("Listing groups.\n")

    for group in groups_xml:
        # Count number of reports
        numberRows = numberRows + 1
        # Cast/convert to text to show in list
        rowNumber = str(numberRows)

        name = "".join(group.xpath("name/text()"))
        group_id = group.get("id")
        group_members = "".join(group.xpath("users/text()"))

        rows.append([rowNumber, name, group_id, group_members])

    print(Table(heading=heading, rows=rows))


if __name__ == "__gmp__":
    main(gmp, args)
