# SPDX-FileCopyrightText: 2024 Martin Boller
#
# SPDX-License-Identifier: GPL-3.0-or-later

from argparse import Namespace

from gvm.protocols.gmp import Gmp
from gvmtools.helper import Table


def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=unused-argument

    response_xml = gmp.get_roles(filter_string="rows=-1")
    roles_xml = response_xml.xpath("role")

    heading = ["#", "Name", "Id", "Members"]

    rows = []
    numberRows = 0

    print("Listing roles.\n")

    for role in roles_xml:
        # Count number of reports
        numberRows = numberRows + 1
        # Cast/convert to text to show in list
        rowNumber = str(numberRows)

        name = "".join(role.xpath("name/text()"))
        role_id = role.get("id")
        role_members = "".join(role.xpath("users/text()"))

        rows.append([rowNumber, name, role_id, role_members])

    print(Table(heading=heading, rows=rows))


if __name__ == "__gmp__":
    main(gmp, args)
