# SPDX-FileCopyrightText: 2024 Martin Boller
#
# SPDX-License-Identifier: GPL-3.0-or-later

from argparse import Namespace

from gvm.protocols.gmp import Gmp
from gvmtools.helper import Table


def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=unused-argument

    response_xml = gmp.get_policies(filter_string="rows=-1")
    policies_xml = response_xml.xpath("config")

    heading = ["#", "Name", "Id", "NVT Count"]

    rows = []
    numberRows = 0

    print("Listing compliance policies.\n")

    for policy in policies_xml:
        # Count number of reports
        numberRows = numberRows + 1
        # Cast/convert to text to show in list
        rowNumber = str(numberRows)

        name = "".join(policy.xpath("name/text()"))
        policy_id = policy.get("id")
        policy_nvt = "".join(policy.xpath("nvt_count/text()"))

        rows.append([rowNumber, name, policy_id, policy_nvt])

    print(Table(heading=heading, rows=rows))


if __name__ == "__gmp__":
    main(gmp, args)
