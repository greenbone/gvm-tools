# SPDX-FileCopyrightText: 2024 Martin Boller
#
# SPDX-License-Identifier: GPL-3.0-or-later

from argparse import Namespace

from gvm.protocols.gmp import Gmp
from gvmtools.helper import Table


def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=unused-argument

    response_xml = gmp.get_port_lists(filter_string="rows=-1")
    portlists_xml = response_xml.xpath("port_list")

    heading = ["#", "Name", "Id", "Ports All", "Ports TCP", "Ports UDP"]

    rows = []
    numberRows = 0

    print("Listing portlists.\n")

    for portlist in portlists_xml:
        # Count number of reports
        numberRows = numberRows + 1
        # Cast/convert to text to show in list
        rowNumber = str(numberRows)

        name = "".join(portlist.xpath("name/text()"))
        port_list_id = portlist.get("id")
        port_all = "".join(portlist.xpath("port_count/all/text()"))
        port_tcp = "".join(portlist.xpath("port_count/tcp/text()"))
        port_udp = "".join(portlist.xpath("port_count/udp/text()"))

        rows.append(
            [rowNumber, name, port_list_id, port_all, port_tcp, port_udp]
        )

    print(Table(heading=heading, rows=rows))


if __name__ == "__gmp__":
    main(gmp, args)
