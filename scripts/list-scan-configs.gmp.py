# SPDX-FileCopyrightText: 2024 Martin Boller
#
# SPDX-License-Identifier: GPL-3.0-or-later

from argparse import Namespace

from gvm.protocols.gmp import Gmp
from gvmtools.helper import Table


def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=unused-argument

    response_xml = gmp.get_scan_configs(filter_string="rows=-1")
    scan_configs_xml = response_xml.xpath("config")

    heading = ["#", "Name", "Id", "NVT Count"]

    rows = []
    numberRows = 0

    print("Listing scan configurations.\n")

    for scan_config in scan_configs_xml:
        # Count number of reports
        numberRows = numberRows + 1
        # Cast/convert to text to show in list
        rowNumber = str(numberRows)

        name = "".join(scan_config.xpath("name/text()"))
        scan_config_id = scan_config.get("id")
        scan_config_nvt = "".join(scan_config.xpath("nvt_count/text()"))

        rows.append([rowNumber, name, scan_config_id, scan_config_nvt])

    print(Table(heading=heading, rows=rows))


if __name__ == "__gmp__":
    main(gmp, args)
