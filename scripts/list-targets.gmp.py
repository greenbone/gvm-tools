# -*- coding: utf-8 -*-
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
# Based on other Greenbone scripts 
#
# Martin Boller
#

from argparse import Namespace

from gvm.protocols.gmp import Gmp

from gvmtools.helper import Table


def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=unused-argument

    response_xml = gmp.get_targets(filter_string="rows=-1")
    targets_xml = response_xml.xpath("target")

    heading = ["#", "Name", "Id", "Count", "SSH Credential", "SMB Cred", "ESXi Cred", "SNMP Cred", "Alive test"]

    rows = []
    numberRows = 0

    print(
        "Listing targets.\n"
    )

    for target in targets_xml:
        # Count number of reports
        numberRows = numberRows + 1
        # Cast/convert to text to show in list
        rowNumber = str(numberRows)

        name = "".join(target.xpath("name/text()"))
        maxhosts = "".join(target.xpath("max_hosts/text()"))
        sshcred = "".join(target.xpath("ssh_credential/name/text()"))
        smbcred = "".join(target.xpath("smb_credential/name/text()"))
        esxicred = "".join(target.xpath("esxi_credential/name/text()"))
        snmpcred = "".join(target.xpath("snmp_credential/name/text()"))
        target_id = target.get("id")
        alive_test = "".join(target.xpath("alive_tests/text()"))
        rows.append([rowNumber, name, target_id, maxhosts, sshcred, smbcred, esxicred, snmpcred, alive_test])

    print(Table(heading=heading, rows=rows))


if __name__ == "__gmp__":
    main(gmp, args)
