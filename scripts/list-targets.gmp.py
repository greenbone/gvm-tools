# SPDX-FileCopyrightText: 2024 Martin Boller
#
# SPDX-License-Identifier: GPL-3.0-or-later

from argparse import Namespace

from gvm.protocols.gmp import Gmp
from gvmtools.helper import Table


def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=unused-argument

    response_xml = gmp.get_targets(filter_string="rows=-1")
    targets_xml = response_xml.xpath("target")

    heading = [
        "#",
        "Name",
        "Id",
        "Count",
        "SSH Credential",
        "SMB Cred",
        "ESXi Cred",
        "SNMP Cred",
        "Alive test",
    ]

    rows = []
    numberRows = 0

    print("Listing targets.\n")

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
        rows.append(
            [
                rowNumber,
                name,
                target_id,
                maxhosts,
                sshcred,
                smbcred,
                esxicred,
                snmpcred,
                alive_test,
            ]
        )

    print(Table(heading=heading, rows=rows))


if __name__ == "__gmp__":
    main(gmp, args)
