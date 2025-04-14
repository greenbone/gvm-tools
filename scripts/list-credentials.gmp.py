# SPDX-FileCopyrightText: 2024 Martin Boller
#
# SPDX-License-Identifier: GPL-3.0-or-later

from argparse import Namespace

from gvm.protocols.gmp import Gmp
from gvmtools.helper import Table


def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=unused-argument

    response_xml = gmp.get_credentials(filter_string="rows=-1")
    credentials_xml = response_xml.xpath("credential")

    heading = ["#", "Id", "Name", "Type", "Insecure use"]

    rows = []
    numberRows = 0

    print("Listing credentials.\n")

    for credential in credentials_xml:
        # Count number of reports
        numberRows = numberRows + 1
        # Cast/convert to text to show in list
        rowNumber = str(numberRows)

        name = "".join(credential.xpath("name/text()"))
        credential_id = credential.get("id")
        cred_type = "".join(credential.xpath("type/text()"))
        if cred_type.upper() == "UP":
            cred_type = "Username + Password (up)"
        elif cred_type.upper() == "USK":
            cred_type = "Username + SSH Key (usk)"
        elif cred_type.upper() == "SMIME":
            cred_type = "S/MIME Certificate (smime)"
        elif cred_type.upper() == "PGP":
            cred_type = "PGP Encryption Key (pgp)"
        elif cred_type.upper() == "SNMP":
            cred_type = "Simple Network Management Protocol (snmp)"
        elif cred_type.upper() == "PW":
            cred_type = "Password only (pw)"
        cred_insecureuse = "".join(credential.xpath("allow_insecure/text()"))
        if cred_insecureuse == "1":
            cred_insecureuse = "Yes"
        else:
            cred_insecureuse = "No"

        rows.append(
            [rowNumber, credential_id, name, cred_type, cred_insecureuse]
        )

    print(Table(heading=heading, rows=rows))


if __name__ == "__gmp__":
    main(gmp, args)
