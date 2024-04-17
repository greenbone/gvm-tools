# -*- coding: utf-8 -*-
#
# Loosely based on the create-targets-from-host-list.gmp.py
# As provided by Greenbone in the gvm-tools repo
#
# Martin Boller
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
# Run with gvm-script --gmp-username admin-user --gmp-password password socket create-credentials-from-csv.gmp.py credentials.csv
#
#

import sys
import time
import csv

from argparse import ArgumentParser, Namespace, RawTextHelpFormatter
from pathlib import Path
from typing import List
from gvm.errors import GvmResponseError

from gvm.protocols.gmp import Gmp

from gvmtools.helper import error_and_exit

HELP_TEXT = (
    "This script pulls Credential information "
    "from a csv file and creates a credential for each row. \n"
    "use the same credential names when creating targets! \n\n"
    "csv file may contain Name of target, Login, password, and ssh-key \n"
    "Name,Type,Login,Password,ssh-key \n\n"
    "Please note: SNMP and ESX not supported yet "
)


def check_args(args):
    len_args = len(args.script) - 1
    if len_args != 2:
        message = """
        This script pulls credentials from a csv file and creates a \
credential for each row in the csv file.
        One parameter after the script name is required.

        1. <credentials_csvfile>  -- csv file containing names and secrets required for scan credentials

        Example:
            $ gvm-script --gmp-username name --gmp-password pass \
ssh --hostname <gsm> scripts/create_credentials_from_csv.gmp.py \
<credentials-csvfile>
        """
        print(message)
        sys.exit()


def parse_args(args: Namespace) -> Namespace:  # pylint: disable=unused-argument
    """Parsing args ..."""

    parser = ArgumentParser(
        prefix_chars="+",
        add_help=False,
        formatter_class=RawTextHelpFormatter,
        description=HELP_TEXT,
    )

    parser.add_argument(
        "+h",
        "++help",
        action="help",
        help="Show this help message and exit.",
    )

    parser.add_argument(
        "cred_file",
        type=str,
        help=("CSV File containing credentials"),
    )
    script_args, _ = parser.parse_known_args(args)
    return script_args

def credential_id(
    gmp: Gmp,
    credName: str,
):
    response_xml = gmp.get_credentials(filter_string="rows=-1, name=" + credName)
    credentials_xml = response_xml.xpath("credential")
    cred_id = ""

    for credential in credentials_xml:
        name = "".join(credential.xpath("name/text()"))
        cred_id = credential.get("id")
    return cred_id

def create_credentials(   
    gmp: Gmp,
    cred_file: Path,
):
    try:
        numberCredentials = 0
        with open(cred_file, encoding="utf-8") as csvFile:
            content = csv.reader(csvFile, delimiter=',')  #read the data
            for row in content:   #loop through each row
                if len(row) == 0:
                    continue
                cred_name = row[0]
                cred_type = row[1]
                userName = row[2]
                userPW = row[3]
                comment = f"Created: {time.strftime('%Y/%m/%d-%H:%M:%S')}"

                if credential_id(gmp, cred_name):
                    print(f"Credential: {cred_name} exist, not creating...")
                    continue

                if cred_type == "UP":
                    try:
                        print("Creating credential: " + cred_name)
                        gmp.create_credential(
                        name=cred_name,
                        credential_type=gmp.types.CredentialType.USERNAME_PASSWORD,
                        login=userName,
                        password=userPW,
                        comment=comment,
                        )
                        numberCredentials = numberCredentials + 1
                    except GvmResponseError as gvmerr:
                        print(f"{gvmerr=}, name: {cred_name}")
                        pass
                elif cred_type == "SSH":
                    with open(row[4]) as key_file:
                        key = key_file.read()

                    try:                    
                        print("Creating credential: " + cred_name)
                        gmp.create_credential(
                            name=cred_name,
                            credential_type=gmp.types.CredentialType.USERNAME_SSH_KEY,
                            login=userName,
                            key_phrase=userPW,
                            private_key=key,
                            comment=comment,
                            )
                        numberCredentials = numberCredentials + 1
                    except GvmResponseError as gvmerr:
                        print(f"{gvmerr=}, name: {cred_name}")
                        pass
                elif cred_type == "SNMP":
                        # Unfinished, copy of UP for now
                    try:
                        print("Creating credential: " + cred_name)
                        gmp.create_credential(
                        name=cred_name,
                        credential_type=gmp.types.CredentialType.USERNAME_SSH_KEY,
                        login=userName,
                        key_phrase=userPW,
                        private_key=key,
                        comment=comment,
                        )
                        numberCredentials = numberCredentials + 1
                    except GvmResponseError as gvmerr:
                        print(f"{gvmerr=}, name: {cred_name}")
                        pass

                elif cred_type == "ESX":
                        # Unfinished, copy of UP for now
                    try:
                        print("Creating credential: " + cred_name)
                        gmp.create_credential(
                        name=cred_name,
                        credential_type=gmp.types.CredentialType.USERNAME_SSH_KEY,
                        login=userName,
                        key_phrase=userPW,
                        private_key=key,
                        comment=comment,
                        )
                        numberCredentials = numberCredentials + 1
                    except GvmResponseError as gvmerr:
                        print(f"{gvmerr=}, name: {cred_name}")
                        pass
        csvFile.close()   #close the csv file

    except IOError as e:
        error_and_exit(f"Failed to read cred_file: {str(e)} (exit)")

    if len(row) == 0:
        error_and_exit("Credentials file is empty (exit)")
    
    return numberCredentials
    
def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=undefined-variable
    if args.script:
        args = args.script[1:]

    parsed_args = parse_args(args=args)

    print(
        "Creating credentials.\n"
    )

    numberCredentials = create_credentials(
        gmp,
        parsed_args.cred_file,
    )

    numberCredentials = str(numberCredentials)
    print("    [" + numberCredentials + "] Credential(s) created!\n")


if __name__ == "__gmp__":
    main(gmp, args)
