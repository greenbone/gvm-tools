# -*- coding: utf-8 -*-
#
# Loosely based on the create-targetw-from-host-list
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
# Run with gvm-script --gmp-username admin-user --gmp-password password socket create-targets-from-csv.gmp.py hostname-server targets.csv
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
    "This script pulls targetname, hostnames/IP addresses, and credentials "
    "from a csv file and creates a target for each row. \n\n"
    "csv file to contain name of target, ips, and up to 4 credentials previously created \n"
    "name,ip-addresses,credential1,credential2,credential3,credential4"
)


def check_args(args):
    len_args = len(args.script) - 1
    if len_args != 1:
        message = """
        This script pulls target names from a csv file and creates a target \
for each row.
        One parameter after the script name is required.

        1. <targets_csvfile>  -- text file containing Targetname and hostnames or IP-addresses

        Example:
            $ gvm-script --gmp-username name --gmp-password pass \
ssh --hostname <gsm> scripts/create_targets_from_csv.gmp <targets_csvfile>
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
        "targets_csv_file",
        type=str,
        help=("File containing host names / IPs"),
    )

    ports = parser.add_mutually_exclusive_group()
    ports.add_argument(
        "+pl",
        "++port-list-id",
        type=str,
        dest="port_list_id",
        help="UUID of existing port list.",
    )
    ports.add_argument(
        "+pr",
        "++port-range",
        dest="port_range",
        type=str,
        help=(
            "Port range to create port list from, e.g. "
            "T:1-1234 for ports 1-1234/TCP"
        ),
    )

    ports.set_defaults(
        port_list_id="730ef368-57e2-11e1-a90f-406186ea4fc5"
    )  # All TCP and Nmap top 100 UDP
    # Default portlists see also script list-portlists.gmp.py
    # | Name                          | ID                                  
    # - | ----------------------------- | ------------------------------------
    # 1 | All IANA assigned TCP         | 33d0cd82-57c6-11e1-8ed1-406186ea4fc5
    # 2 | All IANA assigned TCP and UDP | 4a4717fe-57d2-11e1-9a26-406186ea4fc5
    # 3 | All TCP and Nmap top 100 UDP  | 730ef368-57e2-11e1-a90f-406186ea4fc5

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

def target_id(
    gmp: Gmp,
    targetName: str,
):
    response_xml = gmp.get_targets(filter_string="rows=-1, name=" + targetName)
    targets_xml = response_xml.xpath("target")
    target_id = ""

    for target in targets_xml:
        name = "".join(target.xpath("name/text()"))
        target_id = target.get("id")
    return target_id

def create_targets(   
    gmp: Gmp,
    target_csv_file: Path,
    port_list_id: str,
):
    try:
        numberTargets = 0
        with open(target_csv_file, encoding="utf-8") as csvFile:
            content = csv.reader(csvFile, delimiter=',')  #read the data
            for row in content:   #loop through each row
                if len(row) == 0:
                    continue
                name = row[0]
                hosts = [row[1]]
                smbCred = credential_id(gmp, row[2])
                sshCred = credential_id(gmp, row[3])
                snmpCred = credential_id(gmp, row[4])
                esxCred = credential_id(gmp, row[5])
                aliveTest = row[6]
                if not aliveTest:
                    aliveTest = "Scan Config Default" 
                alive_test = gmp.types.AliveTest(
                    (aliveTest)
                )
                comment = f"Created: {time.strftime('%Y/%m/%d-%H:%M:%S')}"
                try:
                    if target_id(gmp, name):
                        print(f"Target: {name} exist, not creating...")
                        continue

                    print("Creating target: " + name)
                    gmp.create_target(
                    name=name, comment=comment, hosts=hosts, port_list_id=port_list_id, smb_credential_id=smbCred, ssh_credential_id=sshCred, alive_test=alive_test
                    )
                    numberTargets = numberTargets + 1
                except GvmResponseError as gvmerr:
                    print(f"{gvmerr=}, name: {name}")
                    pass
        csvFile.close()   #close the csv file
    except IOError as e:
        error_and_exit(f"Failed to read target_csv_file: {str(e)} (exit)")

    if len(row) == 0:
        error_and_exit("Host file is empty (exit)")
    
    return numberTargets
    
def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=undefined-variable
    if args.script:
        args = args.script[1:]

    parsed_args = parse_args(args=args)
    #port_list_id="4a4717fe-57d2-11e1-9a26-406186ea4fc5"

    print(
        "Creating targets.\n"
    )
    
    numberTargets = create_targets(
        gmp,
        parsed_args.targets_csv_file,
        parsed_args.port_list_id
    )

    numberTargets = str(numberTargets)
    print("    [" + numberTargets + "] Target(s) created!\n")


if __name__ == "__gmp__":
    main(gmp, args)
