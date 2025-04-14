# SPDX-FileCopyrightText: 2017-2021 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

import csv
import sys
from argparse import Namespace

from gvm.protocols.gmp import Gmp


def check_args(args):
    len_args = len(args.script) - 1
    if len_args != 1:
        message = """
        This script reads host data from a csv file and sync it with the gsm.
        It needs one parameters after the script name.

        1. <csv_file> - should contain a table of IP-addresses with an
                        optional a comment

        Example:
            $ gvm-script --gmp-username name --gmp-password pass \
    ssh --hostname <gsm> scripts/sync-hosts.gmp.py <csv_file>
        """
        print(message)
        sys.exit()


def sync_hosts(gmp, filename):
    with open(filename, newline="", encoding="utf-8") as f:
        reader = csv.reader(f, delimiter=",", quotechar="|")
        for row in reader:
            if len(row) == 2:
                ip = row[0]
                comment = row[1]

                # check if host exists
                ret = gmp.get_hosts(filter_string=f"ip={ip}")
                if ret.xpath("host"):
                    print(f"\nAsset with IP {ip} exist")
                    host_id = ret.xpath("host/@id")[0]
                    gmp.delete_host(host_id=host_id)
                else:
                    print(f"Asset with ip {ip} does not exist. Sync...")
                    ret = gmp.create_host(name=ip, comment=comment)

                    if "OK" in ret.xpath("@status_text")[0]:
                        print("Asset synced")


def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=undefined-variable

    check_args(args)

    file = args.script[1]

    sync_hosts(gmp, file)


if __name__ == "__gmp__":
    main(gmp, args)
