# SPDX-FileCopyrightText: 2019-2021 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

import datetime
import sys
from argparse import Namespace

from gvm.protocols.gmp import Gmp


def check_args(args):
    len_args = len(args.script) - 1
    message = """
        This script starts a new scan on the given host.
        It needs one parameters after the script name.

        1. <host_ip>        IP Address of the host system
        2. <port_list_id>   Port List UUID for scanning the host system.
                            Preconfigured UUID might be under
                            /var/lib/gvm/data-objects/gvmd/20.08/port_lists/.
                            ex. iana-tcp-udp is
                            "4a4717fe-57d2-11e1-9a26-406186ea4fc5".

                Example:
            $ gvm-script --gmp-username name --gmp-password pass \
ssh --hostname <gsm> scripts/scan-new-system.gmp.py <host_ip> <port_list_id>
    """
    if len_args != 2:
        print(message)
        sys.exit()


def create_target(gmp, ipaddress, port_list_id):
    # create a unique name by adding the current datetime
    name = f"Suspect Host {ipaddress} {str(datetime.datetime.now())}"

    response = gmp.create_target(
        name=name, hosts=[ipaddress], port_list_id=port_list_id
    )
    return response.get("id")


def create_task(gmp, ipaddress, target_id, scan_config_id, scanner_id):
    name = f"Scan Suspect Host {ipaddress}"
    response = gmp.create_task(
        name=name,
        config_id=scan_config_id,
        target_id=target_id,
        scanner_id=scanner_id,
    )
    return response.get("id")


def start_task(gmp, task_id):
    response = gmp.start_task(task_id)
    # the response is
    # <start_task_response><report_id>id</report_id></start_task_response>
    return response[0].text


def main(gmp: Gmp, args: Namespace) -> None:
    check_args(args)

    ipaddress = args.argv[1]
    port_list_id = args.argv[2]

    target_id = create_target(gmp, ipaddress, port_list_id)

    full_and_fast_scan_config_id = "daba56c8-73ec-11df-a475-002264764cea"
    openvas_scanner_id = "08b69003-5fc2-4037-a479-93b440211c73"
    task_id = create_task(
        gmp,
        ipaddress,
        target_id,
        full_and_fast_scan_config_id,
        openvas_scanner_id,
    )

    report_id = start_task(gmp, task_id)

    print(
        f"Started scan of host {ipaddress}. "
        f"Corresponding report ID is {report_id}"
    )


if __name__ == "__gmp__":
    # pylint: disable=undefined-variable
    main(gmp, args)
