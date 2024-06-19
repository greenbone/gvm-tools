# SPDX-FileCopyrightText: 2017-2021 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
import time
from argparse import ArgumentParser, Namespace, RawTextHelpFormatter
from pathlib import Path
from typing import List

from gvm.protocols.gmp import Gmp
from gvmtools.helper import error_and_exit

HELP_TEXT = (
    "This script pulls hostnames from a text "
    "file and creates a target for each."
)


def check_args(args):
    len_args = len(args.script) - 1
    if len_args != 2:
        message = """
        This script pulls hostnames from a text file and creates a target \
for each.
        One parameter after the script name is required.

        1. <hostname>        -- IP of the GVM host
        2. <hosts_textfile>  -- text file containing hostnames

        Example:
            $ gvm-script --gmp-username name --gmp-password pass \
ssh --hostname <gsm> scripts/create_targets_from_host_list.gmp \
<hostname> <hosts_textfile>
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
        "hostname",
        type=str,
        help="Host name to create targets for.",
    )

    parser.add_argument(
        "hosts_file",
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
        port_list_id="4a4717fe-57d2-11e1-9a26-406186ea4fc5"
    )  # All IANA assigned TCP and UDP
    script_args, _ = parser.parse_known_args(args)
    return script_args


def load_host_list(host_file):
    try:
        with open(host_file, encoding="utf-8") as f:
            content = f.readlines()
        host_list = [x.strip() for x in content]
        host_list = list(filter(None, host_list))
    except IOError as e:
        error_and_exit(f"Failed to read host_file: {str(e)} (exit)")

    if len(host_list) == 0:
        error_and_exit("Host file is empty (exit)")

    return host_list


def send_targets(
    gmp: Gmp,
    host_name: str,
    host_file: Path,
    host_list: List[str],
    port_list_id: str,
):
    print(f"\nSending targets from {host_file} to {host_name}...")

    for host in host_list:
        name = f"Target for {host}"
        comment = f"Created: {time.strftime('%Y/%m/%d-%H:%M:%S')}"
        hosts = [host]

        gmp.create_target(
            name=name, comment=comment, hosts=hosts, port_list_id=port_list_id
        )


def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=undefined-variable
    if args.script:
        args = args.script[1:]

    parsed_args = parse_args(args=args)

    hosts_list = load_host_list(parsed_args.hosts_file)

    if parsed_args.port_range:
        print(parsed_args.port_range)
        resp = gmp.create_port_list(
            name=f"Port list for target {parsed_args.hostname}",
            port_range=parsed_args.port_range,
            comment="Port List created by gvm-script",
        )
        port_list_id = resp.xpath("//@id")[0]
        print(f"Port list {port_list_id} created!\n")
    else:
        port_list_id = parsed_args.port_list_id
    send_targets(
        gmp,
        parsed_args.hostname,
        parsed_args.hosts_file,
        hosts_list,
        port_list_id,
    )

    print("\n  Target(s) created!\n")


if __name__ == "__gmp__":
    main(gmp, args)
