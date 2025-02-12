# SPDX-FileCopyrightText: 2025 Martin Boller
#
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Loosely based on other greenbone scripts
#
# Run with: gvm-script --gmp-username admin-user --gmp-password password socket list-hosts.gmp.py <days>
# example: gvm-script --gmp-username admin --gmp-password top$ecret socket list-hosts.gmp.py 2


import sys
from argparse import ArgumentParser, Namespace, RawTextHelpFormatter
from datetime import date, datetime, time, timedelta

from gvm.errors import GvmResponseError
from gvm.protocols.gmp import Gmp
from gvmtools.helper import Table

HELP_TEXT = (
    "This script generates a table of hosts (assets) "
    "from Greenbone Vulnerability Manager.\n\n"
    "table will contain:\n"
    "Hostname, IP Address, MAC Address, Operating System, last seen, and severity\n"
)

def check_args(args):
    len_args = len(args.script) - 1
    if len_args < 1:
        message = """
        This script requests information about all hosts <days> days prior to today (included) and 
        displays it as a table. It requires one parameter after the script name:
        1. days -- number of days prior to today to pull hosts information from

        Examples:
            $ gvm-script --gmp-username username --gmp-password password socket list-hosts.gmp.py <days>
            $ gvm-script --gmp-username admin --gmp-password 0f6fa69b-32bb-453a-9aa4-b8c9e56b3d00 socket list-hosts.gmp.py 4
        """
        print(message)
        sys.exit()

def parse_args(args: Namespace) -> Namespace:  # pylint: disable=unused-argument
    """Parsing args ..."""

    parser = ArgumentParser(
        prefix_chars="+",
        add_help=False,
        formatter_class=RawTextHelpFormatter,
    )

    parser.add_argument(
        "+h",
        "++help",
        action="help",
        help="Show this help message and exit.",
    )

    parser.add_argument(
        "delta_days",
        type=int,
        help=("Number of days in the past to pull hosts information")
    )

    script_args, _ = parser.parse_known_args(args)
    return script_args

def list_hosts(gmp: Gmp, from_date: date, to_date: date) -> None:
    host_filter = (
        f"rows=-1 "
        f"and modified>{from_date.isoformat()} "
        f"and modified<{to_date.isoformat()}"
    )

    # Get the XML of hosts
    hosts_xml = gmp.get_hosts(filter_string=host_filter)
    heading = [
        "#",
        "IP Address",
        "Hostname",
        "MAC Address",
        "Operating System",
        "Last Seen",
        "CVSS",
    ]
    rows=[]
    numberRows = 0

    print(
        "Listing hosts.\n"
        f"From: {from_date}\n"
        f"To:   {to_date}\n"
    )

    for host in hosts_xml.xpath("asset"):
        try:
            # ip will always be there            
            ip = host.xpath("name/text()")[0]
            host_seendates = host.xpath("modification_time/text()")
            host_lastseen = host_seendates[0]
        
            try:
                # hostnames and other attributes may not be there  
                hostnames = host.xpath('identifiers/identifier/name[text()="hostname"]/../value/text()')
                if len(hostnames) == 0:
                    hostname = ""
                    pass
                else:
                    hostname = hostnames[0]
            except GvmResponseError:
                continue    
            
            try:
                host_macs = host.xpath('identifiers/identifier/name[text()="MAC"]/../value/text()')
                if len(host_macs) == 0:
                    host_mac = ""
                    pass
                else:
                    host_mac = host_macs[0]
            except GvmResponseError:
                continue

            try:
                host_severity = host.xpath('host/severity/value/text()')
                if len(host_severity) == 0:
                    host_severity = "0.0"
                    pass
                else:
                    host_severity = host_severity[0]
            except GvmResponseError:
                continue
            
            try:
                host_os = host.xpath('host/detail/name[text()="best_os_txt"]/../value/text()')
                if len(host_os) == 0:
                    host_os = ""
                    pass
                else:
                    host_os = host_os[0]
            except GvmResponseError:
                continue            
        
        except GvmResponseError:
            continue

        # Count number of hosts
        numberRows = numberRows + 1
        # Cast/convert to text to show in list
        rowNumber = str(numberRows)
        rows.append(
            [
                rowNumber,
                ip,
                hostname,
                host_mac,
                host_os,
                host_lastseen,
                host_severity
            ]
        )
        
    print(Table(heading=heading, rows=rows))

def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=undefined-variable
    check_args(args)
    if args.script:
        args = args.script[1:]
    parsed_args = parse_args(args=args)
    delta_days = parsed_args.delta_days
    # simply getting yesterday from midnight to today (now)
    from_date = (datetime.combine(datetime.today(), time.min) - timedelta(days=delta_days))
    to_date = datetime.now()
    #print(from_date, to_date)

    list_hosts(gmp, from_date, to_date)

if __name__ == "__gmp__":
    main(gmp, args)
