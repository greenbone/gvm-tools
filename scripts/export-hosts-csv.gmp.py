# SPDX-FileCopyrightText: 2025 Martin Boller
#
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Loosely based on other greenbone scripts
#
# Run with: gvm-script --gmp-username admin-user --gmp-password password socket export-hosts-csv.gmp.py <csv file> days
# example: gvm-script --gmp-username admin --gmp-password top$ecret socket export-hosts-csv.gmp.py hosts.csv 2


import sys
import csv

from gvm.protocols.gmp import Gmp
from gvm.errors import GvmResponseError
from gvmtools.helper import error_and_exit
from datetime import datetime, timedelta, time, date
from argparse import ArgumentParser, Namespace, RawTextHelpFormatter
from pathlib import Path
from typing import List

HELP_TEXT = (
    "This script generates a csv file with hosts (assets) "
    "in Greenbone Vulnerability Manager.\n"
    "csv file will contain: "
    "Hostname, IP Address, MAC Address, Operating System, last seen, and severity\n"
)

def check_args(args):
    len_args = len(args.script) - 1
    if len_args < 1:
        message = """
        This script requests all hosts within the last day and exports it as a csv 
        file locally. It requires one parameter after the script name.

        1. filename     -- name of the csv file of the report
        2. days         -- number of days from today to pull hosts from (optional: Default 1)
        Examples:
            $ gvm-script --gmp-username name --gmp-password pass \
ssh --hostname <gsm> scripts/export-hosts-csv.gmp.py <csv_file> 2
            $ gvm-script --gmp-username admin --gmp-password '0f6fa69b-32bb-453a-9aa4-b8c9e56b3d00' socket export-hosts-csv.gmp.py hosts.csv 4
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
        "csv_filename",
        type=str,
        help=("CSV File containing credentials"),
    )

    parser.add_argument(
        "delta_days",
        type=int,
        help=("Number of days in the past to pull hosts information")
    )

    script_args, _ = parser.parse_known_args(args)
    return script_args

def list_hosts(gmp: Gmp, from_date: date, to_date: date, csvfilename) -> None:
    host_filter = (
        f"rows=-1 and modified>{from_date.isoformat()} "
        f"and modified<{to_date.isoformat()}"
    )

    try:
        # Get the XML of hosts
        hosts_xml = gmp.get_hosts(filter_string=host_filter)
        host_info=[]

        for host in hosts_xml.xpath("asset"):
            # IP and modification time will be there
            ip = host.xpath("name/text()")[0]
            host_seendates = host.xpath("modification_time/text()")
            host_lastseen = host_seendates[0]
            
            hostnames = host.xpath('identifiers/identifier/name[text()="hostname"]/../value/text()')
            if len(hostnames) == 0:
                continue
            hostname = hostnames[0]
            
            host_macs = host.xpath('identifiers/identifier/name[text()="MAC"]/../value/text()')
            if len(host_macs) == 0:
                continue
            host_mac = host_macs[0]
            
            host_severity = host.xpath('host/severity/value/text()')[0]
            if len(host_severity) == 0:
                continue
            
            host_os = host.xpath('host/detail/name[text()="best_os_txt"]/../value/text()')[0]
            if len(host_os) == 0:
                continue
            
            host_info.append([hostname, ip, host_mac, host_os, host_lastseen, host_severity])
    except GvmResponseError as gvmerr:
        print(f"{gvmerr=}, name: {ip}")
        pass
    # Write the list host_info to csv file
    writecsv(csvfilename, host_info)

    #print('Done. CSV created: ' + str(csv_path))

def writecsv(csv_filename, hostinfo: dict):
    field_names = ["hostname", "ip", "host_mac", "host_os", "host_lastseen", "host_severity"]
    try:
        with open(csv_filename, 'w') as csvfile: 
            writer = csv.writer(csvfile, delimiter=',', quoting=csv.QUOTE_ALL)
            writer.writerow(field_names)
            writer.writerows(hostinfo)
            csvfile.close
    except IOError as e:
        error_and_exit(f"Failed to write csv file: {str(e)} (exit)")

def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=undefined-variable
    # argv[0] contains the csv file name
    check_args(args)
    if args.script:
        args = args.script[1:]
    parsed_args = parse_args(args=args)

    delta_days = parsed_args.delta_days
    # simply getting yesterday from midnight to midnight today
    from_date = (datetime.combine(datetime.today(), time.min) - timedelta(days=delta_days))
    night_time = datetime.strptime('235959','%H%M%S').time()
    to_date = datetime.combine(datetime.now(), night_time) 
    # get the hosts
    list_hosts(
        gmp,
        from_date,
        to_date,
        parsed_args.csv_filename
    )

if __name__ == "__gmp__":
    main(gmp, args)
