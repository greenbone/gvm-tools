# SPDX-FileCopyrightText: 2025 Martin Boller
#
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Loosely based on other greenbone scripts
#
# Run with: gvm-script --gmp-username admin-user --gmp-password password socket export-hosts-csv.gmp.py <csv file> days
# example: gvm-script --gmp-username admin --gmp-password top$ecret socket export-hosts-csv.gmp.py hosts.csv 2


import sys

from argparse import Namespace

from gvm.protocols.gmp import Gmp

from gvm.errors import GvmResponseError

from gvmtools.helper import Table

from datetime import datetime, timedelta, time, date


def list_hosts(gmp: Gmp, from_date: date, to_date: date) -> None:
    host_filter = (
        f"rows=-1 and modified>{from_date.isoformat()} "
        f"and modified<{to_date.isoformat()}"
    )

    # Get the XML of hosts
    hosts_xml = gmp.get_hosts(filter_string=host_filter)
    heading = ["#", "hostname", "IP-Address", "MAC", "OS", "Last Seen", "Severity"]
    rows=[]
    numberRows = 0

    print(
        "Listing hosts.\n"
    )

    for host in hosts_xml.xpath("asset"):
        try:
            # ip will always be there            
            ip = host.xpath("name/text()")[0]
            host_seendates = host.xpath("modification_time/text()")
            host_lastseen = host_seendates[0]
        
            # hostnames and other attributes may not be there  
            hostnames = host.xpath('identifiers/identifier/name[text()="hostname"]/../value/text()')
            if len(hostnames) == 0:
                hostname = "No hostname"
                continue
            else:
                hostname = hostnames[0]

            host_macs = host.xpath('identifiers/identifier/name[text()="MAC"]/../value/text()')
            if len(host_macs) == 0:
                host_mac = "NaN"
                continue
            else:
                host_mac = host_macs[0]

            host_severity = host.xpath('host/severity/value/text()')[0]
            if len(host_severity) == 0:
                host_severity = "NaN"
                continue

            host_os = host.xpath('host/detail/name[text()="best_os_txt"]/../value/text()')[0]
            if len(host_os) == 0:
                host_os = "Unknown"
                continue
        except GvmResponseError as gvmerr:
            continue

        # Count number of hosts
        numberRows = numberRows + 1
        # Cast/convert to text to show in list
        rowNumber = str(numberRows)
        rows.append([rowNumber, hostname, ip, host_mac, host_os, host_lastseen, host_severity])

    print(Table(heading=heading, rows=rows))

def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=undefined-variable

    # simply getting yesterday from midnight to midnight today
    from_date = (datetime.combine(datetime.today(), time.min) - timedelta(days=1))
    night_time = datetime.strptime('235959','%H%M%S').time()
    to_date = datetime.combine(datetime.now(), night_time) 
    #print(from_date, to_date)

    list_hosts(gmp, from_date, to_date)

if __name__ == "__gmp__":
    main(gmp, args)
