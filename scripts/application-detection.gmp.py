# SPDX-FileCopyrightText: 2017-2021 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
from argparse import Namespace

from gvm.protocols.gmp import Gmp


def check_args(args):
    len_args = len(args.script) - 1
    if len_args != 1:
        message = """
        This script will display all hosts with the searched applications!

        1. <application>  -- Name of the application

        Example:
            $ gvm-script --gmp-username name --gmp-password pass \
    ssh --hostname <gsm> scripts/application-detection.gmp.py <application>
        """
        print(message)
        sys.exit()


def print_assets(gmp, appname):
    res = gmp.get_reports(details=False)

    reports = res.xpath("/get_reports_response/report")
    for report in reports:
        report_id = report.attrib["id"]
        print_assets_for_host(gmp, appname, report_id)


def print_assets_for_host(gmp, appname, report_id):
    res = gmp.get_report(
        report_id, details=True, filter_string="rows=1 result_hosts_only=0"
    )

    hosts = res.xpath("/get_reports_response/report/report/host")

    for host in hosts:
        ip = host.xpath("ip/text()")
        if len(ip) == 0:
            continue
        else:
            ip = ip[0]

        hostname = host.xpath('detail/name[text()="hostname"]/../value/text()')
        if len(hostname) == 0:
            hostname = ""
        else:
            hostname = hostname[0]

        apps = host.xpath(
            'detail/name[text() = "App"]/../value['
            f'contains(text(), "{appname}")]/text()'
        )
        if len(apps) == 0:
            continue

        print(f"{ip} ({hostname})")
        for app in apps:
            print("\t" + app)
        print("\n")


def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=undefined-variable

    check_args(args)

    print_assets(gmp, args.script[1])


if __name__ == "__gmp__":
    main(gmp, args)
