# -*- coding: utf-8 -*-
# Copyright (C) 2017-2021 Greenbone Networks GmbH
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

import sys
from argparse import Namespace
from datetime import date, timedelta
from lxml.etree import Element
from gvm.protocols.gmp import Gmp

from terminaltables import AsciiTable


def check_args(args: Namespace) -> None:
    len_args = len(args.script) - 1
    if len_args < 2:
        message = """
        This script will display all vulnerabilities from the hosts of the
        reports in a given month!
        
        1. <month>  -- month of the monthly report
        2. <year>   -- year of the monthly report

        The third is 'with-tables' parameter to activate a verbose output of
        hosts. Explicitly made for GOS 3.1.

        Example:
            $ gvm-script --gmp-username name --gmp-password pass \
    ssh --hostname <gsm> scripts/monthly-report.gmp.py 05 2017 with-tables
        """
        print(message)
        sys.exit()


def get_reports_xml(gmp: Gmp, from_date: date, to_date: date) -> Element:
    """Getting the Reports in the defined time period"""

    report_filter = (
        f'rows=-1 created>{from_date.isoformat()} and '
        f'created<{to_date.isoformat()}'
    )

    return gmp.get_reports(filter_string=report_filter)


def print_result_sums(
    reports_xml: Element, from_date: date, to_date: date
) -> None:
    report_count = len(reports_xml.xpath('report'))
    print(f'Found {report_count} reports')

    sum_high = reports_xml.xpath(
        'sum(report/report/result_count/hole/full/text())'
    )
    sum_medium = reports_xml.xpath(
        'sum(report/report/result_count/warning/full/text())'
    )
    sum_low = reports_xml.xpath(
        'sum(report/report/result_count/info/full/text())'
    )

    print(
        f'Summary of results from {from_date.isoformat()} '
        f'to {to_date.isoformat()}'
    )
    print(f'High: {int(sum_high)}')
    print(f'Medium: {int(sum_medium)}')
    print(f'Low: {int(sum_low)}')


def print_result_tables(gmp: Gmp, reports_xml: Element) -> None:
    report_list = reports_xml.xpath('report')

    for report in report_list:
        report_id = report.xpath('report/@id')[0]
        name = report.xpath('name/text()')[0]

        res = gmp.get_report(report_id)

        print(f'\nReport: {report_id}')

        table_data = [['Hostname', 'IP', 'Bericht', 'high', 'medium', 'low']]

        for host in res.xpath('report/report/host'):
            hostname = host.xpath(
                'detail/name[text()="hostname"]/../' 'value/text()'
            )
            if len(hostname) > 0:
                hostname = str(hostname[0])
            else:
                hostname = ""

            ip = host.xpath('ip/text()')[0]
            high = host.xpath('result_count/hole/page/text()')[0]
            medium = host.xpath('result_count/warning/page/text()')[0]
            low = host.xpath('result_count/info/page/text()')[0]

            table_data.append([hostname, ip, name, high, medium, low])

        table = AsciiTable(table_data)
        print(table.table + '\n')


def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=undefined-variable

    check_args(args)

    month = int(args.script[1])
    year = int(args.script[2])
    from_date = date(year, month, 1)
    to_date = from_date + timedelta(days=31)
    # To have the first day in month
    to_date = to_date.replace(day=1)

    reports_xml = get_reports_xml(gmp, from_date, to_date)

    print_result_sums(reports_xml, from_date, to_date)
    if "with-tables" in args.script:
        print_result_tables(gmp, reports_xml)


if __name__ == '__gmp__':
    main(gmp, args)
