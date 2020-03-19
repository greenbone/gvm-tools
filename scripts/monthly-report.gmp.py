# -*- coding: utf-8 -*-
# Copyright (C) 2017-2019 Greenbone Networks GmbH
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

from datetime import date, timedelta

from terminaltables import AsciiTable


def check_args(args):
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
        quit()


def print_reports(gmp, args, from_date, to_date):
    report_filter = "rows=-1 and created>{0} and created<{1}".format(
        from_date.isoformat(), to_date.isoformat()
    )

    reports_xml = gmp.get_reports(filter=report_filter)
    report_list = reports_xml.xpath('report')

    sum_high = reports_xml.xpath(
        'sum(report/report/result_count/hole/full/' 'text())'
    )
    sum_medium = reports_xml.xpath(
        'sum(report/report/result_count/warning/' 'full/text())'
    )
    sum_low = reports_xml.xpath(
        'sum(report/report/result_count/info/full/' 'text())'
    )

    print('Found {0} reports'.format(len(report_list)))

    if 'with-tables' in args.script:
        for report in report_list:
            report_id = report.xpath('report/@id')[0]
            name = report.xpath('name/text()')[0]

            res = gmp.get_report(report_id)

            print('\nReport: {0}'.format(report_id))

            table_data = [
                ['Hostname', 'IP', 'Bericht', 'high', 'medium', 'low']
            ]

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
                host.clear()
                del host

            table = AsciiTable(table_data)
            print(table.table + '\n')
            res.clear()
            del res

    print(
        'Summary of results from {3} to {4}\nHigh: {0}\nMedium: {1}\nLow: '
        '{2}\n\n'.format(
            int(sum_high),
            int(sum_medium),
            int(sum_low),
            from_date.isoformat(),
            to_date.isoformat(),
        )
    )


def main(gmp, args):
    # pylint: disable=undefined-variable

    check_args(args)

    month = int(args.script[1])
    year = int(args.script[2])
    from_date = date(year, month, 1)
    to_date = from_date + timedelta(days=31)
    # To have the first day in month
    to_date = to_date.replace(day=1)

    print_reports(gmp, args, from_date, to_date)


if __name__ == '__gmp__':
    main(gmp, args)
