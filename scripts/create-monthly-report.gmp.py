# -*- coding: utf-8 -*-
# Copyright (C) 2021 Greenbone Networks GmbH
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

from argparse import ArgumentParser, RawTextHelpFormatter

HELP_TEXT = ""


def get_last_reports_from_tasks(gmp, from_date, to_date):
    task_filter = "rows=-1 and created>{0} and created<{1}".format(
        from_date.isoformat(), to_date.isoformat()
    )

    tasks_xml = gmp.get_tasks(filter=task_filter)
    for report in tasks_xml.xpath('task/last_report/report/@id'):
        print(report)


def combine_reports(gmp, args):
    new_uuid = generate_uuid()
    combined_report = e.Element(
        'report',
        {
            'id': new_uuid,
            'format_id': 'd5da9f67-8551-4e51-807b-b6a873d70e34',
            'extension': 'xml',
            'content_type': 'text/xml',
        },
    )
    report_elem = e.Element('report', {'id': new_uuid})
    ports_elem = e.Element('ports', {'start': '1', 'max': '-1'})
    results_elem = e.Element('results', {'start': '1', 'max': '-1'})
    combined_report.append(report_elem)
    report_elem.append(results_elem)

    if 'first_task' in args.script:
        arg_len = args.script[1:-1]
    else:
        arg_len = args.script[1:]

    hosts = []
    for argument in arg_len:
        current_report = gmp.get_report(argument, details=True)[0]
        for port in current_report.xpath('report/ports/port'):
            ports_elem.append(port)
        for result in current_report.xpath('report/results/result'):
            results_elem.append(result)
        for host in current_report.xpath('report/host'):
            report_elem.append(host)

    return combined_report


def parse_args(args):  # pylint: disable=unused-argument
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
        "+d",
        "++date",
        type=str,
        required=True,
        dest="date",
        help="The month and year to collect reports from: (mm/yyyy)",
    )

    parser.add_argument(
        "+t",
        "++tags",
        nargs='+',
        type=str,
        dest="tags",
        help="Filter the reports by given tag(s).",
    )

    script_args, _ = parser.parse_known_args()
    return script_args


def main(gmp, args):
    # pylint: disable=undefined-variable

    parsed_args = parse_args(args)

    month, year = parsed_args.date.split('/')
    from_date = date(int(year), int(month), 1)
    to_date = from_date + timedelta(days=31)
    # To have the first day in month
    to_date = to_date.replace(day=1)

    print(from_date)
    print(to_date)

    get_last_reports_from_tasks(gmp, from_date, to_date)


if __name__ == '__gmp__':
    main(gmp, args)
