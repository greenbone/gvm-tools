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

from uuid import UUID
from typing import List
from datetime import date, timedelta
from argparse import ArgumentParser, RawTextHelpFormatter

from gvmtools.helper import generate_uuid, error_and_exit

from lxml import etree as e

from gvm.xml import pretty_print

HELP_TEXT = ''


def get_last_reports_from_tasks(gmp, from_date, to_date, tags: List):
    """ Get the last reports from the tasks in the given time period """

    task_filter = 'rows=-1 '
    period_filter = 'created>{0} and created<{1}'.format(
        from_date.isoformat(), to_date.isoformat()
    )
    filter_parts = []
    if tags:
        for tag in tags:
            filter_parts.append('{} and {}'.format(period_filter, tag))

        tags_filter = ' or '.join(filter_parts)
        task_filter += tags_filter
    else:
        task_filter += period_filter

    print('Filtering the task with the filter term [{}]'.format(task_filter))

    tasks_xml = gmp.get_tasks(filter=task_filter)
    reports = []
    for report in tasks_xml.xpath('task/last_report/report/@id'):
        reports.append(str(report))

    # remove duplicates ... just in case
    reports = list(dict.fromkeys(reports))

    return reports


def combine_reports(gmp, reports: List, filter_term: str):
    """ Combining the filtered ports, results and hosts of the given report ids into one new report."""
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

    hosts = []
    for report in reports:
        current_report = gmp.get_report(
            report, filter=filter_term, details=True
        )[0]
        pretty_print(current_report.find('report').find('result_count'))
        for port in current_report.xpath('report/ports/port'):
            ports_elem.append(port)
        for result in current_report.xpath('report/results/result'):
            results_elem.append(result)
        for host in current_report.xpath('report/host'):
            report_elem.append(host)

    return combined_report


def send_report(gmp, combined_report, period_start, period_end):
    """Creating a container task and sending the combined report to the GSM

    gmp: the GMP object
    combined_report: the combined report xml object
    period_start: the start date
    period_end: the end date
    """

    task_name = 'Consolidated Report [{} - {}]'.format(period_start, period_end)

    res = gmp.create_container_task(
        name=task_name, comment='Created with gvm-tools.'
    )

    task_id = res.xpath('//@id')[0]

    combined_report = e.tostring(combined_report)

    res = gmp.import_report(combined_report, task_id=task_id)

    return res.xpath('//@id')[0]


def parse_tags(tags: List):
    """Parsing and validating the given tags

    tags (List): A list containing tags:
                 name, tag-id, name=value

    Returns a list containing tag="name", tag_id="id" ...
    """
    filter_tags = []
    for tag in tags:
        try:
            UUID(tag, version=4)
            filter_tags.append('tag_id="{}"'.format(tag))
        except ValueError:
            filter_tags.append('tag="{}"'.format(tag))

    return filter_tags


def parse_period(period: List):
    """Parsing and validating the given time period

    period (List): A list with two entries containing
                   dates in the format yyyy/mm/dd

    Returns two date-objects containing the passed dates
    """
    try:
        s_year, s_month, s_day = map(int, period[0].split('/'))
    except ValueError as e:
        error_and_exit(
            'Start date [{}] is not a correct date format:\n{}'.format(
                period[0], e.args[0]
            )
        )
    try:
        e_year, e_month, e_day = map(int, period[1].split('/'))
    except ValueError as e:
        error_and_exit(
            'End date [{}] is not a correct date format:\n{}'.format(
                period[1], e.args[0]
            )
        )

    try:
        period_start = date(s_year, s_month, s_day)
    except ValueError as e:
        error_and_exit('Start date: {}'.format(e.args[0]))

    try:
        period_end = date(e_year, e_month, e_day)
    except ValueError as e:
        error_and_exit('End date: {}'.format(e.args[0]))

    if period_end < period_start:
        error_and_exit('The start date seems to after the end date.')

    return period_start, period_end


def parse_args(args):  # pylint: disable=unused-argument
    """ Parsing args ... """

    parser = ArgumentParser(
        prefix_chars='+',
        add_help=False,
        formatter_class=RawTextHelpFormatter,
        description=HELP_TEXT,
    )

    parser.add_argument(
        '+h',
        '++help',
        action='help',
        help='Show this help message and exit.',
    )

    parser.add_argument(
        '+p',
        '++period',
        nargs=2,
        type=str,
        required=True,
        dest='period',
        help='Choose a time period that is filtering the tasks. Use the date format YYYY/MM/DD.',
    )

    parser.add_argument(
        '+t',
        '++tags',
        nargs='+',
        type=str,
        dest='tags',
        help=(
            'Filter the tasks by given tag(s).\n'
            'If you pass more than on tag, they will be concatenated with '
            or '\n'
            'You can pass tag names, tag ids or tag name=value to this argument'
        ),
    )

    parser.add_argument(
        '+f',
        '++filter',
        nargs='+',
        type=str,
        dest='filter',
        help='Filter the results by given filter(s).',
    )

    script_args, _ = parser.parse_known_args()
    return script_args


def main(gmp, args):
    # pylint: disable=undefined-variable

    parsed_args = parse_args(args)

    period_start, period_end = parse_period(parsed_args.period)

    print(
        'Combining reports from tasks within the time period [{}, {}]'.format(
            period_start, period_end
        )
    )

    filter_tags = None
    if parsed_args.tags:
        filter_tags = parse_tags(parsed_args.tags)

    reports = get_last_reports_from_tasks(
        gmp, period_start, period_end, filter_tags
    )

    print("Combining {} found reports.".format(len(reports)))

    filter_term = ''
    if parsed_args.filter:
        filter_term = ' '.join(parsed_args.filter)
        print(
            'Filtering the results by the following filter term [{}]'.format(
                filter_term
            )
        )
    else:
        print('No result filter given.')

    combined_report = combine_reports(gmp, reports, filter_term)

    send_report(gmp, combined_report, period_start, period_end)


if __name__ == '__gmp__':
    main(gmp, args)
