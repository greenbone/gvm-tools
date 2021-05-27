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
from typing import List, Tuple
from datetime import date
from argparse import ArgumentParser, Namespace, RawTextHelpFormatter
from lxml import etree as e
from gvm.protocols.gmp import Gmp
from gvm.errors import GvmError

from gvmtools.helper import generate_uuid, error_and_exit

HELP_TEXT = (
    'This script creates a consolidated report and imports it to the GSM. '
    'You are able to set a time period. Within this period the last report'
    'of all tasks will be consolidated. You can additionally filter the '
    'tasks by one or more tags and the results with a filter id or filter '
    'term.\n'
    ' Usable with gvm-script (gvm-tools). Help: gvm-script -h'
)


def parse_tags(tags: List[str]) -> List[str]:
    """Parsing and validating the given tags

    tags (List): A list containing tags:
                 name, tag-id, name=value

    Returns a list containing tag="name", tag_id="id" ...
    """
    filter_tags = []
    for tag in tags:
        try:
            UUID(tag, version=4)
            filter_tags.append(f'tag_id="{tag}"')
        except ValueError:
            filter_tags.append(f'tag="{tag}"')

    return filter_tags


def parse_period(period: List[str]) -> Tuple[date, date]:
    """Parsing and validating the given time period

    period (List): A list with two entries containing
                   dates in the format yyyy/mm/dd

    Returns two date-objects containing the passed dates
    """
    try:
        s_year, s_month, s_day = map(int, period[0].split('/'))
    except ValueError as e:
        error_and_exit(
            f'Start date [{period[0]}] is not a '
            f'correct date format:\n{e.args[0]}.'
        )
    try:
        e_year, e_month, e_day = map(int, period[1].split('/'))
    except ValueError as e:
        error_and_exit(
            f'End date [{period[1]}] is not '
            f'a correct date format:\n{e.args[0]}.'
        )

    try:
        period_start = date(s_year, s_month, s_day)
    except ValueError as e:
        error_and_exit(f'Start date: {e.args[0]}')

    try:
        period_end = date(e_year, e_month, e_day)
    except ValueError as e:
        error_and_exit(f'End date: {e.args[0]}')

    if period_end < period_start:
        error_and_exit('The start date seems to after the end date.')

    return period_start, period_end


def parse_args(args: Namespace) -> Namespace:  # pylint: disable=unused-argument
    """Parsing args ..."""

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
        help=(
            'Choose a time period that is filtering the tasks.\n'
            'Use the date format YYYY/MM/DD.'
        ),
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

    filter_args = parser.add_mutually_exclusive_group()

    filter_args.add_argument(
        '++filter-terms',
        nargs='+',
        type=str,
        dest='filter_term',
        help='Filter the results by given filter terms.',
    )

    filter_args.add_argument(
        '++filter-id',
        type=str,
        dest='filter_id',
        help='Filter the results by given filter id.',
    )

    script_args, _ = parser.parse_known_args()
    return script_args


def generate_task_filter(
    period_start: date, period_end: date, tags: List[str]
) -> str:
    """Generate the tasks filter

    period_start: the start date
    period_end: the end date
    tags: list of tags for the filter

    Returns an task filter string
    """
    task_filter = 'rows=-1 '

    # last is for the timestamp of the last report in that task
    period_filter = (
        f'last>{period_start.isoformat()} ' f'and last<{period_end.isoformat()}'
    )
    filter_parts = []
    if tags:
        for tag in tags:
            filter_parts.append(f'{period_filter} and {tag}')

        tags_filter = ' or '.join(filter_parts)
        task_filter += tags_filter
    else:
        task_filter += period_filter

    return task_filter


def get_last_reports_from_tasks(gmp: Gmp, task_filter: str) -> List[str]:
    """Get the last reports from the tasks in the given time period

    gmp: the GMP object
    task_filter: task filter string

    """

    print(f'Filtering the task with the filter term [{task_filter}]')

    tasks_xml = gmp.get_tasks(filter_string=task_filter)
    reports = []
    for report in tasks_xml.xpath('task/last_report/report/@id'):
        reports.append(str(report))

    # remove duplicates ... just in case
    reports = list(dict.fromkeys(reports))

    return reports


def combine_reports(
    gmp: Gmp, reports: List[str], filter_term: str, filter_id: str
) -> e.Element:
    """Combining the filtered ports, results and hosts of the given
    report ids into one new report.

    gmp: the GMP object
    reports (List): List of report_ids
    filter_term (str): the result filter string
    """

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
    report_elem.append(ports_elem)
    report_elem.append(results_elem)

    for report in reports:
        try:
            if filter_id:
                current_report = gmp.get_report(
                    report,
                    filter_id=filter_id,
                    details=True,
                    ignore_pagination=True,
                ).find('report')
            else:
                current_report = gmp.get_report(
                    report,
                    filter_string=filter_term,
                    details=True,
                    ignore_pagination=True,
                ).find('report')
        except GvmError:
            print(f"Could not find the report [{report}]")
        for port in current_report.xpath('report/ports/port'):
            ports_elem.append(port)
        for result in current_report.xpath('report/results/result'):
            results_elem.append(result)
        for host in current_report.xpath('report/host'):
            report_elem.append(host)

    return combined_report


def send_report(
    gmp: Gmp, combined_report: e.Element, period_start: date, period_end: date
) -> str:
    """Creating a container task and sending the combined report to the GSM

    gmp: the GMP object
    combined_report: the combined report xml object
    period_start: the start date
    period_end: the end date
    """

    task_name = f'Consolidated Report [{period_start} - {period_end}]'

    res = gmp.create_container_task(
        name=task_name, comment='Created with gvm-tools.'
    )

    task_id = res.xpath('//@id')[0]

    combined_report = e.tostring(combined_report)

    res = gmp.import_report(combined_report, task_id=task_id, in_assets=True)

    return res.xpath('//@id')[0]


def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=undefined-variable

    parsed_args = parse_args(args=args)

    period_start, period_end = parse_period(period=parsed_args.period)

    print(
        'Combining reports from tasks within the '
        f'time period [{period_start}, {period_end}]'
    )

    # Generate Task Filter
    filter_tags = None
    if parsed_args.tags:
        filter_tags = parse_tags(tags=parsed_args.tags)

    task_filter = generate_task_filter(
        period_start=period_start,
        period_end=period_end,
        tags=filter_tags,
    )

    # Find reports
    reports = get_last_reports_from_tasks(gmp=gmp, task_filter=task_filter)

    print("Combining {len(reports)} found reports.")

    filter_term = ''
    if parsed_args.filter_term:
        filter_term = ' '.join(parsed_args.filter_term)
        print(
            'Filtering the results by the '
            f'following filter term [{filter_term}]'
        )
    elif parsed_args.filter_id:
        try:
            filter_xml = gmp.get_filter(filter_id=parsed_args.filter_id).find(
                'filter'
            )
            filter_term = filter_xml.find('term').text
            print(
                'Filtering the results by the following filter term '
                f'[{filter_term}]'
            )
        except GvmError:
            print(
                "Filter with the ID [{parsed_args.filter_id}] is not existing."
            )
    else:
        print('No results filter given.')

    # Combine the reports
    combined_report = combine_reports(
        gmp=gmp,
        reports=reports,
        filter_term=filter_term,
        filter_id=parsed_args.filter_id,
    )

    # Import the generated report to GSM
    report = send_report(
        gmp=gmp,
        combined_report=combined_report,
        period_start=period_start,
        period_end=period_end,
    )

    print(f"Successfully imported new consolidated report [{report}]")


if __name__ == '__gmp__':
    main(gmp, args)
