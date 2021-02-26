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

import time
import sys

from argparse import Namespace
from lxml import etree as e
from gvm.protocols.gmp import Gmp

from gvmtools.helper import generate_uuid


def check_args(args: Namespace) -> None:
    len_args = len(args.script) - 1
    if len_args < 2:
        message = """
        This script will combine desired reports into a single report. \
    The combined report will then be sent to a desired container task. \
    This script will create a container task for the combined report to\
    be sent to, however, if you would like the report to be sent to an \
    existing task, place the report of the desired task first and add  \
    the argument 'first_task'.

        1. <report_1_uuid> --uuid of report to be combined
        2. <report_2_uuid> --uuid of report to be combined
        ...
        n. <report_n_uuid> --uuid of report to be combined

        Example for starting up the routine:
            $ gvm-script --gmp-username=namessh --gmp-password=pass ssh --hostname=hostname  \
     scripts/combine-reports.gmp.py \
    "d15a337c-56f3-4208-a462-afeb79eb03b7" \
    "303fa0a6-aa9b-43c4-bac0-66ae0b2d1698" 'first_task'

        """
        print(message)
        sys.exit()


def combine_reports(gmp: Gmp, args: Namespace) -> e.Element:
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

    for argument in arg_len:
        current_report = gmp.get_report(
            argument, details=True, ignore_pagination=True
        )[0]
        for port in current_report.xpath('report/ports/port'):
            ports_elem.append(port)
        for result in current_report.xpath('report/results/result'):
            results_elem.append(result)
        for host in current_report.xpath('report/host'):
            report_elem.append(host)

    return combined_report


def send_report(gmp: Gmp, args: Namespace, combined_report: e.Element) -> str:
    if 'first_task' in args.script:
        main_report = gmp.get_report(args.script[1])[0]
        task_id = main_report.xpath('//task/@id')[0]
    else:
        the_time = time.strftime("%Y/%m/%d-%H:%M:%S")
        task_id = ''
        task_name = "Combined_Report_{}".format(the_time)

        res = gmp.create_container_task(
            name=task_name, comment="Created with gvm-tools."
        )

        task_id = res.xpath('//@id')[0]

    combined_report = e.tostring(combined_report)

    res = gmp.import_report(combined_report, task_id=task_id, in_assets=True)

    return res.xpath('//@id')[0]


def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=undefined-variable

    check_args(args)

    combined_report = combine_reports(gmp, args)
    send_report(gmp, args, combined_report)


if __name__ == '__gmp__':
    main(gmp, args)
