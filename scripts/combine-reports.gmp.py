# -*- coding: utf-8 -*-
# Copyright (C) 2018-2019 Greenbone Networks GmbH
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

import uuid
import time

from lxml import etree as e


def check_args(args):
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
        quit(1)


def generate_uuid():
    return str(uuid.uuid4())


def gen_combined_report(gmp, args):
    id_assign = str(generate_uuid())
    report = e.Element(
        'report',
        {
            'id': id_assign,
            'format_id': 'd5da9f67-8551-4e51-807b-b6a873d70e34',
            'extension': 'xml',
            'content_type': 'text/xml',
        },
    )
    report_elem = e.Element('report', {'id': id_assign})
    results_elem = e.Element('results', {'start': '1', 'max': '-1'})
    report.append(report_elem)
    report_elem.append(results_elem)

    if 'first_task' in args.script:
        arg_len = args.script[1:-1]
    else:
        arg_len = args.script[1:]
    for argument in arg_len:
        current_report = gmp.get_report(argument)[0]
        for result in current_report.xpath('report/results/result'):
            results_elem.append(result)

    send_report(gmp, args, report)


def send_report(gmp, args, report):
    if 'first_task' in args.script:
        main_report = gmp.get_report(args.script[1])[0]
        task_id = main_report.xpath('//task/@id')[0]
        task_name = ''
    else:
        the_time = time.strftime("%Y/%m/%d-%H:%M:%S")
        task_id = ''
        task_name = "Combined_Report_{}".format(the_time)

    report = e.tostring(report)

    gmp.import_report(report, task_id=task_id, task_name=task_name)


def main(gmp, args):
    # pylint: disable=undefined-variable

    check_args(args)

    gen_combined_report(gmp, args)


if __name__ == '__gmp__':
    main(gmp, args)
