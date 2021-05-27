# -*- coding: utf-8 -*-
# Copyright (C) 2018-2021 Greenbone Networks GmbH
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
from argparse import ArgumentParser, Namespace, RawTextHelpFormatter
from gvm.protocols.gmp import Gmp

from gvmtools.helper import create_xml_tree, error_and_exit, yes_or_no

HELP_TEXT = """
        This script pulls tasks data from an xml document and feeds it to \
            a desired GSM
        Usage examples: 
            $ gvm-script --gmp-username name --gmp-password pass ssh --hostname
            ... send-task.gmp.py +h
            ... send-task.gmp.py ++x xml_file
    """


def numerical_option(statement, list_range):
    choice = int(input(statement))

    if choice in range(1, list_range + 1):
        return choice
    else:
        return numerical_option(
            "Please enter valid number from {} to {}...".format(1, list_range),
            list_range,
        )


def interactive_options(gmp, task, keywords):
    options_dict = {}
    options_dict['config'] = gmp.get_scan_configs()
    options_dict['scanner'] = gmp.get_scanners()
    options_dict['target'] = gmp.get_targets()

    for option in options_dict:
        object_dict, object_list = {}, []
        object_id = task.find(option).get('id')
        object_xml = options_dict[option]

        for i in object_xml.findall(option):
            object_dict[i.find('name').text] = i.xpath('@id')[0]
            object_list.append(i.find('name').text)

        if object_id in object_dict.values():
            keywords['{}_id'.format(option)] = object_id
        elif object_id not in object_dict.values() and len(object_dict) != 0:
            response = yes_or_no(
                "\nRequired Field: failed to detect {}_id: {}... "
                "\nWould you like to select from available options, or exit "
                "the script?".format(
                    option, task.xpath('{}/@id'.format(option))[0]
                )
            )

            if response is True:
                counter = 1
                print("{} options:".format(option.capitalize()))
                for j in object_list:
                    print("    {} - {}".format(counter, j))
                    counter += 1
                answer = numerical_option(
                    "\nPlease enter the number of your choice.",
                    len(object_list),
                )
                keywords['{}_id'.format(option)] = object_dict[
                    object_list[answer - 1]
                ]
            else:
                print("\nTerminating...")
                sys.exit()
        else:
            error_and_exit(
                "Failed to detect {}_id"
                "\nThis field is required therefore the script is unable to "
                "continue.\n".format(option)
            )


def parse_send_xml_tree(gmp, xml_tree):
    task_xml_elements = xml_tree.xpath('task')
    print(task_xml_elements)
    if not task_xml_elements:
        error_and_exit("No tasks found.")
    tasks = []
    for task in task_xml_elements:
        keywords = {'name': task.find('name').text}

        if task.find('comment').text is not None:
            keywords['comment'] = task.find('comment').text

        interactive_options(gmp, task, keywords)

        if task.find('schedule_periods') is not None:
            keywords['schedule_periods'] = int(
                task.find('schedule_periods').text
            )

        if task.find('observers').text:
            keywords['observers'] = task.find('observers').text

        if task.xpath('schedule/@id')[0]:
            keywords['schedule_id'] = task.xpath('schedule/@id')[0]

        if task.xpath('preferences/preference'):
            preferences, scanner_name_list, value_list = {}, [], []

            for preference in task.xpath('preferences/preference'):
                scanner_name_list.append(preference.find('scanner_name').text)
                if preference.find('value').text is not None:
                    value_list.append(preference.find('value').text)
                else:
                    value_list.append('')
            preferences['scanner_name'] = scanner_name_list
            preferences['value'] = value_list
            keywords['preferences'] = preferences

        new_task = gmp.create_task(**keywords)

        tasks.append(new_task.xpath('//@id')[0])
    return tasks


def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=undefined-variable, unused-argument

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
        "+x",
        "++xml-file",
        dest='xml',
        type=str,
        required=True,
        help='xml file containing tasks',
    )

    script_args, _ = parser.parse_known_args()

    # check_args(args)

    print('\nSending task(s)...')

    xml_tree = create_xml_tree(script_args.xml)
    tasks = parse_send_xml_tree(gmp, xml_tree)
    for task in tasks:
        print(task)
    print('\nTask(s) sent!\n')


if __name__ == '__gmp__':
    main(gmp, args)  # pylint: disable=undefined-variable
