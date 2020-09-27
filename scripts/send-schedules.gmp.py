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

import sys

from lxml import etree as e


def check_args(args):
    len_args = len(args.script) - 1
    if len_args != 1:
        message = """
        This script pulls schedule data from an xml document and feeds it to \
    a desired GSM
        One parameter after the script name is required.

        1. <xml_doc>  -- .xml file containing schedules

        Example:
            $ gvm-script --gmp-username name --gmp-password pass \
    ssh --hostname <gsm> scripts/send-schedules.gmp.py example_file.xml

        """
        print(message)
        quit()
    if int(gmp.get_protocol_version()[0]) < 8:
        print("This script requires GMP version 8")
        quit()


def error_and_exit(msg):
    print("Error: {}\n".format(msg), file=sys.stderr)
    sys.exit(1)


def create_xml_tree(xml_doc):
    try:
        xml_tree = e.parse(xml_doc)
        xml_tree = e.tostring(xml_tree)
        xml_tree = e.XML(xml_tree)
    except IOError as err:
        error_and_exit("Failed to read xml_file: {} (exit)".format(str(err)))

    if len(xml_tree) == 0:
        error_and_exit("XML file is empty (exit)")

    return xml_tree


def parse_send_xml_tree(gmp, xml_tree):
    for schedule in xml_tree.xpath('schedule'):
        name = schedule.find('name').text

        comment = schedule.find('comment').text
        if comment is None:
            comment = ''

        ical = schedule.find('icalendar').text

        timezone = schedule.find('timezone_abbrev').text
        if timezone is None:
            timezone = schedule.find('timezone').text

        gmp.create_schedule(
            name=name, comment=comment, timezone=timezone, icalendar=ical
        )


def main(gmp, args):
    # pylint: disable=undefined-variable

    check_args(args)

    xml_doc = args.script[1]

    print('\nSending schedules...')

    xml_tree = create_xml_tree(xml_doc)
    parse_send_xml_tree(gmp, xml_tree)

    print('\n  Schedule(s) created!\n')


if __name__ == '__gmp__':
    main(gmp, args)
