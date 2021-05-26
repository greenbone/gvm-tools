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
from lxml.etree import Element
from gvm.protocols.gmp import Gmp

from gvmtools.helper import create_xml_tree


def check_args(gmp: Gmp, args: Namespace) -> None:
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
        sys.exit()
    major, minor = gmp.get_protocol_version()
    if major < 21 and minor < 5:
        print(f"This script requires GMP version {major}.{minor}")
        sys.exit()


def parse_send_xml_tree(gmp: Gmp, xml_tree: Element) -> None:
    for schedule in xml_tree.xpath('schedule'):
        name = schedule.find('name').text

        comment = schedule.find('comment').text
        if comment is None:
            comment = ''

        ical = schedule.find('icalendar').text

        timezone = schedule.find('timezone').text

        gmp.create_schedule(
            name=name, comment=comment, timezone=timezone, icalendar=ical
        )


def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=undefined-variable

    check_args(gmp=gmp, args=args)

    xml_doc = args.script[1]

    print('\nSending schedules...')

    xml_tree = create_xml_tree(xml_doc)
    parse_send_xml_tree(gmp, xml_tree)

    print('\n  Schedule(s) created!\n')


if __name__ == '__gmp__':
    main(gmp, args)
