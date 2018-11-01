# -*- coding: utf-8 -*-
# Copyright (C) 2018 Greenbone Networks GmbH
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

import getpass

from lxml import etree

from gmp.errors import GmpError


def authenticate(gmp, args):
    """Authentication helper

    Tries to get authentication username and password from args and if not
    present asks the username and/or password from the terminal.

    Attributes:
        gmp: A protocol instance
        args: The parsed arguments

    Raises:
        GmpError: Raises GmpError if authentication fails.
    """
    if gmp.is_authenticated():
        return

    username = args.gmp_username
    password = args.gmp_password

    # Ask for login credentials if none are given.
    if not username:
        while len(username) == 0:
            username = input('Enter username: ')

    if not password:
        password = getpass.getpass(
            'Enter password for {0}: '.format(username))

    try:
        gmp.authenticate(username, password)
    except GmpError as e:
        print('Could not authenticate. Please check your credentials.')
        raise e


def pretty_print(xml):
    """Prints beautiful XML-Code

    This function gets an object of list<lxml.etree._Element>
    or directly a lxml element.
    Print it with good readable format.

    Arguments:
        xml: List<lxml.etree.Element> or directly a lxml element
    """
    if isinstance(xml, list):
        for item in xml:
            if etree.iselement(item):
                print(etree.tostring(item, pretty_print=True).decode('utf-8'))
            else:
                print(item)
    elif etree.iselement(xml):
        print(etree.tostring(xml, pretty_print=True).decode('utf-8'))
