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
import os
import sys

from gvm.errors import GvmError
from gvm.xml import pretty_print


__all__ = ['authenticate', 'pretty_print', 'run_script']


class Table:
    def __init__(self, heading=None, rows=None, divider=' | '):
        self.heading = heading or []
        self.rows = rows or []
        self.divider = divider

    def _calculate_dimensions(self):
        column_sizes = []

        for column in self.heading:
            column_sizes.append(len(column))

        for row in self.rows:
            for i, column in enumerate(row):
                dim = column_sizes[i]
                column_size = len(column)

                if dim < column_size:
                    column_sizes[i] = column_size

        return column_sizes

    def _create_column(self, column, size):
        return '{}{}'.format(column, ' ' * (size - len(column)))

    def _create_row(self, columns):
        return self.divider.join(columns)

    def __str__(self):
        column_sizes = self._calculate_dimensions()

        row_strings = []

        heading_columns = []
        heading_divider_columns = []

        for i, column in enumerate(self.heading):
            column_size = column_sizes[i]

            heading_columns.append(self._create_column(column, column_size))
            heading_divider_columns.append(
                self._create_column('-' * column_size, column_size)
            )

        row_strings.append(self._create_row(heading_columns))
        row_strings.append(self._create_row(heading_divider_columns))

        for row in self.rows:
            row_columns = []

            for i, column in enumerate(row):
                column_size = column_sizes[i]
                row_columns.append(self._create_column(column, column_size))

            row_strings.append(self._create_row(row_columns))

        return "\n".join(row_strings)


def do_not_run_as_root():
    if hasattr(os, 'geteuid') and os.geteuid() == 0:
        raise RuntimeError('This tool MUST NOT be run as root user.')


def authenticate(gmp, username=None, password=None):
    """Authentication helper

    Tries to get authentication username and password from arguments and if not
    present asks the username and/or password from the terminal.

    Arguments:
        gmp: A protocol instance
        username (:obj:`str`, optional): Username to authenticate with. If None,
            username will be read from terminal.
        password (:obj:`str`, optional): Password to authenticate with. If None,
            password will be read from the terminal.

    Returns:
        tuple: (username, password) tuple

    Raises:
        GmpError: Raises GmpError if authentication fails.
    """
    if gmp.is_authenticated():
        return

    # Ask for login credentials if none are given.
    if not username:
        while username is None or len(username) == 0:
            username = input('Enter username: ')

    if not password:
        password = getpass.getpass('Enter password for {0}: '.format(username))

    try:
        gmp.authenticate(username, password)
        return (username, password)
    except GvmError as e:
        print('Could not authenticate. Please check your credentials.')
        raise e


def run_script(path, global_vars):
    """Loads and executes a file as a python script

    Arguments:
        path (str): Path to the script file
        vars (dict): Variables passed as globals to the script
    """
    try:
        file = open(path, 'r', newline='').read()
    except FileNotFoundError:
        print('Script {path} does not exist'.format(path=path), file=sys.stderr)
        sys.exit(2)

    exec(file, global_vars)  # pylint: disable=exec-used
