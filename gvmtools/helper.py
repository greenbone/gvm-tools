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
        while len(username) == 0:
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
