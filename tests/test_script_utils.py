# -*- coding: utf-8 -*-
# Copyright (C) 2020 Greenbone Networks GmbH
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

import unittest
from unittest.mock import patch
from io import BytesIO
from pathlib import Path
from lxml import etree

from gvmtools.script_utils import create_xml_tree, error_and_exit, yes_or_no

CWD = Path(__file__).absolute().parent


class ScriptUtilsTestCase(unittest.TestCase):
    @patch('builtins.input', lambda *args: 'y')
    def test_yes(self):
        yes = yes_or_no('foo?')
        self.assertTrue(yes)

    @patch('builtins.input', lambda *args: 'n')
    def test_no(self):
        no = yes_or_no('bar?')
        self.assertFalse(no)

    def test_error_and_exit(self):
        with self.assertRaises(SystemExit):
            error_and_exit('foo')

    def test_create_xml_tree(self):
        tree = create_xml_tree(BytesIO(b'<foo><baz/><bar>glurp</bar></foo>'))
        self.assertIsInstance(
            tree, etree._Element  # pylint: disable=protected-access
        )
        self.assertEqual(tree.tag, 'foo')

    def test_create_xml_tree_invalid_file(self):
        target_xml_path = CWD / 'invalid_file.xml'

        with self.assertRaises(SystemExit):
            with self.assertRaises(OSError):
                create_xml_tree(str(target_xml_path))

    def test_create_xml_tree_invalid_xml(self):
        with self.assertRaises(SystemExit):
            with self.assertRaises(etree.Error):
                create_xml_tree(BytesIO(b'<foo><baz/><bar>glurp<bar></foo>'))
