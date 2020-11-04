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
from pathlib import Path
from argparse import Namespace
from lxml import etree
from . import GmpMockFactory, load_module


CWD = Path(__file__).absolute().parent


class SendTargetTestCase(unittest.TestCase):
    def setUp(self):
        self.send_targets = load_module(
            Path(CWD.parent.parent / 'scripts'), 'send-targets'
        )

    @patch('gvm.protocols.latest.Gmp', new_callable=GmpMockFactory)
    def test_sent_target(self, mock_gmp: GmpMockFactory):
        target_xml_path = CWD / 'example_target.xml'
        target_xml_str = target_xml_path.read_text()

        mock_gmp.mock_response(
            'get_credentials',
            '<get_credentials_response status="200" status_text="OK">'
            '<credential id="6da5b7de-92ad-4dd2-8610-d5711b9c5937">'
            '</credential>'
            '<credential id="7802648d-1a31-4f69-bb30-00766a1ae1e6">'
            '</credential>'
            '<credential id="70a63257-4923-4bf4-a9bb-dd8b710b2d80">'
            '</credential>'
            '<credential id="2bac0c76-795e-4742-b17a-808a0ec8e409">'
            '</credential>'
            '</get_credentials_response>',
        )
        mock_gmp.mock_response(
            'create_target',
            '<create_target_response status="201" status_text="OK,'
            'resource created" id="6c9f73f5-f14c-42bf-ab44-edb8d2493dbc"/>',
        )

        target = etree.XML(target_xml_str)

        self.send_targets.parse_send_xml_tree(mock_gmp.gmp_protocol, target)

    @patch('builtins.input', lambda *args: 'n')
    @patch('gvm.protocols.latest.Gmp', new_callable=GmpMockFactory)
    def test_sent_target_no_credential(self, mock_gmp: GmpMockFactory):
        target_xml_path = CWD / 'example_target.xml'
        target_xml_str = target_xml_path.read_text()

        mock_gmp.mock_response(
            'get_credentials',
            '<get_credentials_response status="200" status_text="OK">'
            '<credential id="70a63257-4923-4bf4-a9bb-dd8b710b2d80">'
            '</credential>'
            '<credential id="2bac0c76-795e-4742-b17a-808a0ec8e409">'
            '</credential>'
            '</get_credentials_response>',
        )
        mock_gmp.mock_response(
            'create_target',
            '<create_target_response status="201" status_text="OK,'
            'resource created" id="6c9f73f5-f14c-42bf-ab44-edb8d2493dbc"/>',
        )

        target = etree.XML(target_xml_str)

        with self.assertRaises(SystemExit):
            self.send_targets.parse_send_xml_tree(mock_gmp.gmp_protocol, target)

    def test_args(self):
        args = Namespace(script=['foo'])
        with self.assertRaises(SystemExit):
            self.send_targets.check_args(args)

        args2 = Namespace(script=['foo', 'bar', 'baz'])

        with self.assertRaises(SystemExit):
            self.send_targets.check_args(args2)

    @patch('builtins.input', lambda *args: 'y')
    def test_yes(self):
        yes = self.send_targets.yes_or_no('foo?')
        self.assertTrue(yes)

    @patch('builtins.input', lambda *args: 'n')
    def test_no(self):
        no = self.send_targets.yes_or_no('bar?')
        self.assertFalse(no)

    def test_error_and_exit(self):
        with self.assertRaises(SystemExit):
            self.send_targets.error_and_exit('foo')

    def test_create_xml_tree(self):
        target_xml_path = CWD / 'example_target.xml'

        tree = self.send_targets.create_xml_tree(str(target_xml_path))
        self.assertIsInstance(
            tree, etree._Element  # pylint: disable=protected-access
        )
        self.assertEqual(tree.tag, 'get_targets_response')

    def test_create_xml_tree_invalid_file(self):
        target_xml_path = CWD / 'invalid_file.xml'

        with self.assertRaises(SystemExit):
            with self.assertRaises(OSError):
                self.send_targets.create_xml_tree(str(target_xml_path))

    def test_create_xml_tree_invalid_xml(self):
        target_xml_path = CWD / 'invalid_xml.xml'

        with self.assertRaises(SystemExit):
            with self.assertRaises(etree.Error):
                self.send_targets.create_xml_tree(str(target_xml_path))
