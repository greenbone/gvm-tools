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
import importlib
from unittest.mock import patch, MagicMock
from pathlib import Path
from argparse import Namespace
from lxml import etree

CWD = Path(__file__).absolute().parent


class SendTargetTestCase(unittest.TestCase):
    def setUp(self):
        self.send_targets = importlib.import_module(
            'scripts.send-targets', 'gvmtools'
        )

    def test_sent_target(self):
        target_xml_path = CWD / 'example_target.xml'
        target_xml_str = target_xml_path.read_text()
        gmp = self.create_gmp_mock()

        target = etree.XML(target_xml_str)

        self.send_targets.parse_send_xml_tree(gmp, target)

    def create_gmp_mock(self):
        mock_gmp = MagicMock()
        credentials = etree.XML(
            """
<get_credentials_response status="200" status_text="OK">
    <credential id="6da5b7de-92ad-4dd2-8610-d5711b9c5937">
        <owner>
            <name>jloechte</name>
        </owner>
        <name>test_</name>
        <comment>comm</comment>
        <creation_time>2020-09-17T07:34:32Z</creation_time>
        <modification_time>2020-09-30T00:46:44Z</modification_time>
        <writable>1</writable>
        <in_use>1</in_use>
        <permissions>
            <permission>
                <name>Everything</name>
            </permission>
        </permissions>
        <allow_insecure>0</allow_insecure>
        <login>sdfsdf</login>
        <type>up</type>
        <full_type>username + password</full_type>
        <formats>
            <format>exe</format>
        </formats>
    </credential>
    <credential id="7802648d-1a31-4f69-bb30-00766a1ae1e6">
        <owner>
            <name>jloechte</name>
        </owner>
        <name>Unnamed</name>
        <comment></comment>
        <creation_time>2020-09-29T20:44:49Z</creation_time>
        <modification_time>2020-09-29T20:45:00Z</modification_time>
        <writable>1</writable>
        <in_use>1</in_use>
        <permissions>
            <permission>
                <name>Everything</name>
            </permission>
        </permissions>
        <allow_insecure>0</allow_insecure>
        <login>rterte</login>
        <type>usk</type>
        <full_type>username + SSH key</full_type>
        <formats>
            <format>key</format>
            <format>rpm</format>
            <format>deb</format>
        </formats>
    </credential>
    <credential id="70a63257-4923-4bf4-a9bb-dd8b710b2d80">
        <owner>
            <name>jloechte</name>
        </owner>
        <name>Unnamedas</name>
        <comment></comment>
        <creation_time>2020-09-29T21:31:50Z</creation_time>
        <modification_time>2020-09-29T21:32:57Z</modification_time>
        <writable>1</writable>
        <in_use>0</in_use>
        <permissions>
            <permission>
                <name>Everything</name>
            </permission>
        </permissions>
        <allow_insecure>0</allow_insecure>
        <login>abc</login>
        <type>snmp</type>
        <full_type>SNMP</full_type>
        <formats></formats>
        <auth_algorithm>sha1</auth_algorithm>
        <privacy>
            <algorithm>des</algorithm>
        </privacy>
    </credential>
    <credential id="2bac0c76-795e-4742-b17a-808a0ec8e409">
        <owner>
            <name>jloechte</name>
        </owner>
        <name>work</name>
        <comment>test</comment>
        <creation_time>2020-08-18T18:35:04Z</creation_time>
        <modification_time>2020-09-29T20:43:16Z</modification_time>
        <writable>1</writable>
        <in_use>1</in_use>
        <permissions>
            <permission>
                <name>Everything</name>
            </permission>
        </permissions>
        <allow_insecure>0</allow_insecure>
        <login>jloechte</login>
        <type>up</type>
        <full_type>username + password</full_type>
        <formats>
            <format>exe</format>
        </formats>
    </credential>
    <filters id="">
        <term>first=1 rows=10 sort=name</term>
        <keywords>
            <keyword>
                <column>first</column>
                <relation>=</relation>
                <value>1</value>
            </keyword>
            <keyword>
                <column>rows</column>
                <relation>=</relation>
                <value>10</value>
            </keyword>
            <keyword>
                <column>sort</column>
                <relation>=</relation>
                <value>name</value>
            </keyword>
        </keywords>
    </filters>
    <sort>
        <field>name<order>ascending</order>
        </field>
    </sort>
    <credentials start="1" max="-2"/>
    <credential_count>4<filtered>4</filtered>
        <page>4</page>
    </credential_count>
</get_credentials_response>
        """
        )
        mock_gmp.get_credentials = MagicMock(return_value=credentials)
        target = etree.XML(
            """<create_target_response status="201" status_text="OK,
            resource created" id="6c9f73f5-f14c-42bf-ab44-edb8d2493dbc"/>"""
        )
        mock_gmp.create_target = MagicMock(return_value=target)
        return mock_gmp

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

    def test_create_xml_tree_invalid_fxml(self):
        target_xml_path = CWD / 'invalid_xml.xml'

        with self.assertRaises(SystemExit):
            with self.assertRaises(etree.Error):
                self.send_targets.create_xml_tree(str(target_xml_path))
