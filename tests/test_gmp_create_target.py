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

import unittest

from gmp.xml import GmpCommandFactory


class GMPCreateTargetCommandTestCase(unittest.TestCase):

    TARGET_NAME = 'Unittest Target'
    TARGET_HOST = '127.0.0.1'
    COMMENT = 'This is a comment'
    UUID = '00000000-0000-0000-0000-000000000000'
    PORT = '1234'
    ALIVE_TEST = 'ICMP Ping'
    PORT_RANGE = 'T:10-20,U:10-30'

    def setUp(self):
        self.gmp = GmpCommandFactory()

    def tearDown(self):
        pass

    def test_valid_name_make_unique_true_correct_cmd(self):
        cmd = self.gmp.create_target_command(self.TARGET_NAME,
                                             True,
                                             {'hosts': self.TARGET_HOST})

        self.assertEqual('<create_target><name>' + self.TARGET_NAME +
                         '<make_unique>1</make_unique></name>'
                         '<hosts>' + self.TARGET_HOST + '</hosts>'
                         '</create_target>', cmd)

    def test_valid_name_make_unique_false_correct_cmd(self):
        cmd = self.gmp.create_target_command(self.TARGET_NAME,
                                             False,
                                             {'hosts': self.TARGET_HOST})

        self.assertEqual('<create_target><name>' + self.TARGET_NAME +
                         '<make_unique>0</make_unique></name>'
                         '<hosts>' + self.TARGET_HOST + '</hosts>'
                         '</create_target>', cmd)

    def test_empty_name_value_error(self):
        with self.assertRaises(ValueError) as context:
            self.gmp.create_target_command(
                "", True, {'hosts': self.TARGET_HOST})

        self.assertEqual('create_target requires a name element',
                         str(context.exception))

    def test_asset_hosts_correct_cmd(self):
        cmd = self.gmp.create_target_command(
            self.TARGET_NAME, True,
            {'asset_hosts': {'filter': self.TARGET_HOST}})

        self.assertEqual('<create_target><name>' + self.TARGET_NAME +
                         '<make_unique>1</make_unique></name>'
                         '<asset_hosts filter="' + self.TARGET_HOST + '"/>'
                         '</create_target>',
                         cmd)

    def test_no_host_no_asset_hosts_value_error(self):
        with self.assertRaises(ValueError) as context:
            self.gmp.create_target_command(self.TARGET_NAME, True, {})

        self.assertEqual('create_target requires either a hosts or '
                         'an asset_hosts element',
                         str(context.exception))

    def test_comment_correct_cmd(self):
        cmd = self.gmp.create_target_command(
            self.TARGET_NAME,
            True,
            {
                'hosts': self.TARGET_HOST,
                'comment': self.COMMENT
            })

        self.assertEqual('<create_target><name>' + self.TARGET_NAME +
                         '<make_unique>1</make_unique></name>'
                         '<hosts>' + self.TARGET_HOST + '</hosts>'
                         '<comment>' + self.COMMENT + '</comment>'
                         '</create_target>',
                         cmd)

    def test_copy_correct_cmd(self):
        cmd = self.gmp.create_target_command(
            self.TARGET_NAME,
            True,
            {
                'hosts': self.TARGET_HOST,
                'copy': self.UUID
            })

        self.assertEqual('<create_target><name>' + self.TARGET_NAME +
                         '<make_unique>1</make_unique></name>'
                         '<hosts>' + self.TARGET_HOST + '</hosts>'
                         '<copy>' + self.UUID + '</copy>'
                         '</create_target>',
                         cmd)

    def test_exclude_hosts_correct_cmd(self):
        cmd = self.gmp.create_target_command(
            self.TARGET_NAME,
            True,
            {
                'hosts': self.TARGET_HOST,
                'exclude_hosts': self.TARGET_HOST
            })

        self.assertEqual(
            '<create_target><name>' + self.TARGET_NAME +
            '<make_unique>1</make_unique></name>'
            '<hosts>' + self.TARGET_HOST + '</hosts>'
            '<exclude_hosts>' + self.TARGET_HOST + '</exclude_hosts>'
            '</create_target>',
            cmd)

    def test_ssh_credential_correct_cmd(self):
        cmd = self.gmp.create_target_command(
            self.TARGET_NAME,
            True,
            {
                'hosts': self.TARGET_HOST,
                'ssh_credential':
                    {
                        'id': self.UUID
                    }
            })

        self.assertEqual(
            '<create_target><name>' + self.TARGET_NAME +
            '<make_unique>1</make_unique></name>'
            '<hosts>' + self.TARGET_HOST + '</hosts>'
            '<ssh_credential id="' + self.UUID + '"></ssh_credential>'
            '</create_target>',
            cmd)

    def test_ssh_credential_with_port_correct_cmd(self):
        cmd = self.gmp.create_target_command(
            self.TARGET_NAME,
            True,
            {
                'hosts': self.TARGET_HOST,
                'ssh_credential':
                    {
                        'id': self.UUID,
                        'port': self.PORT
                    }
            })

        self.assertEqual(
            '<create_target><name>' + self.TARGET_NAME +
            '<make_unique>1</make_unique></name>'
            '<hosts>' + self.TARGET_HOST + '</hosts>'
            '<ssh_credential id="' + self.UUID + '">'
            '<port>' + self.PORT + '</port></ssh_credential>'
            '</create_target>',
            cmd)

    def test_ssh_credential_no_id_value_error(self):
        with self.assertRaises(ValueError) as context:
            self.gmp.create_target_command(
                self.TARGET_NAME,
                True,
                {
                    'hosts': self.TARGET_HOST,
                    'ssh_credential': {}
                })

        self.assertEqual('ssh_credential requires an id attribute',
                         str(context.exception))

    def test_smb_credential_correct_cmd(self):
        cmd = self.gmp.create_target_command(
            self.TARGET_NAME,
            True,
            {
                'hosts': self.TARGET_HOST,
                'smb_credential':
                    {
                        'id': self.UUID
                    }
            })

        self.assertEqual('<create_target><name>' + self.TARGET_NAME +
                         '<make_unique>1</make_unique></name>'
                         '<hosts>' + self.TARGET_HOST + '</hosts>'
                         '<smb_credential id="' + self.UUID + '"/>'
                         '</create_target>',
                         cmd)

    def test_smb_credential_no_id_value_error(self):
        with self.assertRaises(ValueError) as context:
            self.gmp.create_target_command(
                self.TARGET_NAME,
                True,
                {
                    'hosts': self.TARGET_HOST,
                    'smb_credential': {}
                })

        self.assertEqual('smb_credential requires an id attribute',
                         str(context.exception))

    def test_esxi_credential_correct_cmd(self):
        cmd = self.gmp.create_target_command(
            self.TARGET_NAME,
            True,
            {
                'hosts': self.TARGET_HOST,
                'esxi_credential':
                    {
                        'id': self.UUID
                    }
            })

        self.assertEqual(
            '<create_target><name>' + self.TARGET_NAME +
            '<make_unique>1</make_unique></name>'
            '<hosts>' + self.TARGET_HOST + '</hosts>'
            '<esxi_credential id="' + self.UUID + '"/>'
            '</create_target>',
            cmd)

    def test_esxi_credential_no_id_value_error(self):
        with self.assertRaises(ValueError) as context:
            self.gmp.create_target_command(
                self.TARGET_NAME,
                True,
                {
                    'hosts': self.TARGET_HOST,
                    'esxi_credential': {}
                })

        self.assertEqual('esxi_credential requires an id attribute',
                         str(context.exception))

    def test_snmp_credential_correct_cmd(self):
        cmd = self.gmp.create_target_command(
            self.TARGET_NAME,
            True,
            {
                'hosts': self.TARGET_HOST,
                'snmp_credential':
                    {
                        'id': self.UUID
                    }
            })

        self.assertEqual('<create_target><name>' + self.TARGET_NAME +
                         '<make_unique>1</make_unique></name>'
                         '<hosts>' + self.TARGET_HOST + '</hosts>'
                         '<snmp_credential id="' + self.UUID + '"/>'
                         '</create_target>',
                         cmd)

    def test_snmp_credential_no_id_value_error(self):
        with self.assertRaises(ValueError) as context:
            self.gmp.create_target_command(
                self.TARGET_NAME,
                True,
                {
                    'hosts': self.TARGET_HOST,
                    'snmp_credential': {}
                })

        self.assertEqual('snmp_credential requires an id attribute',
                         str(context.exception))

    def test_alive_tests_correct_cmd(self):
        cmd = self.gmp.create_target_command(
            self.TARGET_NAME,
            True,
            {
                'hosts': self.TARGET_HOST,
                'alive_tests': self.ALIVE_TEST
            })

        self.assertEqual('<create_target><name>' + self.TARGET_NAME +
                         '<make_unique>1</make_unique></name>'
                         '<hosts>' + self.TARGET_HOST + '</hosts>'
                         '<alive_tests>' + self.ALIVE_TEST + '</alive_tests>'
                         '</create_target>',
                         cmd)

    def test_reverse_lookup_only_true_correct_cmd(self):
        cmd = self.gmp.create_target_command(
            self.TARGET_NAME,
            True,
            {
                'hosts': self.TARGET_HOST,
                'reverse_lookup_only': True
            })

        self.assertEqual(
            '<create_target><name>' + self.TARGET_NAME +
            '<make_unique>1</make_unique></name>'
            '<hosts>' + self.TARGET_HOST + '</hosts>'
            '<reverse_lookup_only>1</reverse_lookup_only>'
            '</create_target>',
            cmd)

    def test_reverse_lookup_only_false_correct_cmd(self):
        cmd = self.gmp.create_target_command(
            self.TARGET_NAME,
            True,
            {
                'hosts': self.TARGET_HOST,
                'reverse_lookup_only': False
            })

        self.assertEqual(
            '<create_target><name>' + self.TARGET_NAME +
            '<make_unique>1</make_unique></name>'
            '<hosts>' + self.TARGET_HOST + '</hosts>'
            '<reverse_lookup_only>0</reverse_lookup_only>'
            '</create_target>',
            cmd)

    def test_reverse_lookup_unify_true_correct_cmd(self):
        cmd = self.gmp.create_target_command(
            self.TARGET_NAME,
            True,
            {
                'hosts': self.TARGET_HOST,
                'reverse_lookup_unify': True
            })

        self.assertEqual('<create_target><name>' + self.TARGET_NAME +
                         '<make_unique>1</make_unique></name>'
                         '<hosts>' + self.TARGET_HOST + '</hosts>'
                         '<reverse_lookup_unify>1</reverse_lookup_unify>'
                         '</create_target>',
                         cmd)

    def test_reverse_lookup_unify_false_correct_cmd(self):
        cmd = self.gmp.create_target_command(
            self.TARGET_NAME,
            True,
            {
                'hosts': self.TARGET_HOST,
                'reverse_lookup_unify': False
            })

        self.assertEqual('<create_target><name>' + self.TARGET_NAME +
                         '<make_unique>1</make_unique></name>'
                         '<hosts>' + self.TARGET_HOST + '</hosts>'
                         '<reverse_lookup_unify>0</reverse_lookup_unify>'
                         '</create_target>',
                         cmd)

    def test_port_range_correct_cmd(self):
        cmd = self.gmp.create_target_command(
            self.TARGET_NAME,
            True,
            {
                'hosts': self.TARGET_HOST,
                'port_range': self.PORT_RANGE
            })

        self.assertEqual(
            '<create_target><name>' + self.TARGET_NAME +
            '<make_unique>1</make_unique></name>'
            '<hosts>' + self.TARGET_HOST + '</hosts>'
            '<port_range>' + self.PORT_RANGE + '</port_range>'
            '</create_target>',
            cmd)

    def test_port_list_correct_cmd(self):
        cmd = self.gmp.create_target_command(
            self.TARGET_NAME,
            True,
            {
                'hosts': self.TARGET_HOST,
                'port_list':
                    {
                        'id': self.UUID
                    }
            })

        self.assertEqual('<create_target><name>' + self.TARGET_NAME +
                         '<make_unique>1</make_unique></name>'
                         '<hosts>' + self.TARGET_HOST + '</hosts>'
                         '<port_list id="' + self.UUID + '"/>'
                         '</create_target>',
                         cmd)

    def test_port_list_no_id_value_error(self):
        with self.assertRaises(ValueError) as context:
            self.gmp.create_target_command(
                self.TARGET_NAME,
                True,
                {
                    'hosts': self.TARGET_HOST,
                    'port_list': {}
                })

        self.assertEqual('port_list requires an id attribute',
                         str(context.exception))


if __name__ == '__main__':
    unittest.main()
