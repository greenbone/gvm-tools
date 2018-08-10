# -*- coding: utf-8 -*-
# Description:
# Testcases to test gmp protocol
#
# Authors:
# Michael Wiegand <michael.wiegand@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
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
from gmp.gmp import _gmp

class GMPCreateTargetCommandTestCase(unittest.TestCase):
    TARGET_NAME = 'Unittest Target'
    TARGET_HOST = '127.0.0.1'
    COMMENT = 'This is a comment'
    UUID = '00000000-0000-0000-0000-000000000000'
    PORT = '1234'
    ALIVE_TEST = 'ICMP Ping'
    PORT_RANGE = 'T:10-20,U:10-30'

    def setUp(self):
        self.gmp = _gmp()

    def tearDown(self):
        pass

    def test_ValidNameMakeUniqueTrue_CorrectCmd(self):
        cmd = self.gmp.createTargetCommand(self.TARGET_NAME,
                                           True,
                                           {'hosts': self.TARGET_HOST})

        self.assertEqual('<create_target><name>' + self.TARGET_NAME +
                         '<make_unique>1</make_unique></name>'
                         '<hosts>' + self.TARGET_HOST + '</hosts>'
                         '</create_target>', cmd)

    def test_ValidNameMakeUniqueFalse_CorrectCmd(self):
        cmd = self.gmp.createTargetCommand(self.TARGET_NAME,
                                           False,
                                           {'hosts': self.TARGET_HOST})

        self.assertEqual('<create_target><name>' + self.TARGET_NAME +
                         '<make_unique>0</make_unique></name>'
                         '<hosts>' + self.TARGET_HOST + '</hosts>'
                         '</create_target>', cmd)

    def test_EmptyName_ValueError(self):
        with self.assertRaises(ValueError) as context:
            self.gmp.createTargetCommand("", True, {'hosts': self.TARGET_HOST})

        self.assertEqual('create_target requires a name element',
                         str(context.exception))

    def test_AssetHosts_CorrectCmd(self):
        cmd = self.gmp.createTargetCommand(self.TARGET_NAME,
                True,
                {'asset_hosts': {'filter': self.TARGET_HOST}})

        self.assertEqual('<create_target><name>' + self.TARGET_NAME +
                '<make_unique>1</make_unique></name>'
                '<asset_hosts filter="' + self.TARGET_HOST + '"/>'
                '</create_target>',
                cmd)

    def test_NoHostNoAssetHosts_ValueError(self):
        with self.assertRaises(ValueError) as context:
            self.gmp.createTargetCommand(self.TARGET_NAME, True, {})

        self.assertEqual('create_target requires either a hosts or '
                         'an asset_hosts element',
                         str(context.exception))

    def test_Comment_CorrectCmd(self):
        cmd = self.gmp.createTargetCommand(self.TARGET_NAME,
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

    def test_Copy_CorrectCmd(self):
        cmd = self.gmp.createTargetCommand(self.TARGET_NAME,
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

    def test_ExcludeHosts_CorrectCmd(self):
        cmd = self.gmp.createTargetCommand(self.TARGET_NAME,
                True,
                {
                    'hosts': self.TARGET_HOST,
                    'exclude_hosts': self.TARGET_HOST
                    })

        self.assertEqual('<create_target><name>' + self.TARGET_NAME +
                '<make_unique>1</make_unique></name>'
                '<hosts>' + self.TARGET_HOST + '</hosts>'
                '<exclude_hosts>' + self.TARGET_HOST + '</exclude_hosts>'
                '</create_target>',
                cmd)

    def test_SSHCredential_CorrectCmd(self):
        cmd = self.gmp.createTargetCommand(self.TARGET_NAME,
                True,
                {
                    'hosts': self.TARGET_HOST,
                    'ssh_credential':
                    {
                        'id': self.UUID
                        }
                    })

        self.assertEqual('<create_target><name>' + self.TARGET_NAME +
                '<make_unique>1</make_unique></name>'
                '<hosts>' + self.TARGET_HOST + '</hosts>'
                '<ssh_credential id="' + self.UUID + '"></ssh_credential>'
                '</create_target>',
                cmd)

    def test_SSHCredentialWithPort_CorrectCmd(self):
        cmd = self.gmp.createTargetCommand(self.TARGET_NAME,
                True,
                {
                    'hosts': self.TARGET_HOST,
                    'ssh_credential':
                    {
                        'id': self.UUID,
                        'port': self.PORT
                        }
                    })

        self.assertEqual('<create_target><name>' + self.TARGET_NAME +
                '<make_unique>1</make_unique></name>'
                '<hosts>' + self.TARGET_HOST + '</hosts>'
                '<ssh_credential id="' + self.UUID + '">'
                '<port>' + self.PORT + '</port></ssh_credential>'
                '</create_target>',
                cmd)

    def test_SSHCredentialNoID_ValueError(self):
        with self.assertRaises(ValueError) as context:
            self.gmp.createTargetCommand(self.TARGET_NAME,
                True,
                {
                    'hosts': self.TARGET_HOST,
                    'ssh_credential': {}
                    })

        self.assertEqual('ssh_credential requires an id attribute',
                str(context.exception))

    def test_SMBCredential_CorrectCmd(self):
        cmd = self.gmp.createTargetCommand(self.TARGET_NAME,
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

    def test_SMBCredentialNoID_ValueError(self):
        with self.assertRaises(ValueError) as context:
            self.gmp.createTargetCommand(self.TARGET_NAME,
                True,
                {
                    'hosts': self.TARGET_HOST,
                    'smb_credential': {}
                    })

        self.assertEqual('smb_credential requires an id attribute',
                str(context.exception))

    def test_ESXiCredential_CorrectCmd(self):
        cmd = self.gmp.createTargetCommand(self.TARGET_NAME,
                True,
                {
                    'hosts': self.TARGET_HOST,
                    'esxi_credential':
                    {
                        'id': self.UUID
                        }
                    })

        self.assertEqual('<create_target><name>' + self.TARGET_NAME +
                '<make_unique>1</make_unique></name>'
                '<hosts>' + self.TARGET_HOST + '</hosts>'
                '<esxi_credential id="' + self.UUID + '"/>'
                '</create_target>',
                cmd)

    def test_ESXiCredentialNoID_ValueError(self):
        with self.assertRaises(ValueError) as context:
            self.gmp.createTargetCommand(self.TARGET_NAME,
                True,
                {
                    'hosts': self.TARGET_HOST,
                    'esxi_credential': {}
                    })

        self.assertEqual('esxi_credential requires an id attribute',
                str(context.exception))

    def test_SNMPCredential_CorrectCmd(self):
        cmd = self.gmp.createTargetCommand(self.TARGET_NAME,
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

    def test_SNMPCredentialNoID_ValueError(self):
        with self.assertRaises(ValueError) as context:
            self.gmp.createTargetCommand(self.TARGET_NAME,
                True,
                {
                    'hosts': self.TARGET_HOST,
                    'snmp_credential': {}
                    })

        self.assertEqual('snmp_credential requires an id attribute',
                str(context.exception))

    def test_AliveTests_CorrectCmd(self):
        cmd = self.gmp.createTargetCommand(self.TARGET_NAME,
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

    def test_ReverseLookupOnlyTrue_CorrectCmd(self):
        cmd = self.gmp.createTargetCommand(self.TARGET_NAME,
                True,
                {
                    'hosts': self.TARGET_HOST,
                    'reverse_lookup_only': True
                    })

        self.assertEqual('<create_target><name>' + self.TARGET_NAME +
                '<make_unique>1</make_unique></name>'
                '<hosts>' + self.TARGET_HOST + '</hosts>'
                '<reverse_lookup_only>1</reverse_lookup_only>'
                '</create_target>',
                cmd)

    def test_ReverseLookupOnlyFalse_CorrectCmd(self):
        cmd = self.gmp.createTargetCommand(self.TARGET_NAME,
                True,
                {
                    'hosts': self.TARGET_HOST,
                    'reverse_lookup_only': False
                    })

        self.assertEqual('<create_target><name>' + self.TARGET_NAME +
                '<make_unique>1</make_unique></name>'
                '<hosts>' + self.TARGET_HOST + '</hosts>'
                '<reverse_lookup_only>0</reverse_lookup_only>'
                '</create_target>',
                cmd)

    def test_ReverseLookupUnifyTrue_CorrectCmd(self):
        cmd = self.gmp.createTargetCommand(self.TARGET_NAME,
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

    def test_ReverseLookupUnifyFalse_CorrectCmd(self):
        cmd = self.gmp.createTargetCommand(self.TARGET_NAME,
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

    def test_PortRange_CorrectCmd(self):
        cmd = self.gmp.createTargetCommand(self.TARGET_NAME,
                True,
                {
                    'hosts': self.TARGET_HOST,
                    'port_range': self.PORT_RANGE
                    })

        self.assertEqual('<create_target><name>' + self.TARGET_NAME +
                '<make_unique>1</make_unique></name>'
                '<hosts>' + self.TARGET_HOST + '</hosts>'
                '<port_range>' + self.PORT_RANGE + '</port_range>'
                '</create_target>',
                cmd)

    def test_PortList_CorrectCmd(self):
        cmd = self.gmp.createTargetCommand(self.TARGET_NAME,
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

    def test_PortListNoID_ValueError(self):
        with self.assertRaises(ValueError) as context:
            self.gmp.createTargetCommand(self.TARGET_NAME,
                True,
                {
                    'hosts': self.TARGET_HOST,
                    'port_list': {}
                    })

        self.assertEqual('port_list requires an id attribute',
                str(context.exception))


class GMPCreateReportCommandTestCase(unittest.TestCase):
    TASK_ID = '00000000-0000-0000-0000-000000000001'
    TASK_NAME = 'unit test task'
    COMMENT = 'This is a comment'
    REPORT_XML_STRING = (
        '<report id="67a62fb7-b238-4f0e-bc48-59bde8939cdc"><results max="1"' +
        ' start="1"><result id="f180b40f-49dd-4856-81ed-8c1195afce80">' +
        '<severity>0.0</severity><nvt oid="1.3.6.1.4.1.25623.1.0.10330"/>' +
        '<host>132.67.253.114</host></result></results></report>'
    )

    def setUp(self):
        self.gmp = _gmp()

    def tearDown(self):
        pass

    def test_Create_ReportCmd_Taskid(self):
        cmd = self.gmp.createReportCommand(self.REPORT_XML_STRING,
                                           {
                                               'task_id': self.TASK_ID,
                                           })

        self.assertEqual('<create_report><task id="' + self.TASK_ID + '"/>' +
                         self.REPORT_XML_STRING + '</create_report>',
                         cmd)

    def test_Create_ReportCmd_Taskname(self):
        cmd = self.gmp.createReportCommand(self.REPORT_XML_STRING,
                                           {
                                               'task_name': self.TASK_NAME,
                                               'comment': self.COMMENT,
                                           })

        self.assertEqual('<create_report><task>' +
                         '<name>' + self.TASK_NAME + '</name>' +
                         '<comment>' + self.COMMENT + '</comment>' +
                         '</task>' + self.REPORT_XML_STRING + '</create_report>',
                         cmd)

    def test_Create_ReportCmd_noreport(self):
        NO_REPORT = None
        args = {
            'task_name': self.TASK_NAME,
            'comment': self.COMMENT,
        }

        self.assertRaises(ValueError,
                          self.gmp.createReportCommand,
                          NO_REPORT,
                          args
        )

    def test_Create_ReportCmd_notask(self):
        args = {'comment': self.COMMENT}
        self.assertRaises(ValueError,
                          self.gmp.createReportCommand,
                          self.REPORT_XML_STRING,
                          args
        )

if __name__ == '__main__':
    unittest.main()
