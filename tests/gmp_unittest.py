# -*- coding: utf-8 -*-
# Description:
# Testcases to test gmp protocol
#
# Authors:
# Raphael Grewe <raphael.grewe@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
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
from gmp.gvm_connection import (SSHConnection,
                                GMPError)
import warnings
import lxml

# UnitOfWork_StateUnderTest_ExpectedBehavior
# Sum_NegativeNumberAs2ndParam_ExceptionThrown ()


class GMPTest(unittest.TestCase):
    hostname = 'localhost'
    CURRENT_VERSION = '8.0'
    AUTHENTICATION_ERR_MSG = 'Authentication failed'
    STATUS_TEXT_OK = 'OK'

    def setUp(self):
        warnings.simplefilter("ignore", ResourceWarning)
        self.gmp = SSHConnection(hostname=self.hostname, port=22,
                                 timeout=5, ssh_user='gmp',
                                 ssh_password='', shell_mode=True)

    def tearDown(self):
        self.gmp.close()

    def test_Authenticate_WrongUsernameAs1stParam_ExceptionThrown(self):
        with self.assertRaises(GMPError) as context:
            self.gmp.authenticate('amin', 'admin')

        self.assertEqual(self.AUTHENTICATION_ERR_MSG, str(context.exception))

    def test_Authenticate_WrongPasswordAs2stParam_ExceptionThrown(self):
        with self.assertRaises(GMPError) as context:
            self.gmp.authenticate('admin', 'admn')

        self.assertEqual(self.AUTHENTICATION_ERR_MSG, str(context.exception))

    def test_Authenticate_RightCredentialsWithCorrectCommand_CorrectVersionNumber(self):
        result = self.gmp.authenticate('admin', 'admin', '<get_version/>')
        version = result.xpath('get_version_response/version/text()')[0]

        self.assertEqual(self.CURRENT_VERSION, version)

    def test_Authenticate_RightCredentials_OKAsStatustext(self):

        result = self.gmp.authenticate('admin', 'admin')
        status_text = result.xpath('@status_text')[0]
        self.assertEqual(self.STATUS_TEXT_OK, status_text)
