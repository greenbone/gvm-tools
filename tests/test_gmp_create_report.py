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

from gmp.xml import _GmpCommandFactory as GmpCommandFactory


class GMPCreateReportCommandTestCase(unittest.TestCase):

    TASK_ID = '00000000-0000-0000-0000-000000000001'
    TASK_NAME = 'unit test task'
    COMMENT = 'This is a comment'
    REPORT_XML_STRING = (
        '<report id="67a62fb7-b238-4f0e-bc48-59bde8939cdc">'
        '<results max="1" start="1">'
        '<result id="f180b40f-49dd-4856-81ed-8c1195afce80">'
        '<severity>0.0</severity>'
        '<nvt oid="1.3.6.1.4.1.25623.1.0.10330"/>'
        '<host>132.67.253.114</host>'
        '</result></results></report>'
    )

    def setUp(self):
        self.gmp = GmpCommandFactory()

    def tearDown(self):
        pass

    def test_create_report_cmd_task_id(self):
        cmd = self.gmp.create_report_command(
            self.REPORT_XML_STRING,
            {
                'task_id': self.TASK_ID,
            })

        self.assertEqual(
            '<create_report>'
            '<task id="{0}"/>'
            '{1}'
            '</create_report>'.format(self.TASK_ID, self.REPORT_XML_STRING),
            cmd)

    def test_create_teport_cmd_task_name(self):
        cmd = self.gmp.create_report_command(
            self.REPORT_XML_STRING,
            {
                'task_name': self.TASK_NAME,
                'comment': self.COMMENT,
            })

        self.assertEqual(
            '<create_report>'
            '<task>'
            '<name>{0}</name>'
            '<comment>{1}</comment>'
            '</task>'
            '{2}'
            '</create_report>'.format(self.TASK_NAME, self.COMMENT,
                                      self.REPORT_XML_STRING),
            cmd)

    def test_create_report_cmd_noreport(self):
        args = {
            'task_name': self.TASK_NAME,
            'comment': self.COMMENT,
        }

        self.assertRaises(ValueError,
                          self.gmp.create_report_command,
                          None,
                          args)

    def test_create_report_cmd_notask(self):
        args = {'comment': self.COMMENT}
        self.assertRaises(ValueError,
                          self.gmp.create_report_command,
                          self.REPORT_XML_STRING,
                          args)


if __name__ == '__main__':
    unittest.main()
