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


class GMPCreateTaskCommandTestCase(unittest.TestCase):

    TASK_NAME = "important task"
    CONFIG_ID = "cd0641e7-40b8-4e2c-811e-6b39d6d4b904"
    TARGET_ID = '267a3405-e84a-47da-97b2-5fa0d2e8995e'
    SCANNER_ID = 'b64c81b2-b9de-11e3-a2e9-406186ea4fc5'
    ALERT_ID = '3ab38c6a-30ac-407a-98db-ad6e74c98b9a'
    COMMENT = 'this task has been created for test purposes'

    def setUp(self):
        self.gmp = GmpCommandFactory()

    def test_without_alert_correct_cmd(self):
        cmd = self.gmp.create_task_command(
            self.TASK_NAME, self.CONFIG_ID, self.TARGET_ID, self.SCANNER_ID,
            comment=self.COMMENT)

        self.assertEqual(
            '<create_task>'
            '<name>{0}</name>'
            '<comment>{1}</comment>'
            '<config id="{2}"/><target id="{3}"/><scanner id="{4}"/>'
            '</create_task>'.format(self.TASK_NAME, self.COMMENT,
                                    self.CONFIG_ID, self.TARGET_ID,
                                    self.SCANNER_ID),
            cmd)

    def test_single_alert_correct_cmd(self):
        cmd = self.gmp.create_task_command(
            self.TASK_NAME, self.CONFIG_ID, self.TARGET_ID, self.SCANNER_ID,
            self.ALERT_ID, self.COMMENT)

        self.assertEqual(
            '<create_task>'
            '<name>{0}</name>'
            '<comment>{1}</comment>'
            '<config id="{2}"/><target id="{3}"/><scanner id="{4}"/>'
            '<alert id="{5}"/>'
            '</create_task>'.format(self.TASK_NAME, self.COMMENT,
                                    self.CONFIG_ID, self.TARGET_ID,
                                    self.SCANNER_ID, self.ALERT_ID),
            cmd)

    def test_multiple_alerts_correct_cmd(self):
        alert_id2 = 'fb3d6f82-d706-4f99-9e53-d7d85257e25f'
        alert_id3 = 'a33864a9-d3fd-44b3-8717-972bfb01dfcf'
        alert_ids = [self.ALERT_ID, alert_id2, alert_id3]

        cmd = self.gmp.create_task_command(
            self.TASK_NAME, self.CONFIG_ID, self.TARGET_ID, self.SCANNER_ID,
            alert_ids, self.COMMENT)

        self.assertEqual(
            '<create_task>'
            '<name>{0}</name>'
            '<comment>{1}</comment>'
            '<config id="{2}"/><target id="{3}"/><scanner id="{4}"/>'
            '<alert id="{5}"/><alert id="{6}"/><alert id="{7}"/>'
            '</create_task>'.format(self.TASK_NAME, self.COMMENT,
                                    self.CONFIG_ID, self.TARGET_ID,
                                    self.SCANNER_ID, self.ALERT_ID,
                                    alert_id2, alert_id3),
            cmd)


if __name__ == '__main__':
    unittest.main()
