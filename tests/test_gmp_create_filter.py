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

from gmp.xml import GmpCommandFactory, FILTER_NAMES


class GMPCreateFilterCommandTestCase(unittest.TestCase):

    FILTER_NAME = "special filter"

    def setUp(self):
        self.gmp = GmpCommandFactory()

    def test_all_available_filters_correct_cmd(self):
        for filter_type in FILTER_NAMES:
            cmd = self.gmp.create_filter_command(
                name=self.FILTER_NAME, make_unique=True,
                kwargs={
                    'term': 'sort-reverse=threat result_hosts_only=1 '
                            'notes=1 overrides=1 levels=hml first=1 rows=1000',
                    'type': filter_type
                })

            self.assertEqual(
                '<create_filter>'
                '<name>{0}<make_unique>1</make_unique></name>'
                '<term>sort-reverse=threat result_hosts_only=1 notes=1 '
                'overrides=1 levels=hml first=1 rows=1000</term>'
                '<type>{1}</type>'
                '</create_filter>'.format(self.FILTER_NAME, filter_type),
                cmd)


if __name__ == '__main__':
    unittest.main()
