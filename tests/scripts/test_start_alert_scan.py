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
# along with this program.  If not, see<http://www.gnu.org/licenses/>


import unittest
from unittest.mock import patch
from pathlib import Path
from . import GmpMockFactory, load_script

CWD = Path(__file__).absolute().parent


class StartAlertScanTestCase(unittest.TestCase):
    def setUp(self):
        self.start_alert_scan = load_script(
            (CWD.parent.parent / 'scripts'), 'start-alert-scan'
        )

    @patch('gvm.protocols.latest.Gmp', new_callable=GmpMockFactory)
    def test_get_config(self, mock_gmp: GmpMockFactory):
        configs_file = CWD / 'get_configs.xml'
        configs = configs_file.read_text()
        mock_gmp.mock_response('get_configs', configs)

        # Full and Fast
        config_id = self.start_alert_scan.get_config(
            gmp=mock_gmp.gmp_protocol, config=0
        )
        self.assertEqual(config_id, 'daba56c8-73ec-11df-a475-002264764cea')

        # Full and Fast ultimate
        config_id = self.start_alert_scan.get_config(
            gmp=mock_gmp.gmp_protocol, config=1
        )
        self.assertEqual(config_id, '698f691e-7489-11df-9d8c-002264764cea')

        # Full and Fast deep
        config_id = self.start_alert_scan.get_config(
            gmp=mock_gmp.gmp_protocol, config=2
        )
        self.assertEqual(config_id, '708f25c4-7489-11df-8094-002264764cea')

        # Full and Fast deep ultimate
        config_id = self.start_alert_scan.get_config(
            gmp=mock_gmp.gmp_protocol, config=3
        )
        self.assertEqual(config_id, '74db13d6-7489-11df-91b9-002264764cea')

        # System Discovery
        config_id = self.start_alert_scan.get_config(
            gmp=mock_gmp.gmp_protocol, config=4
        )
        self.assertEqual(config_id, 'bbca7412-a950-11e3-9109-406186ea4fc5')

        with self.assertRaises(ValueError):
            config_id = self.start_alert_scan.get_config(
                gmp=mock_gmp.gmp_protocol, config=-1
            )

    @patch('gvm.protocols.latest.Gmp', new_callable=GmpMockFactory)
    def test_get_alert(self, mock_gmp: GmpMockFactory):
        sender_email = "sender@test.com"
        recipient_email = "recipient@test.com"
        alert_name = "test_alert"
        alert_id = '3eefd4b9-59ec-48d6-b84d-f6a73bdb909f'

        alerts_file = CWD / 'get_alerts.xml'
        alerts = alerts_file.read_text()
        mock_gmp.mock_response('get_alerts', alerts)
        mock_gmp.mock_response(
            'create_alert',
            '<create_alert_response status="201" status_text='
            f'"OK, resource created" id="{alert_id}"/>',
        )

        returned_id = self.start_alert_scan.get_alert(
            gmp=mock_gmp.gmp_protocol,
            alert_name=alert_name,
            recipient_email=recipient_email,
            sender_email=sender_email,
        )

        self.assertEqual(alert_id, returned_id)
