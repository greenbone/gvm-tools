# -*- coding: utf-8 -*-
# Copyright (C) 2020-2021 Greenbone Networks GmbH
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
    def test_get_scan_config(self, mock_gmp: GmpMockFactory):
        configs_file = CWD / 'get_scan_configs.xml'
        configs = configs_file.read_text()
        mock_gmp.mock_response('get_scan_configs', configs)

        # Full and Fast
        config_id = self.start_alert_scan.get_scan_config(
            gmp=mock_gmp.gmp_protocol, config=0
        )
        self.assertEqual(config_id, 'daba56c8-73ec-11df-a475-002264764cea')

        # Full and Fast ultimate
        config_id = self.start_alert_scan.get_scan_config(
            gmp=mock_gmp.gmp_protocol, config=1
        )
        self.assertEqual(config_id, '698f691e-7489-11df-9d8c-002264764cea')

        # Full and Fast deep
        config_id = self.start_alert_scan.get_scan_config(
            gmp=mock_gmp.gmp_protocol, config=2
        )
        self.assertEqual(config_id, '708f25c4-7489-11df-8094-002264764cea')

        # Full and Fast deep ultimate
        config_id = self.start_alert_scan.get_scan_config(
            gmp=mock_gmp.gmp_protocol, config=3
        )
        self.assertEqual(config_id, '74db13d6-7489-11df-91b9-002264764cea')

        # System Discovery
        config_id = self.start_alert_scan.get_scan_config(
            gmp=mock_gmp.gmp_protocol, config=4
        )
        self.assertEqual(config_id, 'bbca7412-a950-11e3-9109-406186ea4fc5')

        with self.assertRaises(ValueError):
            config_id = self.start_alert_scan.get_scan_config(
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

    @patch('gvm.protocols.latest.Gmp', new_callable=GmpMockFactory)
    def test_get_target(self, mock_gmp: GmpMockFactory):
        target_name = "test_target"
        hosts = ['127.0.0.1', '8.8.8.8']
        ports = 'T:1-3,5,7,9,11,13,17-25'
        port_list_name = "test_port_list"

        port_list_id = '6742e61a-a7b0-45dd-a8e1-35751c970958'
        target_id = '3b76a0c2-14fc-4de2-868c-35132977a25e'

        mock_gmp.mock_response(
            'create_port_list',
            '<create_port_list_response status="201" status_text='
            f'"OK, resource created" id="{port_list_id}"/>',
        )

        mock_gmp.mock_response(
            'create_target',
            '<create_target_response status="201" status_text='
            f'"OK, resource created" id="{target_id}"/>',
        )

        returned_id = self.start_alert_scan.get_target(
            gmp=mock_gmp.gmp_protocol,
            target_name=target_name,
            hosts=hosts,
            ports=ports,
            port_list_name=port_list_name,
        )

        self.assertEqual(target_id, returned_id)

    @patch('gvm.protocols.latest.Gmp', new_callable=GmpMockFactory)
    def test_create_and_start_task(self, mock_gmp: GmpMockFactory):
        alert_name = 'test_alert'
        alert_id = '3eefd4b9-59ec-48d6-b84d-f6a73bdb909f'
        target_id = '3b76a0c2-14fc-4de2-868c-35132977a25e'
        config_id = 'daba56c8-73ec-11df-a475-002264764cea'
        scanner_id = '08b69003-5fc2-4037-a479-93b440211c73'

        task_id = 'd78453ab-d907-44b6-abe0-2ef54a77f1c2'

        mock_gmp.mock_response(
            'create_task',
            '<create_task_response status="201" status_text='
            f'"OK, resource created" id="{task_id}"/>',
        )

        mock_gmp.mock_response(
            'get_tasks',
            """
<get_tasks_response status="200" status_text="OK">
  <apply_overrides>0</apply_overrides>
  <filters id="">
    <term>
        apply_overrides=0 min_qod=70
        name="Alert Scan for Alert test_alert" first=1 rows=100 sort=name
    </term>
    <keywords>
      <keyword>
        <column>apply_overrides</column>
        <relation>=</relation>
        <value>0</value>
      </keyword>
      <keyword>
        <column>min_qod</column>
        <relation>=</relation>
        <value>70</value>
      </keyword>
      <keyword>
        <column>name</column>
        <relation>=</relation>
        <value>"Alert Scan for Alert test_alert"</value>
      </keyword>
      <keyword>
        <column>first</column>
        <relation>=</relation>
        <value>1</value>
      </keyword>
      <keyword>
        <column>rows</column>
        <relation>=</relation>
        <value>100</value>
      </keyword>
      <keyword>
        <column>sort</column>
        <relation>=</relation>
        <value>name</value>
      </keyword>
    </keywords>
  </filters>
  <sort>
    <field>name<order>ascending</order></field>
  </sort>
  <tasks start="1" max="100"/>
  <task_count>27<filtered>0</filtered><page>0</page></task_count>
</get_tasks_response>
            """,
        )

        task_name = "Alert Scan for Alert {}".format(alert_name)

        returned_name = self.start_alert_scan.create_and_start_task(
            gmp=mock_gmp.gmp_protocol,
            config_id=config_id,
            target_id=target_id,
            scanner_id=scanner_id,
            alert_id=alert_id,
            alert_name=alert_name,
        )

        self.assertEqual(task_name, returned_name)
