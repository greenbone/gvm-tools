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
"""
Module for communication with gvmd
"""

import logging

from io import StringIO

from lxml import etree

from gmp.error import GmpError
from gmp.xml import GmpCommandFactory

logger = logging.getLogger(__name__)


def arguments_to_string(kwargs):
    """Convert arguments

    Converts dictionaries into gmp arguments string

    Arguments:
        kwargs {dict} -- Arguments

    Returns:
        string -- Arguments as string
    """
    msg = ''
    for key, value in kwargs.items():
        msg += str(key) + '=\'' + str(value) + '\' '

    return msg

def _check_command_status(xml):
    """Check gmp response

    Look into the gmp response and check for the status in the root element

    Arguments:
        xml {string} -- XML-Source

    Returns:
        bool -- True if valid, otherwise False
    """

    if xml is 0 or xml is None:
        logger.error('XML Command is empty')
        return False

    try:
        parser = etree.XMLParser(encoding='utf-8', recover=True)

        root = etree.XML(xml, parser=parser)
        status = root.attrib['status']
        return status is not None and status[0] == '2'

    except etree.Error as e:
        logger.error('etree.XML(xml): %s', e)
        return False


class Gmp:
    """Wrapper for Greenbone Management Protocol
    """

    def __init__(self, connection):
        # GMP Message Creator
        self._generator = GmpCommandFactory()
        self._connection = connection

        self._connected = False

        # Is authenticated on gvm
        self._authenticated = False

    def _read(self):
        """Read a command response from gvmd

        Try to read from the open connection.

        Check for status attribute in xml code.

        If the program is in shell-mode, then it returns a lxml root element,
        otherwise the plain xml.

        If the response is either None or the length is zero,
        then the connection was terminated from the server.

        Returns:
            lxml.etree._Element or <string> -- Response from server.
        """
        response = self._connection.read()

        logger.debug('read() %i Bytes response: %s', len(response), response)

        if response is None or len(str(response)) == 0:
            raise OSError('Connection was closed by remote server')

        if getattr(self, 'raw_response', False):
            return response

        if getattr(self, 'shell_mode', False):
            parser = etree.XMLParser(encoding='utf-8', recover=True)

            logger.info('Shell mode activated')
            f = StringIO(response)
            tree = etree.parse(f, parser)
            return tree.getroot()
        else:
            return response

    def _connect(self):
        if not self.is_connected():
            self._connection.connect()
            self._connected = True

    def is_connected(self):
        return self._connected

    def is_authenticated(self):
        return self._authenticated

    def disconnect(self):
        if self.is_connected():
            self._connection.disconnect()
            self._connected = False

    def send_command(self, cmd):
        """Send a command to gsad
        """
        self._connect()
        self._connection.send(cmd)
        return self._read()

    def authenticate(self, username, password):
        """Authenticate on GVM.

        The generated authenticate command will be send to server.
        After that a response is read from socket.

        Keyword Arguments:
            username {str} -- Username
            password {str} -- Password

        Returns:
            None or <string> -- Response from server.
        """
        cmd = self._generator.create_authenticate_command(
            username=username, password=password)

        return self.send_command(cmd)

    def create_agent(self, installer, signature, name, comment='', copy='',
                     howto_install='', howto_use=''):
        cmd = self._generator.create_agent_command(
            installer, signature, name, comment, copy, howto_install,
            howto_use)
        return self.send_command(cmd)

    def create_alert(self, name, condition, event, method, filter_id='',
                     copy='', comment=''):
        cmd = self._generator.create_alert_command(name, condition, event,
                                                   method, filter_id, copy,
                                                   comment)
        return self.send_command(cmd)

    def create_asset(self, name, asset_type, comment=''):
        # TODO: Add the missing second method. Also the docs are not complete!
        cmd = self._generator.create_asset_command(name, asset_type, comment)
        return self.send_command(cmd)

    def create_config(self, copy_id, name):
        cmd = self._generator.create_config_command(copy_id, name)
        return self.send_command(cmd)

    def create_credential(self, name, **kwargs):
        cmd = self._generator.create_credential_command(name, kwargs)
        return self.send_command(cmd)

    def create_filter(self, name, make_unique, **kwargs):
        cmd = self._generator.create_filter_command(name, make_unique,
                                                    kwargs)
        return self.send_command(cmd)

    def create_group(self, name, **kwargs):
        cmd = self._generator.create_group_command(name, kwargs)
        return self.send_command(cmd)

    # TODO: Create notes with comment returns bogus element. Research
    def create_note(self, text, nvt_oid, **kwargs):
        cmd = self._generator.create_note_command(text, nvt_oid, kwargs)
        return self.send_command(cmd)

    def create_override(self, text, nvt_oid, **kwargs):
        cmd = self._generator.create_override_command(text, nvt_oid, kwargs)
        return self.send_command(cmd)

    def create_permission(self, name, subject_id, permission_type, **kwargs):
        cmd = self._generator.create_permission_command(
            name, subject_id, permission_type, kwargs)
        return self.send_command(cmd)

    def create_port_list(self, name, port_range, **kwargs):
        cmd = self._generator.create_port_list_command(name, port_range, kwargs)
        return self.send_command(cmd)

    def create_port_range(self, port_list_id, start, end, port_range_type,
                          comment=''):
        cmd = self._generator.create_port_range_command(
            port_list_id, start, end, port_range_type, comment)
        return self.send_command(cmd)

    def create_report(self, report_xml_string, **kwargs):
        cmd = self._generator.create_report_command(report_xml_string, kwargs)
        return self.send_command(cmd)

    def create_role(self, name, **kwargs):
        cmd = self._generator.create_role_command(name, kwargs)
        return self.send_command(cmd)

    def create_scanner(self, name, host, port, scanner_type, ca_pub,
                       credential_id, **kwargs):
        cmd = self._generator.create_scanner_command(name, host, port,
                                                     scanner_type, ca_pub,
                                                     credential_id, kwargs)
        return self.send_command(cmd)

    def create_schedule(self, name, **kwargs):
        cmd = self._generator.create_schedule_command(name, kwargs)
        return self.send_command(cmd)

    def create_tag(self, name, resource_id, resource_type, **kwargs):
        cmd = self._generator.create_tag_command(name, resource_id,
                                                 resource_type, kwargs)
        return self.send_command(cmd)

    def create_target(self, name, make_unique, **kwargs):
        # TODO: Missing variables
        cmd = self._generator.create_target_command(name, make_unique, kwargs)
        return self.send_command(cmd)

    def create_task(self, name, config_id, target_id, scanner_id,
                    alert_ids=None, comment=''):
        if alert_ids is None:
            alert_ids = []
        cmd = self._generator.create_task_command(
            name, config_id, target_id, scanner_id, alert_ids, comment)
        return self.send_command(cmd)

    def create_user(self, name, password, copy='', hosts_allow='0',
                    ifaces_allow='0', role_ids=(), hosts=None, ifaces=None):
        cmd = self._generator.create_user_command(
            name, password, copy, hosts_allow, ifaces_allow, role_ids, hosts,
            ifaces)
        return self.send_command(cmd)

    def delete_agent(self, **kwargs):
        cmd = '<delete_agent {0}/>'.format(arguments_to_string(kwargs))
        return self.send_command(cmd)

    def delete_alert(self, **kwargs):
        cmd = '<delete_alert {0}/>'.format(arguments_to_string(kwargs))
        return self.send_command(cmd)

    def delete_asset(self, asset_id, ultimate=0):
        cmd = '<delete_asset asset_id="{0}" ultimate="{1}"/>'.format(
            asset_id, ultimate)
        return self.send_command(cmd)

    def delete_config(self, config_id, ultimate=0):
        cmd = '<delete_config config_id="{0}" ultimate="{1}"/>'.format(
            config_id, ultimate)
        return self.send_command(cmd)

    def delete_credential(self, credential_id, ultimate=0):
        cmd = '<delete_credential credential_id="{0}" ultimate="{1}"/>'.format(
            credential_id, ultimate)
        return self.send_command(cmd)

    def delete_filter(self, filter_id, ultimate=0):
        cmd = '<delete_filter filter_id="{0}" ultimate="{1}"/>'.format(
            filter_id, ultimate)
        return self.send_command(cmd)

    def delete_group(self, group_id, ultimate=0):
        cmd = '<delete_group group_id="{0}" ultimate="{1}"/>'.format(
            group_id, ultimate)
        return self.send_command(cmd)

    def delete_note(self, note_id, ultimate=0):
        cmd = '<delete_note note_id="{0}" ultimate="{1}"/>'.format(
            note_id, ultimate)
        return self.send_command(cmd)

    def delete_override(self, override_id, ultimate=0):
        cmd = '<delete_override override_id="{0}" ultimate="{1}"/>'.format(
            override_id, ultimate)
        return self.send_command(cmd)

    def delete_permission(self, permission_id, ultimate=0):
        cmd = '<delete_permission permission_id="{0}" ultimate="{1}"/>'.format(
            permission_id, ultimate)
        return self.send_command(cmd)

    def delete_port_list(self, port_list_id, ultimate=0):
        cmd = '<delete_port_list port_list_id="{0}" ultimate="{1}"/>'.format(
            port_list_id, ultimate)
        return self.send_command(cmd)

    def delete_port_range(self, port_range_id):
        cmd = '<delete_port_range port_range_id="{0}"/>'.format(port_range_id)
        return self.send_command(cmd)

    def delete_report(self, report_id):
        cmd = '<delete_report report_id="{0}"/>'.format(report_id)
        return self.send_command(cmd)

    def delete_report_format(self, report_format_id, ultimate=0):
        cmd = '<delete_report_format report_format_id="{0}" ' \
            'ultimate="{1}"/>'.format(report_format_id, ultimate)
        return self.send_command(cmd)

    def delete_role(self, role_id, ultimate=0):
        cmd = '<delete_role role_id="{0}" ultimate="{1}"/>'.format(
            role_id, ultimate)
        return self.send_command(cmd)

    def delete_scanner(self, scanner_id, ultimate=0):
        cmd = '<delete_scanner scanner_id="{0}" ultimate="{1}"/>'.format(
            scanner_id, ultimate)
        return self.send_command(cmd)

    def delete_schedule(self, schedule_id, ultimate=0):
        # if self.ask_yes_or_no('Are you sure to delete this schedule? '):
        cmd = '<delete_schedule schedule_id="{0}" ultimate="{1}"/>'.format(
            schedule_id, ultimate)
        return self.send_command(cmd)

    def delete_tag(self, tag_id, ultimate=0):
        cmd = '<delete_tag tag_id="{0}" ultimate="{1}"/>'.format(
            tag_id, ultimate)
        return self.send_command(cmd)

    def delete_target(self, target_id, ultimate=0):
        cmd = '<delete_target target_id="{0}" ultimate="{1}"/>'.format(
            target_id, ultimate)
        return self.send_command(cmd)

    def delete_task(self, task_id, ultimate=0):
        cmd = '<delete_task task_id="{0}" ultimate="{1}"/>'.format(
            task_id, ultimate)
        return self.send_command(cmd)

    def delete_user(self, **kwargs):
        user_id = kwargs.get('user_id', '')
        if user_id:
            user_id = ' user_id="%s"' % user_id

        name = kwargs.get('name', '')
        if name:
            name = ' name="%s"' % name

        inheritor_id = kwargs.get('inheritor_id', '')
        if inheritor_id:
            inheritor_id = ' inheritor_id="%s"' % inheritor_id

        inheritor_name = kwargs.get('inheritor_name', '')
        if inheritor_name:
            inheritor_name = ' inheritor_name="%s"' % inheritor_name

        cmd = '<delete_user{0}{1}{2}{3}/>'.format(
            user_id, name, inheritor_id, inheritor_name)
        return self.send_command(cmd)

    def describe_auth(self):
        return self.send_command('<describe_auth/>')

    def empty_trashcan(self):
        return self.send_command('<empty_trashcan/>')

    def get_agents(self, **kwargs):
        cmd = '<get_agents {0}/>'.format(arguments_to_string(kwargs))
        return self.send_command(cmd)

    def get_aggregates(self, **kwargs):
        cmd = '<get_aggregates {0}/>'.format(arguments_to_string(kwargs))
        return self.send_command(cmd)

    def get_alerts(self, **kwargs):
        cmd = '<get_alerts {0}/>'.format(arguments_to_string(kwargs))
        return self.send_command(cmd)

    def get_assets(self, **kwargs):
        cmd = '<get_assets {0}/>'.format(arguments_to_string(kwargs))
        return self.send_command(cmd)

    def get_credentials(self, **kwargs):
        cmd = '<get_credentials {0}/>'.format(arguments_to_string(kwargs))
        return self.send_command(cmd)

    def get_configs(self, **kwargs):
        cmd = '<get_configs {0}/>'.format(arguments_to_string(kwargs))
        return self.send_command(cmd)

    def get_feeds(self, **kwargs):
        cmd = '<get_feeds {0}/>'.format(arguments_to_string(kwargs))
        return self.send_command(cmd)

    def get_filters(self, **kwargs):
        cmd = '<get_filters {0}/>'.format(arguments_to_string(kwargs))
        return self.send_command(cmd)

    def get_groups(self, **kwargs):
        cmd = '<get_groups {0}/>'.format(arguments_to_string(kwargs))
        return self.send_command(cmd)

    def get_info(self, **kwargs):
        cmd = '<get_info {0}/>'.format(arguments_to_string(kwargs))
        return self.send_command(cmd)

    def get_notes(self, **kwargs):
        cmd = '<get_notes {0}/>'.format(arguments_to_string(kwargs))
        return self.send_command(cmd)

    def get_nvts(self, **kwargs):
        cmd = '<get_nvts {0}/>'.format(arguments_to_string(kwargs))
        return self.send_command(cmd)

    def get_nvt_families(self, **kwargs):
        cmd = '<get_nvt_families {0}/>'.format(arguments_to_string(kwargs))
        return self.send_command(cmd)

    def get_overrides(self, **kwargs):
        cmd = '<get_overrides {0}/>'.format(arguments_to_string(kwargs))
        return self.send_command(cmd)

    def get_permissions(self, **kwargs):
        cmd = '<get_permissions {0}/>'.format(arguments_to_string(kwargs))
        return self.send_command(cmd)

    def get_port_lists(self, **kwargs):
        cmd = '<get_port_lists {0}/>'.format(arguments_to_string(kwargs))
        return self.send_command(cmd)

    def get_preferences(self, **kwargs):
        cmd = '<get_preferences {0}/>'.format(arguments_to_string(kwargs))
        return self.send_command(cmd)

    def get_reports(self, **kwargs):
        cmd = '<get_reports {0}/>'.format(arguments_to_string(kwargs))
        return self.send_command(cmd)

    def get_report_formats(self, **kwargs):
        cmd = '<get_report_formats {0}/>'.format(arguments_to_string(kwargs))
        return self.send_command(cmd)

    def get_results(self, **kwargs):
        cmd = '<get_results {0}/>'.format(arguments_to_string(kwargs))
        return self.send_command(cmd)

    def get_roles(self, **kwargs):
        cmd = '<get_roles {0}/>'.format(arguments_to_string(kwargs))
        return self.send_command(cmd)

    def get_scanners(self, **kwargs):
        cmd = '<get_scanners {0}/>'.format(arguments_to_string(kwargs))
        return self.send_command(cmd)

    def get_schedules(self, **kwargs):
        cmd = '<get_schedules {0}/>'.format(arguments_to_string(kwargs))
        return self.send_command(cmd)

    def get_settings(self, **kwargs):
        cmd = '<get_settings {0}/>'.format(arguments_to_string(kwargs))
        return self.send_command(cmd)

    def get_system_reports(self, **kwargs):
        cmd = '<get_system_reports {0}/>'.format(arguments_to_string(kwargs))
        return self.send_command(cmd)

    def get_tags(self, **kwargs):
        cmd = '<get_tags {0}/>'.format(arguments_to_string(kwargs))
        return self.send_command(cmd)

    def get_targets(self, **kwargs):
        cmd = '<get_targets {0}/>'.format(arguments_to_string(kwargs))
        return self.send_command(cmd)

    def get_tasks(self, **kwargs):
        cmd = '<get_tasks {0}/>'.format(arguments_to_string(kwargs))
        return self.send_command(cmd)

    def get_users(self, **kwargs):
        cmd = '<get_users {0}/>'.format(arguments_to_string(kwargs))
        return self.send_command(cmd)

    def get_version(self):
        return self.send_command('<get_version/>')

    def help(self, **kwargs):
        cmd = '<help {0} />'.format(arguments_to_string(kwargs))
        return self.send_command(cmd)

    def modify_agent(self, agent_id, name='', comment=''):
        cmd = self._generator.modify_agent_command(agent_id, name, comment)
        return self.send_command(cmd)

    def modify_alert(self, alert_id, **kwargs):
        cmd = self._generator.modify_alert_command(alert_id, kwargs)
        return self.send_command(cmd)

    def modify_asset(self, asset_id, comment):
        cmd = '<modify_asset asset_id="%s"><comment>%s</comment>' \
              '</modify_asset>' % (asset_id, comment)
        return self.send_command(cmd)

    def modify_auth(self, group_name, auth_conf_settings):
        cmd = self._generator.modify_auth_command(group_name,
                                                  auth_conf_settings)
        return self.send_command(cmd)

    def modify_config(self, selection, **kwargs):
        cmd = self._generator.modify_config_command(selection, kwargs)
        return self.send_command(cmd)

    def modify_credential(self, credential_id, **kwargs):
        cmd = self._generator.modify_credential_command(
            credential_id, kwargs)
        return self.send_command(cmd)

    def modify_filter(self, filter_id, **kwargs):
        cmd = self._generator.modify_filter_command(filter_id, kwargs)
        return self.send_command(cmd)

    def modify_group(self, group_id, **kwargs):
        cmd = self._generator.modify_group_command(group_id, kwargs)
        return self.send_command(cmd)

    def modify_note(self, note_id, text, **kwargs):
        cmd = self._generator.modify_note_command(note_id, text, kwargs)
        return self.send_command(cmd)

    def modify_override(self, override_id, text, **kwargs):
        cmd = self._generator.modify_override_command(override_id, text,
                                                      kwargs)
        return self.send_command(cmd)

    def modify_permission(self, permission_id, **kwargs):
        cmd = self._generator.modify_permission_command(
            permission_id, kwargs)
        return self.send_command(cmd)

    def modify_port_list(self, port_list_id, **kwargs):
        cmd = self._generator.modify_port_list_command(port_list_id, kwargs)
        return self.send_command(cmd)

    def modify_report(self, report_id, comment):
        cmd = '<modify_report report_id="{0}"><comment>{1}</comment>' \
              '</modify_report>'.format(report_id, comment)
        return self.send_command(cmd)

    def modify_report_format(self, report_format_id, **kwargs):
        cmd = self._generator.modify_report_format_command(report_format_id,
                                                           kwargs)
        return self.send_command(cmd)

    def modify_role(self, role_id, **kwargs):
        cmd = self._generator.modify_role_command(role_id, kwargs)
        return self.send_command(cmd)

    def modify_scanner(self, scanner_id, host, port, scanner_type, **kwargs):
        cmd = self._generator.modify_scanner_command(scanner_id, host, port,
                                                     scanner_type, kwargs)
        return self.send_command(cmd)

    def modify_schedule(self, schedule_id, **kwargs):
        cmd = self._generator.modify_schedule_command(schedule_id, kwargs)
        return self.send_command(cmd)

    def modify_setting(self, setting_id, name, value):
        cmd = '<modify_setting setting_id="{0}"><name>{1}</name>' \
              '<value>{2}</value></modify_setting>' \
              ''.format(setting_id, name, value)
        return self.send_command(cmd)

    def modify_tag(self, tag_id, **kwargs):
        cmd = self._generator.modify_tag_command(tag_id, kwargs)
        return self.send_command(cmd)

    def modify_target(self, target_id, **kwargs):
        cmd = self._generator.modify_target_command(target_id, kwargs)
        return self.send_command(cmd)

    def modify_task(self, task_id, **kwargs):
        cmd = self._generator.modify_task_command(task_id, kwargs)
        return self.send_command(cmd)

    def modify_user(self, **kwargs):
        cmd = self._generator.modify_user_command(kwargs)
        return self.send_command(cmd)

    def move_task(self, task_id, slave_id):
        cmd = '<move_task task_id="{0}" slave_id="{1}"/>'.format(
            task_id, slave_id)
        return self.send_command(cmd)

    def restore(self, entity_id):
        cmd = '<restore id="{0}"/>'.format(entity_id)
        return self.send_command(cmd)

    def resume_task(self, task_id):
        cmd = '<resume_task task_id="{0}"/>'.format(task_id)
        return self.send_command(cmd)

    def start_task(self, task_id):
        cmd = '<start_task task_id="{0}"/>'.format(task_id)
        return self.send_command(cmd)

    def stop_task(self, task_id):
        cmd = '<stop_task task_id="{0}"/>'.format(task_id)
        return self.send_command(cmd)

    def sync_cert(self):
        cmd = '<sync_cert/>'
        return self.send_command(cmd)

    def sync_config(self):
        cmd = '<sync_config/>'
        return self.send_command(cmd)

    def sync_feed(self):
        cmd = '<sync_feed/>'
        return self.send_command(cmd)

    def sync_scap(self):
        cmd = '<sync_scap/>'
        return self.send_command(cmd)

    def test_alert(self, alert_id):
        cmd = '<test_alert alert_id="{0}"/>'.format(alert_id)
        return self.send_command(cmd)

    def verify_agent(self, agent_id):
        cmd = '<verify_agent agent_id="{0}"/>'.format(agent_id)
        return self.send_command(cmd)

    def verify_report_format(self, report_format_id):
        cmd = '<verify_report_format report_format_id="{0}"/>'.format(
            report_format_id)
        return self.send_command(cmd)

    def verify_scanner(self, scanner_id):
        cmd = '<verify_scanner scanner_id="{0}"/>'.format(scanner_id)
        return self.send_command(cmd)
