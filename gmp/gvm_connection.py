# -*- coding: utf-8 -*-
# Description:
# GVM-Connection classes for communication with the GVM.
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

import logging
import paramiko
import socket
import ssl
import time

from lxml import etree
from io import StringIO

from gmp.gmp import _gmp

logger = logging.getLogger(__name__)

BUF_SIZE = 1024


class GMPError(Exception):
    pass


class GVMConnection:
    """Wrapper for GMP

    This class helps users to connect to their GVM via Secure Shell,
    UNIX-Socket or secured connection on port 9390.

    Variables:
        gmp_generator {object} -- Instance of the gmp generator.
        authenticated {bool} -- GMP-User authenticated.
    """

    def __init__(self):
        # GMP Message Creator
        self.gmp_generator = _gmp()

        # Is authenticated on gvm
        self.authenticated = False

        # initialize variables
        self.sock = None

    def readAll(self):
        # just a stub
        pass

    def sendAll(self, cmd):
        # just a stub
        pass

    def send(self, cmd):
        """Call the sendAll(string) method.

        Nothing more ;-)

        Arguments:
            cmd {string} -- XML-Source
        """
        try:
            self.sendAll(cmd)
            logger.debug(cmd)
        except paramiko.SSHException as e:
            print(e)
        except OSError as e:
            logger.info(e)
            raise

    def read(self):
        """Call the readAll() method of the chosen connection type.

        Try to read all from the open socket connection.
        Check for status attribute in xml code.
        If the program is in shell-mode, then it returns a lxml root element,
        otherwise the plain xml.
        If the response is either None or the length is zero,
        then the connection was terminated from the server.

        Returns:
            lxml.etree._Element or <string> -- Response from server.
        """
        response = self.readAll()
        logger.debug('read() {0} Bytes response: {1}'.format(
            len(response), response))

        if response is None or len(str(response)) == 0:
            raise OSError('Connection was closed by remote server')

        if hasattr(self, 'raw_response') and self.raw_response is True: #pylint: disable=E1101
            return response

        self.checkCommandStatus(response)

        if hasattr(self, 'shell_mode') and self.shell_mode is True: #pylint: disable=E1101
            parser = etree.XMLParser(encoding='utf-8', recover=True)

            logger.info('Shell mode activated')
            f = StringIO(response)
            tree = etree.parse(f, parser)
            return tree.getroot()
        else:
            return response

    def close(self):
        try:
            if self.sock is not None:
                self.sock.close()
        except OSError as e:
            logger.debug('Connection closing error: {0}'.format(e))

    def checkCommandStatus(self, xml):
        """Check gmp response

        Look into the gmp response and check for the status in the root element

        Arguments:
            xml {string} -- XML-Source

        Returns:
            bool -- True if valid, otherwise False
        """

        if xml is 0 or xml is None:
            raise GMPError('XML Command is empty')

        try:
            parser = etree.XMLParser(encoding='utf-8', recover=True)
            if etree.iselement(xml):
                root = etree.ElementTree(xml, parser=parser).getroot()
            else:
                root = etree.XML(xml, parser=parser)
            status = root.attrib['status']
            status_text = root.attrib['status_text']

            if not self.authenticated:
                auth = root.find('authenticate_response')
                if auth is not None:
                    status = auth.attrib['status']
                    status_text = auth.attrib['status_text']
                    if status != '400':
                        self.authenticated = True

            if 'OK' not in status_text:
                logger.info('An error occurred on gvm: ' + status_text)
                raise GMPError(status_text)

        except etree.Error as e:
            logger.error('etree.XML(xml): ' + str(e))
            raise

    def argumentsToString(self, kwargs):
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

    def ask_yes_or_no(self, text):
        yes = set(['yes', 'y', 'ye', ''])
        no = set(['no', 'n'])

        choice = input(text).lower()
        if choice in yes:
            return True
        elif choice in no:
            return False
        else:
            return self.ask_yes_or_no(text)

    def authenticate(self, username, password, withCommand=''):
        """Authenticate on GVM.

        The generated authenticate command will be send to server.
        After that a response is read from socket.

        Keyword Arguments:
            username {str} -- Username
            password {str} -- Password
            withCommands {str} -- XML commands (default: {''})

        Returns:
            None or <string> -- Response from server.
        """
        cmd = self.gmp_generator.createAuthenticateCommand(
            username=username, password=password,
            withCommands=str(withCommand))

        self.send(cmd)
        return self.read()

    def create_agent(self, installer, signature, name, comment='', copy='',
                     howto_install='', howto_use=''):
        cmd = self.gmp_generator.createAgentCommand(
            installer, signature, name, comment, copy, howto_install,
            howto_use)
        self.send(cmd)
        return self.read()

    def create_alert(self, name, condition, event, method, filter_id='',
                     copy='', comment=''):
        cmd = self.gmp_generator.createAlertCommand(name, condition, event,
                                                    method, filter_id, copy,
                                                    comment)
        self.send(cmd)
        return self.read()

    def create_asset(self, name, asset_type, comment=''):
        # TODO: Add the missing second method. Also the docs are not complete!
        cmd = self.gmp_generator.createAssetCommand(name, asset_type, comment)
        self.send(cmd)
        return self.read()

    def create_config(self, copy_id, name):
        cmd = self.gmp_generator.createConfigCommand(copy_id, name)
        self.send(cmd)
        return self.read()

    def create_credential(self, name, **kwargs):
        cmd = self.gmp_generator.createCredentialCommand(name, kwargs)
        self.send(cmd)
        return self.read()

    def create_filter(self, name, make_unique, **kwargs):
        cmd = self.gmp_generator.createFilterCommand(name, make_unique, kwargs)
        self.send(cmd)
        return self.read()

    def create_group(self, name, **kwargs):
        cmd = self.gmp_generator.createGroupCommand(name, kwargs)
        self.send(cmd)
        return self.read()

    # TODO: Create notes with comment returns bogus element. Research
    def create_note(self, text, nvt_oid, **kwargs):
        cmd = self.gmp_generator.createNoteCommand(text, nvt_oid, kwargs)
        self.send(cmd)
        return self.read()

    def create_override(self, text, nvt_oid, **kwargs):
        cmd = self.gmp_generator.createOverrideCommand(text, nvt_oid, kwargs)
        self.send(cmd)
        return self.read()

    def create_permission(self, name, subject_id, type, **kwargs):
        cmd = self.gmp_generator.createPermissionCommand(name, subject_id,
                                                         type, kwargs)
        self.send(cmd)
        return self.read()

    def create_port_list(self, name, port_range, **kwargs):
        cmd = self.gmp_generator.createPortListCommand(name, port_range,
                                                       kwargs)
        self.send(cmd)
        return self.read()

    def create_port_range(self, port_list_id, start, end, type, comment=''):
        cmd = self.gmp_generator.createPortRangeCommand(port_list_id, start,
                                                        end, type, comment)
        self.send(cmd)
        return self.read()

    def create_report(self, report_xml_string, **kwargs):
        cmd = self.gmp_generator.createReportCommand(report_xml_string, kwargs)
        self.send(cmd)
        return self.read()

    def create_report_format(self):
        # TODO: Seems to be a complex task. It is needed?
        raise NotImplementedError

    def create_role(self, name, **kwargs):
        cmd = self.gmp_generator.createRoleCommand(name, kwargs)
        self.send(cmd)
        return self.read()

    def create_scanner(self, name, host, port, type, ca_pub, credential_id,
                       **kwargs):
        cmd = self.gmp_generator.createScannerCommand(name, host, port, type,
                                                      ca_pub, credential_id,
                                                      kwargs)
        self.send(cmd)
        return self.read()

    def create_schedule(self, name, **kwargs):
        cmd = self.gmp_generator.createScheduleCommand(name, kwargs)
        self.send(cmd)
        return self.read()

    def create_tag(self, name, resource_id, resource_type, **kwargs):
        cmd = self.gmp_generator.createTagCommand(name, resource_id,
                                                  resource_type, kwargs)
        self.send(cmd)
        return self.read()

    def create_target(self, name, make_unique, **kwargs):
        # TODO: Missing variables
        cmd = self.gmp_generator.createTargetCommand(name, make_unique, kwargs)
        self.send(cmd)
        return self.read()

    def create_task(self, name, config_id, target_id, scanner_id, alert_id='', comment=''):
        cmd = self.gmp_generator.createTaskCommand(
            name, config_id, target_id, scanner_id, alert_id, comment)
        self.send(cmd)
        return self.read()

    def create_user(self, name, password, copy='', hosts_allow='0',
                    ifaces_allow='0', role_ids=(), hosts=None, ifaces=None):
        cmd = self.gmp_generator.createUserCommand(
            name, password, copy, hosts_allow, ifaces_allow, role_ids,
            hosts, ifaces)
        self.send(cmd)
        return self.read()

    def delete_agent(self, **kwargs):
        self.send('<delete_agent {0}/>'.format(self.argumentsToString(kwargs)))
        return self.read()

    def delete_alert(self, **kwargs):
        # if self.ask_yes_or_no('Are you sure to delete this alert? '):
            self.send(
                '<delete_alert {0}/>'.format(self.argumentsToString(kwargs)))
            return self.read()

    def delete_asset(self, asset_id, ultimate=0):
        # if self.ask_yes_or_no('Are you sure to delete this asset? '):
            self.send('<delete_asset asset_id="{0}" ultimate="{1}"/>'
                      .format(asset_id, ultimate))
            return self.read()

    def delete_config(self, config_id, ultimate=0):
        # if self.ask_yes_or_no('Are you sure to delete this config? '):
            self.send('<delete_config config_id="{0}" ultimate="{1}"/>'
                      .format(config_id, ultimate))
            return self.read()

    def delete_credential(self, credential_id, ultimate=0):
        # if self.ask_yes_or_no('Are you sure to delete this credential? '):
        self.send(
            '<delete_credential credential_id="{0}" ultimate="{1}"/>'.format
            (credential_id, ultimate))
        return self.read()

    def delete_filter(self, filter_id, ultimate=0):
        # if self.ask_yes_or_no('Are you sure to delete this filter? '):
            self.send('<delete_filter filter_id="{0}" ultimate="{1}"/>'
                      .format(filter_id, ultimate))
            return self.read()

    def delete_group(self, group_id, ultimate=0):
        # if self.ask_yes_or_no('Are you sure to delete this group? '):
            self.send('<delete_group group_id="{0}" ultimate="{1}"/>'
                      .format(group_id, ultimate))
            return self.read()

    def delete_note(self, note_id, ultimate=0):
        # if self.ask_yes_or_no('Are you sure to delete this note? '):
            self.send('<delete_note note_id="{0}" ultimate="{1}"/>'
                      .format(note_id, ultimate))
            return self.read()

    def delete_override(self, override_id, ultimate=0):
        # if self.ask_yes_or_no('Are you sure to delete this override? '):
            self.send('<delete_override override_id="{0}" ultimate="{1}"/>'
                      .format(override_id, ultimate))
            return self.read()

    def delete_permission(self, permission_id, ultimate=0):
        # if self.ask_yes_or_no('Are you sure to delete this permission? '):
            self.send('<delete_permission permission_id="{0}" ultimate="{1}"/>'
                      .format(permission_id, ultimate))
            return self.read()

    def delete_port_list(self, port_list_id, ultimate=0):
        # if self.ask_yes_or_no('Are you sure to delete this port_list? '):
            self.send('<delete_port_list port_list_id="{0}" ultimate="{1}"/>'
                      .format(port_list_id, ultimate))
            return self.read()

    def delete_port_range(self, port_range_id):
        # if self.ask_yes_or_no('Are you sure to delete this port_range? '):
            self.send('<delete_port_range port_range_id="{0}"/>'
                      .format(port_range_id))
            return self.read()

    def delete_report(self, report_id):
        # if self.ask_yes_or_no('Are you sure to delete this report? '):
            self.send('<delete_report report_id="{0}"/>'
                      .format(report_id))
            return self.read()

    def delete_report_format(self, report_format_id, ultimate=0):
        # if self.ask_yes_or_no('Are you sure to delete this report_format? '):
            self.send('<delete_report_format report_format_id="{0}" \
ultimate="{1}"/>'.format(report_format_id, ultimate))
            return self.read()

    def delete_role(self, role_id, ultimate=0):
        # if self.ask_yes_or_no('Are you sure to delete this role? '):
            self.send('<delete_role role_id="{0}" ultimate="{1}"/>'
                      .format(role_id, ultimate))
            return self.read()

    def delete_scanner(self, scanner_id, ultimate=0):
        # if self.ask_yes_or_no('Are you sure to delete this scanner? '):
            self.send('<delete_scanner scanner_id="{0}" ultimate="{1}"/>'
                      .format(scanner_id, ultimate))
            return self.read()

    def delete_schedule(self, schedule_id, ultimate=0):
        # if self.ask_yes_or_no('Are you sure to delete this schedule? '):
            self.send('<delete_schedule schedule_id="{0}" ultimate="{1}"/>'
                      .format(schedule_id, ultimate))
            return self.read()

    def delete_tag(self, tag_id, ultimate=0):
        # if self.ask_yes_or_no('Are you sure to delete this tag? '):
            self.send('<delete_tag tag_id="{0}" ultimate="{1}"/>'
                      .format(tag_id, ultimate))
            return self.read()

    def delete_target(self, target_id, ultimate=0):
        # if self.ask_yes_or_no('Are you sure to delete this target? '):
            self.send('<delete_target target_id="{0}" ultimate="{1}"/>'
                      .format(target_id, ultimate))
            return self.read()

    def delete_task(self, task_id, ultimate=0):
        # if self.ask_yes_or_no('Are you sure to delete this task? '):
            self.send('<delete_task task_id="{0}" ultimate="{1}"/>'
                      .format(task_id, ultimate))
            return self.read()

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

        self.send('<delete_user{0}{1}{2}{3}/>'
                  .format(user_id, name, inheritor_id, inheritor_name))
        return self.read()

    def describe_auth(self):
        self.send('<describe_auth/>')
        return self.read()

    def empty_trashcan(self):
        self.send('<empty_trashcan/>')
        return self.read()

    def get_agents(self, **kwargs):
        self.send('<get_agents {0}/>'.format(self.argumentsToString(kwargs)))
        return self.read()

    def get_aggregates(self, **kwargs):
        self.send(
            '<get_aggregates {0}/>'.format(self.argumentsToString(kwargs)))
        return self.read()

    def get_alerts(self, **kwargs):
        self.send('<get_alerts {0}/>'.format(self.argumentsToString(kwargs)))
        return self.read()

    def get_assets(self, **kwargs):
        self.send('<get_assets {0}/>'.format(self.argumentsToString(kwargs)))
        return self.read()

    def get_credentials(self, **kwargs):
        self.send(
            '<get_credentials {0}/>'.format(self.argumentsToString(kwargs)))
        return self.read()

    def get_configs(self, **kwargs):
        self.send('<get_configs {0}/>'.format(self.argumentsToString(kwargs)))
        return self.read()

    def get_feeds(self, **kwargs):
        self.send('<get_feeds {0}/>'.format(self.argumentsToString(kwargs)))
        return self.read()

    def get_filters(self, **kwargs):
        self.send('<get_filters {0}/>'.format(self.argumentsToString(kwargs)))
        return self.read()

    def get_groups(self, **kwargs):
        self.send('<get_groups {0}/>'.format(self.argumentsToString(kwargs)))
        return self.read()

    def get_info(self, **kwargs):
        self.send('<get_info {0}/>'.format(self.argumentsToString(kwargs)))
        return self.read()

    def get_notes(self, **kwargs):
        self.send('<get_notes {0}/>'.format(self.argumentsToString(kwargs)))
        return self.read()

    def get_nvts(self, **kwargs):
        self.send('<get_nvts {0}/>'.format(self.argumentsToString(kwargs)))
        return self.read()

    def get_nvt_families(self, **kwargs):
        self.send(
            '<get_nvt_families {0}/>'.format(self.argumentsToString(kwargs)))
        return self.read()

    def get_overrides(self, **kwargs):
        self.send(
            '<get_overrides {0}/>'.format(self.argumentsToString(kwargs)))
        return self.read()

    def get_permissions(self, **kwargs):
        self.send(
            '<get_permissions {0}/>'.format(self.argumentsToString(kwargs)))
        return self.read()

    def get_port_lists(self, **kwargs):
        self.send(
            '<get_port_lists {0}/>'.format(self.argumentsToString(kwargs)))
        return self.read()

    def get_preferences(self, **kwargs):
        self.send(
            '<get_preferences {0}/>'.format(self.argumentsToString(kwargs)))
        return self.read()

    def get_reports(self, **kwargs):
        self.send('<get_reports {0}/>'
                  .format(self.argumentsToString(kwargs)))
        return self.read()

    def get_report_formats(self, **kwargs):
        self.send(
            '<get_report_formats {0}/>'.format(self.argumentsToString(kwargs)))
        return self.read()

    def get_results(self, **kwargs):
        self.send('<get_results {0}/>'.format(self.argumentsToString(kwargs)))
        return self.read()

    def get_roles(self, **kwargs):
        self.send('<get_roles {0}/>'.format(self.argumentsToString(kwargs)))
        return self.read()

    def get_scanners(self, **kwargs):
        self.send('<get_scanners {0}/>'.format(self.argumentsToString(kwargs)))
        return self.read()

    def get_schedules(self, **kwargs):
        self.send(
            '<get_schedules {0}/>'.format(self.argumentsToString(kwargs)))
        return self.read()

    def get_settings(self, **kwargs):
        self.send('<get_settings {0}/>'.format(self.argumentsToString(kwargs)))
        return self.read()

    def get_system_reports(self, **kwargs):
        self.send(
            '<get_system_reports {0}/>'.format(self.argumentsToString(kwargs)))
        return self.read()

    def get_tags(self, **kwargs):
        self.send('<get_tags {0}/>'.format(self.argumentsToString(kwargs)))
        return self.read()

    def get_targets(self, **kwargs):
        self.send('<get_targets {0}/>'.format(self.argumentsToString(kwargs)))
        return self.read()

    def get_tasks(self, **kwargs):
        self.send('<get_tasks {0}/>'.format(self.argumentsToString(kwargs)))
        return self.read()

    def get_users(self, **kwargs):
        self.send('<get_users {0}/>'.format(self.argumentsToString(kwargs)))
        return self.read()

    def get_version(self):
        self.send('<get_version/>')
        return self.read()

    def help(self, **kwargs):
        self.send('<help {0} />'.format(self.argumentsToString(kwargs)))
        return self.read()

    def modify_agent(self, agent_id, name='', comment=''):
        cmd = self.gmp_generator.modifyAgentCommand(agent_id, name, comment)
        self.send(cmd)
        return self.read()

    def modify_alert(self, alert_id, **kwargs):
        cmd = self.gmp_generator.modifyAlertCommand(alert_id, kwargs)
        self.send(cmd)
        return self.read()

    def modify_asset(self, asset_id, comment):
        cmd = '<modify_asset asset_id="%s"><comment>%s</comment>' \
              '</modify_asset>' % (asset_id, comment)
        self.send(cmd)
        return self.read()

    def modify_auth(self, group_name,  auth_conf_settings):
        cmd = self.gmp_generator.modifyAuthCommand(group_name,
                                                   auth_conf_settings)
        self.send(cmd)
        return self.read()

    def modify_config(self, selection, **kwargs):
        cmd = self.gmp_generator.modifyConfigCommand(selection, kwargs)
        self.send(cmd)
        return self.read()

    def modify_credential(self, credential_id, **kwargs):
        cmd = self.gmp_generator.modifyCredentialCommand(credential_id, kwargs)
        self.send(cmd)
        return self.read()

    def modify_filter(self, filter_id, **kwargs):
        cmd = self.gmp_generator.modifyFilterCommand(filter_id, kwargs)
        self.send(cmd)
        return self.read()

    def modify_group(self, group_id, **kwargs):
        cmd = self.gmp_generator.modifyGroupCommand(group_id, kwargs)
        self.send(cmd)
        return self.read()

    def modify_note(self, note_id, text, **kwargs):
        cmd = self.gmp_generator.modifyNoteCommand(note_id, text, kwargs)
        self.send(cmd)
        return self.read()

    def modify_override(self, override_id, text, **kwargs):
        cmd = self.gmp_generator.modifyOverrideCommand(override_id, text,
                                                       kwargs)
        self.send(cmd)
        return self.read()

    def modify_permission(self, permission_id, **kwargs):
        cmd = self.gmp_generator.modifyPermissionCommand(permission_id, kwargs)
        self.send(cmd)
        return self.read()

    def modify_port_list(self, port_list_id, **kwargs):
        cmd = self.gmp_generator.modifyPortListCommand(port_list_id, kwargs)
        self.send(cmd)
        return self.read()

    def modify_report(self, report_id, comment):
        cmd = '<modify_report report_id="{0}"><comment>{1}</comment>' \
              '</modify_report>'.format(report_id, comment)
        self.send(cmd)
        return self.read()

    def modify_report_format(self, report_format_id, **kwargs):
        cmd = self.gmp_generator.modifyReportFormatCommand(report_format_id,
                                                           kwargs)
        self.send(cmd)
        return self.read()

    def modify_role(self, role_id, **kwargs):
        cmd = self.gmp_generator.modifyRoleCommand(role_id, kwargs)
        self.send(cmd)
        return self.read()

    def modify_scanner(self, scanner_id, host, port, type, **kwargs):
        cmd = self.gmp_generator.modifyScannerCommand(scanner_id, host, port,
                                                      type, kwargs)
        self.send(cmd)
        return self.read()

    def modify_schedule(self, schedule_id, **kwargs):
        cmd = self.gmp_generator.modifyScheduleCommand(schedule_id, kwargs)
        self.send(cmd)
        return self.read()

    def modify_setting(self, setting_id, name, value):
        cmd = '<modify_setting setting_id="{0}"><name>{1}</name>' \
              '<value>{2}</value></modify_setting>' \
              ''.format(setting_id, name, value)
        self.send(cmd)
        return self.read()

    def modify_tag(self, tag_id, **kwargs):
        cmd = self.gmp_generator.modifyTagCommand(tag_id, kwargs)
        self.send(cmd)
        return self.read()

    def modify_target(self, target_id, **kwargs):
        cmd = self.gmp_generator.modifyTargetCommand(target_id, kwargs)
        self.send(cmd)
        return self.read()

    def modify_task(self, task_id, **kwargs):
        cmd = self.gmp_generator.modifyTaskCommand(task_id, kwargs)
        self.send(cmd)
        return self.read()

    def modify_user(self, **kwargs):
        cmd = self.gmp_generator.modifyUserCommand(kwargs)
        self.send(cmd)
        return self.read()

    def move_task(self, task_id, slave_id):
        self.send('<move_task task_id="{0}" slave_id="{1}"/>'
                  .format(task_id, slave_id))
        return self.read()

    def restore(self, id):
        self.send('<restore id="{0}"/>'.format(id))
        return self.read()

    def resume_task(self, task_id):
        self.send('<resume_task task_id="{0}"/>'.format(task_id))
        return self.read()

    def run_wizard(self):
        # TODO: Is this required?
        raise NotImplementedError

    def start_task(self, task_id):
        self.send('<start_task task_id="{0}"/>'.format(task_id))
        return self.read()

    def stop_task(self, task_id):
        self.send('<stop_task task_id="{0}"/>'.format(task_id))
        return self.read()

    def sync_cert(self):
        self.send('<sync_cert/>')
        return self.read()

    def sync_config(self):
        self.send('<sync_config/>')
        return self.read()

    def sync_feed(self):
        self.send('<sync_feed/>')
        return self.read()

    def sync_scap(self):
        self.send('<sync_scap/>')
        return self.read()

    def test_alert(self, id):
        self.send('<test_alert alert_id="{0}"/>'.format(id))
        return self.read()

    def verify_agent(self, id):
        self.send('<verify_agent agent_id="{0}"/>'.format(id))
        return self.read()

    def verify_report_format(self, id):
        self.send('<verify_report_format report_format_id="{0}"/>'.format(id))
        return self.read()

    def verify_scanner(self, id):
        self.send('<verify_scanner scanner_id="{0}"/>'.format(id))
        return self.read()


class SSHConnection(GVMConnection):
    """SSH Class to connect, read and write from GVM via SSH

    [description]

    Variables:
        sock {[type]} -- Channel from paramiko after successful connection

    """

    def __init__(self, **kwargs):
        super().__init__()
        self.hostname = kwargs.get('hostname', '127.0.0.1')
        self.port = kwargs.get('port', 22)
        self.raw_response = kwargs.get('raw_response', False)
        self.timeout = kwargs.get('timeout', 5)
        self.ssh_user = kwargs.get('ssh_user', 'gmp')
        self.ssh_password = kwargs.get('ssh_password', '')
        self.shell_mode = kwargs.get('shell_mode', False)
        self.sock = paramiko.SSHClient()
        # self.sock.load_system_host_keys()
        # self.sock.set_missing_host_key_policy(paramiko.WarningPolicy())
        self.sock.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            self.sock.connect(
                hostname=self.hostname,
                username=self.ssh_user,
                password=self.ssh_password,
                timeout=self.timeout,
                port=int(self.port),
                allow_agent=False,
                look_for_keys=False)
            self.channel = self.sock.invoke_shell()

        except (paramiko.BadHostKeyException,
                paramiko.AuthenticationException,
                paramiko.SSHException, OSError) as e:
            logger.debug('SSH Connection failed: ' + str(e))
            raise

    def readAll(self):
        self.first_element = None
        self.parser = etree.XMLPullParser(('start','end'))
        read_bytes = 0
        garbage_bytes = len(self.cmd) +1
        # Remove command string from result
        while not read_bytes == garbage_bytes:
            read_bytes += len(self.channel.recv(garbage_bytes-read_bytes))

        response = b''

        while True:
            data = self.channel.recv(BUF_SIZE)

            # Connection was closed by server
            if not data:
                break

            self.parser.feed(data)

            response += data

            if self.valid_xml():
                break

        return response.decode('utf-8')

    def sendAll(self, cmd):
        logger.debug('SSH:send(): ' + cmd)
        self.cmd = str(cmd) + '\n'
        self.channel.sendall(self.cmd)

    def valid_xml(self):
        for action, obj in self.parser.read_events():
            if not self.first_element and action in 'start':
                self.first_element = obj.tag

            if self.first_element and action in 'end' and str(self.first_element) == str(obj.tag):
                return True
        return False


class TLSConnection(GVMConnection):
    """TLS class to connect, read and write from GVM via tls secured socket

    [description]

    Variables:
        sock {socket.socket} -- Socket that holds the connection
    """

    def __init__(self, **kwargs):
        super().__init__()
        self.hostname = kwargs.get('hostname', '127.0.0.1')
        self.port = kwargs.get('port', 9390)
        self.raw_response = kwargs.get('raw_response', False)
        self.timeout = kwargs.get('timeout', 60)
        self.shell_mode = kwargs.get('shell_mode', False)
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        self.sock = context.wrap_socket(socket.socket(socket.AF_INET))
        self.sock.settimeout(self.timeout)
        self.sock.connect((self.hostname, int(self.port)))

    def sendAll(self, cmd):
        self.sock.send(cmd.encode())

    def readAll(self):
        response = ''
        while True:
            data = self.sock.read(BUF_SIZE)

            response += data.decode(errors='ignore')
            if len(data) < BUF_SIZE:
                break
        return response


class UnixSocketConnection(GVMConnection):
    """UNIX-Socket class to connect, read, write from GVM
    via direct communicating UNIX-Socket

    [description]

    Variables:
        sock {socket.socket} -- Socket that holds the connection
        sockpath {string} -- Path to UNIX-Socket
    """

    def __init__(self, **kwargs):
        super().__init__()
        self.raw_response = kwargs.get('raw_response', False)
        self.sockpath = kwargs.get('sockpath',
                                   '/usr/local/var/run/gvmd.sock')
        self.shell_mode = kwargs.get('shell_mode', False)
        self.timeout = kwargs.get('timeout', 60)
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) #pylint: disable=E1101
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.sockpath)

    def readAll(self):
        response = ''
        while True:
            data = self.sock.recv(BUF_SIZE)
            # Todo: Why does the sleep helps here? Sometimes it will break
            # here because the message is missing some bytes at the end.
            # Same script and with tls or ssh, then it works flawless without
            # "sleep()"
            time.sleep(0.000001)
            response += data.decode()
            if len(data) < BUF_SIZE:
                break

        return response

    def sendAll(self, cmd):
        self.sock.send(cmd.encode())
