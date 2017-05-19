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

from libs.gmp import _gmp

logger = logging.getLogger(__name__)

BUF_SIZE = 1024


class GMPError(Exception):
    pass


class NotImplemented(Exception):
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

    def send(self, cmd):
        """Call the sendAll(string) method.

        Nothing more ;-)

        Arguments:
            cmd {string} -- XML-Source
        """
        try:
            self.sendAll(cmd)
            time.sleep(0.1)
        except paramiko.SSHException as e:
            print(e)
        except OSError as e:
            logger.info(e)

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

        self.checkCommandStatus(response)

        if hasattr(self, 'shell_mode') and self.shell_mode is True:
            logger.info('Shell mode activated')
            f = StringIO(response)
            tree = etree.parse(f)
            return tree.getroot()
        else:
            return response

    def close(self):
        try:
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
            if(etree.iselement(xml)):
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
            msg += str(key) + '="' + str(value) + '" '

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
        self.read()

    def create_agent(self, installer, signature, name, comment='', copy='',
                     howto_install='', howto_use=''):
        cmd = self.gmp_generator.createAgentCommand(
            installer, signature, name, comment, copy, howto_install,
            howto_use)
        self.send(cmd)
        return self.read()

    def create_alert(self):
        # , name, comment='', copy='', condition, event, method, filter
        raise NotImplemented

    def create_asset(self):
        raise NotImplemented

    def create_config(self, copy_id, name):
        cmd = self.gmp_generator.createConfigCommand(copy_id, name)
        self.send(cmd)
        return self.read()

    def create_credential(self):
        raise NotImplemented

    def create_filter(self):
        raise NotImplemented

    def create_group(self):
        raise NotImplemented

    def create_note(self):
        raise NotImplemented

    def create_override(self):
        raise NotImplemented

    def create_permission(self):
        raise NotImplemented

    def create_port_list(self):
        raise NotImplemented

    def create_port_range(self):
        raise NotImplemented

    def create_report(self):
        raise NotImplemented

    def create_report_format(self):
        raise NotImplemented

    def create_role(self):
        raise NotImplemented

    def create_scanner(self):
        raise NotImplemented

    def create_schedule(self):
        raise NotImplemented

    def create_tag(self):
        raise NotImplemented

    def create_target(self, name, hosts):
        cmd = self.gmp_generator.createTargetCommand(name, hosts)
        self.send(cmd)
        return self.read()

    def create_task(self, name, config_id, target_id, scanner_id, comment=''):
        cmd = self.gmp_generator.createTaskCommand(
            name, config_id, target_id, scanner_id, comment)
        self.send(cmd)
        return self.read()

    def create_user(self, name, password, copy='', hosts_allow=None,
                    ifaces_allow=None, role_ids=()):
        cmd = self.gmp_generator.createUserCommand(
            name, copy, hosts_allow, ifaces_allow, password, role_ids)
        self.send(cmd)
        return self.read()

    def delete_agent(self, **kwargs):
        self.send('<delete_agent {0}/>'.format(self.argumentsToString(kwargs)))
        return self.read()

    def delete_alert(self, **kwargs):
        if self.ask_yes_or_no('Are you sure to delete this alert? '):
            self.send(
                '<delete_alert {0}/>'.format(self.argumentsToString(kwargs)))
            return self.read()

    def delete_asset(self, asset_id, ultimate):
        if self.ask_yes_or_no('Are you sure to delete this asset? '):
            self.send('<delete_asset asset_id="{0}" ultimate="{1}"/>'
                      .format(asset_id, ultimate))
            return self.read()

    def delete_config(self, config_id, ultimate):
        if self.ask_yes_or_no('Are you sure to delete this config? '):
            self.send('<delete_config config_id="{0}" ultimate="{1}"/>'
                      .format(config_id, ultimate))
            return self.read()

    def delete_credential(self, credential_id, ultimate):
        if self.ask_yes_or_no('Are you sure to delete this credential? '):
            self.send(
                '<delete_credential cedential_id="{0}" ultimate="{1}"/>'.format
                (credential_id, ultimate))
            return self.read()

    def delete_filter(self, filter_id, ultimate):
        if self.ask_yes_or_no('Are you sure to delete this filter? '):
            self.send('<delete_filter filter_id="{0}" ultimate="{1}"/>'
                      .format(filter_id, ultimate))
            return self.read()

    def delete_group(self, group_id, ultimate):
        if self.ask_yes_or_no('Are you sure to delete this group? '):
            self.send('<delete_group group_id="{0}" ultimate="{1}"/>'
                      .format(group_id, ultimate))
            return self.read()

    def delete_note(self, note_id, ultimate):
        if self.ask_yes_or_no('Are you sure to delete this note? '):
            self.send('<delete_note note_id="{0}" ultimate="{1}"/>'
                      .format(note_id, ultimate))
            return self.read()

    def delete_override(self, override_id, ultimate):
        if self.ask_yes_or_no('Are you sure to delete this override? '):
            self.send('<delete_override override_id="{0}" ultimate="{1}"/>'
                      .format(override_id, ultimate))
            return self.read()

    def delete_permission(self, permission_id, ultimate):
        if self.ask_yes_or_no('Are you sure to delete this permission? '):
            self.send('<delete_permission permission_id="{0}" ultimate="{1}"/>'
                      .format(permission_id, ultimate))
            return self.read()

    def delete_port_list(self, port_list_id, ultimate):
        if self.ask_yes_or_no('Are you sure to delete this port_list? '):
            self.send('<delete_port_list port_list_id="{0}" ultimate="{1}"/>'
                      .format(port_list_id, ultimate))
            return self.read()

    def delete_port_range(self, port_range_id):
        if self.ask_yes_or_no('Are you sure to delete this port_range? '):
            self.send('<delete_port_range port_range_id="{0}"/>'
                      .format(port_range_id))
            return self.read()

    def delete_report(self, report_id):
        if self.ask_yes_or_no('Are you sure to delete this report? '):
            self.send('<delete_report report_id="{0}"/>'
                      .format(report_id))
            return self.read()

    def delete_report_format(self, report_format_id, ultimate):
        if self.ask_yes_or_no('Are you sure to delete this report_format? '):
            self.send('<delete_report_format report_format_id="{0}" \
ultimate="{1}"/>'.format(report_format_id, ultimate))
            return self.read()

    def delete_role(self, role_id, ultimate):
        if self.ask_yes_or_no('Are you sure to delete this role? '):
            self.send('<delete_role role_id="{0}" ultimate="{1}"/>'
                      .format(role_id, ultimate))
            return self.read()

    def delete_scanner(self, scanner_id, ultimate):
        if self.ask_yes_or_no('Are you sure to delete this scanner? '):
            self.send('<delete_scanner scanner_id="{0}" ultimate="{1}"/>'
                      .format(scanner_id, ultimate))
            return self.read()

    def delete_schedule(self, schedule_id, ultimate):
        if self.ask_yes_or_no('Are you sure to delete this schedule? '):
            self.send('<delete_schedule schedule_id="{0}" ultimate="{1}"/>'
                      .format(schedule_id, ultimate))
            return self.read()

    def delete_tag(self, tag_id, ultimate):
        if self.ask_yes_or_no('Are you sure to delete this tag? '):
            self.send('<delete_tag tag_id="{0}" ultimate="{1}"/>'
                      .format(tag_id, ultimate))
            return self.read()

    def delete_target(self, target_id, ultimate):
        if self.ask_yes_or_no('Are you sure to delete this target? '):
            self.send('<delete_target target_id="{0}" ultimate="{1}"/>'
                      .format(target_id, ultimate))
            return self.read()

    def delete_task(self, task_id, ultimate):
        if self.ask_yes_or_no('Are you sure to delete this task? '):
            self.send('<delete_task task_id="{0}" ultimate="{1}"/>'
                      .format(task_id, ultimate))
            return self.read()

    def delete_user(self):
        raise NotImplemented

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

    def get_port_lists(self):
        self.send('<get_port_lists/>')
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

    def modify_agent(self, id, name='', comment=''):
        cmd = self.gmp_generator.modifyAgentCommand(id, name, comment)
        self.send(cmd)
        return self.read()

    def modify_alert(self):
        raise NotImplemented

    def modify_asset(self):
        raise NotImplemented

    def modify_auth(self):
        raise NotImplemented

    def modify_config(self, selection, **kwargs):
        cmd = self.gmp_generator.modifyConfigCommand(selection, kwargs)
        self.send(cmd)
        return self.read()

    def modify_credential(self):
        raise NotImplemented

    def modify_filter(self):
        raise NotImplemented

    def modify_group(self):
        raise NotImplemented

    def modify_note(self):
        raise NotImplemented

    def modify_override(self):
        raise NotImplemented

    def modify_permission(self):
        raise NotImplemented

    def modify_port_list(self):
        raise NotImplemented

    def modify_report(self):
        raise NotImplemented

    def modify_report_format(self):
        raise NotImplemented

    def modify_role(self):
        raise NotImplemented

    def modify_scanner(self):
        raise NotImplemented

    def modify_schedule(self):
        raise NotImplemented

    def modify_setting(self):
        raise NotImplemented

    def modify_tag(self):
        raise NotImplemented

    def modify_target(self):
        raise NotImplemented

    def modify_task(self):
        raise NotImplemented

    def modify_user(self):
        raise NotImplemented

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
        raise NotImplemented

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
        self.timeout = kwargs.get('timeout', 5)
        self.ssh_user = kwargs.get('ssh_user', 'gmp')
        self.ssh_password = kwargs.get('ssh_password', '')
        self.shell_mode = kwargs.get('shell_mode', False)
        self.sock = paramiko.SSHClient()
        # self.sock.set_missing_host_key_policy(paramiko.WarningPolicy())
        self.sock.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            self.sock.connect(
                hostname=self.hostname,
                username=self.ssh_user,
                password=self.ssh_password,
                timeout=self.timeout,
                port=int(self.port))
            self.channel = self.sock.invoke_shell()

        except (paramiko.BadHostKeyException,
                paramiko.AuthenticationException,
                paramiko.SSHException, OSError) as e:
            logger.debug('SSH Connection failed: ' + str(e))
            raise

        time.sleep(0.1)
        # Empty the socket with a read command.
        debug = self.readAll()
        logger.debug(debug)

    def readAll(self):
        response = ''
        while self.channel.recv_ready():
            response += self.channel.recv(BUF_SIZE).decode()
        logger.debug('SSH read() {0} Bytes response: {1}'.format(
            len(response), response))
        # Split the response, because the request is in response too.
        list = response.partition('\r\n')
        if len(list) > 1:
            return list[2]

        return 0

    def sendAll(self, cmd):
        logger.debug('SSH:send(): ' + cmd)
        self.channel.sendall(str(cmd) + '\n')
        time.sleep(0.5)


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
        self.timeout = kwargs.get('timeout', 60)
        self.shell_mode = kwargs.get('shell_mode', False)
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        self.sock = context.wrap_socket(socket.socket(socket.AF_INET))
        self.sock.settimeout(self.timeout)
        self.sock.connect((self.hostname, self.port))

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
        self.sockpath = kwargs.get('sockpath',
                                   '/usr/local/var/run/openvasmd.sock')
        self.shell_mode = kwargs.get('shell_mode', False)
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
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
