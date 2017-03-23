# -*- coding: utf-8 -*-
# $Id$
# Description:
# GVM-Connection classes for communication with the GSM.
#
# Authors:
# Raphael Grewe <raphael.grewe@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

import logging
import paramiko
import socket
import ssl
import sys
import time

from lxml import etree
from io import StringIO

from gmp import _gmp

logger = logging.getLogger(__name__)
logging.basicConfig(filename='gmp.log', level=logging.DEBUG)

BUF_SIZE = 1024


class GMPError(Exception):
    pass


class GVMConnection:
    """Wrapper for GMP

    This class helps users to connect to their GVM via Secure Shell,
    UNIX-Socket or secured connection on port 9390.

    Variables:
        gmp_generator {[type]} -- Instance of the gmp generator.
        authenticated {bool} -- GMP-User authenticated.
    """

    def __init__(self):
        # GMP Message Creator
        self.gmp_generator = _gmp()

        # Is authenticated on gvm
        self.authenticated = False

    def send(self, cmd):
        """Call the sendAll(string) method of the chosen connection type.

        Nothing more ;-)

        Arguments:
            cmd {string} -- XML-Source
        """
        try:
            logger.debug('send(): ' + cmd)
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
        logger.debug('read() response: ' + str(response))

        if response is None or len(str(response)) == 0:
            raise OSError('Connection was closed by server')

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
            return False

        try:
            parser = etree.XMLParser(encoding='utf-8', recover=True)
            root = etree.XML(xml, parser=parser)
            status = root.attrib['status']
            status_text = root.attrib['status_text']

            if status != '200':
                raise GMPError("GMP-Response failure: " + status_text)
                logger.info('An error occured on gvm: ' + status_text)
                return False

            return True

        except etree.Error as e:
            logger.error('etree.XML(xml): ' + str(e))

    def authenticate(self, username='admin', password='admin', withCommand=''):
        """Authenticate on GVM.

        The generated authenticate command will be send to server.
        After that a response is read from socket.

        Keyword Arguments:
            withCommands {str} -- XML commands (default: {''})

        Returns:
            None or <string> -- Response from server.
        """
        cmd = self.gmp_generator.createAuthenticateCommand(
            username=username, password=password,
            withCommands=str(withCommand))

        self.send(cmd)

        return self.read()

    def get_version(self):
        self.send('<get_version/>')
        return self.read()

    def get_tasks(self):
        self.send('<get_tasks/>')
        return self.read()

    def get_port_lists(self):
        self.send('<get_port_lists/>')
        return self.read()

    def get_results(self, filter=''):
        self.send('<get_results filter="{0}"/>'.format(filter))
        return self.read()

    def get_reports(self, filter='', type=''):
        self.send('<get_reports type="{0}" filter="{1}"/>'
                  .format(type, filter))
        return self.read()

    def get_assets(self, filter=''):
        self.send('<get_assets filter="{0}"/>'.format(filter))
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
            print('SSH Connection failed: ' + str(e))
            sys.exit(1)

        time.sleep(0.1)
        # Empty the socket with a read command.
        debug = self.readAll()
        logger.debug(debug)

    def readAll(self):
        response = ''
        while self.channel.recv_ready():
            response += self.channel.recv(BUF_SIZE).decode()
        logger.debug('read ssh response: ' + str(response))
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
        self.shell_mode = kwargs.get('shell_mode', False)
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        context.check_hostname = False
        self.sock = context.wrap_socket(socket.socket(socket.AF_INET))
        self.sock.connect((self.hostname, self.port))

    def sendAll(self, cmd):
        self.sock.send(cmd.encode())

    def readAll(self):
        response = ''
        while True:
            data = self.sock.read(BUF_SIZE)

            response += data.decode(errors='ignore')
            # print(len(data))
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

            response += data.decode()
            print(len(data))
            if len(data) < BUF_SIZE:
                break

        return response

    def sendAll(self, cmd):
        self.sock.send(cmd.encode())
