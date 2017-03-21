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

import getpass
import logging
import paramiko
import re
import socket
import ssl
import sys
import time

from lxml import etree, objectify
from io import StringIO

from gmp import _gmp


logging.getLogger(__name__).addHandler(logging.NullHandler())
logging.basicConfig(filename='gmp.log', level=logging.DEBUG)

BUF_SIZE = 8096


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class GVMConnection:
    """Wrapper for GMP

    This class helps users to connect to their GVM via Secure Shell, 
    UNIX-Socket or secured connection on port 9390.

    Variables:
        SSH {number} -- Enum value for SSH connection.
        TLS {number} -- Enum value for TLS connection.
        UNIX_SOCKET {number} -- Enum value for UNIX-Socket connection.
        current_connection {[type]} -- Holds the currently used connection. SSHConnection, TLSConnection, UnixSocketConnection
        argv {[type]} -- Arguments from main program
        gmp_generator {[type]} -- Instance of the gmp generator. This creates gmp commands.
        shell_mode {bool} -- Shell-Mode true or false.
        authenticated {bool} -- GMP-User authenticated.
    """
    SSH = 0
    TLS = 1
    UNIX_SOCKET = 2

    # Holds the socket
    current_connection = None

    # All startparameters and config arguments
    argv = None

    # GMP Message Creator
    gmp_generator = _gmp()

    # Shell_Mode
    shell_mode = False

    # Is authenticated on gvm
    authenticated = False

    def __init__(self, connection_type, argv):
        """Initialize values

        First makes main prpgram arguments class readable for all methods. 
        Then deciding if program is in shell-mode or simple cli.
        'connection_type' holds the number to start the right connection.

        Arguments:
            connection_type {number} -- Either SSH, TLS or UNIX_SOCKET
            argv {object} -- Argument values from main program
        """
        # logging.debug(argv)
        self.argv = argv

        if 'gvm-pyshell' in sys.argv[0]:
            self.shell_mode = True

        if connection_type == self.SSH:
            self.createSSHConnection()
        elif connection_type == self.TLS:
            self.createTLSConnection()
        elif connection_type == self.UNIX_SOCKET:
            self.createUnixSocketConnection()
        else:
            sys.exit('Connection type is not available.')

    def createSSHConnection(self):
        try:
            self.current_connection = SSHConnection(
                self.argv.hostname, self.argv.port, self.argv.ssh_user, '', 5)
        except Exception as ex:
            sys.exit('Something is wrong with ssh connection data: ' + str(ex))

    def createTLSConnection(self):
        try:
            self.current_connection = TLSConnection(self.argv.hostname)
        except (ssl.SSLError, socket.error) as ex:
            sys.exit('Something is wrong with tls connection data: ' + str(ex))

    def createUnixSocketConnection(self):
        try:
            self.current_connection = UnixSocketConnection(self.argv.socket)
        except Exception as ex:
            sys.exit('Something is wrong with unix socket connection: ' + str(ex))

    def send(self, cmd):
        """Call the send(string) method of the choosed connection type.

        Nothing more ;-)

        Arguments:
            cmd {string} -- XML-Source
        """
        try:
            cmd = re.sub('[\s+]', '', cmd)
            logging.debug('send(): ' + cmd)
            self.current_connection.send(cmd)
            time.sleep(0.1)
        except Exception as ex:
            sys.exit(ex)

    def read(self):
        """Call the readAll() method of the choosed connection type.

        Try to read all from the open socket connection. 
        Check for status attribute in xml code.
        If the program is in shell-mode, then it returns a lxml root element, otherwise the plain xml.
        If the response is either None or the length is zero, then the connection 
        was terminated from the server.

        Returns:
            lxml.etree._Element or <string> -- Response from server.
        """
        try:
            result = self.current_connection.readAll()
            logging.debug('read() result: ' + result)            

            if result == None or len(str(result)) == 0:
                sys.exit('Connection closed by server')

            status = self.checkCommandStatus(result)

            if not status:
                sys.exit("GMP Response status not ok")

            if self.shell_mode:
                logging.info('Shell mode activated')
                f = StringIO(result)
                tree = etree.parse(f)
                return tree.getroot()
            else:
                return result
        except Exception as ex:
            # Empty exception is thrown if server close the connection.
            logging.error('read() exception: ' + str(ex))

    def close(self):
        """Call the close() method of the choosed connection type.

        Nothing more, too ;-)
        """
        try:
            self.current_connection.close()
        except Exception as ex:
            sys.exit(ex)

    def authenticate(self):
        return self.authenticate('')

    def authenticate(self, username='admin', password='admin'):
        """Authenticate on GVM.

        Sets the gmp credentials variables and call the the right authenticate() method.

        Keyword Arguments:
            username {str} -- GMP Username (default: {'admin'})
            password {str} -- GMP Password (default: {'admin'})
        """
        self.argv.gmp_username = username
        self.argv.gmp_password = password
        self.authenticate('')

    def authenticate(self, withCommands=''):
        """Authenticate on GVM.

        Check if username and/or password for gvm is set. 
        If no password is set before it asks in a password prompt for it.
        The generated authenticate command will be send to server.
        After that a response is read from socket. 

        Keyword Arguments:
            withCommands {str} -- XML commands, that could be send with the authenticate command (default: {''})

        Returns:
            None or <string> -- Response from server.
        """
        if self.argv.gmp_username:
            if not self.argv.gmp_password:
                self.argv.gmp_password = getpass.getpass(
                    'Please enter password for ' + self.argv.gmp_username + ': ')

        cmd = self.gmp_generator.createAuthenticateCommand(
            username=self.argv.gmp_username, password=self.argv.gmp_password, withCommands=str(withCommands))
        
        self.send(cmd)

        time.sleep(0.2)

        result = self.read()

        return result

    def checkCommandStatus(self, xml):
        """Check gmp response

        Look into the gmp response and check for the status in the root element

        Arguments:
            xml {string} -- XML-Source

        Returns:
            bool -- True if valid, otherwise False
        """
        try:
            root = etree.XML(xml)
            status = root.attrib['status']
            status_text = root.attrib['status_text']

            if status != '200':
                logging.info('An error occured on gvm: ' + status_text)
                return False

            return True

        except Exception as ex:
            logging.error('etree.XML(xml): ' + ex)

    def get_version(self):
        self.send('<get_version/>')
        return self.read()

    def get_tasks(self):
        self.send('<get_tasks/>')
        return self.read()

    def get_port_lists(self):
        self.send('<get_port_lists/>')
        return self.read()


class SSHConnection:
    """SSH Class to connect, read and write from GVM via SSH

    [description]

    Variables:
        ssh_hostname {str} -- SSH Hostname or IP-Address
        ssh_port {number} -- SSH Port
        ssh_username {str} -- SSH Username
        ssh_password {str} -- SSH Password
        ssh_timeout {number} -- SSH Timeout
        sock {[type]} -- Channel from paramiko after successful connection
        gmp_stdin {[type]} -- Channels standard input socket
        gmp_stdout {[type]} -- Channels standard output socket
    """
    ssh_hostname = '127.0.0.1'
    ssh_port = 22
    ssh_username = 'gmp'
    ssh_password = ''
    ssh_timeout = 5

    sock = None
    gmp_stdin = None
    gmp_stdout = None

    def __init__(self, hostname, port, username, password, timeout):
        self.sock = paramiko.SSHClient()
        # self.sock.set_missing_host_key_policy(paramiko.WarningPolicy())
        self.sock.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self.sock.connect(
                hostname=hostname, username=username, password=password, timeout=timeout, port=int(port))
            channel = self.sock.invoke_shell()

            self.gmp_stdin = channel.makefile('wb')
            self.gmp_stdout = channel.makefile('r')

        except (paramiko.BadHostKeyException, paramiko.AuthenticationException, paramiko.SSHException, socket.error) as e:
            print('SSH Connection failed: ' + str(e))
            sys.exit(1)

        time.sleep(0.5)
        # Empty the socket with a read command.
        debug = self.readAll()
        logging.debug(debug)

    def readAll(self):
        length = len(self.gmp_stdout.channel.in_buffer)
        result = self.gmp_stdout.read(length).decode()
        # print(result)
        # Split the result, because the request is in response too.
        list = result.splitlines()
        # print(list)
        if len(list) > 1:
            return list[1]

        return 0

    def send(self, cmd):
        try:
            logging.debug('SSH:send(): ' + cmd)
            self.gmp_stdin.write(str(cmd) + '\n')
        except socket.error as e:
            print('An error occured: ' + bcolors.FAIL + str(e) +
                  bcolors.ENDC + '\nAddional information in the log files')
            sys.exit(3)

    def close(self):
        """For the SSH Connection first close the stdin and stdout and then the channel
        """
        try:
            self.gmp_stdout.close()
            self.gmp_stdin.close()
            self.sock.close()
        except Exception as e:
            print(str(e))


class TLSConnection:
    """TLS class to connect, read and write from GVM via tls secured socket

    [description]

    Variables:
        sock {socket.socket} -- Socket that holds the connection
    """
    sock = None

    def __init__(self, hostname='127.0.0.1', port=9390):
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        context.check_hostname = False
        self.sock = context.wrap_socket(socket.socket(socket.AF_INET))
        self.sock.connect((hostname, port))

    def send(self, cmd):
        self.sock.send(cmd.encode())

    def readAll(self):
        message = ''
        while True:
            data = self.sock.recv(BUF_SIZE)

            message += data.decode()
            if len(data) < BUF_SIZE:
                break

        return message

    def close(self):
        self.sock.close()


class UnixSocketConnection:
    """UNIX-Socket class to connect, read, write from GVM via direct communicating UNIX-Socket

    [description]

    Variables:
        sock {socket.socket} -- Socket that holds the connection
    """
    sock = None

    def __init__(self, socket_path):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(socket_path)

    def readAll(self):
        message = ''
        while True:
            data = self.sock.recv(BUF_SIZE)

            message += data.decode()
            if len(data) < BUF_SIZE:
                break

        return message

    def send(self, cmd):
        self.sock.send(cmd.encode())

    def close(self):
        self.sock.close()
