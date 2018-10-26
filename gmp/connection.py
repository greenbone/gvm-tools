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
Module for connections to gvmd daemon
"""
import logging
import socket as socketlib
import ssl
import time

import paramiko

from lxml import etree

from gmp.error import GmpError

logger = logging.getLogger(__name__)

BUF_SIZE = 1024
DEFAULT_READ_TIMEOUT = 60 # in seconds
DEFAULT_TIMEOUT = 60 # in seconds
DEFAULT_GVM_PORT = 9390
DEFAULT_UNIX_SOCKET_PATH = '/usr/local/var/run/gvmd.sock'
MAX_SSH_DATA_LENGTH = 4095

class XmlReader:
    """
    Read a XML command until its closing element
    """

    def _start_xml(self):
        self._first_element = None
        self._parser = etree.XMLPullParser(('start', 'end'))

    def _is_end_xml(self):
        for action, obj in self._parser.read_events():
            if not self._first_element and action in 'start':
                self._first_element = obj.tag

            if self._first_element and action in 'end' and \
                    str(self._first_element) == str(obj.tag):
                return True
        return False

    def _feed_xml(self, data):
        try:
            self._parser.feed(data)
        except etree.ParseError as e:
            raise GmpError("Can't parse xml response. Response data "
                           "read {0}".format(data), e)


class GmpConnection:
    """
    Base class for establishing a connection to gvmd.
    """

    def __init__(self, socket, timeout=DEFAULT_TIMEOUT):
        """
          Arguments:
            socket -- A socket
        """
        self._socket = socket
        self._timeout = timeout

    def connect(self):
        """Establish a connection to gvmd
        """
        raise NotImplementedError

    def send(self, data):
        """Send data to gvmd
        """
        if isinstance(data, str):
            self._socket.send(data.encode())
        else:
            self._socket.send(data)

    def read(self):
        """Read data from gvmd
        """
        raise NotImplementedError

    def disconnect(self):
        """Close the connection to gvmd
        """
        try:
            if self._socket is not None:
                self._socket.close()
        except OSError as e:
            logger.debug('Connection closing error: %s', e)


class SSHConnection(GmpConnection, XmlReader):
    """
    SSH Class to connect, read and write from GVM via SSH
    """

    def __init__(self, timeout=DEFAULT_TIMEOUT, hostname='127.0.0.1', port=22,
                 username='gmp', password=''):
        socket = paramiko.SSHClient()
        socket.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        super().__init__(socket, timeout=timeout)

        self.hostname = hostname
        self.port = int(port)
        self.username = username
        self.password = password

    def _send_in_chunks(self, data, chunk_size):
        i_start = 0
        i_end = chunk_size
        sent_bytes = 0
        length = len(data)

        while sent_bytes < length:
            time.sleep(0.01)

            self._stdin.channel.send(data[i_start:i_end])

            i_start = i_end
            if i_end > length:
                i_end = length
            else:
                i_end = i_end + chunk_size

            sent_bytes += (i_end - i_start)

        return sent_bytes

    def connect(self):
        try:
            self._socket.connect(
                hostname=self.hostname,
                username=self.username,
                password=self.password,
                timeout=self._timeout,
                port=int(self.port),
                allow_agent=False,
                look_for_keys=False)
            self._stdin, self._stdout, self._stderr = self._socket.exec_command(
                "", get_pty=False)

        except (paramiko.BadHostKeyException,
                paramiko.AuthenticationException,
                paramiko.SSHException, OSError) as e:
            logger.debug('SSH Connection failed: %s', e)
            raise

    def read(self):
        response = ''

        self._start_xml()

        while True:
            data = self._stdout.channel.recv(BUF_SIZE)
            # Connection was closed by server
            if not data:
                break

            self._feed_xml(data)

            response += data.decode('utf-8')

            if self._is_end_xml():
                break

        return response

    def send(self, data):
        logger.debug('SSH:send(): %s', data)
        if len(data) > MAX_SSH_DATA_LENGTH:
            sent_bytes = self._send_in_chunks(data, MAX_SSH_DATA_LENGTH)
            logger.debug("SSH: %s bytes sent.", sent_bytes)
        else:
            self._stdin.channel.send(data)


class TLSConnection(GmpConnection):
    """
    TLS class to connect, read and write from gvmd via tls secured socket
    """

    def __init__(self, certfile=None, cafile=None, keyfile=None,
                 hostname='127.0.0.1', port=DEFAULT_GVM_PORT,
                 timeout=DEFAULT_TIMEOUT):
        if certfile and cafile and keyfile:
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH,
                                                 cafile=cafile)
            context.check_hostname = False
            context.load_cert_chain(certfile=certfile, keyfile=keyfile)
            new_socket = socketlib.socket(socketlib.AF_INET,
                                          socketlib.SOCK_STREAM)
            sock = context.wrap_socket(new_socket, server_side=False)
        else:
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
            sock = context.wrap_socket(socketlib.socket(socketlib.AF_INET))

        super().__init__(sock, timeout=timeout)

        self.hostname = hostname
        self.port = port

    def connect(self):
        self._socket.settimeout(self._timeout)
        self._socket.connect((self.hostname, int(self.port)))

    def read(self):
        response = ''

        while True:
            data = self._socket.read(BUF_SIZE)

            response += data.decode(errors='ignore')
            if len(data) < BUF_SIZE:
                break

        return response


class UnixSocketConnection(GmpConnection, XmlReader):
    """
    UNIX-Socket class to connect, read, write from gsad via direct
    communicating UNIX-Socket
    """

    def __init__(self, path=DEFAULT_UNIX_SOCKET_PATH, timeout=DEFAULT_TIMEOUT,
                 read_timeout=DEFAULT_READ_TIMEOUT):
        socket = socketlib.socket(socketlib.AF_UNIX, socketlib.SOCK_STREAM)

        super().__init__(socket, timeout=timeout)

        self.read_timeout = read_timeout
        self.path = path

    def connect(self):
        """Connect to the UNIX socket
        """
        self._socket.settimeout(self._timeout)
        self._socket.connect(self.path)

    def read(self):
        """Read from the UNIX socket
        """
        response = ''

        break_timeout = time.time() + self.read_timeout
        old_timeout = self._socket.gettimeout()
        self._socket.settimeout(5)  # in seconds

        self._start_xml()

        while time.time() < break_timeout:
            data = b''

            try:
                data = self._socket.recv(BUF_SIZE)
            except (socketlib.timeout) as exception:
                logger.debug('Warning: No data recieved '
                             'from server: %s', exception)
                continue

            self._feed_xml(data)

            response += data.decode('utf-8')

            if len(data) < BUF_SIZE:
                if self._is_end_xml():
                    break

        self._socket.settimeout(old_timeout)
        return response
