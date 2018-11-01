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

import logging

from gmp.errors import GmpError

logger = logging.getLogger(__name__)


class Protocol:
    """Base class for different protocols

    Attributes:
        connection (:class:`gmp.connections.GmpConnection`): Connection to use
            to talk with the remote daemon. See :mod:`gmp.connections` for
            possible connection types.
        transform (`callable`_, optional): Optional transform callable to
            convert response data. After each request the callable gets passed
            the plain response data which can be used to check the data and/or
            conversion into different representaitions like a xml dom.

            See :mod:`gmp.transforms` for existing transforms.
    """

    def __init__(self, connection, transform=None):
        self._connection = connection

        self._connected = False

        self._transform_callable = transform

    def _read(self):
        """Read a command response from gvmd

        Returns:
            str: Response from server.
        """
        response = self._connection.read()

        logger.debug('read() %i Bytes response: %s', len(response), response)

        if response is None or len(str(response)) == 0:
            raise GmpError('Connection was closed by remote server')

        return response

    def _send(self, data):
        """Send a command to the server

        Args:
            data (str): Data to be send over the connection to the server
        """
        self._connect()
        self._connection.send(data)

    def _connect(self):
        if not self.is_connected():
            self._connection.connect()
            self._connected = True

    def _transform(self, data):
        transform = self._transform_callable
        if transform is None:
            return data
        return transform(data)

    def is_connected(self):
        """Status of the current connection

        Returns:
            bool: True if a connection to the remote server has been
                  established.
        """
        return self._connected

    def disconnect(self):
        """Disconnect the connection

        Ends and closes the connection.
        """
        if self.is_connected():
            self._connection.disconnect()
            self._connected = False

    def send_command(self, cmd):
        """Send a command to the remote server

        If the class isn't connected to the server yet the connection will be
        established automatically.

        Arguments:
            cmd (str): Command as string to be send over the connection to
                the server.

        Returns:
            any: The actual returned type depends on the set transform.

            Per default - if no transform is set explicitly - the response is
            returned as string.
        """
        self._send(cmd)
        response = self._read()
        return self._transform(response)
