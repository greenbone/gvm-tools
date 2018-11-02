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
Module for communication to a daemon speaking Open Scanner Protocol version 1
"""
from gmp.protocols.base import Protocol
from gmp.xml import XmlCommand

PROTOCOL_VERSION = (1, 2,)

class Osp(Protocol):

    @staticmethod
    def get_protocol_version():
        """Allow to determine the Open Scanner Protocol version.

            Returns:
                str: Implemented version of the Open Scanner Protocol
        """
        return '.'.join(str(x) for x in PROTOCOL_VERSION)

    def get_version(self):
        """Get the version of the OSPD server which is connected to."""
        cmd = XmlCommand('get_version')
        return self.send_command(cmd.to_string())

    def help(self):
        """Get the help text."""
        cmd = XmlCommand('help')
        return self.send_command(cmd.to_string())

    def get_scans(self, scan_id=None, details='1', pop_results='0'):
        """Get the stored scans.

         Args:
            scan_id (uuid): Identifier for a scan.
            details (boolean): Whether to get full scan reports.
            pop_results (boolean) Whether to remove the fetched results.

        Returns:
            str: Response from server.
        """
        cmd = XmlCommand('get_scans')
        if scan_id:
            cmd.set_attribute('scan_id', scan_id)
        cmd.set_attribute('details', details)
        cmd.set_attribute('pop_results', pop_results)

        return self.send_command(cmd.to_string())

    def delete_scan(self, scan_id):
        """Delete a finished scan.
        Args:
            scan_id (uuid): Identifier for a finished scan.
        Returns:
            str: Response from server.
        """
        cmd = XmlCommand('delete_scan')
        if scan_id:
            cmd.set_attribute('scan_id', scan_id)

        return self.send_command(cmd.to_string())

    def get_scanner_details(self):
        """Return scanner description and parameters."""
        cmd = XmlCommand('get_scanner_details')
        return self.send_command(cmd.to_string())

    def get_vts(self, vt_id=None):
        """Return information about vulnerability tests,
        if offered by scanner.

        Args:
            vt_id (uuid): Identifier for a vulnerability test.
        Returns:
            str: Response from server.
        """
        cmd = XmlCommand('get_vts')
        if vt_id:
            cmd.set_attribute('vt_id', vt_id)

        return self.send_command(cmd.to_string())

    def start_scan(self):
        """Start a new scan.

        Args:
            scan_id (uuid): Identifier for a running scan.
        Returns:
            str: Response from server.
        """

    def stop_scan(self, scan_id=None):
        """Stop a currently running scan.

        Args:
            scan_id (uuid): Identifier for a running scan.
        Returns:
            str: Response from server.
        """
        cmd = XmlCommand('stop_scan')
        if scan_id:
            cmd.set_attribute('scan_id', scan_id)

        return self.send_command(cmd.to_string())
