# -*- coding: utf-8 -*-
# $Id$
# Description:
# GVM-Shell for communication with the GVM UNIX-Socket over SSH.
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


class _gmp:
    """GMP - Greenbone Manager Protocol
    """

    def createAuthenticateCommand(self, username='admin', password='admin',
                                  withCommands=''):
        """Generates string for authentification on GVM

        Creates the gmp authentication xml string.
        Inserts the username and password into it.

        Keyword Arguments:
            username {str} -- Username for GVM User (default: {'admin'})
            password {str} -- Password for GVM User (default: {'admin'})
            withCommands {str} -- Additional commands default: {''})
        """

        return '<commands><authenticate><credentials><username>{0}</username>\
<password>{1}</password></credentials></authenticate>{2}</commands>'.format(
            username, password, withCommands)
