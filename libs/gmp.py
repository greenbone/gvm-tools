# -*- coding: utf-8 -*-
# Description:
# GVM-PyShell for communication with the GVM.
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


class _gmp:
    """GMP - Greenbone Manager Protocol
    """

    def createAuthenticateCommand(self, username, password, withCommands=''):
        """Generates string for authentification on GVM

        Creates the gmp authentication xml string.
        Inserts the username and password into it.

        Keyword Arguments:
            username {str} -- Username for GVM User
            password {str} -- Password for GVM User
            withCommands {str} -- Additional commands default: {''})
        """

        return '<commands><authenticate><credentials><username>{0}</username>\
<password>{1}</password></credentials></authenticate>{2}</commands>'.format(
            username, password, withCommands)
