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

    def createConfigCommand(self, copy_id, name):
        return '<create_config><copy>{0}</copy><name>{1}</name>\
</create_config>'.format(copy_id, name)

    def createTargetCommand(self, name, hosts):
        return '<create_target><name>{0}</name><hosts>{1}</hosts>\
</create_target>'.format(name, hosts)

    def modifyConfigCommand(self, selection, kwargs):
        assert selection in ('nvt_pref', 'sca_pref',
                             'family_selection', 'nvt_selection')
        config_id = kwargs.get('config_id')

        if selection in 'nvt_pref':
            nvt_oid = kwargs.get('nvt_oid')
            name = kwargs.get('name')
            value = kwargs.get('value')

            return '<modify_config config_id="{0}"><preference>\
<nvt oid="{1}"/><name>{2}</name><value>{3}</value>\
</preference></modify_config>'.format(config_id, nvt_oid, name, value)

        elif selection in 'nvt_selection':
            nvt_oid = kwargs.get('nvt_oid')
            family = kwargs.get('family')

            return '<modify_config config_id="{0}"><nvt_selection>\
<family>{1}</family><nvt oid="{2}"/>\
</nvt_selection></modify_config>'.format(config_id, family, nvt_oid)

        elif selection in 'family_selection':
            family = kwargs.get('family')

            return '<modify_config config_id="{0}"><family_selection>\
<growing>1</growing><family><name>{1}</name><all>1</all><growing>1</growing>\
</family>\</family_selection></modify_config>'.format(config_id, family)
        else:
            raise NotImplemented

    def createTaskCommand(self, name, config_id, target_id, scanner_id,
                          comment=''):
        return '<create_task><name>{0}</name><comment>{1}</comment>\
<config id="{2}"/><target id="{3}"/><scanner id="{4}"/>\
</create_task>'.format(name, comment, config_id, target_id, scanner_id)
