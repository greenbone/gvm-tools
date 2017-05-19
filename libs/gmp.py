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
        if len(withCommands) is 0:
            return '<authenticate><credentials><username>{0}' \
                   '</username><password>{1}</password></credentials>' \
                   '</authenticate>'.format(username, password, withCommands)
        else:
            return '<commands><authenticate><credentials><username>{0}' \
                   '</username><password>{1}</password></credentials>' \
                   '</authenticate>{2}</commands>'.format(username, password,
                                                          withCommands)

    def createAgentCommand(self, installer, signature, name, comment='',
                           copy='', howto_install='', howto_use=''):

        if comment:
            comment = '<comment>{0}</comment>'.format(comment)

        if copy:
            copy = '<copy>{0}</copy>'.format(copy)

        if howto_install:
            howto_install = '<howto_install>{0}</howto_install>'.format(
                howto_install)

        if howto_use:
            howto_use = '<howto_use>{0}</howto_use>'.format(howto_use)

        return '<create_agent><installer>{0}<signature>{1}</signature>' \
               '</installer><name>{2}</name>{3}{4}{5}{6}' \
               '</create_agent>'.format(installer, signature, name, comment,
                                        copy, howto_install, howto_use)

    def createUserCommand(self, name, password, copy='', hosts_allow=None,
                          ifaces_allow=None, role_ids=()):

        if copy:
            copy = '<copy>{0}</copy>'.format(copy)

        if password:
            password = '<password>{0}</password>'.format(password)

        if hosts_allow is not None:
            hosts_allow = '<hosts {0}/>'.format(hosts_allow)
        else:
            hosts_allow = ''

        if ifaces_allow is not None:
            ifaces_allow = '<hosts {0}/>'.format(ifaces_allow)
        else:
            ifaces_allow = ''

        role_txt = ''
        if len(role_ids) > 0:
            for role in role_ids:
                role_txt += '<role id="{0}" />'.format(role)

        return '<create_user><name>{0}</name>{1}{2}{3}{4}{5}' \
               '</create_user>'.format(name, copy, hosts_allow, ifaces_allow,
                                       password, role_txt)

    def createConfigCommand(self, copy_id, name):
        return '<create_config><copy>{0}</copy><name>{1}</name>' \
               '</create_config>'.format(copy_id, name)

    def createTargetCommand(self, name, hosts):
        return '<create_target><name>{0}</name><hosts>{1}</hosts>' \
               '</create_target>'.format(name, hosts)

    def modifyAgentCommand(self, id, name='', comment=''):
        assert id
        if name:
            name = '<name>{0}</name>'.format(name)

        if comment:
            comment = '<comment>{0}</comment>'.format(comment)

        return '<modify_agent agent_id="{0}">{1}{2}' \
               '</modify_agent>'.format(id, name, comment)

    def modifyConfigCommand(self, selection, kwargs):
        assert selection in ('nvt_pref', 'sca_pref',
                             'family_selection', 'nvt_selection')
        config_id = kwargs.get('config_id')

        if selection in 'nvt_pref':
            nvt_oid = kwargs.get('nvt_oid')
            name = kwargs.get('name')
            value = kwargs.get('value')

            return '<modify_config config_id="{0}"><preference>' \
                   '<nvt oid="{1}"/><name>{2}</name><value>{3}</value>' \
                   '</preference></modify_config>'.format(config_id, nvt_oid,
                                                          name, value)

        elif selection in 'nvt_selection':
            nvt_oid = kwargs.get('nvt_oid')
            family = kwargs.get('family')
            nvts = ''
            if type(nvt_oid) is list:
                for nvt in nvt_oid:
                    nvts += '<nvt oid="%s"/>' % nvt
            else:
                nvts = '<nvt oid="%s"/>' % nvt_oid

            return '<modify_config config_id="{0}"><nvt_selection>' \
                   '<family>{1}</family>{2}</nvt_selection></modify_config>' \
                   ''.format(config_id, family, nvts)

        elif selection in 'family_selection':
            family = kwargs.get('family')

            return '<modify_config config_id="{0}"><family_selection>' \
                   '<growing>1</growing><family><name>{1}</name><all>1</all>' \
                   '<growing>1</growing></family>\</family_selection>' \
                   '</modify_config>'.format(config_id, family)
        else:
            raise NotImplemented

    def createTaskCommand(self, name, config_id, target_id, scanner_id,
                          comment=''):
        return '<create_task><name>{0}</name><comment>{1}</comment>' \
               '<config id="{2}"/><target id="{3}"/><scanner id="{4}"/>' \
               '</create_task>'.format(name, comment, config_id, target_id,
                                       scanner_id)
