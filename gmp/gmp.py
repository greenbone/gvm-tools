# -*- coding: utf-8 -*-
# Description:
# Commandcreator for gmp commands.
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

    def createAlertCommand(self, name, condition, event, method, filter_id='',
                           copy='', comment=''):

        if len(condition) > 1:
            conditions = '<condition>%s' % condition[0]
            for value, key in condition[1].items():
                conditions += '<data>{0}<name>{1}</name></data>' \
                              ''.format(value, key)
            conditions += '</condition>'

        if len(event) > 1:
            events = '<event>%s' % event[0]
            for value, key in event[1].items():
                events += '<data>{0}<name>{1}</name></data>' \
                          ''.format(value, key)
            events += '</event>'

        if len(method) > 1:
            methods = '<method>%s' % method[0]
            for value, key in method[1].items():
                methods += '<data>{0}<name>{1}</name></data>' \
                           ''.format(value, key)
            methods += '</method>'

        if filter_id:
            filter_id = '<filter id=%s/>' % filter_id

        return '<create_alert><name>{0}</name>' \
               '{1}{2}{3}{4}' \
               '</create_alert>'.format(name, conditions, events, methods,
                                        filter_id)

    def createAssetCommand(self, name, asset_type, comment=''):
        assert asset_type in ('host', 'os')

        if comment:
            comment = '<comment>%s</comment>' % comment

        return '<create_asset><asset>' \
               '<type>{0}</type>' \
               '<name>{1}</name>' \
               '{2}</asset></create_asset>'.format(asset_type, name, comment)

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

    def createConfigCommand(self, copy_id, name):
        return '<create_config><copy>{0}</copy><name>{1}</name>' \
               '</create_config>'.format(copy_id, name)

    def createCredentialCommand(self, name, kwargs):

        comment = kwargs.get('comment', '')
        if comment:
            comment = '<comment>%s</comment>' % comment

        copy = kwargs.get('copy', '')
        if copy:
            copy = '<copy>%s</copy>' % copy

        allow_insecure = kwargs.get('allow_insecure', '')
        if allow_insecure:
            allow_insecure = '<allow_insecure>%s</allow_insecure>' \
                             '' % allow_insecure

        certificate = kwargs.get('certificate', '')
        if certificate:
            certificate = '<certificate>%s</certificate>' % certificate

        key = kwargs.get('key', '')
        if key:
            phrase = key['phrase']
            private = key['private']
            assert phrase
            assert private

            key = '<key><phrase>{0}</phrase><private>{1}</private></key>' \
                  ''.format(phrase, private)

        login = kwargs.get('login', '')
        if login:
            login = '<login>%s</login>' % login

        password = kwargs.get('password', '')
        if password:
            password = '<password>%s</password>' % password

        auth_algorithm = kwargs.get('auth_algorithm', '')
        if auth_algorithm:
            assert auth_algorithm in ('md5', 'sha1')
            auth_algorithm = '<auth_algorithm>%s</auth_algorithm>' \
                             '' % auth_algorithm

        community = kwargs.get('community', '')
        if community:
            community = '<community>%s</community>' % community

        privacy = kwargs.get('privacy', '')
        if privacy:
            algorithm = privacy.algorithm
            assert algorithm in ('aes', 'des')
            p_password = privacy.password
            privacy = '<privacy><algorithm>{0}</algorithm><password>{1} ' \
                      '</password></privacy>'.format(algorithm, p_password)

        cred_type = kwargs.get('type', '')
        if cred_type:
            assert cred_type in ('cc', 'snmp', 'up', 'usk')
            cred_type = '<type>%s</type>' % cred_type

        return '<create_credential><name>{0}</name>' \
               '{1}{2}{3}{4}{5}{6}{7}{8}{9}{10}{11}' \
               '</create_credential>' \
               ''.format(name, comment, copy, allow_insecure, certificate,
                         key, login, password, auth_algorithm, community,
                         privacy, cred_type)

    def createFilterCommand(self, name, make_unique, kwargs):

        comment = kwargs.get('comment', '')
        if comment:
            comment = '<comment>%s</comment>' % comment

        copy = kwargs.get('copy', '')
        if copy:
            copy = '<copy>%s</copy>' % copy

        term = kwargs.get('term', '')
        if term:
            term = '<term>%s</term>' % term

        filter_type = kwargs.get('type', '')
        if filter_type:
            assert filter_type in ('cc', 'snmp', 'up', 'usk')
            filter_type = '<type>%s</type>' % filter_type

        return '<create_filter><name>{0}<make_unique>{1}</make_unique></name>' \
               '{2}{3}{4}</create_filter>'.format(name, make_unique, comment,
                                                  copy, term, filter_type)

    def createGroupCommand(self, name, kwargs):

        comment = kwargs.get('comment', '')
        if comment:
            comment = '<comment>%s</comment>' % comment

        copy = kwargs.get('copy', '')
        if copy:
            copy = '<copy>%s</copy>' % copy

        special = kwargs.get('special', '')
        if special:
            special = '<specials><full /></specials>'

        users = kwargs.get('users', '')
        if users:
            users = '<users>%s</users>' % users

        return '<create_group><name>{0}</name>{1}{2}{3}{4}</create_group>' \
               ''.format(name, comment, copy, special, users)

    def createNoteCommand(self, text, nvt_oid, kwargs):

        active = kwargs.get('active', '')
        if active:
            active = '<active>%s</active>' % active

        comment = kwargs.get('comment', '')
        if comment:
            comment = '<comment>%s</comment>' % comment

        copy = kwargs.get('copy', '')
        if copy:
            copy = '<copy>%s</copy>' % copy

        hosts = kwargs.get('hosts', '')
        if hosts:
            hosts = '<hosts>%s</hosts>' % hosts

        port = kwargs.get('port', '')
        if port:
            port = '<port>%s</port>' % port

        result_id = kwargs.get('result_id', '')
        if result_id:
            result_id = '<result id="%s"/>' % result_id

        severity = kwargs.get('severity', '')
        if severity:
            severity = '<severity>%s</severity>' % severity

        task_id = kwargs.get('task_id', '')
        if task_id:
            task_id = '<task id="%s"/>' % task_id

        threat = kwargs.get('threat', '')
        if threat:
            threat = '<threat>%s</threat>' % threat

        return '<create_note><text>{0}</text><nvt oid="{1}"></nvt>{2}{3}{4}{5}{6}' \
               '{7}{8}{9}{10}</create_note>' \
               ''.format(text, nvt_oid, active, comment, copy, hosts, port,
                         result_id, severity, task_id, threat)

    def createOverrideCommand(self, text, nvt_oid, kwargs):

        active = kwargs.get('active', '')
        if active:
            active = '<active>%s</active>' % active

        comment = kwargs.get('comment', '')
        if comment:
            comment = '<comment>%s</comment>' % comment

        copy = kwargs.get('copy', '')
        if copy:
            copy = '<copy>%s</copy>' % copy

        hosts = kwargs.get('hosts', '')
        if hosts:
            hosts = '<hosts>%s</hosts>' % hosts

        port = kwargs.get('port', '')
        if port:
            port = '<port>%s</port>' % port

        result_id = kwargs.get('result_id', '')
        if result_id:
            result_id = '<result id="%s"/>' % result_id

        severity = kwargs.get('severity', '')
        if severity:
            severity = '<severity>%s</severity>' % severity

        new_severity = kwargs.get('new_severity', '')
        if new_severity:
            new_severity = '<new_severity>%s</new_severity>' % new_severity

        task_id = kwargs.get('task_id', '')
        if task_id:
            task_id = '<task id="%s"/>' % task_id

        threat = kwargs.get('threat', '')
        if threat:
            threat = '<threat>%s</threat>' % threat

        new_threat = kwargs.get('new_threat', '')
        if new_threat:
            new_threat = '<new_threat>%s</new_threat>' % new_threat

        return '<create_override><text>{0}</text><nvt oid="{1}"></nvt>{2}{3}{4}{5}{6}' \
               '{7}{8}{9}{10}{11}{12}</create_override>' \
               ''.format(text, nvt_oid, active, comment, copy, hosts, port,
                         result_id, severity, task_id, threat, new_severity,
                         new_threat)

    def createPermissionCommand(self, name, subject_id, type, kwargs):
        # pretty(gmp.create_permission('get_version',
        # 'cc9cac5e-39a3-11e4-abae-406186ea4fc5', 'role'))
        # libs.gvm_connection.GMPError: Error in NAME
        # TODO: Research why!!

        assert name
        assert subject_id
        assert type in ('user', 'group', 'role')

        comment = kwargs.get('comment', '')
        if comment:
            comment = '<comment>%s</comment>' % comment

        copy = kwargs.get('copy', '')
        if copy:
            copy = '<copy>%s</copy>' % copy

        resource = kwargs.get('resource', '')
        if resource:
            resource_id = resource.id
            resource_type = resource.type

            resource = '<resource id="%s"><type>%s</type></resource>' \
                       '' % (resource_id, resource_type)

        return '<create_permission><name>{0}</name><subject id="{1}"><type>{2}' \
               '</type></subject>{3}{4}{5}</create_permission>' \
               ''.format(name, subject_id, type, resource, copy, comment)

    def createPortListCommand(self, name, port_range, kwargs):

        assert name
        assert port_range

        comment = kwargs.get('comment', '')
        if comment:
            comment = '<comment>%s</comment>' % comment

        copy = kwargs.get('copy', '')
        if copy:
            copy = '<copy>%s</copy>' % copy

        return '<create_port_list><name>{0}</name><port_range>{1}</port_range>' \
               '{2}{3}</create_port_list>' \
               ''.format(name, port_range, copy, comment)

    def createPortRangeCommand(self, port_list_id, start, end, type,
                               comment=''):

        assert port_list_id
        assert type

        return '<create_port_range>' \
               '<port_list id="{0}"/>' \
               '<start>{1}</start>' \
               '<end>{2}</end>' \
               '<type>{3}</type>{4}' \
               '</create_port_range>' \
               ''.format(port_list_id, start, end, type, comment)

    def createReportCommand(self, report_xml_string, kwargs):

        assert report_xml_string

        task_id = kwargs.get('task_id', '')
        task_name = kwargs.get('task_name', '')
        task = ''

        comment = kwargs.get('comment', '')
        if comment:
            comment = '<comment>%s</comment>' % comment

        if task_id:
            task = '<task id="%s"></task>' % (task_id)
        elif task_name:
            task = '<task><name>%s</name>%s</task>' % (task_name, comment)
        else:
            raise ValueError('create_report requires an id or name for a task')

        in_assets = kwargs.get('in_assets', '')
        if in_assets:
            in_assets = '<in_assets>%s</in_assets>' % in_assets

        return '<create_report>' \
               '{0}{1}{2}' \
               '</create_report>' \
               ''.format(task, in_assets, report_xml_string)

    def createRoleCommand(self, name, kwargs):

        assert name

        comment = kwargs.get('comment', '')
        if comment:
            comment = '<comment>%s</comment>' % comment

        copy = kwargs.get('copy', '')
        if copy:
            copy = '<copy>%s</copy>' % copy

        users = kwargs.get('users', '')
        if users:
            users = '<users>%s</users>' % users

        return '<create_role>' \
               '<name>{0}</name>' \
               '{1}{2}{3}' \
               '</create_role>' \
               ''.format(name, users, copy, comment)

    def createScannerCommand(self, name, host, port, type, ca_pub,
                             credential_id, kwargs):
        assert name
        assert host
        assert port
        assert type
        assert ca_pub
        assert credential_id

        comment = kwargs.get('comment', '')
        if comment:
            comment = '<comment>%s</comment>' % comment

        copy = kwargs.get('copy', '')
        if copy:
            copy = '<copy>%s</copy>' % copy

        return '<create_scanner>' \
               '<name>{0}</name>' \
               '<host>{1}</host>' \
               '<port>{2}</port>' \
               '<type>{3}</type>' \
               '<ca_pub>{4}</ca_pub>' \
               '<credential id="{5}"/>' \
               '{6}{7}' \
               '</create_scanner>' \
               ''.format(name, host, port, type, ca_pub, credential_id, copy,
                         comment)

    def createScheduleCommand(self, name, kwargs):
        assert name

        comment = kwargs.get('comment', '')
        if comment:
            comment = '<comment>%s</comment>' % comment

        copy = kwargs.get('copy', '')
        if copy:
            copy = '<copy>%s</copy>' % copy

        first_time = kwargs.get('first_time', '')
        print(first_time)
        if first_time:
            first_time_minute = first_time['minute']
            first_time_hour = first_time['hour']
            first_time_day_of_month = first_time['day_of_month']
            first_time_month = first_time['month']
            first_time_year = first_time['year']

            first_time = '<first_time>' \
                         '<minute>%s</minute>' \
                         '<hour>%s</hour>' \
                         '<day_of_month>%s</day_of_month>' \
                         '<month>%s</month>' \
                         '<year>%s</year>' \
                         '</first_time>' \
                         '' % (first_time_minute, first_time_hour,
                               first_time_day_of_month, first_time_month,
                               first_time_year)

        duration = kwargs.get('duration', '')
        if len(duration) > 1:
            duration = '<duration>%s<unit>%s</unit>' \
                       '' % (duration[0], duration[1])

        period = kwargs.get('period', '')
        if len(period) > 1:
            period = '<period>%s<unit>%s</unit>' % (period[0], period[1])

        timezone = kwargs.get('timezone', '')

        return '<create_schedule><name>{0}</name>' \
               '{1}{2}{3}{4}{5}{6}' \
               '</create_schedule>' \
               ''.format(name, comment, copy, first_time, duration, period,
                         timezone)

    def createTagCommand(self, name, resource_id, resource_type, kwargs):

        comment = kwargs.get('comment', '')
        if comment:
            comment = '<comment>%s</comment>' % comment

        copy = kwargs.get('copy', '')
        if copy:
            copy = '<copy>%s</copy>' % copy

        value = kwargs.get('value', '')
        if value:
            value = '<value>%s</value>' % value

        active = kwargs.get('active', '')
        if active:
            active = '<active>%s</active>' % active

        return '<create_tag><name>{0}</name><resource id="{1}">' \
               '<type>{2}</type></resource>{3}{4}{5}{6}</create_tag>' \
               ''.format(name, resource_id, resource_type, copy, value,
                         comment, active)

    def createTargetCommand(self, name, make_unique, kwargs):
        assert name

        if 'asset_hosts' in kwargs:
            hosts = kwargs.get('asset_hosts')
            filter = hosts['filter']

            hosts = '<asset_hosts filter="%s"/>' % filter

        elif 'hosts' in kwargs:
            hosts = kwargs.get('hosts')
            hosts = '<hosts>%s</hosts>' % hosts
        else:
            pass

        return '<create_target><name>{0}</name>{1}' \
               '</create_target>'.format(name, hosts)

    def createTaskCommand(self, name, config_id, target_id, scanner_id,
                          comment=''):
        return '<create_task><name>{0}</name><comment>{1}</comment>' \
               '<config id="{2}"/><target id="{3}"/><scanner id="{4}"/>' \
               '</create_task>'.format(name, comment, config_id, target_id,
                                       scanner_id)

    def createUserCommand(self, name, password, copy='', hosts_allow='0',
                          ifaces_allow='0', role_ids=(), hosts=None,
                          ifaces=None):

        if copy:
            copy = '<copy>{0}</copy>'.format(copy)

        if password:
            password = '<password>{0}</password>'.format(password)

        if hosts is not None:
            hosts_allow = '<hosts allow="{0}">{1}</hosts>' \
                              .format(hosts_allow, hosts)
        else:
            hosts_allow = ''

        if ifaces is not None:
            ifaces_allow = '<ifaces allow="{0}">{1}</ifaces>' \
                              .format(ifaces_allow, ifaces)
        else:
            ifaces_allow = ''

        role_txt = ''
        if len(role_ids) > 0:
            for role in role_ids:
                role_txt += '<role id="{0}" />'.format(role)

        return '<create_user><name>{0}</name>{1}{2}{3}{4}{5}' \
               '</create_user>'.format(name, copy, hosts_allow, ifaces_allow,
                                       password, role_txt)

    def modifyAgentCommand(self, agent_id, name='', comment=''):

        assert agent_id
        if name:
            name = '<name>{0}</name>'.format(name)

        if comment:
            comment = '<comment>{0}</comment>'.format(comment)

        return '<modify_agent agent_id="{0}">{1}{2}' \
               '</modify_agent>'.format(agent_id, name, comment)

    def modifyAlertCommand(self, alert_id, kwargs):

        assert alert_id

        name = kwargs.get('name', '')
        if name:
            name = '<name>%s</name>' % name

        comment = kwargs.get('comment', '')
        if comment:
            comment = '<comment>%s</comment>' % comment

        filter_id = kwargs.get('filter_id', '')
        if filter_id:
            filter_id = '<filter id=%s/>' % filter_id

        event = kwargs.get('event', '')
        events = ''
        if len(event) > 1:
            events = '<event>%s' % event[0]
            for value, key in event[1].items():
                events += '<data>{0}<name>{1}</name></data>' \
                          ''.format(value, key)
            events += '</event>'

        condition = kwargs.get('condition', '')
        conditions = ''
        if len(condition) > 1:
            conditions = '<condition>%s' % condition[0]
            for value, key in condition[1].items():
                conditions += '<data>{0}<name>{1}</name></data>' \
                              ''.format(value, key)
            conditions += '</condition>'

        method = kwargs.get('method', '')
        methods = ''
        if len(method) > 1:
            methods = '<method>%s' % method[0]
            for value, key in method[1].items():
                methods += '<data>{0}<name>{1}</name></data>' \
                           ''.format(value, key)
            methods += '</method>'

        return '<modify_alert alert_id="{0}">{1}{2}{3}{4}{5}{6}' \
               '</modify_alert>'.format(alert_id, name, comment, filter_id,
                                        events, conditions, methods)

    def modifyAuthCommand(self, group_name,  auth_conf_settings):

        assert group_name
        assert auth_conf_settings
        auth_conf_setting = ''

        for key, value in auth_conf_settings.items():
            auth_conf_setting += '<auth_conf_setting>' \
                                 '<key>%s</key>' \
                                 '<value>%s</value>' \
                                 '</auth_conf_setting>' % (key, value)

        return '<modify_auth><group name="{0}">{1}</group>' \
               '</modify_auth>'.format(group_name, auth_conf_setting)

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

    def modifyCredentialCommand(self, credential_id, kwargs):

        assert credential_id

        comment = kwargs.get('comment', '')
        if comment:
            comment = '<comment>%s</comment>' % comment

        name = kwargs.get('name', '')
        if name:
            name = '<name>%s</name>' % name

        allow_insecure = kwargs.get('allow_insecure', '')
        if allow_insecure:
            allow_insecure = '<allow_insecure>%s</allow_insecure>' \
                             '' % allow_insecure

        certificate = kwargs.get('certificate', '')
        if certificate:
            certificate = '<certificate>%s</certificate>' % certificate

        key = kwargs.get('key', '')
        if key:
            phrase = key['phrase']
            private = key['private']
            assert phrase
            assert private

            key = '<key><phrase>{0}</phrase><private>{1}</private></key>' \
                  ''.format(phrase, private)

        login = kwargs.get('login', '')
        if login:
            login = '<login>%s</login>' % login

        password = kwargs.get('password', '')
        if password:
            password = '<password>%s</password>' % password

        auth_algorithm = kwargs.get('auth_algorithm', '')
        if auth_algorithm:
            assert auth_algorithm in ('md5', 'sha1')
            auth_algorithm = '<auth_algorithm>%s</auth_algorithm>' \
                             '' % auth_algorithm

        community = kwargs.get('community', '')
        if community:
            community = '<community>%s</community>' % community

        privacy = kwargs.get('privacy', '')
        if privacy:
            algorithm = privacy.algorithm
            assert algorithm in ('aes', 'des')
            p_password = privacy.password
            privacy = '<privacy><algorithm>{0}</algorithm><password>{1} ' \
                      '</password></privacy>'.format(algorithm, p_password)

        cred_type = kwargs.get('type', '')
        if cred_type:
            assert cred_type in ('cc', 'snmp', 'up', 'usk')
            cred_type = '<type>%s</type>' % cred_type

        return '<modify_credential>{0}' \
               '{1}{2}{3}{4}{5}{6}{7}{8}{9}{10}{11}' \
               '</modify_credential>' \
               ''.format(comment, name, allow_insecure, certificate,
                         key, login, password, auth_algorithm, community,
                         privacy, cred_type)

    def modifyFilterCommand(self, filter_id, kwargs):

        assert filter_id

        comment = kwargs.get('comment', '')
        if comment:
            comment = '<comment>%s</comment>' % comment

        name = kwargs.get('name', '')
        if name:
            name = '<name>%s</name>' % name

        copy = kwargs.get('copy', '')
        if copy:
            copy = '<copy>%s</copy>' % copy

        term = kwargs.get('term', '')
        if term:
            term = '<term>%s</term>' % term

        filter_type = kwargs.get('type', '')
        if filter_type:
            assert filter_type in ('cc', 'snmp', 'up', 'usk')
            filter_type = '<type>%s</type>' % filter_type

        return '<modify_filter filter_id="{0}">{1}{2}{3}{4}</modify_filter>' \
               ''.format(filter_id, comment, name, term, filter_type)

    def modifyGroupCommand(self, group_id, kwargs):

        assert group_id

        comment = kwargs.get('comment', '')
        if comment:
            comment = '<comment>%s</comment>' % comment

        name = kwargs.get('name', '')
        if name:
            name = '<name>%s</name>' % name

        users = kwargs.get('users', '')
        if users:
            users = '<users>%s</users>' % users

        return '<modify_group group_id="{0}">{1}{2}{3}</modify_group>' \
               ''.format(group_id, name, comment, users)

    def modifyNoteCommand(self, note_id, text, kwargs):

        assert note_id
        assert text

        active = kwargs.get('active', '')
        if active:
            active = '<active>%s</active>' % active

        hosts = kwargs.get('hosts', '')
        if hosts:
            hosts = '<hosts>%s</hosts>' % hosts

        port = kwargs.get('port', '')
        if port:
            port = '<port>%s</port>' % port

        result_id = kwargs.get('result_id', '')
        if result_id:
            result_id = '<result id="%s"/>' % result_id

        severity = kwargs.get('severity', '')
        if severity:
            severity = '<severity>%s</severity>' % severity

        task_id = kwargs.get('task_id', '')
        if task_id:
            task_id = '<task id="%s"/>' % task_id

        threat = kwargs.get('threat', '')
        if threat:
            threat = '<threat>%s</threat>' % threat

        return '<modify_note note_id="{0}"><text>{1}</text>{2}{3}{4}{5}{6}' \
               '{7}{8}</modify_note>' \
               ''.format(note_id, text, active, hosts, port,
                         result_id, severity, task_id, threat)

    def modifyOverrideCommand(self, override_id, text, kwargs):

        active = kwargs.get('active', '')
        if active:
            active = '<active>%s</active>' % active

        hosts = kwargs.get('hosts', '')
        if hosts:
            hosts = '<hosts>%s</hosts>' % hosts

        port = kwargs.get('port', '')
        if port:
            port = '<port>%s</port>' % port

        result_id = kwargs.get('result_id', '')
        if result_id:
            result_id = '<result id="%s"/>' % result_id

        severity = kwargs.get('severity', '')
        if severity:
            severity = '<severity>%s</severity>' % severity

        new_severity = kwargs.get('new_severity', '')
        if new_severity:
            new_severity = '<new_severity>%s</new_severity>' % new_severity

        task_id = kwargs.get('task_id', '')
        if task_id:
            task_id = '<task id="%s"/>' % task_id

        threat = kwargs.get('threat', '')
        if threat:
            threat = '<threat>%s</threat>' % threat

        new_threat = kwargs.get('new_threat', '')
        if new_threat:
            new_threat = '<new_threat>%s</new_threat>' % new_threat

        return '<modify_override override_id="{0}"><text>{1}</text>{2}{3}{4}{5}{6}' \
               '{7}{8}{9}{10}</modify_override>' \
               ''.format(override_id, text, active, hosts, port, result_id,
                         severity, task_id, threat, new_severity, new_threat)

    def modifyPermissionCommand(self, permission_id, kwargs):

        assert permission_id

        comment = kwargs.get('comment', '')
        if comment:
            comment = '<comment>%s</comment>' % comment

        name = kwargs.get('name', '')
        if name:
            name = '<name>%s</name>' % name

        resource = kwargs.get('resource', '')
        if resource:
            resource_id = resource['id']
            resource_type = resource['type']

            resource = '<resource id="%s"><type>%s</type></resource>' \
                       '' % (resource_id, resource_type)

        subject = kwargs.get('subject', '')
        if subject:
            subject_id = subject['id']
            subject_type = subject['type']

            subject = '<subject id="%s"><type>%s</type></subject>' \
                      '' % (subject_id, subject_type)

        return '<modify_permission permission_id="{0}">{1}{2}{3}{4}</modify_permission>' \
               ''.format(permission_id, name, comment, resource, subject)

    def modifyPortListCommand(self, port_list_id, kwargs):

        assert port_list_id

        comment = kwargs.get('comment', '')
        if comment:
            comment = '<comment>%s</comment>' % comment

        name = kwargs.get('name', '')
        if name:
            name = '<name>%s</name>' % name

        return '<modify_port_list port_list_id="{0}">{1}{2}</modify_port_list>' \
               ''.format(port_list_id, name, comment)

    def modifyReportFormatCommand(self, report_format_id, kwargs):

        if len(kwargs) < 1:
            raise Exception('modify_report_format: Missing parameter')

        active = kwargs.get('active', '')
        if active:
            active = '<active>%s</active>' % active

        name = kwargs.get('name', '')
        if name:
            name = '<name>%s</name>' % name

        summary = kwargs.get('summary', '')
        if summary:
            summary = '<summary>%s</summary>' % summary

        param = kwargs.get('param', '')
        if param:
            p_name = param[0]
            p_value = param[1]
            param = '<param><name>%s</name><value>%s</value></param>' \
                    '' % (p_name, p_value)

    def modifyRoleCommand(self, role_id, kwargs):

        assert role_id

        comment = kwargs.get('comment', '')
        if comment:
            comment = '<comment>%s</comment>' % comment

        name = kwargs.get('name', '')
        if name:
            name = '<name>%s</name>' % name

        users = kwargs.get('users', '')
        if users:
            users = '<users>%s</users>' % users

        return '<modify_role role_id="{0}">{1}{2}{3}</modify_role>' \
               ''.format(role_id, name, users, comment)

    def modifyScannerCommand(self, scanner_id, host, port, type, kwargs):

        assert scanner_id
        assert host
        assert port
        assert type

        comment = kwargs.get('comment', '')
        if comment:
            comment = '<comment>%s</comment>' % comment

        name = kwargs.get('name', '')
        if name:
            name = '<name>%s</name>' % name

        ca_pub = kwargs.get('ca_pub', '')
        if ca_pub:
            ca_pub = '<ca_pub>%s</ca_pub>' % ca_pub

        credential_id = kwargs.get('credential_id', '')
        if credential_id:
            credential_id = '<credential id="%s"/>' % credential_id

        return '<modify_scanner scanner_id="{0}">' \
               '<host>{1}</host>' \
               '<port>{2}</port>' \
               '<type>{3}</type>' \
               '{4}{5}{6}' \
               '</modify_scanner>' \
               ''.format(scanner_id, host, port, type, name, ca_pub,
                         credential_id, comment)

    def modifyScheduleCommand(self, schedule_id, kwargs):

        assert schedule_id

        comment = kwargs.get('comment', '')
        if comment:
            comment = '<comment>%s</comment>' % comment

        name = kwargs.get('name', '')
        if name:
            name = '<name>%s</name>' % name

        first_time = kwargs.get('first_time', '')
        if first_time:
            first_time_minute = first_time['minute']
            first_time_hour = first_time['hour']
            first_time_day_of_month = first_time['day_of_month']
            first_time_month = first_time['month']
            first_time_year = first_time['year']

            first_time = '<first_time>' \
                         '<minute>%s</minute>' \
                         '<hour>%s</hour>' \
                         '<day_of_month>%s</day_of_month>' \
                         '<month>%s</month>' \
                         '<year>%s</year>' \
                         '</first_time>' \
                         '' % (first_time_minute, first_time_hour,
                               first_time_day_of_month, first_time_month,
                               first_time_year)

        duration = kwargs.get('duration', '')
        if len(duration) > 1:
            duration = '<duration>%s<unit>%s</unit>' \
                       '' % (duration[0], duration[1])

        period = kwargs.get('period', '')
        if len(period) > 1:
            period = '<period>%s<unit>%s</unit>' % (period[0], period[1])

        timezone = kwargs.get('timezone', '')

        return '<modify_schedule schedule_id="{0}">' \
               '{1}{2}{3}{4}{5}{6}' \
               '</modify_schedule>' \
               ''.format(schedule_id, comment, name, first_time, duration,
                         period, timezone)

    def modifyTagCommand(self, tag_id, kwargs):

        assert tag_id

        comment = kwargs.get('comment', '')
        if comment:
            comment = '<comment>%s</comment>' % comment

        name = kwargs.get('name', '')
        if name:
            name = '<name>%s</name>' % name

        value = kwargs.get('value', '')
        if value:
            value = '<value>%s</value>' % value

        active = kwargs.get('active', '')
        if active:
            active = '<active>%s</active>' % active

        resource = kwargs.get('resource', '')
        if resource:
            resource_id = resource['id']
            resource_type = resource['type']

            resource = '<resource id="%s"><type>%s</type></resource>' \
                       '' % (resource_id, resource_type)

        return '<modify_tag tag_id="{0}">{3}{4}{5}{6}</modify_tag>' \
               ''.format(tag_id, name, resource, value, comment, active)

    def modifyTargetCommand(self, target_id, kwargs):
        raise NotImplemented

    def modifyTaskCommand(self):
        raise NotImplemented

    def modifyUserCommand(self, kwargs):

        user_id = kwargs.get('user_id', '')
        if user_id:
            user_id = 'user_id="%s"' % user_id

        name = kwargs.get('name', '')
        if name and not user_id:
            name = '<name>%s</name>' % name

        if not user_id and not name:
            assert('user_id or name are required')

        new_name = kwargs.get('new_name', '')
        if new_name:
            new_name = '<new_name>%s</new_name>' % new_name

        password = kwargs.get('password', '')
        if password:
            password = '<password>%s</password>' % password

        role_ids = kwargs.get('role_ids', '')
        role_txt = ''
        if len(role_ids) > 0:
            for role in role_ids:
                role_txt += '<role id="%s" />' % role

        hosts = kwargs.get('hosts', '')
        hosts_allow = kwargs.get('hosts_allow', '')
        if hosts or hosts_allow:
            hosts_allow = '<hosts allow="%s">%s</hosts>' % (hosts_allow, hosts)

        ifaces = kwargs.get('ifaces', '')
        ifaces_allow = kwargs.get('ifaces_allow', '')
        if ifaces or ifaces_allow:
            ifaces_allow = '<ifaces allow="%s">%s</ifaces>' % (ifaces_allow,
                                                               ifaces)

        sources = kwargs.get('sources', '')
        if sources:
            sources = '<sources>%s</sources>' % sources

        return '<modify_user {0}>{1}{2}{3}{4}{5}{6}{7}' \
               '</modify_user>'.format(user_id, name, new_name, password,
                                       role_txt, hosts_allow, ifaces_allow,
                                       sources)
