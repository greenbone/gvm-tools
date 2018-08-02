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
from lxml import etree
import defusedxml.ElementTree as secET

class _gmp:
    """GMP - Greenbone Manager Protocol
    """

    def createAgentCommand(self, installer, signature, name, comment='',
                           copy='', howto_install='', howto_use=''):

        xmlRoot = etree.Element('create_agent')
        _xmlInstaller = etree.SubElement(xmlRoot, 'installer')
        _xmlInstaller.text = installer
        _xmlSignature = etree.SubElement(_xmlInstaller, 'signature')
        _xmlSignature.text = signature
        _xmlName = etree.SubElement(xmlRoot, 'name')
        _xmlName.text = name

        if comment:
            _xmlComment = etree.SubElement(xmlRoot, 'comment')
            _xmlComment.text = comment

        if copy:
            _xmlCopy = etree.SubElement(xmlRoot, 'copy')
            _xmlCopy.text = copy

        if howto_install:
            _xmlHowtoinstall = etree.SubElement(xmlRoot, 'howto_install')
            _xmlHowtoinstall.text = howto_install

        if howto_use:
            _xmlHowtouse = etree.SubElement(xmlRoot, 'howto_use')
            _xmlHowtouse.text = howto_use

        return etree.tostring(xmlRoot).decode('utf-8')

    def createAlertCommand(self, name, condition, event, method, filter_id='',
                           copy='', comment=''):

        xmlRoot = etree.Element('create_alert')
        _xmlName = etree.SubElement(xmlRoot, 'name')
        _xmlName.text = name

        if len(condition) > 1:
            _xmlConditions = etree.SubElement(xmlRoot, 'condition')
            _xmlConditions.text = condition[0]
            for value, key in condition[1].items():
                _xmlData = etree.SubElement(_xmlConditions, 'data')
                _xmlData.text = value
                _xmlName = etree.SubElement(_xmlData, 'name')
                _xmlName.text = key
        elif condition[0] == "Always":
            _xmlConditions = etree.SubElement(xmlRoot, 'condition')
            _xmlConditions.text = condition[0]

        if len(event) > 1:
            _xmlEvents = etree.SubElement(xmlRoot, 'event')
            _xmlEvents.text = event[0]
            for value, key in event[1].items():
                _xmlData = etree.SubElement(_xmlEvents, 'data')
                _xmlData.text = value
                _xmlName = etree.SubElement(_xmlData, 'name')
                _xmlName.text = key

        if len(method) > 1:
            _xmlMethods = etree.SubElement(xmlRoot, 'method')
            _xmlMethods = method[0]
            for value, key in method[1].items():
                _xmlData = etree.SubElement(_xmlMethods, 'data')
                _xmlData.text = value
                _xmlName = etree.SubElement(_xmlData, 'name')
                _xmlName.text = key

        if filter_id:
            _xmlFilter = etree.SubElement(xmlRoot, 'filter', id=filter_id)

        if copy:
            _xmlCopy = etree.SubElement(xmlRoot, 'copy')
            _xmlCopy = copy

        if comment:
            _xmlComment = etree.SubElement(xmlRoot, 'comment')
            _xmlComment = comment

        return etree.tostring(xmlRoot).decode('utf-8')

    def createAssetCommand(self, name, asset_type, comment=''):
        if asset_type not in ('host', 'os'):
            raise ValueError('create_asset requires asset_type to be either '
                             'host or os')
        xmlRoot = etree.Element('create_asset')
        _xmlAsset = etree.SubElement(xmlRoot, 'asset')
        _xmlType = etree.SubElement(_xmlAsset, 'type')
        _xmlType.text = asset_type
        _xmlName = etree.SubElement(_xmlAsset, 'name')
        _xmlName.text = name

        if comment:
            _xmlComment = etree.SubElement(_xmlAsset, 'comment')
            _xmlComment.text = comment

        return etree.tostring(xmlRoot).decode('utf-8')

    def createAuthenticateCommand(self, username, password, withCommands=''):
        """Generates string for authentification on GVM

        Creates the gmp authentication xml string.
        Inserts the username and password into it.

        Keyword Arguments:
            username {str} -- Username for GVM User
            password {str} -- Password for GVM User
            withCommands {str} -- Additional commands default: {''})
        """

        xmlRoot = etree.Element('authenticate')
        _xmlCredentials = etree.SubElement(xmlRoot, 'credentials')
        _xmlUser = etree.SubElement(_xmlCredentials, 'username')
        _xmlUser.text = username
        _xmlPass = etree.SubElement(_xmlCredentials, 'password')
        _xmlPass.text = password
        if len(withCommands) is 0:
            return etree.tostring(xmlRoot).decode('utf-8')

        xmlRootCmd = etree.Element('commands')
        cmds = secET.fromstring(withCommands)
        xmlRootCmd.append(xmlRoot)
        xmlRootCmd.append(cmds)
        return etree.tostring(xmlRootCmd).decode('utf-8')

    def createConfigCommand(self, copy_id, name):

        xmlRoot = etree.Element('create_config')
        _xmlCopy = etree.SubElement(xmlRoot, 'copy')
        _xmlCopy.text = copy_id
        _xmlName = etree.SubElement(xmlRoot, 'name')
        _xmlName.text = name
        return etree.tostring(xmlRoot).decode('utf-8')

    def createCredentialCommand(self, name, kwargs):

        xmlRoot = etree.Element('create_credential')
        _xmlName = etree.SubElement(xmlRoot, 'name')
        _xmlName.text = name

        comment = kwargs.get('comment', '')
        if comment:
            _xmlComment = etree.SubElement(xmlRoot, 'comment')
            _xmlComment.text = comment

        copy = kwargs.get('copy', '')
        if copy:
            _xmlCopy = etree.SubElement(xmlRoot, 'copy')
            _xmlCopy.text = copy

        allow_insecure = kwargs.get('allow_insecure', '')
        if allow_insecure:
            _xmlAllowinsecure = etree.SubElement(xmlRoot, 'allow_insecure')
            _xmlAllowinsecure.text = allow_insecure

        certificate = kwargs.get('certificate', '')
        if certificate:
            _xmlCertificate = etree.SubElement(xmlRoot, 'certificate')
            _xmlCertificate.text = certificate

        key = kwargs.get('key', '')
        if key:
            phrase = key['phrase']
            private = key['private']
            if not phrase:
                raise ValueError('create_credential requires a phrase element')
            if not private:
                raise ValueError('create_credential requires a '
                                 'private element')

            _xmlKey = etree.SubElement(xmlRoot, 'key')
            _xmlKeyphrase = etree.SubElement(_xmlKey, 'phrase')
            _xmlKeyphrase.text = phrase
            _xmlKeyprivate = etree.SubElement(_xmlKey, 'private')
            _xmlKeyprivate.text = private

        login = kwargs.get('login', '')
        if login:
            _xmlLogin = etree.SubElement(xmlRoot, 'login')
            _xmlLogin.text = login

        password = kwargs.get('password', '')
        if password:
            _xmlPass = etree.SubElement(xmlRoot, 'password')
            _xmlPass.text = password

        auth_algorithm = kwargs.get('auth_algorithm', '')
        if auth_algorithm:
            if auth_algorithm not in ('md5', 'sha1'):
                raise ValueError('create_credential requires auth_algorithm '
                                 'to be either md5 or sha1')
            _xmlAuthalg = etree.SubElement(xmlRoot, 'auth_algorithm')
            _xmlAuthalg.text = auth_algorithm

        community = kwargs.get('community', '')
        if community:
            _xmlCommunity = etree.SubElement(xmlRoot, 'community')
            _xmlCommunity.text = community

        privacy = kwargs.get('privacy', '')
        if privacy:
            algorithm = privacy.algorithm
            if algorithm not in ('aes', 'des'):
                raise ValueError('create_credential requires algorithm '
                                 'to be either aes or des')
            p_password = privacy.password
            _xmlPrivacy = etree.SubElement(xmlRoot, 'privacy')
            _xmlAlgorithm = etree.SubElement(_xmlPrivacy, 'algorithm')
            _xmlAlgorithm.text = algorithm
            _xmlPpass = etree.SubElement(_xmlPrivacy, 'password')
            _xmlPpass.text = p_password

        cred_type = kwargs.get('type', '')
        if cred_type:
            if cred_type not in ('cc', 'snmp', 'up', 'usk'):
                raise ValueError('create_credential requires type '
                                 'to be either cc, snmp, up or usk')
            _xmlCredtype = etree.SubElement(xmlRoot, 'type')
            _xmlCredtype.text = cred_type

        return etree.tostring(xmlRoot).decode('utf-8')

    def createFilterCommand(self, name, make_unique, kwargs):

        xmlRoot = etree.Element('create_filter')
        _xmlName = etree.SubElement(xmlRoot, 'name')
        _xmlName.text = name
        _xmlUnique = etree.SubElement(_xmlName, 'make_unique')
        _xmlUnique.text = make_unique

        comment = kwargs.get('comment', '')
        if comment:
            _xmlComment = etree.SubElement(xmlRoot, 'comment')
            _xmlComment.text = comment

        copy = kwargs.get('copy', '')
        if copy:
            _xmlCopy = etree.SubElement(xmlRoot, 'copy')
            _xmlCopy.text = copy

        term = kwargs.get('term', '')
        if term:
            _xmlTerm = etree.SubElement(xmlRoot, 'term')
            _xmlTerm.text = term

        filter_type = kwargs.get('type', '')
        if filter_type:
            if filter_type not in ('cc', 'snmp', 'up', 'usk'):
                raise ValueError('create_filter requires type '
                                 'to be either cc, snmp, up or usk')
            _xmlFiltertype = etree.SubElement(xmlRoot, 'type')
            _xmlFiltertype.text = filter_type

        return etree.tostring(xmlRoot).decode('utf-8')

    def createGroupCommand(self, name, kwargs):

        xmlRoot = etree.Element('create_group')
        _xmlName = etree.SubElement(xmlRoot, 'name')
        _xmlName.text = name

        comment = kwargs.get('comment', '')
        if comment:
            _xmlComment = etree.SubElement(xmlRoot, 'comment')
            _xmlComment.text = comment

        copy = kwargs.get('copy', '')
        if copy:
            _xmlCopy = etree.SubElement(xmlRoot, 'copy')
            _xmlCopy.text = copy

        special = kwargs.get('special', '')
        if special:
            _xmlSpecial = etree.SubElement(xmlRoot, 'specials')
            _xmlFull = etree.SubElement(_xmlSpecial, 'full')

        users = kwargs.get('users', '')
        if users:
            users = '<users>%s</users>' % users
            _xmlUser = etree.SubElement(xmlRoot, 'users')
            _xmlUser.text = users

        return etree.tostring(xmlRoot).decode('utf-8')

    def createNoteCommand(self, text, nvt_oid, kwargs):

        xmlRoot = etree.Element('create_note')
        _xmlText = etree.SubElement(xmlRoot, 'text')
        _xmlText.text = text
        _xmlNvt = etree.SubElement(xmlRoot, 'nvt', oid=nvt_oid)

        active = kwargs.get('active', '')
        if active:
            _xmlActive = etree.SubElement(xmlRoot, 'active')
            _xmlActive.text = active

        comment = kwargs.get('comment', '')
        if comment:
            _xmlComment = etree.SubElement(xmlRoot, 'comment')
            _xmlComment.text = comment

        copy = kwargs.get('copy', '')
        if copy:
            _xmlCopy = etree.SubElement(xmlRoot, 'copy')
            _xmlCopy.text = copy

        hosts = kwargs.get('hosts', '')
        if hosts:
            _xmlHosts = etree.SubElement(xmlRoot, 'hosts')
            _xmlHosts.text = hosts

        port = kwargs.get('port', '')
        if port:
            _xmlPort = etree.SubElement(xmlRoot, 'port')
            _xmlPort.text = port

        result_id = kwargs.get('result_id', '')
        if result_id:
            _xmlResultid = etree.SubElement(xmlRoot, 'result', id=result_id)

        severity = kwargs.get('severity', '')
        if severity:
            _xmlSeverity = etree.SubElement(xmlRoot, 'severity')
            _xmlSeverity.text = severity

        task_id = kwargs.get('task_id', '')
        if task_id:
            _xmlTaskid = etree.SubElement(xmlRoot, 'task', id=task_id)

        threat = kwargs.get('threat', '')
        if threat:
            _xmlThreat = etree.SubElement(xmlRoot, 'threat')
            _xmlThreat.text = threat

        return etree.tostring(xmlRoot).decode('utf-8')

    def createOverrideCommand(self, text, nvt_oid, kwargs):

        xmlRoot = etree.Element('create_override')
        _xmlText = etree.SubElement(xmlRoot, 'text')
        _xmlText.text = text
        _xmlNvt = etree.SubElement(xmlRoot, 'nvt', oid=nvt_oid)

        active = kwargs.get('active', '')
        if active:
            _xmlActive = etree.SubElement(xmlRoot, 'active')
            _xmlActive.text = active

        comment = kwargs.get('comment', '')
        if comment:
            _xmlComment = etree.SubElement(xmlRoot, 'comment')
            _xmlComment.text = comment

        copy = kwargs.get('copy', '')
        if copy:
            _xmlCopy = etree.SubElement(xmlRoot, 'copy')
            _xmlCopy.text = copy

        hosts = kwargs.get('hosts', '')
        if hosts:
            _xmlHosts = etree.SubElement(xmlRoot, 'hosts')
            _xmlHosts.text = hosts

        port = kwargs.get('port', '')
        if port:
            _xmlPort = etree.SubElement(xmlRoot, 'port')
            _xmlPort.text = port

        result_id = kwargs.get('result_id', '')
        if result_id:
            _xmlResultid = etree.SubElement(xmlRoot, 'result', id=result_id)

        severity = kwargs.get('severity', '')
        if severity:
            _xmlSeverity = etree.SubElement(xmlRoot, 'severity')
            _xmlSeverity.text = severity

        new_severity = kwargs.get('new_severity', '')
        if new_severity:
            _xmlNSeverity = etree.SubElement(xmlRoot, 'new_severity')
            _xmlNSeverity.text = new_severity

        task_id = kwargs.get('task_id', '')
        if task_id:
            _xmlTaskid = etree.SubElement(xmlRoot, 'task', id=task_id)

        threat = kwargs.get('threat', '')
        if threat:
            _xmlThreat = etree.SubElement(xmlRoot, 'threat')
            _xmlThreat.text = threat

        new_threat = kwargs.get('new_threat', '')
        if new_threat:
            _xmlNThreat = etree.SubElement(xmlRoot, 'new_threat')
            _xmlNThreat.text = new_threat

        return etree.tostring(xmlRoot).decode('utf-8')

    def createPermissionCommand(self, name, subject_id, type, kwargs):
        # pretty(gmp.create_permission('get_version',
        # 'cc9cac5e-39a3-11e4-abae-406186ea4fc5', 'role'))
        # libs.gvm_connection.GMPError: Error in NAME
        # TODO: Research why!!

        if not name:
            raise ValueError('create_permission requires a name element')
        if not subject_id:
            raise ValueError('create_permission requires a subject_id element')
        if type not in ('user', 'group', 'role'):
            raise ValueError('create_permission requires type '
                             'to be either user, group or role')

        xmlRoot = etree.Element('create_permission')
        _xmlName = etree.SubElement(xmlRoot, 'name')
        _xmlName.text = name
        _xmlSubject = etree.SubElement(xmlRoot, 'subject', id=subject_id)
        _xmlType = etree.SubElement(_xmlSubject, 'type')
        _xmlType.text = type

        comment = kwargs.get('comment', '')
        if comment:
            _xmlComment = etree.SubElement(xmlRoot, 'comment')
            _xmlComment.text = comment

        copy = kwargs.get('copy', '')
        if copy:
            _xmlCopy = etree.SubElement(xmlRoot, 'copy')
            _xmlCopy.text = copy

        resource = kwargs.get('resource', '')
        if resource:
            resource_id = resource.id
            resource_type = resource.type
            _xmlResource = etree.SubElement(xmlRoot, 'resource', id=resource_id)
            _xmlRType = etree.SubElement(_xmlResource, 'type')
            _xmlRType.text = resource_type

        return etree.tostring(xmlRoot).decode('utf-8')

    def createPortListCommand(self, name, port_range, kwargs):

        if not name:
            raise ValueError('create_port_list requires a name element')
        if not port_range:
            raise ValueError('create_port_list requires a port_range element')

        xmlRoot = etree.Element('create_port_list')
        _xmlName = etree.SubElement(xmlRoot, 'name')
        _xmlName.text = name
        _xmlPortrange = etree.SubElement(xmlRoot, 'port_range')
        _xmlPortrange.text = port_range

        comment = kwargs.get('comment', '')
        if comment:
            _xmlComment = etree.SubElement(xmlRoot, 'comment')
            _xmlComment.text = comment

        copy = kwargs.get('copy', '')
        if copy:
            _xmlCopy = etree.SubElement(xmlRoot, 'copy')
            _xmlCopy.text = copy

        return etree.tostring(xmlRoot).decode('utf-8')

    def createPortRangeCommand(self, port_list_id, start, end, type,
                               comment=''):

        if not port_list_id:
            raise ValueError('create_port_range requires '
                             'a port_list_id element')
        if not type:
            raise ValueError('create_port_range requires a type element')

        xmlRoot = etree.Element('create_port_range')
        _xmlPlist = etree.SubElement(xmlRoot, 'port_list', id=port_list_id)
        _xmlStart = etree.SubElement(xmlRoot, 'start')
        _xmlStart.text = start
        _xmlEnd = etree.SubElement(xmlRoot, 'end')
        _xmlEnd.text = end
        _xmlType = etree.SubElement(xmlRoot, 'type')
        _xmlType.text = type

        if len(comment):
            _xmlComment = etree.SubElement(xmlRoot, 'comment')
            _xmlComment.text = comment

        return etree.tostring(xmlRoot).decode('utf-8')

    def createReportCommand(self, report_xml_string, kwargs):

        if not report_xml_string:
            raise ValueError('create_report requires a report')

        task_id = kwargs.get('task_id', '')
        task_name = kwargs.get('task_name', '')
        task = ''

        xmlRoot = etree.Element('create_report')
        comment = kwargs.get('comment', '')
        if task_id:
            _xmlTask = etree.SubElement(xmlRoot, 'task', id=task_id)
        elif task_name:
            _xmlTask = etree.SubElement(xmlRoot, 'task')
            _xmlName = etree.SubElement(_xmlTask, 'name')
            _xmlName.text = task_name
            if comment:
                _xmlComment = etree.SubElement(_xmlTask, 'comment')
                _xmlComment.text = comment
        else:
            raise ValueError('create_report requires an id or name for a task')

        in_assets = kwargs.get('in_assets', '')
        if in_assets:
            _xmlInAsset = etree.SubElement(xmlRoot, 'in_assets')
            _xmlInAsset.text = in_assets

        xmlReport = secET.fromstring(report_xml_string)
        xmlRoot.append(Report)

        return etree.tostring(xmlRoot).decode('utf-8')

    def createRoleCommand(self, name, kwargs):

        if not name:
            raise ValueError('create_role requires a name element')

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
        if not name:
            raise ValueError('create_scanner requires a name element')
        if not host:
            raise ValueError('create_scanner requires a host element')
        if not port:
            raise ValueError('create_scanner requires a port element')
        if not type:
            raise ValueError('create_scanner requires a type element')
        if not ca_pub:
            raise ValueError('create_scanner requires a ca_pub element')
        if not credential_id:
            raise ValueError('create_scanner requires a credential_id element')

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
        if not name:
            raise ValueError('create_schedule requires a name element')

        comment = kwargs.get('comment', '')
        if comment:
            comment = '<comment>%s</comment>' % comment

        copy = kwargs.get('copy', '')
        if copy:
            copy = '<copy>%s</copy>' % copy

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
            duration = '<duration>%s<unit>%s</unit></duration>' \
                       '' % (duration[0], duration[1])

        period = kwargs.get('period', '')
        if len(period) > 1:
            period = '<period>%s<unit>%s</unit></period>' \
                     '' % (period[0], period[1])

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

        if not name:
            raise ValueError('create_target requires a name element')

        if make_unique:
            unique = 1
        else:
            unique = 0

        if 'asset_hosts' in kwargs:
            hosts = kwargs.get('asset_hosts')
            filter = hosts['filter']

            hosts = '<asset_hosts filter="%s"/>' % filter
        elif 'hosts' in kwargs:
            hosts = kwargs.get('hosts')
            hosts = '<hosts>%s</hosts>' % hosts
        else:
            raise ValueError('create_target requires either a hosts or '
                             'an asset_hosts element')

        optional_args = ''

        if 'comment' in kwargs:
            optional_args += '<comment>%s</comment>' % kwargs.get('comment')

        if 'copy' in kwargs:
            # NOTE: It seems that hosts/asset_hosts is silently ignored by the
            # server when copy is supplied. But for specification conformance
            # we raise the ValueError above and consider copy optional.
            optional_args += '<copy>%s</copy>' % kwargs.get('copy')

        if 'exclude_hosts' in kwargs:
            optional_args += '<exclude_hosts>%s</exclude_hosts>' % kwargs.get('exclude_hosts')

        if 'ssh_credential' in kwargs:
            ssh_credential = kwargs.get('ssh_credential')
            if 'id' in ssh_credential:
                optional_args += '<ssh_credential id="%s">' % ssh_credential['id']
                if 'port' in ssh_credential:
                    optional_args += '<port>%s</port>' % ssh_credential['port']
                optional_args += '</ssh_credential>'
            else:
                raise ValueError('ssh_credential requires an id attribute')

        if 'smb_credential' in kwargs:
            smb_credential = kwargs.get('smb_credential')
            if 'id' in smb_credential:
                optional_args += '<smb_credential id="%s"/>' % smb_credential['id']
            else:
                raise ValueError('smb_credential requires an id attribute')

        if 'esxi_credential' in kwargs:
            esxi_credential = kwargs.get('esxi_credential')
            if 'id' in esxi_credential:
                optional_args += '<esxi_credential id="%s"/>' % esxi_credential['id']
            else:
                raise ValueError('esxi_credential requires an id attribute')

        if 'snmp_credential' in kwargs:
            snmp_credential = kwargs.get('snmp_credential')
            if 'id' in snmp_credential:
                optional_args += '<snmp_credential id="%s"/>' % snmp_credential['id']
            else:
                raise ValueError('snmp_credential requires an id attribute')

        if 'alive_tests' in kwargs:
            # NOTE: As the alive_tests are referenced by their name and some
            # names contain ampersand ('&') characters it should be considered
            # replacing any characters special to XML in the variable with
            # their corresponding entities.
            optional_args += '<alive_tests>%s</alive_tests>' % kwargs.get('alive_tests')

        if 'reverse_lookup_only' in kwargs:
            reverse_lookup_only = kwargs.get('reverse_lookup_only')
            if reverse_lookup_only:
                optional_args += '<reverse_lookup_only>1</reverse_lookup_only>'
            else:
                optional_args += '<reverse_lookup_only>0</reverse_lookup_only>'

        if 'reverse_lookup_unify' in kwargs:
            reverse_lookup_unify = kwargs.get('reverse_lookup_unify')
            if reverse_lookup_unify:
                optional_args += '<reverse_lookup_unify>1</reverse_lookup_unify>'
            else:
                optional_args += '<reverse_lookup_unify>0</reverse_lookup_unify>'

        if 'port_range' in kwargs:
            optional_args += '<port_range>%s</port_range>' % kwargs.get('port_range')

        if 'port_list' in kwargs:
            port_list = kwargs.get('port_list')
            if 'id' in port_list:
                optional_args += '<port_list id="%s"/>' % port_list['id']
            else:
                raise ValueError('port_list requires an id attribute')

        return '<create_target>' \
                '<name>{0}<make_unique>{1}</make_unique></name>' \
                '{2}' \
                '{3}' \
               '</create_target>'.format(name,
                       unique,
                       hosts,
                       optional_args)

    def createTaskCommand(self, name, config_id, target_id, scanner_id,
                          alert_id='', comment=''):
        xmlRoot = etree.Element('create_task')
        _xmlName = etree.SubElement(xmlRoot, 'name')
        _xmlName.text = name
        _xmlComment = etree.SubElement(xmlRoot, 'comment')
        _xmlComment.text = comment
        _xmlConfig = etree.SubElement(xmlRoot, 'config', id=config_id)
        _xmlTarget = etree.SubElement(xmlRoot, 'target', id=target_id)
        _xmlScanner = etree.SubElement(xmlRoot, 'scanner', id=scanner_id)
        #if given the alert_id is wrapped and integrated suitably as xml
        if len(alert_id)>0:
            _xmlAlert = etree.SubElement(xmlRoot, 'alert', id=str(alert_id))
        return etree.tostring(xmlRoot).decode('utf-8')

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

        if not agent_id:
            raise ValueError('modify_agent requires an agent_id element')
        if name:
            name = '<name>{0}</name>'.format(name)

        if comment:
            comment = '<comment>{0}</comment>'.format(comment)

        return '<modify_agent agent_id="{0}">{1}{2}' \
               '</modify_agent>'.format(agent_id, name, comment)

    def modifyAlertCommand(self, alert_id, kwargs):

        if not alert_id:
            raise ValueError('modify_alert requires an agent_id element')

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

        if not group_name:
            raise ValueError('modify_auth requires a group element '
                             'with a name attribute')
        if not auth_conf_settings:
            raise ValueError('modify_auth requires '
                             'an auth_conf_settings element')
        auth_conf_setting = ''

        for key, value in auth_conf_settings.items():
            auth_conf_setting += '<auth_conf_setting>' \
                                 '<key>%s</key>' \
                                 '<value>%s</value>' \
                                 '</auth_conf_setting>' % (key, value)

        return '<modify_auth><group name="{0}">{1}</group>' \
               '</modify_auth>'.format(group_name, auth_conf_setting)

    def modifyConfigCommand(self, selection, kwargs):

        if selection not in ('nvt_pref', 'sca_pref',
                             'family_selection', 'nvt_selection'):
            raise ValueError('selection must be one of nvt_pref, sca_pref, '
                             'family_selection or nvt_selection')
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
            if isinstance(nvt_oid, list):
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
                   '<growing>1</growing></family></family_selection>' \
                   '</modify_config>'.format(config_id, family)
        else:
            raise NotImplementedError

    def modifyCredentialCommand(self, credential_id, kwargs):

        if not credential_id:
            raise ValueError('modify_credential requires '
                             'a credential_id attribute')

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
            if not phrase:
                raise ValueError('modify_credential requires a phrase element')
            if not private:
                raise ValueError('modify_credential requires '
                                 'a private element')

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
            if auth_algorithm not in ('md5', 'sha1'):
                raise ValueError('modify_credential requires auth_algorithm '
                                 'to be either md5 or sha1')
            auth_algorithm = '<auth_algorithm>%s</auth_algorithm>' \
                             '' % auth_algorithm

        community = kwargs.get('community', '')
        if community:
            community = '<community>%s</community>' % community

        privacy = kwargs.get('privacy', '')
        if privacy:
            algorithm = privacy.algorithm
            if algorithm not in ('aes', 'des'):
                raise ValueError('modify_credential requires algorithm '
                                 'to be either aes or des')
            p_password = privacy.password
            privacy = '<privacy><algorithm>{0}</algorithm><password>{1} ' \
                      '</password></privacy>'.format(algorithm, p_password)

        cred_type = kwargs.get('type', '')
        if cred_type:
            if cred_type not in ('cc', 'snmp', 'up', 'usk'):
                raise ValueError('modify_credential requires type '
                                 'to be either cc, snmp, up or usk')
            cred_type = '<type>%s</type>' % cred_type

        return '<modify_credential credential_id="{0}">' \
               '{1}{2}{3}{4}{5}{6}{7}{8}{9}{10}{11}' \
               '</modify_credential>' \
               ''.format(credential_id, comment, name, allow_insecure,
                         certificate, key, login, password, auth_algorithm,
                         community, privacy, cred_type)

    def modifyFilterCommand(self, filter_id, kwargs):

        if not filter_id:
            raise ValueError('modify_filter requires a filter_id attribute')

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
            if filter_type not in ('cc', 'snmp', 'up', 'usk'):
                raise ValueError('modify_filter requires type '
                                 'to be either cc, snmp, up or usk')
            filter_type = '<type>%s</type>' % filter_type

        return '<modify_filter filter_id="{0}">{1}{2}{3}{4}</modify_filter>' \
               ''.format(filter_id, comment, name, term, filter_type)

    def modifyGroupCommand(self, group_id, kwargs):

        if not group_id:
            raise ValueError('modify_group requires a group_id attribute')

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

        if not note_id:
            raise ValueError('modify_note requires a note_id attribute')
        if not text:
            raise ValueError('modify_note requires a text element')

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

        if not permission_id:
            raise ValueError('modify_permission requires '
                             'a permission_id element')

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

        if not port_list_id:
            raise ValueError('modify_port_list requires '
                             'a port_list_id attribute')

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

        if not role_id:
            raise ValueError('modify_role requires a role_id element')

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

        if not scanner_id:
            raise ValueError('modify_scanner requires a scanner_id element')
        if not host:
            raise ValueError('modify_scanner requires a host element')
        if not port:
            raise ValueError('modify_scanner requires a port element')
        if not type:
            raise ValueError('modify_scanner requires a type element')

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
               '{4}{5}{6}{7}' \
               '</modify_scanner>' \
               ''.format(scanner_id, host, port, type, name, ca_pub,
                         credential_id, comment)

    def modifyScheduleCommand(self, schedule_id, kwargs):

        if not schedule_id:
            raise ValueError('modify_schedule requires a schedule_id element')

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
        if timezone:
            timezone = '<timezone>%s</timezone>' % timezone

        return '<modify_schedule schedule_id="{0}">' \
               '{1}{2}{3}{4}{5}{6}' \
               '</modify_schedule>' \
               ''.format(schedule_id, comment, name, first_time, duration,
                         period, timezone)

    def modifyTagCommand(self, tag_id, kwargs):

        if not tag_id:
            raise ValueError('modify_tag requires a tag_id element')

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

        return '<modify_tag tag_id="{0}">{1}{2}{3}{4}{5}</modify_tag>' \
               ''.format(tag_id, name, resource, value, comment, active)

    def modifyTargetCommand(self, target_id, kwargs):

        if not target_id:
            raise ValueError('modify_target requires a target_id element')

        comment = kwargs.get('comment', '')
        if comment:
            comment = '<comment>%s</comment>' % comment

        name = kwargs.get('name', '')
        if name:
            name = '<name>%s</name>' % name

        hosts = kwargs.get('hosts', '')
        if hosts:
            hosts = '<hosts>%s</hosts>' % hosts

        comment = kwargs.get('comment', '')
        if comment:
            comment = '<comment>%s</comment>' % comment

        copy = kwargs.get('copy', '')
        if copy:
            copy = '<copy>%s</copy>' % copy

        exclude_hosts = kwargs.get('exclude_hosts', '')
        if exclude_hosts:
            exclude_hosts = '<exclude_hosts>%s</exclude_hosts>' % exclude_hosts

        alive_tests = kwargs.get('alive_tests', '')
        if alive_tests:
            alive_tests = '<alive_tests>%s</alive_tests>' % alive_tests

        reverse_lookup_only = kwargs.get('reverse_lookup_only', '')
        if reverse_lookup_only:
            reverse_lookup_only = '<reverse_lookup_only>%s</reverse_lookup_only>' % reverse_lookup_only

        reverse_lookup_unify = kwargs.get('reverse_lookup_unify', '')
        if reverse_lookup_unify:
            reverse_lookup_unify = '<reverse_lookup_unify>%s</reverse_lookup_unify>' % reverse_lookup_unify

        port_range = kwargs.get('port_range', '')
        if port_range:
            port_range = '<port_range>%s</port_range>' % port_range

        port_list = kwargs.get('port_list', '')
        if port_list:
            port_list = '<port_list id="%s"/>' % port_list

        return '<modify_target target_id="{0}">{1}{2}{3}{4}{5}{6}  \
                {7}{8}{9}{10}</modify_target>' \
               ''.format(
                         target_id, name, hosts, comment, copy, exclude_hosts,
                         alive_tests, reverse_lookup_only, reverse_lookup_unify,
                         port_range, port_list
                         )

    def modifyTaskCommand(self, task_id, kwargs):

        if not task_id:
            raise ValueError('modify_task requires a task_id element')

        name = kwargs.get('name', '')
        if name:
            name = '<name>%s</name>' % name

        comment = kwargs.get('comment', '')
        if comment:
            comment = '<comment>%s</comment>' % comment

        target_id = kwargs.get('target_id', '')
        if target_id:
            target_id = '<target id="%s"/>' % target_id

        scanner = kwargs.get('scanner', '')
        if scanner:
            scanner = '<scanner_id="%s"></scanner>' % scanner

        schedule_periods = kwargs.get('schedule_periods', '')
        if schedule_periods:
            schedule_periods = '<schedule_periods>%d</schedule_periods>' % schedule_periods

        schedule = kwargs.get('schedule', '')
        if schedule:
            schedule = '<schedule id="%s"/>' % (schedule)

        alert = kwargs.get('alert', '')
        if alert:
            alert = '<alert id="%s"/>' % (alert)

        observers = kwargs.get('observers', '')
        if observers:
            observers = '<observers>%s</observers>' % observers

        preferences = kwargs.get('preferences', '')
        if preferences:
            preferences_list = []
            for n in range(len(preferences["scanner_name"])):
                preferences_scanner_name = preferences["scanner_name"][n]
                preferences_value = preferences["value"][n]
                preference = '<preference><scanner_name>%s</scanner_name><value>%s</value></preference>' \
                             % (preferences_scanner_name, preferences_value)
                preferences_list.append(preference)
            preferences = "".join(preferences_list)
            preferences = '<preferences>%s</preferences>' % preferences

        file = kwargs.get('file', '')
        if file:
            file_name = file['name']
            file_action = file['action']
            if file_action != "update" and file_action !="remove" :
                raise ValueError('action can only be "update" or "remove"!')

            file = '<file name="%s" action="%s"/>' % (file_name, file_action)

        return '<modify_task task_id="{0}">' \
               '{1}{2}{3}{4}{5}{6}{7}{8}{9}{10}' \
               '</modify_task>' \
               ''.format(
                         task_id, comment, alert, name, target_id, observers,
                         preferences, schedule, schedule_periods, scanner,
                         file
                         )

    def modifyUserCommand(self, kwargs):

        user_id = kwargs.get('user_id', '')
        if user_id:
            user_id = 'user_id="%s"' % user_id

        name = kwargs.get('name', '')
        if name and not user_id:
            name = '<name>%s</name>' % name

        if not user_id and not name:
            raise ValueError('modify_user requires '
                             'either a user_id or a name element')

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
