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
import defusedxml.lxml as secET


class _gmp:
    """GMP - Greenbone Management Protocol
    """
    FILTER_NAMES = ['Agent', 'Alert', 'Asset', 'Credential',
             'Filter', 'Group', 'Note', 'Override', 'Permission', 'Port List',
              'Report', 'Report Format', 'Result', 'Role', 'Schedule', 'SecInfo',
               'Config', 'Tag', 'Target', 'Task', 'User']
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
            _xmlMethods.text = method[0]
            for value, key in method[1].items():
                _xmlData = etree.SubElement(_xmlMethods, 'data')
                _xmlData.text = value
                _xmlName = etree.SubElement(_xmlData, 'name')
                _xmlName.text = key

        if filter_id:
            _xmlFilter = etree.SubElement(xmlRoot, 'filter', id=filter_id)

        if copy:
            _xmlCopy = etree.SubElement(xmlRoot, 'copy')
            _xmlCopy.text = copy

        if comment:
            _xmlComment = etree.SubElement(xmlRoot, 'comment')
            _xmlComment.text = comment

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
            if filter_type not in self.FILTER_NAMES:
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
            _xmlResource = etree.SubElement(xmlRoot, 'resource',
                                            id=resource_id)
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
        xmlRoot.append(xmlReport)

        return etree.tostring(xmlRoot).decode('utf-8')

    def createRoleCommand(self, name, kwargs):

        if not name:
            raise ValueError('create_role requires a name element')

        xmlRoot = etree.Element('create_role')
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

        users = kwargs.get('users', '')
        if users:
            _xmlUser = etree.SubElement(xmlRoot, 'users')
            _xmlUser.text = users

        return etree.tostring(xmlRoot).decode('utf-8')

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

        xmlRoot = etree.Element('create_scanner')
        _xmlName = etree.SubElement(xmlRoot, 'name')
        _xmlName.text = name
        _xmlHost = etree.SubElement(xmlRoot, 'host')
        _xmlHost.text = host
        _xmlPort = etree.SubElement(xmlRoot, 'port')
        _xmlPort.text = port
        _xmlType = etree.SubElement(xmlRoot, 'type')
        _xmlType.text = type
        _xmlCAPub = etree.SubElement(xmlRoot, 'ca_pub')
        _xmlCAPub.text = ca_pub
        _xmlCred = etree.SubElement(xmlRoot, 'credential',
                                    id=str(credential_id))

        comment = kwargs.get('comment', '')
        if comment:
            _xmlComment = etree.SubElement(xmlRoot, 'comment')
            _xmlComment.text = comment

        copy = kwargs.get('copy', '')
        if copy:
            _xmlCopy = etree.SubElement(xmlRoot, 'copy')
            _xmlCopy.text = copy

        return etree.tostring(xmlRoot).decode('utf-8')

    def createScheduleCommand(self, name, kwargs):
        if not name:
            raise ValueError('create_schedule requires a name element')

        xmlRoot = etree.Element('create_schedule')
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

        first_time = kwargs.get('first_time', '')
        if first_time:
            first_time_minute = first_time['minute']
            first_time_hour = first_time['hour']
            first_time_day_of_month = first_time['day_of_month']
            first_time_month = first_time['month']
            first_time_year = first_time['year']

            _xmlFtime = etree.SubElement(xmlRoot, 'first_time')
            _xmlMinute = etree.SubElement(_xmlFtime, 'minute')
            _xmlMinute.text = str(first_time_minute)
            _xmlHour = etree.SubElement(_xmlFtime, 'hour')
            _xmlHour.text = str(first_time_hour)
            _xmlDay = etree.SubElement(_xmlFtime, 'day_of_month')
            _xmlDay.text = str(first_time_day_of_month)
            _xmlMonth = etree.SubElement(_xmlFtime, 'month')
            _xmlMonth.text = str(first_time_month)
            _xmlYear = etree.SubElement(_xmlFtime, 'year')
            _xmlYear.text = str(first_time_year)

        duration = kwargs.get('duration', '')
        if len(duration) > 1:
            _xmlDuration = etree.SubElement(xmlRoot, 'duration')
            _xmlDuration.text = str(duration[0])
            _xmlUnit = etree.SubElement(_xmlDuration, 'unit')
            _xmlUnit.text = str(duration[1])

        period = kwargs.get('period', '')
        if len(period) > 1:
            _xmlPeriod = etree.SubElement(xmlRoot, 'period')
            _xmlPeriod.text = str(period[0])
            _xmlPUnit = etree.SubElement(_xmlPeriod, 'unit')
            _xmlPUnit.text = str(period[1])

        timezone = kwargs.get('timezone', '')
        if timezone:
            _xmlTimezone = etree.SubElement(xmlRoot, 'timezone')
            _xmlTimezone.text = str(timezone)

        return etree.tostring(xmlRoot).decode('utf-8')

    def createTagCommand(self, name, resource_id, resource_type, kwargs):

        xmlRoot = etree.Element('create_tag')
        _xmlName = etree.SubElement(xmlRoot, 'name')
        _xmlName.text = name
        _xmlResource = etree.SubElement(xmlRoot, 'resource',
                                        id=str(resource_id))
        _xmlRType = etree.SubElement(_xmlResource, 'type')
        _xmlRType.text = resource_type

        comment = kwargs.get('comment', '')
        if comment:
            _xmlComment = etree.SubElement(xmlRoot, 'comment')
            _xmlComment.text = comment

        copy = kwargs.get('copy', '')
        if copy:
            _xmlCopy = etree.SubElement(xmlRoot, 'copy')
            _xmlCopy.text = copy

        value = kwargs.get('value', '')
        if value:
            _xmlValue = etree.SubElement(xmlRoot, 'value')
            _xmlValue.text = value

        active = kwargs.get('active', '')
        if active:
            _xmlActive = etree.SubElement(xmlRoot, 'active')
            _xmlActive.text = active

        return etree.tostring(xmlRoot).decode('utf-8')

    def createTargetCommand(self, name, make_unique, kwargs):

        if not name:
            raise ValueError('create_target requires a name element')

        xmlRoot = etree.Element('create_target')
        _xmlName = etree.SubElement(xmlRoot, 'name')
        _xmlName.text = name
        if make_unique:
            unique = '1'
        else:
            unique = '0'
        _xmlUnique = etree.SubElement(_xmlName, 'make_unique')
        _xmlUnique.text = unique

        if 'asset_hosts' in kwargs:
            hosts = kwargs.get('asset_hosts')
            filter = hosts['filter']
            _xmlHosts = etree.SubElement(xmlRoot, 'asset_hosts',
                                         filter=str(filter))
        elif 'hosts' in kwargs:
            hosts = kwargs.get('hosts')
            _xmlHosts = etree.SubElement(xmlRoot, 'hosts')
            _xmlHosts.text = hosts
        else:
            raise ValueError('create_target requires either a hosts or '
                             'an asset_hosts element')

        if 'comment' in kwargs:
            _xmlComment = etree.SubElement(xmlRoot, 'comment')
            _xmlComment.text = kwargs.get('comment')

        if 'copy' in kwargs:
            # NOTE: It seems that hosts/asset_hosts is silently ignored by the
            # server when copy is supplied. But for specification conformance
            # we raise the ValueError above and consider copy optional.
            _xmlCopy = etree.SubElement(xmlRoot, 'copy')
            _xmlCopy.text = kwargs.get('copy')

        if 'exclude_hosts' in kwargs:
            _xmlExHosts = etree.SubElement(xmlRoot, 'exclude_hosts')
            _xmlExHosts.text = kwargs.get('exclude_hosts')

        if 'ssh_credential' in kwargs:
            ssh_credential = kwargs.get('ssh_credential')
            if 'id' in ssh_credential:
                _xmlSSH = etree.SubElement(xmlRoot, 'ssh_credential',
                                           id=ssh_credential['id'])
                _xmlSSH.text = ''
                if 'port' in ssh_credential:
                    _xmlSSHport = etree.SubElement(_xmlSSH, 'port')
                    _xmlSSHport.text = ssh_credential['port']
            else:
                raise ValueError('ssh_credential requires an id attribute')

        if 'smb_credential' in kwargs:
            smb_credential = kwargs.get('smb_credential')
            if 'id' in smb_credential:
                _xmlSMB = etree.SubElement(xmlRoot, 'smb_credential',
                                           id=smb_credential['id'])
            else:
                raise ValueError('smb_credential requires an id attribute')

        if 'esxi_credential' in kwargs:
            esxi_credential = kwargs.get('esxi_credential')
            if 'id' in esxi_credential:
                _xmlEsxi = etree.SubElement(xmlRoot, 'esxi_credential',
                                            id=esxi_credential['id'])
            else:
                raise ValueError('esxi_credential requires an id attribute')

        if 'snmp_credential' in kwargs:
            snmp_credential = kwargs.get('snmp_credential')
            if 'id' in snmp_credential:
                _xmlSnmp = etree.SubElement(xmlRoot, 'snmp_credential',
                                            id=snmp_credential['id'])
            else:
                raise ValueError('snmp_credential requires an id attribute')

        if 'alive_tests' in kwargs:
            # NOTE: As the alive_tests are referenced by their name and some
            # names contain ampersand ('&') characters it should be considered
            # replacing any characters special to XML in the variable with
            # their corresponding entities.
            _xmlAlive = etree.SubElement(xmlRoot, 'alive_tests')
            _xmlAlive.text = kwargs.get('alive_tests')

        if 'reverse_lookup_only' in kwargs:
            reverse_lookup_only = kwargs.get('reverse_lookup_only')
            _xmlLookup = etree.SubElement(xmlRoot, 'reverse_lookup_only')
            if reverse_lookup_only:
                _xmlLookup.text = '1'
            else:
                _xmlLookup.text = '0'

        if 'reverse_lookup_unify' in kwargs:
            reverse_lookup_unify = kwargs.get('reverse_lookup_unify')
            _xmlLookupU = etree.SubElement(xmlRoot, 'reverse_lookup_unify')
            if reverse_lookup_unify:
                _xmlLookupU.text = '1'
            else:
                _xmlLookupU.text = '0'

        if 'port_range' in kwargs:
            _xmlPortR = etree.SubElement(xmlRoot, 'port_range')
            _xmlPortR.text = kwargs.get('port_range')

        if 'port_list' in kwargs:
            port_list = kwargs.get('port_list')
            if 'id' in port_list:
                _xmlPortL = etree.SubElement(xmlRoot, 'port_list',
                                             id=str(port_list['id']))
            else:
                raise ValueError('port_list requires an id attribute')

        return etree.tostring(xmlRoot).decode('utf-8')

    def createTaskCommand(self, name, config_id, target_id, scanner_id,
                          alert_ids=None, comment=''):
        if alert_ids is None:
            alert_ids = []
        xmlRoot = etree.Element('create_task')
        _xmlName = etree.SubElement(xmlRoot, 'name')
        _xmlName.text = name
        _xmlComment = etree.SubElement(xmlRoot, 'comment')
        _xmlComment.text = comment
        _xmlConfig = etree.SubElement(xmlRoot, 'config', id=config_id)
        _xmlTarget = etree.SubElement(xmlRoot, 'target', id=target_id)
        _xmlScanner = etree.SubElement(xmlRoot, 'scanner', id=scanner_id)

        #if given the alert_id is wrapped and integrated suitably as xml
        if len(alert_ids)>0:
          if type(alert_ids) == str:
            #if a single id is given as a string wrap it into a list
            alert_ids=[alert_ids]
          if type(alert_ids)==list:
            #parse all given alert id's
            for alert in alert_ids:
              _xmlAlert = etree.SubElement(xmlRoot, 'alert', id=str(alert))
        return etree.tostring(xmlRoot).decode('utf-8')

    def createUserCommand(self, name, password, copy='', hosts_allow='0',
                          ifaces_allow='0', role_ids=(), hosts=None,
                          ifaces=None):
        xmlRoot = etree.Element('create_user')
        _xmlName = etree.SubElement(xmlRoot, 'name')
        _xmlName.text = name

        if copy:
            _xmlCopy = etree.SubElement(xmlRoot, 'copy')
            _xmlCopy.text = copy

        if password:
            _xmlPass = etree.SubElement(xmlRoot, 'password')
            _xmlPass.text = password

        if hosts is not None:
            _xmlHosts = etree.SubElement(xmlRoot, 'hosts',
                                         allow=str(hosts_allow))
            _xmlHosts.text = hosts

        if ifaces is not None:
            _xmlIFaces = etree.SubElement(xmlRoot, 'ifaces',
                                          allow=str(ifaces_allow))
            _xmlIFaces.text = ifaces

        if len(role_ids) > 0:
            for role in role_ids:
                _xmlRole = etree.SubElement(xmlRoot, 'role',
                                            allow=str(role))

        return etree.tostring(xmlRoot).decode('utf-8')

    def modifyAgentCommand(self, agent_id, name='', comment=''):

        if not agent_id:
            raise ValueError('modify_agent requires an agent_id element')

        xmlRoot = etree.Element('modify_agent', agent_id=str(agent_id))
        if name:
            _xmlName = etree.SubElement(xmlRoot, 'name')
            _xmlName.text = name

        if comment:
            _xmlComment = etree.SubElement(xmlRoot, 'comment')
            _xmlComment.text = comment

        return etree.tostring(xmlRoot).decode('utf-8')

    def modifyAlertCommand(self, alert_id, kwargs):

        if not alert_id:
            raise ValueError('modify_alert requires an agent_id element')

        xmlRoot = etree.Element('modify_alert', alert_id=str(alert_id))

        name = kwargs.get('name', '')
        if name:
            _xmlName = etree.SubElement(xmlRoot, 'name')
            _xmlName.text = name

        comment = kwargs.get('comment', '')
        if comment:
            _xmlComment = etree.SubElement(xmlRoot, 'comment')
            _xmlComment.text = comment

        filter_id = kwargs.get('filter_id', '')
        if filter_id:
            _xmlFilter = etree.SubElement(xmlRoot, 'filter', id=filter_id)

        event = kwargs.get('event', '')
        if len(event) > 1:
            _xmlEvent = etree.SubElement(xmlRoot, 'event')
            _xmlEvent.text = event[0]
            for value, key in event[1].items():
                _xmlData = etree.SubElement(_xmlEvent, 'data')
                _xmlData.text = value
                _xmlDName = etree.SubElement(_xmlData, 'name')
                _xmlDName.text = key

        condition = kwargs.get('condition', '')
        if len(condition) > 1:
            _xmlCond = etree.SubElement(xmlRoot, 'condition')
            _xmlCond.text = condition[0]
            for value, key in condition[1].items():
                _xmlData = etree.SubElement(_xmlCond, 'data')
                _xmlData.text = value
                _xmlDName = etree.SubElement(_xmlData, 'name')
                _xmlDName.text = key

        method = kwargs.get('method', '')
        if len(method) > 1:
            _xmlMethod = etree.SubElement(xmlRoot, 'method')
            _xmlMethod.text = method[0]
            for value, key in method[1].items():
                _xmlData = etree.SubElement(_xmlMethod, 'data')
                _xmlData.text = value
                _xmlDName = etree.SubElement(_xmlData, 'name')
                _xmlDName.text = key

        return etree.tostring(xmlRoot).decode('utf-8')

    def modifyAuthCommand(self, group_name,  auth_conf_settings):

        if not group_name:
            raise ValueError('modify_auth requires a group element '
                             'with a name attribute')
        if not auth_conf_settings:
            raise ValueError('modify_auth requires '
                             'an auth_conf_settings element')

        xmlRoot = etree.Element('modify_auth')
        _xmlGroup = etree.SubElement(xmlRoot, 'group', name=str(group_name))

        for key, value in auth_conf_settings.items():
            _xmlAuthConf = etree.SubElement(_xmlGroup, 'auth_conf_setting')
            _xmlKey = etree.SubElement(_xmlAuthConf, 'key')
            _xmlKey.text = key
            _xmlValue = etree.SubElement(_xmlAuthConf, 'value')
            _xmlValue.text = value

        return etree.tostring(xmlRoot).decode('utf-8')

    def modifyConfigCommand(self, selection, kwargs):

        if selection not in ('nvt_pref', 'sca_pref',
                             'family_selection', 'nvt_selection'):
            raise ValueError('selection must be one of nvt_pref, sca_pref, '
                             'family_selection or nvt_selection')
        config_id = kwargs.get('config_id')

        xmlRoot = etree.Element('modify_config', config_id=str(config_id))

        if selection in 'nvt_pref':
            nvt_oid = kwargs.get('nvt_oid')
            name = kwargs.get('name')
            value = kwargs.get('value')
            _xmlPref = etree.SubElement(xmlRoot, 'preference')
            _xmlNvt = etree.SubElement(_xmlPref, 'nvt', oid=nvt_oid)
            _xmlName = etree.SubElement(_xmlPref, 'name')
            _xmlName.text = name
            _xmlValue = etree.SubElement(_xmlPref, 'value')
            _xmlValue.text = value

        elif selection in 'nvt_selection':
            nvt_oid = kwargs.get('nvt_oid')
            family = kwargs.get('family')
            _xmlNvtSel = etree.SubElement(xmlRoot, 'nvt_selection')
            _xmlFamily = etree.SubElement(_xmlNvtSel, 'family')
            _xmlFamily.text = family

            if isinstance(nvt_oid, list):
                for nvt in nvt_oid:
                    _xmlNvt = etree.SubElement(_xmlNvtSel, 'nvt', oid=nvt)
            else:
                _xmlNvt = etree.SubElement(_xmlNvtSel, 'nvt', oid=nvt)

        elif selection in 'family_selection':
            family = kwargs.get('family')
            _xmlFamSel = etree.SubElement(xmlRoot, 'family_selection')
            _xmlGrow = etree.SubElement(_xmlFamSel, 'growing')
            _xmlGrow.text = '1'
            _xmlFamily = etree.SubElement(_xmlFamSel, 'family')
            _xmlName = etree.SubElement(_xmlFamily, 'name')
            _xmlName.text = family
            _xmlAll = etree.SubElement(_xmlFamily, 'all')
            _xmlAll.text = '1'
            _xmlGrowI = etree.SubElement(_xmlFamily, 'growing')
            _xmlGrowI.text = '1'
        else:
            raise NotImplementedError

        return etree.tostring(xmlRoot).decode('utf-8')

    def modifyCredentialCommand(self, credential_id, kwargs):

        if not credential_id:
            raise ValueError('modify_credential requires '
                             'a credential_id attribute')

        xmlRoot = etree.Element('modify_credential',
                                credential_id=credential_id)

        comment = kwargs.get('comment', '')
        if comment:
            _xmlComment = etree.SubElement(xmlRoot, 'comment')
            _xmlComment.text = comment

        name = kwargs.get('name', '')
        if name:
            _xmlName = etree.SubElement(xmlRoot, 'name')
            _xmlName.text = name

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
                raise ValueError('modify_credential requires a phrase element')
            if not private:
                raise ValueError('modify_credential requires '
                                 'a private element')
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
                raise ValueError('modify_credential requires auth_algorithm '
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
                raise ValueError('modify_credential requires algorithm '
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
                raise ValueError('modify_credential requires type '
                                 'to be either cc, snmp, up or usk')
            _xmlCredtype = etree.SubElement(xmlRoot, 'type')
            _xmlCredtype.text = cred_type

        return etree.tostring(xmlRoot).decode('utf-8')

    def modifyFilterCommand(self, filter_id, kwargs):

        if not filter_id:
            raise ValueError('modify_filter requires a filter_id attribute')

        xmlRoot = etree.Element('modify_filter', filter_id=filter_id)

        comment = kwargs.get('comment', '')
        if comment:
            _xmlComment = etree.SubElement(xmlRoot, 'comment')
            _xmlComment.text = comment

        name = kwargs.get('name', '')
        if name:
            _xmlName = etree.SubElement(xmlRoot, 'name')
            _xmlName.text = name

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
                raise ValueError('modify_filter requires type '
                                 'to be either cc, snmp, up or usk')
            _xmlFiltertype = etree.SubElement(xmlRoot, 'type')
            _xmlFiltertype.text = filter_type

        return etree.tostring(xmlRoot).decode('utf-8')

    def modifyGroupCommand(self, group_id, kwargs):

        if not group_id:
            raise ValueError('modify_group requires a group_id attribute')

        xmlRoot = etree.Element('modify_group', group_id=group_id)

        comment = kwargs.get('comment', '')
        if comment:
            _xmlComment = etree.SubElement(xmlRoot, 'comment')
            _xmlComment.text = comment

        name = kwargs.get('name', '')
        if name:
            _xmlName = etree.SubElement(xmlRoot, 'name')
            _xmlName.text = name

        users = kwargs.get('users', '')
        if users:
            _xmlUser = etree.SubElement(xmlRoot, 'users')
            _xmlUser.text = users

        return etree.tostring(xmlRoot).decode('utf-8')

    def modifyNoteCommand(self, note_id, text, kwargs):

        if not note_id:
            raise ValueError('modify_note requires a note_id attribute')
        if not text:
            raise ValueError('modify_note requires a text element')

        xmlRoot = etree.Element('modify_note', note_id=note_id)
        _xmlText = etree.SubElement(xmlRoot, 'text')
        _xmlText.text = text

        active = kwargs.get('active', '')
        if active:
            _xmlActive = etree.SubElement(xmlRoot, 'active')
            _xmlActive.text = active

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

    def modifyOverrideCommand(self, override_id, text, kwargs):

        xmlRoot = etree.Element('modify_override',
                                override_id=override_id)
        _xmlText = etree.SubElement(xmlRoot, 'text')
        _xmlText.text = text

        active = kwargs.get('active', '')
        if active:
            _xmlActive = etree.SubElement(xmlRoot, 'active')
            _xmlActive.text = active

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

    def modifyPermissionCommand(self, permission_id, kwargs):

        if not permission_id:
            raise ValueError('modify_permission requires '
                             'a permission_id element')

        xmlRoot = etree.Element('modify_permission',
                                permission_id=permission_id)

        comment = kwargs.get('comment', '')
        if comment:
            _xmlComment = etree.SubElement(xmlRoot, 'comment')
            _xmlComment.text = comment

        name = kwargs.get('name', '')
        if name:
            _xmlName = etree.SubElement(xmlRoot, 'name')
            _xmlName.text = name

        resource = kwargs.get('resource', '')
        if resource:
            resource_id = resource['id']
            resource_type = resource['type']
            _xmlResource = etree.SubElement(xmlRoot, 'resource',
                                            id=resource_id)
            _xmlRType = etree.SubElement(_xmlResource, 'type')
            _xmlRType.text = resource_type

        subject = kwargs.get('subject', '')
        if subject:
            subject_id = subject['id']
            subject_type = subject['type']
            _xmlSubject = etree.SubElement(xmlRoot, 'subject', id=subject_id)
            _xmlType = etree.SubElement(_xmlSubject, 'type')
            _xmlType.text = subject_type

        return etree.tostring(xmlRoot).decode('utf-8')

    def modifyPortListCommand(self, port_list_id, kwargs):

        if not port_list_id:
            raise ValueError('modify_port_list requires '
                             'a port_list_id attribute')
        xmlRoot = etree.Element('modify_port_list',
                                port_list_id=port_list_id)

        comment = kwargs.get('comment', '')
        if comment:
            _xmlComment = etree.SubElement(xmlRoot, 'comment')
            _xmlComment.text = comment

        name = kwargs.get('name', '')
        if name:
            _xmlName = etree.SubElement(xmlRoot, 'name')
            _xmlName.text = name

        return etree.tostring(xmlRoot).decode('utf-8')

    def modifyReportFormatCommand(self, report_format_id, kwargs):

        if len(kwargs) < 1:
            raise Exception('modify_report_format: Missing parameter')

        xmlRoot = etree.Element('modify_report_format',
                                report_format_id=report_format_id)

        active = kwargs.get('active', '')
        if active:
            _xmlActive = etree.SubElement(xmlRoot, 'active')
            _xmlActive.text = active

        name = kwargs.get('name', '')
        if name:
            _xmlName = etree.SubElement(xmlRoot, 'name')
            _xmlName.text = name

            summary = kwargs.get('summary', '')
        if summary:
            _xmlSummary = etree.SubElement(xmlRoot, 'summary')
            _xmlSummary.text = summary

        param = kwargs.get('param', '')
        if param:
            p_name = param[0]
            p_value = param[1]
            _xmlParam = etree.SubElement(xmlRoot, 'param')
            _xmlPname = etree.SubElement(_xmlParam, 'name')
            _xmlPname.text = p_name
            _xmlValue = etree.SubElement(_xmlParam, 'value')
            _xmlValue.text = p_value

        return etree.tostring(xmlRoot).decode('utf-8')

    def modifyRoleCommand(self, role_id, kwargs):

        if not role_id:
            raise ValueError('modify_role requires a role_id element')

        xmlRoot = etree.Element('modify_role',
                                role_id=role_id)

        comment = kwargs.get('comment', '')
        if comment:
            _xmlComment = etree.SubElement(xmlRoot, 'comment')
            _xmlComment.text = comment

        name = kwargs.get('name', '')
        if name:
            _xmlName = etree.SubElement(xmlRoot, 'name')
            _xmlName.text = name

        users = kwargs.get('users', '')
        if users:
            _xmlUser = etree.SubElement(xmlRoot, 'users')
            _xmlUser.text = users

        return etree.tostring(xmlRoot).decode('utf-8')

    def modifyScannerCommand(self, scanner_id, host, port, type, kwargs):

        if not scanner_id:
            raise ValueError('modify_scanner requires a scanner_id element')
        if not host:
            raise ValueError('modify_scanner requires a host element')
        if not port:
            raise ValueError('modify_scanner requires a port element')
        if not type:
            raise ValueError('modify_scanner requires a type element')

        xmlRoot = etree.Element('modify_scanner', scanner_id=scanner_id)
        _xmlHost = etree.SubElement(xmlRoot, 'host')
        _xmlHost.text = host
        _xmlPort = etree.SubElement(xmlRoot, 'port')
        _xmlPort.text = port
        _xmlType = etree.SubElement(xmlRoot, 'type')
        _xmlType.text = type

        comment = kwargs.get('comment', '')
        if comment:
            _xmlComment = etree.SubElement(xmlRoot, 'comment')
            _xmlComment.text = comment

        name = kwargs.get('name', '')
        if name:
            _xmlName = etree.SubElement(xmlRoot, 'name')
            _xmlName.text = name

        ca_pub = kwargs.get('ca_pub', '')
        if ca_pub:
            _xmlCAPub = etree.SubElement(xmlRoot, 'ca_pub')
            _xmlCAPub.text = ca_pub

        credential_id = kwargs.get('credential_id', '')
        if credential_id:
            _xmlCred = etree.SubElement(xmlRoot, 'credential',
                                        id=str(credential_id))

        return etree.tostring(xmlRoot).decode('utf-8')

    def modifyScheduleCommand(self, schedule_id, kwargs):

        if not schedule_id:
            raise ValueError('modify_schedule requires a schedule_id element')

        xmlRoot = etree.Element('modify_schedule', schedule_id=schedule_id)
        comment = kwargs.get('comment', '')
        if comment:
            _xmlComment = etree.SubElement(xmlRoot, 'comment')
            _xmlComment.text = comment

        name = kwargs.get('name', '')
        if name:
            _xmlName = etree.SubElement(xmlRoot, 'name')
            _xmlName.text = name

        first_time = kwargs.get('first_time', '')
        if first_time:
            first_time_minute = first_time['minute']
            first_time_hour = first_time['hour']
            first_time_day_of_month = first_time['day_of_month']
            first_time_month = first_time['month']
            first_time_year = first_time['year']

            _xmlFtime = etree.SubElement(xmlRoot, 'first_time')
            _xmlMinute = etree.SubElement(_xmlFtime, 'minute')
            _xmlMinute.text = str(first_time_minute)
            _xmlHour = etree.SubElement(_xmlFtime, 'hour')
            _xmlHour.text = str(first_time_hour)
            _xmlDay = etree.SubElement(_xmlFtime, 'day_of_month')
            _xmlDay.text = str(first_time_day_of_month)
            _xmlMonth = etree.SubElement(_xmlFtime, 'month')
            _xmlMonth.text = str(first_time_month)
            _xmlYear = etree.SubElement(_xmlFtime, 'year')
            _xmlYear.text = str(first_time_year)

        duration = kwargs.get('duration', '')
        if len(duration) > 1:
            _xmlDuration = etree.SubElement(xmlRoot, 'duration')
            _xmlDuration.text = str(duration[0])
            _xmlUnit = etree.SubElement(_xmlDuration, 'unit')
            _xmlUnit.text = str(duration[1])

        period = kwargs.get('period', '')
        if len(period) > 1:
            _xmlPeriod = etree.SubElement(xmlRoot, 'period')
            _xmlPeriod.text = str(period[0])
            _xmlPUnit = etree.SubElement(_xmlPeriod, 'unit')
            _xmlPUnit.text = str(period[1])

        timezone = kwargs.get('timezone', '')
        if timezone:
            _xmlTimezone = etree.SubElement(xmlRoot, 'timezone')
            _xmlTimezone.text = str(timezone)

        return etree.tostring(xmlRoot).decode('utf-8')

    def modifyTagCommand(self, tag_id, kwargs):

        if not tag_id:
            raise ValueError('modify_tag requires a tag_id element')

        xmlRoot = etree.Element('modify_tag', tag_id=str(tag_id))

        comment = kwargs.get('comment', '')
        if comment:
            _xmlComment = etree.SubElement(xmlRoot, 'comment')
            _xmlComment.text = comment

        name = kwargs.get('name', '')
        if name:
            _xmlName = etree.SubElement(xmlRoot, 'name')
            _xmlName.text = name

        value = kwargs.get('value', '')
        if value:
            _xmlValue = etree.SubElement(xmlRoot, 'value')
            _xmlValue.text = value

        active = kwargs.get('active', '')
        if active:
            _xmlActive = etree.SubElement(xmlRoot, 'active')
            _xmlActive.text = value

        resource = kwargs.get('resource', '')
        if resource:
            resource_id = resource['id']
            resource_type = resource['type']
            _xmlResource = etree.SubElement(xmlRoot, 'resource',
                                            resource_id=resource_id)
            _xmlRType = etree.SubElement(_xmlResource, 'type')
            _xmlRType.text = resource_type

        return etree.tostring(xmlRoot).decode('utf-8')

    def modifyTargetCommand(self, target_id, kwargs):

        if not target_id:
            raise ValueError('modify_target requires a target_id element')

        xmlRoot = etree.Element('modify_target', target_id=target_id)

        comment = kwargs.get('comment', '')
        if comment:
            _xmlComment = etree.SubElement(xmlRoot, 'comment')
            _xmlComment.text = comment

        name = kwargs.get('name', '')
        if name:
            _xmlName = etree.SubElement(xmlRoot, 'name')
            _xmlName.text = name

        hosts = kwargs.get('hosts', '')
        if hosts:
            _xmlHosts = etree.SubElement(xmlRoot, 'hosts')
            _xmlHosts.text = hosts

        copy = kwargs.get('copy', '')
        if copy:
            _xmlCopy = etree.SubElement(xmlRoot, 'copy')
            _xmlCopy.text = kwargs.get('copy')

        exclude_hosts = kwargs.get('exclude_hosts', '')
        if exclude_hosts:
            _xmlExHosts = etree.SubElement(xmlRoot, 'exclude_hosts')
            _xmlExHosts.text = kwargs.get('exclude_hosts')

        alive_tests = kwargs.get('alive_tests', '')
        if alive_tests:
            _xmlAlive = etree.SubElement(xmlRoot, 'alive_tests')
            _xmlAlive.text = kwargs.get('alive_tests')

        reverse_lookup_only = kwargs.get('reverse_lookup_only', '')
        if reverse_lookup_only:
            _xmlLookup = etree.SubElement(xmlRoot, 'reverse_lookup_only')
            _xmlLookup.text = reverse_lookup_only

        reverse_lookup_unify = kwargs.get('reverse_lookup_unify', '')
        if reverse_lookup_unify:
            _xmlLookupU = etree.SubElement(xmlRoot, 'reverse_lookup_unify')
            _xmlLookupU.text = reverse_lookup_unify

        port_range = kwargs.get('port_range', '')
        if port_range:
            _xmlPortR = etree.SubElement(xmlRoot, 'port_range')
            _xmlPortR.text = kwargs.get('port_range')

        port_list = kwargs.get('port_list', '')
        if port_list:
            _xmlPortL = etree.SubElement(xmlRoot, 'port_list',
                                         id=str(port_list))

        return etree.tostring(xmlRoot).decode('utf-8')

    def modifyTaskCommand(self, task_id, kwargs):

        if not task_id:
            raise ValueError('modify_task requires a task_id element')

        xmlRoot = etree.Element('modify_task', task_id=task_id)

        name = kwargs.get('name', '')
        if name:
            _xmlName = etree.SubElement(xmlRoot, 'name')
            _xmlName.text = name

        comment = kwargs.get('comment', '')
        if comment:
            _xmlComment = etree.SubElement(xmlRoot, 'comment')
            _xmlComment.text = comment

        target_id = kwargs.get('target_id', '')
        if target_id:
            _xmlTarget = etree.SubElement(xmlRoot, 'target', id=target_id)

        scanner = kwargs.get('scanner', '')
        if scanner:
            _xmlScanner = etree.SubElement(xmlRoot, 'scanner', id=scanner)

        schedule_periods = kwargs.get('schedule_periods', '')
        if schedule_periods:
            _xmlPeriod = etree.SubElement(xmlRoot, 'schedule_periods')
            _xmlPeriod.text = str(schedule_periods)

        schedule = kwargs.get('schedule', '')
        if schedule:
            _xmlSched = etree.SubElement(xmlRoot, 'schedule', id=str(schedule))

        alert = kwargs.get('alert', '')
        if alert:
            _xmlAlert = etree.SubElement(xmlRoot, 'alert', id=str(alert))

        observers = kwargs.get('observers', '')
        if observers:
            _xmlObserver = etree.SubElement(xmlRoot, 'observers')
            _xmlObserver.text = str(observers)

        preferences = kwargs.get('preferences', '')
        if preferences:
            _xmlPrefs = etree.SubElement(xmlRoot, 'preferences')
            for n in range(len(preferences["scanner_name"])):
                preferences_scanner_name = preferences["scanner_name"][n]
                preferences_value = preferences["value"][n]
                _xmlPref = etree.SubElement(_xmlPrefs, 'preference')
                _xmlScan = etree.SubElement(_xmlPref, 'scanner_name')
                _xmlScan.text = preferences_scanner_name
                _xmlVal = etree.SubElement(_xmlPref, 'value')
                _xmlVal.text = preferences_value

        file = kwargs.get('file', '')
        if file:
            file_name = file['name']
            file_action = file['action']
            if file_action != "update" and file_action != "remove":
                raise ValueError('action can only be "update" or "remove"!')
            _xmlFile = etree.SubElement(xmlRoot, 'file', name=file_name,
                                        action=file_action)

        return etree.tostring(xmlRoot).decode('utf-8')

    def modifyUserCommand(self, kwargs):

        user_id = kwargs.get('user_id', '')
        name = kwargs.get('name', '')
        if not user_id and not name:
            raise ValueError('modify_user requires '
                             'either a user_id or a name element')

        xmlRoot = etree.Element('modify_user', user_id=str(user_id))

        new_name = kwargs.get('new_name', '')
        if new_name:
            _xmlName = etree.SubElement(xmlRoot, 'new_name')
            _xmlName.text = new_name

        password = kwargs.get('password', '')
        if password:
            _xmlPass = etree.SubElement(xmlRoot, 'password')
            _xmlPass.text = password

        role_ids = kwargs.get('role_ids', '')
        if len(role_ids) > 0:
            for role in role_ids:
                _xmlRole = etree.SubElement(xmlRoot, 'role',
                                            id=str(role))
        hosts = kwargs.get('hosts', '')
        hosts_allow = kwargs.get('hosts_allow', '')
        if hosts or hosts_allow:
            _xmlHosts = etree.SubElement(xmlRoot, 'hosts',
                                         allow=str(hosts_allow))
            _xmlHosts.text = hosts

        ifaces = kwargs.get('ifaces', '')
        ifaces_allow = kwargs.get('ifaces_allow', '')
        if ifaces or ifaces_allow:
            _xmlIFaces = etree.SubElement(xmlRoot, 'ifaces',
                                          allow=str(ifaces_allow))
            _xmlIFaces.text = ifaces

        sources = kwargs.get('sources', '')
        if sources:
            _xmlSource = etree.SubElement(xmlRoot, 'sources')
            _xmlSource.text = sources

        return etree.tostring(xmlRoot).decode('utf-8')
