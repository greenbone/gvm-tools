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

import defusedxml.lxml as secET

from lxml import etree

FILTER_NAMES = [
    'Agent',
    'Alert',
    'Asset',
    'Config',
    'Credential',
    'Filter',
    'Group',
    'Note',
    'Override',
    'Permission',
    'Port List',
    'Report',
    'Report Format',
    'Result',
    'Role',
    'Schedule',
    'SecInfo',
    'Tag',
    'Target',
    'Task',
    'User',
]

class XmlCommandElement:

    def __init__(self, element):
        self._element = element

    def add_element(self, name, text=None, attrs=None):
        node = etree.SubElement(self._element, name, attrib=attrs)
        node.text = text
        return XmlCommandElement(node)

    def set_attribute(self, name, value):
        self._element.set(name, value)

    def set_attributes(self, attrs):
        """Set several attributes at once.

        Arguments:
            attrs (dict): Attributes to be set on the element
        """
        for key, value in attrs.items():
            self._element.set(key, value)

    def append_xml_str(self, xml_text):
        """Append a xml element in string format."""
        node = secET.fromstring(xml_text)
        self._element.append(node)

    def to_string(self):
        return etree.tostring(self._element).decode('utf-8')

    def __str__(self):
        return self.to_string()


class XmlCommand(XmlCommandElement):

    def __init__(self, name):
        super().__init__(etree.Element(name))


class _GmpCommandFactory:

    """Factory to create gmp - Greenbone Manangement Protocol - commands
    """

    def create_agent_command(self, installer, signature, name, comment='',
                             copy='', howto_install='', howto_use=''):

        cmd = XmlCommand('create_agent')
        cmd.add_element('installer', installer)
        cmd.add_element('signature', signature)
        cmd.add_element('name', name)

        if comment:
            cmd.add_element('comment', comment)

        if copy:
            cmd.add_element('copy', copy)

        if howto_install:
            cmd.add_element('howto_install', howto_install)

        if howto_use:
            cmd.add_element('howto_use', howto_use)

        return cmd.to_string()

    def create_alert_command(self, name, condition, event, method, filter_id='',
                             copy='', comment=''):

        cmd = XmlCommand('create_alert')
        cmd.add_element('name', name)

        if len(condition) > 1:
            conditions = cmd.add_element('condition', condition[0])
            for value, key in condition[1].items():
                _data = conditions.add_element('data', value)
                _data.add_element('name', key)

        elif condition[0] == "Always":
            conditions = cmd.add_element('condition', condition[0])

        if len(event) > 1:
            events = cmd.add_element('event', event[0])
            for value, key in event[1].items():
                _data = events.add_element('data', value)
                _data.add_element('name', key)

        if len(method) > 1:
            methods = cmd.add_element('method', method[0])
            for value, key in method[1].items():
                _data = methods.add_element('data', value)
                _data.add_element('name', key)

        if filter_id:
            cmd.add_element('filter', attrs={'id': filter_id})

        if copy:
            cmd.add_element('copy', copy)

        if comment:
            cmd.add_element('comment', comment)

        return cmd.to_string()

    def create_asset_command(self, name, asset_type, comment=''):
        if asset_type not in ('host', 'os'):
            raise ValueError('create_asset requires asset_type to be either '
                             'host or os')
        cmd = XmlCommand('create_asset')
        asset = cmd.add_element('asset')
        asset.add_element('type', asset_type)
        asset.add_element('name', name)

        if comment:
            asset.add_element('comment', comment)

        return cmd.to_string()

    def create_authenticate_command(self, username, password):
        """Generates string for authentification on gvmd

        Creates the gmp authentication xml string.
        Inserts the username and password into it.

        Keyword Arguments:
            username {str} -- Username for GVM User
            password {str} -- Password for GVM User
        """
        cmd = XmlCommand('authenticate')

        credentials = cmd.add_element('credentials')
        credentials.add_element('username', username)
        credentials.add_element('password', password)

        return cmd.to_string()

    def create_config_command(self, copy_id, name):
        """Generates xml string for create config on gvmd."""
        cmd = XmlCommand('create_config')
        cmd.add_element('copy', copy_id)
        cmd.add_element('name', name)

        return cmd.to_string()

    def create_credential_command(self, name, kwargs):
        """Generates xml string for create credential on gvmd."""
        cmd = XmlCommand('create_credential')
        cmd.add_element('name', name)

        comment = kwargs.get('comment', '')
        if comment:
            cmd.add_element('comment', comment)

        copy = kwargs.get('copy', '')
        if copy:
            cmd.add_element('copy', copy)

        allow_insecure = kwargs.get('allow_insecure', '')
        if allow_insecure:
            cmd.add_element('allow_insecure', allow_insecure)

        certificate = kwargs.get('certificate', '')
        if certificate:
            cmd.add_element('certificate', certificate)

        key = kwargs.get('key', '')
        if key:
            phrase = key['phrase']
            private = key['private']
            if not phrase:
                raise ValueError('create_credential requires a phrase element')
            if not private:
                raise ValueError('create_credential requires a '
                                 'private element')

            _xmlkey = cmd.add_element('key')
            _xmlkey.add_element('phrase', phrase)
            _xmlkey.add_element('private', private)

        login = kwargs.get('login', '')
        if login:
            cmd.add_element('login', login)

        password = kwargs.get('password', '')
        if password:
            cmd.add_element('password', password)

        auth_algorithm = kwargs.get('auth_algorithm', '')
        if auth_algorithm:
            if auth_algorithm not in ('md5', 'sha1'):
                raise ValueError('create_credential requires auth_algorithm '
                                 'to be either md5 or sha1')
            cmd.add_element('auth_algorithm', auth_algorithm)

        community = kwargs.get('community', '')
        if community:
            cmd.add_element('community', community)

        privacy = kwargs.get('privacy', '')
        if privacy:
            algorithm = privacy.algorithm
            if algorithm not in ('aes', 'des'):
                raise ValueError('create_credential requires algorithm '
                                 'to be either aes or des')
            p_password = privacy.password
            _xmlprivacy = cmd.add_element('privacy')
            _xmlprivacy.add_element('algorithm', algorithm)
            _xmlprivacy.add_element('password', p_password)

        cred_type = kwargs.get('type', '')
        if cred_type:
            if cred_type not in ('cc', 'snmp', 'up', 'usk'):
                raise ValueError('create_credential requires type '
                                 'to be either cc, snmp, up or usk')
            cmd.add_element('type', cred_type)

        return cmd.to_string()

    def create_filter_command(self, name, make_unique, kwargs):
        """Generates xml string for create filter on gvmd."""

        cmd = XmlCommand('create_filter')
        _xmlname = cmd.add_element('name', name)
        if make_unique:
            _xmlname.add_element('make_unique', '1')
        else:
            _xmlname.add_element('make_unique', '0')

        comment = kwargs.get('comment', '')
        if comment:
            cmd.add_element('comment', comment)

        copy = kwargs.get('copy', '')
        if copy:
            cmd.add_element('copy', copy)

        term = kwargs.get('term', '')
        if term:
            cmd.add_element('term', term)

        filter_type = kwargs.get('type', '')
        if filter_type:
            if filter_type not in FILTER_NAMES:
                raise ValueError('create_filter requires type '
                                 'to be either cc, snmp, up or usk')
            cmd.add_element('type', filter_type)

        return cmd.to_string()

    def create_group_command(self, name, kwargs):
        """Generates xml string for create group on gvmd."""

        cmd = XmlCommand('create_group')
        cmd.add_element('name', name)

        comment = kwargs.get('comment', '')
        if comment:
            cmd.add_element('comment', comment)

        copy = kwargs.get('copy', '')
        if copy:
            cmd.add_element('copy', copy)

        special = kwargs.get('special', '')
        if special:
            _xmlspecial = cmd.add_element('specials')
            _xmlspecial.add_element('full')

        users = kwargs.get('users', '')
        if users:
            cmd.add_element('users', users)

        return cmd.to_string()

    def create_note_command(self, text, nvt_oid, kwargs):
        """Generates xml string for create note on gvmd."""

        cmd = XmlCommand('create_note')
        cmd.add_element('text', text)
        cmd.add_element('nvt', attrs={"oid": nvt_oid})

        active = kwargs.get('active', '')
        if active:
            cmd.add_element('active', active)

        comment = kwargs.get('comment', '')
        if comment:
            cmd.add_element('comment', comment)

        copy = kwargs.get('copy', '')
        if copy:
            cmd.add_element('copy', copy)

        hosts = kwargs.get('hosts', '')
        if hosts:
            cmd.add_element('hosts', hosts)

        port = kwargs.get('port', '')
        if port:
            cmd.add_element('port', port)

        result_id = kwargs.get('result_id', '')
        if result_id:
            cmd.add_element('result', attrs={'id': result_id})

        severity = kwargs.get('severity', '')
        if severity:
            cmd.add_element('severity', severity)

        task_id = kwargs.get('task_id', '')
        if task_id:
            cmd.add_element('task', attrs={'id': task_id})

        threat = kwargs.get('threat', '')
        if threat:
            cmd.add_element('threat', threat)

        return cmd.to_string()

    def create_override_command(self, text, nvt_oid, kwargs):
        """Generates xml string for create override on gvmd."""

        cmd = XmlCommand('create_override')
        cmd.add_element('text', text)
        cmd.add_element('nvt', attrs={'oid': nvt_oid})

        active = kwargs.get('active', '')
        if active:
            cmd.add_element('active', active)

        comment = kwargs.get('comment', '')
        if comment:
            cmd.add_element('comment', comment)

        copy = kwargs.get('copy', '')
        if copy:
            cmd.add_element('copy', copy)

        hosts = kwargs.get('hosts', '')
        if hosts:
            cmd.add_element('hosts', hosts)

        port = kwargs.get('port', '')
        if port:
            cmd.add_element('port', port)

        result_id = kwargs.get('result_id', '')
        if result_id:
            cmd.add_element('result', attrs={'id': result_id})

        severity = kwargs.get('severity', '')
        if severity:
            cmd.add_element('severity', severity)

        new_severity = kwargs.get('new_severity', '')
        if new_severity:
            cmd.add_element('new_severity', new_severity)

        task_id = kwargs.get('task_id', '')
        if task_id:
            cmd.add_element('task', attrs={'id': task_id})

        threat = kwargs.get('threat', '')
        if threat:
            cmd.add_element('threat', threat)

        new_threat = kwargs.get('new_threat', '')
        if new_threat:
            cmd.add_element('new_threat', new_threat)

        return cmd.to_string()

    def create_permission_command(self, name, subject_id, type, kwargs):
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

        cmd = XmlCommand('create_permission')
        cmd.add_element('name', name)
        _xmlsubject = cmd.add_element('subject', attrs={'id': subject_id})
        _xmlsubject.add_element('type', type)

        comment = kwargs.get('comment', '')
        if comment:
            cmd.add_element('comment', comment)

        copy = kwargs.get('copy', '')
        if copy:
            cmd.add_element('copy', copy)

        resource = kwargs.get('resource', '')
        if resource:
            resource_id = resource.id
            resource_type = resource.type
            _xmlresource = cmd.add_element('resource',
                                           attrs={'id': resource_id})
            _xmlresource.add_element('type', resource_type)

        return cmd.to_string()

    def create_port_list_command(self, name, port_range, kwargs):
        """Generates xml string for create port list on gvmd."""
        if not name:
            raise ValueError('create_port_list requires a name element')
        if not port_range:
            raise ValueError('create_port_list requires a port_range element')

        cmd = XmlCommand('create_port_list')
        cmd.add_element('name', name)
        cmd.add_element('port_range', port_range)

        comment = kwargs.get('comment', '')
        if comment:
            cmd.add_element('comment', comment)

        copy = kwargs.get('copy', '')
        if copy:
            cmd.add_element('copy', copy)

        return cmd.to_string()

    def create_port_range_command(self, port_list_id, start, end, type,
                                  comment=''):
        """Generates xml string for create port range on gvmd."""

        if not port_list_id:
            raise ValueError('create_port_range requires '
                             'a port_list_id element')
        if not type:
            raise ValueError('create_port_range requires a type element')

        cmd = XmlCommand('create_port_range')
        cmd.add_element('port_list', attrs={'id': port_list_id})
        cmd.add_element('start', start)
        cmd.add_element('end', end)
        cmd.add_element('type', type)

        if comment:
            cmd.add_element('comment', comment)

        return cmd.to_string()

    def create_report_command(self, report_xml_string, kwargs):
        """Generates xml string for create report on gvmd."""

        if not report_xml_string:
            raise ValueError('create_report requires a report')

        task_id = kwargs.get('task_id', '')
        task_name = kwargs.get('task_name', '')

        cmd = XmlCommand('create_report')
        comment = kwargs.get('comment', '')
        if task_id:
            cmd.add_element('task', attrs={'id': task_id})
        elif task_name:
            _xmltask = cmd.add_element('task')
            _xmltask.add_element('name', task_name)
            if comment:
                _xmltask.add_element('comment', comment)
        else:
            raise ValueError('create_report requires an id or name for a task')

        in_assets = kwargs.get('in_assets', '')
        if in_assets:
            cmd.add_element('in_assets', in_assets)

        cmd.append_xml_str(report_xml_string)

        return cmd.to_string()

    def create_role_command(self, name, kwargs):
        """Generates xml string for create role on gvmd."""

        if not name:
            raise ValueError('create_role requires a name element')

        cmd = XmlCommand('create_role')
        cmd.add_element('name', name)

        comment = kwargs.get('comment', '')
        if comment:
            cmd.add_element('comment', comment)

        copy = kwargs.get('copy', '')
        if copy:
            cmd.add_element('copy', copy)

        users = kwargs.get('users', '')
        if users:
            cmd.add_element('users', users)

        return cmd.to_string()

    def create_scanner_command(self, name, host, port, type, ca_pub,
                               credential_id, kwargs):
        """Generates xml string for create scanner on gvmd."""
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

        cmd = XmlCommand('create_scanner')
        cmd.add_element('name', name)
        cmd.add_element('host', host)
        cmd.add_element('port', port)
        cmd.add_element('type', type)
        cmd.add_element('ca_pub', ca_pub)
        cmd.add_element('credential', attrs={'id': str(credential_id)})

        comment = kwargs.get('comment', '')
        if comment:
            cmd.add_element('comment', comment)

        copy = kwargs.get('copy', '')
        if copy:
            cmd.add_element('copy', copy)

        return cmd.to_string()

    def create_schedule_command(self, name, kwargs):
        """Generates xml string for create schedule on gvmd."""
        if not name:
            raise ValueError('create_schedule requires a name element')

        cmd = XmlCommand('create_schedule')
        cmd.add_element('name', name)

        comment = kwargs.get('comment', '')
        if comment:
            cmd.add_element('comment', comment)

        copy = kwargs.get('copy', '')
        if copy:
            cmd.add_element('copy', copy)

        first_time = kwargs.get('first_time', '')
        if first_time:
            first_time_minute = first_time['minute']
            first_time_hour = first_time['hour']
            first_time_day_of_month = first_time['day_of_month']
            first_time_month = first_time['month']
            first_time_year = first_time['year']

            _xmlftime = cmd.add_element('first_time')
            _xmlftime.add_element('minute', first_time_minute)
            _xmlftime.add_element('hour', str(first_time_hour))
            _xmlftime.add_element('day_of_month', str(first_time_day_of_month))
            _xmlftime.add_element('month', str(first_time_month))
            _xmlftime.add_element('year', str(first_time_year))

        duration = kwargs.get('duration', '')
        if len(duration) > 1:
            _xmlduration = cmd.add_element('duration', str(duration[0]))
            _xmlduration.add_element('unit', str(duration[1]))

        period = kwargs.get('period', '')
        if len(period) > 1:
            _xmlperiod = cmd.add_element('period', str(period[0]))
            _xmlperiod.add_element('unit', str(period[1]))

        timezone = kwargs.get('timezone', '')
        if timezone:
            cmd.add_element('timezone', str(timezone))

        return cmd.to_string()

    def create_tag_command(self, name, resource_id, resource_type, kwargs):
        """Generates xml string for create tag on gvmd."""

        cmd = XmlCommand('create_tag')
        cmd.add_element('name', name)
        _xmlresource = cmd.add_element('resource',
                                       attrs={'id': str(resource_id)})
        _xmlresource.add_element('type', resource_type)

        comment = kwargs.get('comment', '')
        if comment:
            cmd.add_element('comment', comment)

        copy = kwargs.get('copy', '')
        if copy:
            cmd.add_element('copy', copy)

        value = kwargs.get('value', '')
        if value:
            cmd.add_element('value', value)

        active = kwargs.get('active', '')
        if active:
            cmd.add_element('active', active)

        return cmd.to_string()

    def create_target_command(self, name, make_unique, kwargs):
        """Generates xml string for create target on gvmd."""
        if not name:
            raise ValueError('create_target requires a name element')

        cmd = XmlCommand('create_target')
        _xmlname = cmd.add_element('name', name)
        if make_unique:
            _xmlname.add_element('make_unique', '1')
        else:
            _xmlname.add_element('make_unique', '0')

        if 'asset_hosts' in kwargs:
            hosts = kwargs.get('asset_hosts')
            filter = hosts['filter']
            cmd.add_element('asset_hosts', attrs={'filter': str(filter)})
        elif 'hosts' in kwargs:
            hosts = kwargs.get('hosts')
            cmd.add_element('hosts', hosts)
        else:
            raise ValueError('create_target requires either a hosts or '
                             'an asset_hosts element')

        if 'comment' in kwargs:
            cmd.add_element('comment', kwargs.get('comment'))

        if 'copy' in kwargs:
            # NOTE: It seems that hosts/asset_hosts is silently ignored by the
            # server when copy is supplied. But for specification conformance
            # we raise the ValueError above and consider copy optional.
            cmd.add_element('copy', kwargs.get('copy'))

        if 'exclude_hosts' in kwargs:
            cmd.add_element('exclude_hosts', kwargs.get('exclude_hosts'))

        if 'ssh_credential' in kwargs:
            ssh_credential = kwargs.get('ssh_credential')
            if 'id' in ssh_credential:
                _xmlssh = cmd.add_element('ssh_credential', '',
                                          attrs={'id': ssh_credential['id']})
                if 'port' in ssh_credential:
                    _xmlssh.add_element('port', ssh_credential['port'])
            else:
                raise ValueError('ssh_credential requires an id attribute')

        if 'smb_credential' in kwargs:
            smb_credential = kwargs.get('smb_credential')
            if 'id' in smb_credential:
                cmd.add_element('smb_credential',
                                attrs={'id': smb_credential['id']})
            else:
                raise ValueError('smb_credential requires an id attribute')

        if 'esxi_credential' in kwargs:
            esxi_credential = kwargs.get('esxi_credential')
            if 'id' in esxi_credential:
                cmd.add_element('esxi_credential',
                                attrs={'id': esxi_credential['id']})
            else:
                raise ValueError('esxi_credential requires an id attribute')

        if 'snmp_credential' in kwargs:
            snmp_credential = kwargs.get('snmp_credential')
            if 'id' in snmp_credential:
                cmd.add_element('snmp_credential',
                                attrs={'id': snmp_credential['id']})
            else:
                raise ValueError('snmp_credential requires an id attribute')

        if 'alive_tests' in kwargs:
            # NOTE: As the alive_tests are referenced by their name and some
            # names contain ampersand ('&') characters it should be considered
            # replacing any characters special to XML in the variable with
            # their corresponding entities.
            cmd.add_element('alive_tests', kwargs.get('alive_tests'))

        if 'reverse_lookup_only' in kwargs:
            reverse_lookup_only = kwargs.get('reverse_lookup_only')
            if reverse_lookup_only:
                cmd.add_element('reverse_lookup_only', '1')
            else:
                cmd.add_element('reverse_lookup_only', '0')

        if 'reverse_lookup_unify' in kwargs:
            reverse_lookup_unify = kwargs.get('reverse_lookup_unify')
            if reverse_lookup_unify:
                cmd.add_element('reverse_lookup_unify', '1')
            else:
                cmd.add_element('reverse_lookup_unify', '0')

        if 'port_range' in kwargs:
            cmd.add_element('port_range', kwargs.get('port_range'))

        if 'port_list' in kwargs:
            port_list = kwargs.get('port_list')
            if 'id' in port_list:
                cmd.add_element('port_list',
                                attrs={'id': str(port_list['id'])})
            else:
                raise ValueError('port_list requires an id attribute')

        return cmd.to_string()

    def create_task_command(self, name, config_id, target_id, scanner_id,
                            alert_ids=None, comment=''):
        """Generates xml string for create task on gvmd."""

        if alert_ids is None:
            alert_ids = []
        cmd = XmlCommand('create_task')
        cmd.add_element('name', name)
        cmd.add_element('comment', comment)
        cmd.add_element('config', attrs={'id': config_id})
        cmd.add_element('target', attrs={'id': target_id})
        cmd.add_element('scanner', attrs={'id': scanner_id})

        #if given the alert_id is wrapped and integrated suitably as xml
        if len(alert_ids) > 0:
            if isinstance(alert_ids, str):
                #if a single id is given as a string wrap it into a list
                alert_ids = [alert_ids]
            if isinstance(alert_ids, list):
                #parse all given alert id's
                for alert in alert_ids:
                    cmd.add_element('alert', attrs={'id': str(alert)})

        return cmd.to_string()

    def create_user_command(self, name, password, copy='', hosts_allow='0',
                            ifaces_allow='0', role_ids=(), hosts=None,
                            ifaces=None):
        """Generates xml string for create user on gvmd."""
        cmd = XmlCommand('create_user')
        cmd.add_element('name', name)

        if copy:
            cmd.add_element('copy', copy)

        if password:
            cmd.add_element('password', password)

        if hosts is not None:
            cmd.add_element('hosts', hosts, attrs={'allow': str(hosts_allow)})

        if ifaces is not None:
            cmd.add_element('ifaces', ifaces,
                            attrs={'allow': str(ifaces_allow)})

        if len(role_ids) > 0:
            for role in role_ids:
                cmd.add_element('role', attrs={'allow': str(role)})

        return cmd.to_string()

    def modify_agent_command(self, agent_id, name='', comment=''):
        """Generates xml string for modify agent on gvmd."""
        if not agent_id:
            raise ValueError('modify_agent requires an agent_id element')

        cmd = XmlCommand('modify_agent')
        cmd.set_attribute('agent_id', str(agent_id))
        if name:
            cmd.add_element('name', name)
        if comment:
            cmd.add_element('comment', comment)

        return cmd.to_string()

    def modify_alert_command(self, alert_id, kwargs):
        """Generates xml string for modify alert on gvmd."""

        if not alert_id:
            raise ValueError('modify_alert requires an agent_id element')

        cmd = XmlCommand('modify_alert')
        cmd.set_attribute('alert_id', str(alert_id))

        name = kwargs.get('name', '')
        if name:
            cmd.add_element('name', name)

        comment = kwargs.get('comment', '')
        if comment:
            cmd.add_element('comment', comment)

        filter_id = kwargs.get('filter_id', '')
        if filter_id:
            cmd.add_element('filter', attrs={'id': filter_id})

        event = kwargs.get('event', '')
        if len(event) > 1:
            _xmlevent = cmd.add_element('event', event[0])
            for value, key in event[1].items():
                _xmldata = _xmlevent.add_element('data', value)
                _xmldata.add_element('name', key)

        condition = kwargs.get('condition', '')
        if len(condition) > 1:
            _xmlcond = cmd.add_element('condition', condition[0])
            for value, key in condition[1].items():
                _xmldata = _xmlcond.add_element('data', value)
                _xmldata.add_element('name', key)

        method = kwargs.get('method', '')
        if len(method) > 1:
            _xmlmethod = cmd.add_element('method', method[0])
            for value, key in method[1].items():
                _xmldata = _xmlmethod.add_element('data', value)
                _xmldata.add_element('name', key)

        return cmd.to_string()

    def modify_asset_command(self, asset_id, comment):
        """Generates xml string for modify asset on gvmd."""
        cmd = XmlCommand('modify_asset')
        cmd.set_attribute('asset_id', asset_id)
        cmd.add_element('comment', comment)
        return cmd.to_string()

    def modify_auth_command(self, group_name, auth_conf_settings):
        """Generates xml string for modify auth on gvmd."""
        if not group_name:
            raise ValueError('modify_auth requires a group element '
                             'with a name attribute')
        if not auth_conf_settings:
            raise ValueError('modify_auth requires '
                             'an auth_conf_settings element')
        cmd = XmlCommand('modify_auth')
        _xmlgroup = cmd.add_element('group', attrs={'name': str(group_name)})

        for key, value in auth_conf_settings.items():
            _xmlauthconf = _xmlgroup.add_element('auth_conf_setting')
            _xmlauthconf.add_element('key', key)
            _xmlauthconf.add_element('value', value)

        return cmd.to_string()

    def modify_config_command(self, selection, kwargs):
        """Generates xml string for modify config on gvmd."""
        if selection not in ('nvt_pref', 'sca_pref',
                             'family_selection', 'nvt_selection'):
            raise ValueError('selection must be one of nvt_pref, sca_pref, '
                             'family_selection or nvt_selection')
        config_id = kwargs.get('config_id')

        cmd = XmlCommand('modify_config')
        cmd.set_attribute('config_id', str(config_id))

        if selection in 'nvt_pref':
            nvt_oid = kwargs.get('nvt_oid')
            name = kwargs.get('name')
            value = kwargs.get('value')
            _xmlpref = cmd.add_element('preference')
            _xmlpref.add_element('nvt', attrs={'oid': nvt_oid})
            _xmlpref.add_element('name', name)
            _xmlpref.add_element('value', value)

        elif selection in 'nvt_selection':
            nvt_oid = kwargs.get('nvt_oid')
            family = kwargs.get('family')
            _xmlnvtsel = cmd.add_element('nvt_selection')
            _xmlnvtsel.add_element('family', family)

            if isinstance(nvt_oid, list):
                for nvt in nvt_oid:
                    _xmlnvtsel.add_element('nvt', attrs={'oid': nvt})
            else:
                _xmlnvtsel.add_element('nvt', attrs={'oid': nvt_oid})

        elif selection in 'family_selection':
            family = kwargs.get('family')
            _xmlfamsel = cmd.add_element('family_selection')
            _xmlfamsel.add_element('growing', '1')
            _xmlfamily = _xmlfamsel.add_element('family')
            _xmlfamily.add_element('name', family)
            _xmlfamily.add_element('all', '1')
            _xmlfamily.add_element('growing', '1')
        else:
            raise NotImplementedError

        return cmd.to_string()

    def modify_credential_command(self, credential_id, kwargs):
        """Generates xml string for modify credential on gvmd."""
        if not credential_id:
            raise ValueError('modify_credential requires '
                             'a credential_id attribute')

        cmd = XmlCommand('modify_credential')
        cmd.set_attribute('credential_id', credential_id)

        comment = kwargs.get('comment', '')
        if comment:
            cmd.add_element('comment', comment)

        name = kwargs.get('name', '')
        if name:
            cmd.add_element('name', name)

        allow_insecure = kwargs.get('allow_insecure', '')
        if allow_insecure:
            cmd.add_element('allow_insecure', allow_insecure)

        certificate = kwargs.get('certificate', '')
        if certificate:
            cmd.add_element('certificate', certificate)

        key = kwargs.get('key', '')
        if key:
            phrase = key['phrase']
            private = key['private']
            if not phrase:
                raise ValueError('modify_credential requires a phrase element')
            if not private:
                raise ValueError('modify_credential requires '
                                 'a private element')
            _xmlkey = cmd.add_element('key')
            _xmlkey.add_element('phrase', phrase)
            _xmlkey.add_element('private', private)

        login = kwargs.get('login', '')
        if login:
            cmd.add_element('login', login)

        password = kwargs.get('password', '')
        if password:
            cmd.add_element('password', password)

        auth_algorithm = kwargs.get('auth_algorithm', '')
        if auth_algorithm:
            if auth_algorithm not in ('md5', 'sha1'):
                raise ValueError('modify_credential requires auth_algorithm '
                                 'to be either md5 or sha1')
            cmd.add_element('auth_algorithm', auth_algorithm)

        community = kwargs.get('community', '')
        if community:
            cmd.add_element('community', community)

        privacy = kwargs.get('privacy', '')
        if privacy:
            algorithm = privacy.algorithm
            if algorithm not in ('aes', 'des'):
                raise ValueError('modify_credential requires algorithm '
                                 'to be either aes or des')
            p_password = privacy.password
            _xmlprivacy = cmd.add_element('privacy')
            _xmlprivacy.add_element('algorithm', algorithm)
            _xmlprivacy.add_element('password', p_password)

        cred_type = kwargs.get('type', '')
        if cred_type:
            if cred_type not in ('cc', 'snmp', 'up', 'usk'):
                raise ValueError('modify_credential requires type '
                                 'to be either cc, snmp, up or usk')
            cmd.add_element('type', cred_type)

        return cmd.to_string()

    def modify_filter_command(self, filter_id, kwargs):
        """Generates xml string for modify filter on gvmd."""
        if not filter_id:
            raise ValueError('modify_filter requires a filter_id attribute')

        cmd = XmlCommand('modify_filter')
        cmd.set_attribute('filter_id', filter_id)

        comment = kwargs.get('comment', '')
        if comment:
            cmd.add_element('comment', comment)

        name = kwargs.get('name', '')
        if name:
            cmd.add_element('name', name)

        copy = kwargs.get('copy', '')
        if copy:
            cmd.add_element('copy', copy)

        term = kwargs.get('term', '')
        if term:
            cmd.add_element('term', term)

        filter_type = kwargs.get('type', '')
        if filter_type:
            if filter_type not in ('cc', 'snmp', 'up', 'usk'):
                raise ValueError('modify_filter requires type '
                                 'to be either cc, snmp, up or usk')
            cmd.add_element('type', filter_type)

        return cmd.to_string()

    def modify_group_command(self, group_id, kwargs):
        """Generates xml string for modify group on gvmd."""
        if not group_id:
            raise ValueError('modify_group requires a group_id attribute')

        cmd = XmlCommand('modify_group')
        cmd.set_attribute('group_id', group_id)

        comment = kwargs.get('comment', '')
        if comment:
            cmd.add_element('comment', comment)

        name = kwargs.get('name', '')
        if name:
            cmd.add_element('name', name)

        users = kwargs.get('users', '')
        if users:
            cmd.add_element('users', users)

        return cmd.to_string()

    def modify_note_command(self, note_id, text, kwargs):
        """Generates xml string for modify note on gvmd."""
        if not note_id:
            raise ValueError('modify_note requires a note_id attribute')
        if not text:
            raise ValueError('modify_note requires a text element')

        cmd = XmlCommand('modify_note')
        cmd.set_attribute('note_id', note_id)
        cmd.add_element('text', text)

        active = kwargs.get('active', '')
        if active:
            cmd.add_element('active', active)

        hosts = kwargs.get('hosts', '')
        if hosts:
            cmd.add_element('hosts', hosts)

        port = kwargs.get('port', '')
        if port:
            cmd.add_element('port', port)

        result_id = kwargs.get('result_id', '')
        if result_id:
            cmd.add_element('result', attrs={'id': result_id})

        severity = kwargs.get('severity', '')
        if severity:
            cmd.add_element('severity', severity)

        task_id = kwargs.get('task_id', '')
        if task_id:
            cmd.add_element('task', attrs={'id': task_id})

        threat = kwargs.get('threat', '')
        if threat:
            cmd.add_element('threat', threat)

        return cmd.to_string()

    def modify_override_command(self, override_id, text, kwargs):
        """Generates xml string for modify override on gvmd."""
        cmd = XmlCommand('modify_override')
        cmd.set_attribute('override_id', override_id)
        cmd.add_element('text', text)

        active = kwargs.get('active', '')
        if active:
            cmd.add_element('active', active)

        hosts = kwargs.get('hosts', '')
        if hosts:
            cmd.add_element('hosts', hosts)

        port = kwargs.get('port', '')
        if port:
            cmd.add_element('port', port)

        result_id = kwargs.get('result_id', '')
        if result_id:
            cmd.add_element('result', attrs={'id': result_id})

        severity = kwargs.get('severity', '')
        if severity:
            cmd.add_element('severity', severity)

        new_severity = kwargs.get('new_severity', '')
        if new_severity:
            cmd.add_element('new_severity', new_severity)

        task_id = kwargs.get('task_id', '')
        if task_id:
            cmd.add_element('task', attrs={'id': task_id})

        threat = kwargs.get('threat', '')
        if threat:
            cmd.add_element('threat', threat)

        new_threat = kwargs.get('new_threat', '')
        if new_threat:
            cmd.add_element('new_threat', new_threat)

        return cmd.to_string()

    def modify_permission_command(self, permission_id, kwargs):
        """Generates xml string for modify permission on gvmd."""
        if not permission_id:
            raise ValueError('modify_permission requires '
                             'a permission_id element')

        cmd = XmlCommand('modify_permission')
        cmd.set_attribute('permission_id', permission_id)

        comment = kwargs.get('comment', '')
        if comment:
            cmd.add_element('comment', comment)

        name = kwargs.get('name', '')
        if name:
            cmd.add_element('name', name)

        resource = kwargs.get('resource', '')
        if resource:
            resource_id = resource['id']
            resource_type = resource['type']
            _xmlresource = cmd.add_element('resource',
                                           attrs={'id': resource_id})
            _xmlresource.add_element('type', resource_type)

        subject = kwargs.get('subject', '')
        if subject:
            subject_id = subject['id']
            subject_type = subject['type']
            _xmlsubject = cmd.add_element('subject', attrs={'id': subject_id})
            _xmlsubject.add_element('type', subject_type)

        return cmd.to_string()

    def modify_port_list_command(self, port_list_id, kwargs):
        """Generates xml string for modify port list on gvmd."""
        if not port_list_id:
            raise ValueError('modify_port_list requires '
                             'a port_list_id attribute')
        cmd = XmlCommand('modify_port_list')
        cmd.set_attribute('port_list_id', port_list_id)

        comment = kwargs.get('comment', '')
        if comment:
            cmd.add_element('comment', comment)

        name = kwargs.get('name', '')
        if name:
            cmd.add_element('name', name)

        return cmd.to_string()

    def modify_report_command(self, report_id, comment):
        """Generates xml string for modify report on gvmd."""
        cmd = XmlCommand('modify_report')
        cmd.set_attribute('report_id', report_id)
        cmd.add_element('comment', comment)
        return cmd.to_string()

    def modify_report_format_command(self, report_format_id, kwargs):
        """Generates xml string for modify report format on gvmd."""
        if len(kwargs) < 1:
            raise Exception('modify_report_format: Missing parameter')

        cmd = XmlCommand('modify_report_format')
        cmd.set_attribute('report_format_id', report_format_id)

        active = kwargs.get('active', '')
        if active:
            cmd.add_element('active', active)

        name = kwargs.get('name', '')
        if name:
            cmd.add_element('name', name)

        summary = kwargs.get('summary', '')
        if summary:
            cmd.add_element('summary', summary)

        param = kwargs.get('param', '')
        if param:
            p_name = param[0]
            p_value = param[1]
            _xmlparam = cmd.add_element('param')
            _xmlparam.add_element('name', p_name)
            _xmlparam.add_element('value', p_value)

        return cmd.to_string()

    def modify_role_command(self, role_id, kwargs):
        """Generates xml string for modify role on gvmd."""
        if not role_id:
            raise ValueError('modify_role requires a role_id element')

        cmd = XmlCommand('modify_role')
        cmd.set_attribute('role_id', role_id)

        comment = kwargs.get('comment', '')
        if comment:
            cmd.add_element('comment', comment)

        name = kwargs.get('name', '')
        if name:
            cmd.add_element('name', name)

        users = kwargs.get('users', '')
        if users:
            cmd.add_element('users', users)

        return cmd.to_string()

    def modify_scanner_command(self, scanner_id, host, port, scanner_type,
                               kwargs):
        """Generates xml string for modify scanner on gvmd."""
        if not scanner_id:
            raise ValueError('modify_scanner requires a scanner_id element')
        if not host:
            raise ValueError('modify_scanner requires a host element')
        if not port:
            raise ValueError('modify_scanner requires a port element')
        if not scanner_type:
            raise ValueError('modify_scanner requires a type element')

        cmd = XmlCommand('modify_scanner')
        cmd.set_attribute('scanner_id', scanner_id)
        cmd.add_element('host', host)
        cmd.add_element('port', port)
        cmd.add_element('type', scanner_type)

        comment = kwargs.get('comment', '')
        if comment:
            cmd.add_element('comment', comment)

        name = kwargs.get('name', '')
        if name:
            cmd.add_element('name', name)

        ca_pub = kwargs.get('ca_pub', '')
        if ca_pub:
            cmd.add_element('ca_pub', ca_pub)

        credential_id = kwargs.get('credential_id', '')
        if credential_id:
            cmd.add_element('credential', attrs={'id': str(credential_id)})

        return cmd.to_string()

    def modify_schedule_command(self, schedule_id, kwargs):
        """Generates xml string for modify schedule on gvmd."""
        if not schedule_id:
            raise ValueError('modify_schedule requires a schedule_id element')

        cmd = XmlCommand('modify_schedule')
        cmd.set_attribute('schedule_id', schedule_id)
        comment = kwargs.get('comment', '')
        if comment:
            cmd.add_element('comment', comment)

        name = kwargs.get('name', '')
        if name:
            cmd.add_element('name', name)

        first_time = kwargs.get('first_time', '')
        if first_time:
            first_time_minute = first_time['minute']
            first_time_hour = first_time['hour']
            first_time_day_of_month = first_time['day_of_month']
            first_time_month = first_time['month']
            first_time_year = first_time['year']

            _xmlftime = cmd.add_element('first_time')
            _xmlftime.add_element('minute', str(first_time_minute))
            _xmlftime.add_element('hour', str(first_time_hour))
            _xmlftime.add_element('day_of_month', str(first_time_day_of_month))
            _xmlftime.add_element('month', str(first_time_month))
            _xmlftime.add_element('year', str(first_time_year))

        duration = kwargs.get('duration', '')
        if len(duration) > 1:
            _xmlduration = cmd.add_element('duration', str(duration[0]))
            _xmlduration.add_element('unit', str(duration[1]))

        period = kwargs.get('period', '')
        if len(period) > 1:
            _xmlperiod = cmd.add_element('period', str(period[0]))
            _xmlperiod.add_element('unit', str(period[1]))

        timezone = kwargs.get('timezone', '')
        if timezone:
            cmd.add_element('timezone', str(timezone))

        return cmd.to_string()

    def modify_setting_command(self, setting_id, name, value):
        """Generates xml string for modify setting format on gvmd."""
        cmd = XmlCommand('modify_setting')
        cmd.set_attribute('setting_id', setting_id)
        cmd.add_element('name', name)
        cmd.add_element('value', value)

        return cmd.to_string()

    def modify_tag_command(self, tag_id, kwargs):
        """Generates xml string for modify tag on gvmd."""
        if not tag_id:
            raise ValueError('modify_tag requires a tag_id element')

        cmd = XmlCommand('modify_tag')
        cmd.set_attribute('tag_id', str(tag_id))

        comment = kwargs.get('comment', '')
        if comment:
            cmd.add_element('comment', comment)

        name = kwargs.get('name', '')
        if name:
            cmd.add_element('name', name)

        value = kwargs.get('value', '')
        if value:
            cmd.add_element('value', value)

        active = kwargs.get('active', '')
        if active:
            cmd.add_element('active', value)

        resource = kwargs.get('resource', '')
        if resource:
            resource_id = resource['id']
            resource_type = resource['type']
            _xmlresource = cmd.add_element('resource',
                                           attrs={'resource_id': resource_id})
            _xmlresource.add_element('type', resource_type)

        return cmd.to_string()

    def modify_target_command(self, target_id, kwargs):
        """Generates xml string for modify target on gvmd."""
        if not target_id:
            raise ValueError('modify_target requires a target_id element')

        cmd = XmlCommand('modify_target')
        cmd.set_attribute('target_id', target_id)

        comment = kwargs.get('comment', '')
        if comment:
            cmd.add_element('comment', comment)

        name = kwargs.get('name', '')
        if name:
            cmd.add_element('name', name)

        hosts = kwargs.get('hosts', '')
        if hosts:
            cmd.add_element('hosts', hosts)

        copy = kwargs.get('copy', '')
        if copy:
            cmd.add_element('copy', copy)

        exclude_hosts = kwargs.get('exclude_hosts', '')
        if exclude_hosts:
            cmd.add_element('exclude_hosts', exclude_hosts)

        alive_tests = kwargs.get('alive_tests', '')
        if alive_tests:
            cmd.add_element('alive_tests', alive_tests)

        reverse_lookup_only = kwargs.get('reverse_lookup_only', '')
        if reverse_lookup_only:
            cmd.add_element('reverse_lookup_only', reverse_lookup_only)

        reverse_lookup_unify = kwargs.get('reverse_lookup_unify', '')
        if reverse_lookup_unify:
            cmd.add_element('reverse_lookup_unify', reverse_lookup_unify)

        port_range = kwargs.get('port_range', '')
        if port_range:
            cmd.add_element('port_range', port_range)

        port_list = kwargs.get('port_list', '')
        if port_list:
            cmd.add_element('port_list', attrs={'id': str(port_list)})

        return cmd.to_string()

    def modify_task_command(self, task_id, kwargs):
        """Generates xml string for modify task on gvmd."""
        if not task_id:
            raise ValueError('modify_task requires a task_id element')

        cmd = XmlCommand('modify_task')
        cmd.set_attribute('task_id', task_id)

        name = kwargs.get('name', '')
        if name:
            cmd.add_element('name', name)

        comment = kwargs.get('comment', '')
        if comment:
            cmd.add_element('comment', comment)

        target_id = kwargs.get('target_id', '')
        if target_id:
            cmd.add_element('target', attrs={'id': target_id})

        scanner = kwargs.get('scanner', '')
        if scanner:
            cmd.add_element('scanner', attrs={'id': scanner})

        schedule_periods = kwargs.get('schedule_periods', '')
        if schedule_periods:
            cmd.add_element('schedule_periods', str(schedule_periods))

        schedule = kwargs.get('schedule', '')
        if schedule:
            cmd.add_element('schedule', attrs={'id': str(schedule)})

        alert = kwargs.get('alert', '')
        if alert:
            cmd.add_element('alert', attrs={'id': str(alert)})

        observers = kwargs.get('observers', '')
        if observers:
            cmd.add_element('observers', str(observers))

        preferences = kwargs.get('preferences', '')
        if preferences:
            _xmlprefs = cmd.add_element('preferences')
            for n in range(len(preferences["scanner_name"])):
                preferences_scanner_name = preferences["scanner_name"][n]
                preferences_value = preferences["value"][n]
                _xmlpref = _xmlprefs.add_element('preference')
                _xmlpref.add_element('scanner_name', preferences_scanner_name)
                _xmlpref.add_element('value', preferences_value)

        file = kwargs.get('file', '')
        if file:
            file_name = file['name']
            file_action = file['action']
            if file_action != "update" and file_action != "remove":
                raise ValueError('action can only be "update" or "remove"!')
            cmd.add_element('file', attrs={'name': file_name,
                                           'action': file_action})

        return cmd.to_string()

    def modify_user_command(self, kwargs):
        """Generates xml string for modify user on gvmd."""
        user_id = kwargs.get('user_id', '')
        name = kwargs.get('name', '')

        if not user_id and not name:
            raise ValueError('modify_user requires '
                             'either a user_id or a name element')

        cmd = XmlCommand('modify_user')
        cmd.set_attribute('user_id', str(user_id))

        new_name = kwargs.get('new_name', '')
        if new_name:
            cmd.add_element('new_name', new_name)

        password = kwargs.get('password', '')
        if password:
            cmd.add_element('password', password)

        role_ids = kwargs.get('role_ids', '')
        if len(role_ids) > 0:
            for role in role_ids:
                cmd.add_element('role', attrs={'id': str(role)})

        hosts = kwargs.get('hosts', '')
        hosts_allow = kwargs.get('hosts_allow', '')
        if hosts or hosts_allow:
            cmd.add_element('hosts', hosts, attrs={'allow': str(hosts_allow)})

        ifaces = kwargs.get('ifaces', '')
        ifaces_allow = kwargs.get('ifaces_allow', '')
        if ifaces or ifaces_allow:
            cmd.add_element('ifaces', ifaces,
                            attrs={'allow': str(ifaces_allow)})

        sources = kwargs.get('sources', '')
        if sources:
            cmd.add_element('sources', sources)

        return cmd.to_string()

    def delete_agent_command(self, kwargs):
        """Generates xml string for delete agent on gvmd"""
        cmd = XmlCommand('delete_agent')
        for key, value in kwargs.items():
            cmd.set_attribute(key, value)

        return cmd.to_string()

    def delete_alert_command(self, kwargs):
        """Generates xml string for delete alert on gvmd"""
        cmd = XmlCommand('delete_alert')
        for key, value in kwargs.items():
            cmd.set_attribute(key, value)

        return cmd.to_string()

    def delete_asset_command(self, asset_id, ultimate=0):
        """Generates xml string for delete asset on gvmd"""
        cmd = XmlCommand('delete_asset')
        cmd.set_attribute('asset_id', asset_id)
        cmd.set_attribute('ultimate', ultimate)

        return cmd.to_string()

    def delete_config_command(self, config_id, ultimate=0):
        """Generates xml string for delete config on gvmd"""
        cmd = XmlCommand('delete_config')
        cmd.set_attribute('config_id', config_id)
        cmd.set_attribute('ultimate', ultimate)

        return cmd.to_string()

    def delete_credential_command(self, credential_id, ultimate=0):
        """Generates xml string for delete credential on gvmd"""
        cmd = XmlCommand('delete_credential')
        cmd.set_attribute('credential_id', credential_id)
        cmd.set_attribute('ultimate', ultimate)
        return cmd.to_string()

    def delete_filter_command(self, filter_id, ultimate=0):
        """Generates xml string for delete filter on gvmd"""
        cmd = XmlCommand('delete_filter')
        cmd.set_attribute('filter_id', filter_id)
        cmd.set_attribute('ultimate', ultimate)

        return cmd.to_string()

    def delete_group_command(self, group_id, ultimate=0):
        """Generates xml string for delete group on gvmd"""
        cmd = XmlCommand('delete_group')
        cmd.set_attribute('group_id', group_id)
        cmd.set_attribute('ultimate', ultimate)

        return cmd.to_string()

    def delete_note_command(self, note_id, ultimate=0):
        """Generates xml string for delete note on gvmd"""
        cmd = XmlCommand('delete_note')
        cmd.set_attribute('note_id', note_id)
        cmd.set_attribute('ultimate', ultimate)

        return cmd.to_string()

    def delete_override_command(self, override_id, ultimate=0):
        """Generates xml string for delete override on gvmd"""
        cmd = XmlCommand('delete_override')
        cmd.set_attribute('override_id', override_id)
        cmd.set_attribute('ultimate', ultimate)

        return cmd.to_string()

    def delete_permission_command(self, permission_id, ultimate=0):
        """Generates xml string for delete permission on gvmd"""
        cmd = XmlCommand('delete_permission')
        cmd.set_attribute('permission_id', permission_id)
        cmd.set_attribute('ultimate', ultimate)

        return cmd.to_string()

    def delete_port_list_command(self, port_list_id, ultimate=0):
        """Generates xml string for delete port on gvmd"""
        cmd = XmlCommand('delete_port_list')
        cmd.set_attribute('port_list_id', port_list_id)
        cmd.set_attribute('ultimate', ultimate)

        return cmd.to_string()

    def delete_port_range_command(self, port_range_id):
        """Generates xml string for delete port on gvmd"""
        cmd = XmlCommand('delete_port_range')
        cmd.set_attribute('port_range_id', port_range_id)

        return cmd.to_string()

    def delete_report_command(self, report_id):
        """Generates xml string for delete report on gvmd"""
        cmd = XmlCommand('delete_report')
        cmd.set_attribute('report_id', report_id)

        return cmd.to_string()

    def delete_report_format_command(self, report_format_id, ultimate=0):
        """Generates xml string for delete report on gvmd"""
        cmd = XmlCommand('delete_report_format')
        cmd.set_attribute('report_format_id', report_format_id)
        cmd.set_attribute('ultimate', ultimate)

        return cmd.to_string()

    def delete_role_command(self, role_id, ultimate=0):
        """Generates xml string for delete role on gvmd"""
        cmd = XmlCommand('delete_role')
        cmd.set_attribute('role_id', role_id)
        cmd.set_attribute('ultimate', ultimate)

        return cmd.to_string()

    def delete_scanner_command(self, scanner_id, ultimate=0):
        """Generates xml string for delete scanner on gvmd"""
        cmd = XmlCommand('delete_scanner')
        cmd.set_attribute('scanner_id', scanner_id)
        cmd.set_attribute('ultimate', ultimate)

        return cmd.to_string()

    def delete_schedule_command(self, schedule_id, ultimate=0):
        """Generates xml string for delete schedule on gvmd"""
        # if self.ask_yes_or_no('Are you sure to delete this schedule? '):
        cmd = XmlCommand('delete_schedule')
        cmd.set_attribute('schedule_id', schedule_id)
        cmd.set_attribute('ultimate', ultimate)

        return cmd.to_string()

    def delete_tag_command(self, tag_id, ultimate=0):
        """Generates xml string for delete tag on gvmd"""
        cmd = XmlCommand('delete_tag')
        cmd.set_attribute('tag_id', tag_id)
        cmd.set_attribute('ultimate', ultimate)

        return cmd.to_string()

    def delete_target_command(self, target_id, ultimate=0):
        """Generates xml string for delete target on gvmd"""
        cmd = XmlCommand('delete_target')
        cmd.set_attribute('target_id', target_id)
        cmd.set_attribute('ultimate', ultimate)

        return cmd.to_string()

    def delete_task_command(self, task_id, ultimate=0):
        """Generates xml string for delete task on gvmd"""
        cmd = XmlCommand('delete_task')
        cmd.set_attribute('task_id', task_id)
        cmd.set_attribute('ultimate', ultimate)

        return cmd.to_string()

    def delete_user_command(self, kwargs):
        """Generates xml string for delete user on gvmd"""
        cmd = XmlCommand('delete_user')

        user_id = kwargs.get('user_id', '')
        if user_id:
            cmd.set_attribute('user_id', user_id)

        name = kwargs.get('name', '')
        if name:
            cmd.set_attribute('name', name)

        inheritor_id = kwargs.get('inheritor_id', '')
        if inheritor_id:
            cmd.set_attribute('inheritor_id', inheritor_id)

        inheritor_name = kwargs.get('inheritor_name', '')
        if inheritor_name:
            cmd.set_attribute('inheritor_name', inheritor_name)

        return cmd.to_string()

    def describe_auth_command(self):
        """Generates xml string for describe auth on gvmd"""
        cmd = XmlCommand('describe_auth')
        return cmd.to_string()

    def empty_trashcan_command(self):
        """Generates xml string for empty trashcan on gvmd"""
        cmd = XmlCommand('empty_trashcan')
        return cmd.to_string()

    def get_agents_command(self, kwargs):
        """Generates xml string for get agents on gvmd."""
        cmd = XmlCommand('get_agents')
        cmd.set_attributes(kwargs)
        return cmd.to_string()

    def get_aggregates_command(self, kwargs):
        """Generates xml string for get aggregates on gvmd."""
        cmd = XmlCommand('get_aggregates')
        cmd.set_attributes(kwargs)
        return cmd.to_string()

    def get_alerts_command(self, kwargs):
        """Generates xml string for get alerts on gvmd."""
        cmd = XmlCommand('get_alerts')
        cmd.set_attributes(kwargs)
        return cmd.to_string()

    def get_assets_command(self, kwargs):
        """Generates xml string for get assets on gvmd."""
        cmd = XmlCommand('get_assets')
        cmd.set_attributes(kwargs)
        return cmd.to_string()

    def get_credentials_command(self, kwargs):
        """Generates xml string for get credentials on gvmd."""
        cmd = XmlCommand('get_credentials')
        cmd.set_attributes(kwargs)
        return cmd.to_string()

    def get_configs_command(self, kwargs):
        """Generates xml string for get configs on gvmd."""
        cmd = XmlCommand('get_configs')
        cmd.set_attributes(kwargs)
        return cmd.to_string()

    def get_feeds_command(self, kwargs):
        """Generates xml string for get feeds on gvmd."""
        cmd = XmlCommand('get_feeds')
        cmd.set_attributes(kwargs)
        return cmd.to_string()

    def get_filters_command(self, kwargs):
        """Generates xml string for get filters on gvmd."""
        cmd = XmlCommand('get_filters')
        cmd.set_attributes(kwargs)
        return cmd.to_string()

    def get_groups_command(self, kwargs):
        """Generates xml string for get groups on gvmd."""
        cmd = XmlCommand('get_groups')
        cmd.set_attributes(kwargs)
        return cmd.to_string()

    def get_info_command(self, kwargs):
        """Generates xml string for get info on gvmd."""
        cmd = XmlCommand('get_info')
        cmd.set_attributes(kwargs)
        return cmd.to_string()

    def get_notes_command(self, kwargs):
        """Generates xml string for get notes on gvmd."""
        cmd = XmlCommand('get_notes')
        cmd.set_attributes(kwargs)
        return cmd.to_string()

    def get_nvts_command(self, kwargs):
        """Generates xml string for get nvts on gvmd."""
        cmd = XmlCommand('get_nvts')
        cmd.set_attributes(kwargs)
        return cmd.to_string()

    def get_nvt_families_command(self, kwargs):
        """Generates xml string for get nvt on gvmd."""
        cmd = XmlCommand('get_nvt_families')
        cmd.set_attributes(kwargs)
        return cmd.to_string()

    def get_overrides_command(self, kwargs):
        """Generates xml string for get overrides on gvmd."""
        cmd = XmlCommand('get_overrides')
        cmd.set_attributes(kwargs)
        return cmd.to_string()

    def get_permissions_command(self, kwargs):
        """Generates xml string for get permissions on gvmd."""
        cmd = XmlCommand('get_permissions')
        cmd.set_attributes(kwargs)
        return cmd.to_string()

    def get_port_lists_command(self, kwargs):
        """Generates xml string for get port on gvmd."""
        cmd = XmlCommand('get_port_lists')
        cmd.set_attributes(kwargs)
        return cmd.to_string()

    def get_preferences_command(self, kwargs):
        """Generates xml string for get preferences on gvmd."""
        cmd = XmlCommand('get_preferences')
        cmd.set_attributes(kwargs)
        return cmd.to_string()

    def get_reports_command(self, kwargs):
        """Generates xml string for get reports on gvmd."""
        cmd = XmlCommand('get_reports')
        cmd.set_attributes(kwargs)
        return cmd.to_string()

    def get_report_formats_command(self, kwargs):
        """Generates xml string for get report on gvmd."""
        cmd = XmlCommand('get_report_formats')
        cmd.set_attributes(kwargs)
        return cmd.to_string()

    def get_results_command(self, kwargs):
        """Generates xml string for get results on gvmd."""
        cmd = XmlCommand('get_results')
        cmd.set_attributes(kwargs)
        return cmd.to_string()

    def get_roles_command(self, kwargs):
        """Generates xml string for get roles on gvmd."""
        cmd = XmlCommand('get_roles')
        cmd.set_attributes(kwargs)
        return cmd.to_string()

    def get_scanners_command(self, kwargs):
        """Generates xml string for get scanners on gvmd."""
        cmd = XmlCommand('get_scanners')
        cmd.set_attributes(kwargs)
        return cmd.to_string()

    def get_schedules_command(self, kwargs):
        """Generates xml string for get schedules on gvmd."""
        cmd = XmlCommand('get_schedules')
        cmd.set_attributes(kwargs)
        return cmd.to_string()

    def get_settings_command(self, kwargs):
        """Generates xml string for get settings on gvmd."""
        cmd = XmlCommand('get_settings')
        cmd.set_attributes(kwargs)
        return cmd.to_string()

    def get_system_reports_command(self, kwargs):
        """Generates xml string for get system on gvmd."""
        cmd = XmlCommand('get_system')
        cmd.set_attributes(kwargs)
        return cmd.to_string()

    def get_tags_command(self, kwargs):
        """Generates xml string for get tags on gvmd."""
        cmd = XmlCommand('get_tags')
        cmd.set_attributes(kwargs)
        return cmd.to_string()

    def get_targets_command(self, kwargs):
        """Generates xml string for get targets on gvmd."""
        cmd = XmlCommand('get_targets')
        cmd.set_attributes(kwargs)
        return cmd.to_string()

    def get_tasks_command(self, kwargs):
        """Generates xml string for get tasks on gvmd."""
        cmd = XmlCommand('get_tasks')
        cmd.set_attributes(kwargs)
        return cmd.to_string()

    def get_users_command(self, kwargs):
        """Generates xml string for get users on gvmd."""
        cmd = XmlCommand('get_users')
        cmd.set_attributes(kwargs)
        return cmd.to_string()

    def get_version_command(self):
        """Generates xml string for get version on gvmd."""
        cmd = XmlCommand('get_version')
        return cmd.to_string()

    def help_command(self, kwargs):
        """Generates xml string for help on gvmd."""
        cmd = XmlCommand('help')
        cmd.set_attributes(kwargs)
        return cmd.to_string()

    def move_task_command(self, task_id, slave_id):
        """Generates xml string for move task on gvmd."""
        cmd = XmlCommand('move_task')
        cmd.set_attribute('task_id', task_id)
        cmd.set_attribute('slave_id', slave_id)
        return cmd.to_string()

    def restore_command(self, entity_id):
        """Generates xml string for restore on gvmd."""
        cmd = XmlCommand('restore')
        cmd.set_attribute('id', entity_id)
        return cmd.to_string()

    def resume_task_command(self, task_id):
        """Generates xml string for resume task on gvmd."""
        cmd = XmlCommand('resume_task')
        cmd.set_attribute('task_id', task_id)
        return cmd.to_string()

    def start_task_command(self, task_id):
        """Generates xml string for start task on gvmd."""
        cmd = XmlCommand('start_task')
        cmd.set_attribute('task_id', task_id)
        return cmd.to_string()

    def stop_task_command(self, task_id):
        """Generates xml string for stop task on gvmd."""
        cmd = XmlCommand('stop_task')
        cmd.set_attribute('task_id', task_id)
        return cmd.to_string()

    def sync_cert_command(self):
        """Generates xml string for sync cert on gvmd."""
        cmd = XmlCommand('sync_cert')
        return cmd.to_string()

    def sync_config_command(self):
        """Generates xml string for sync config on gvmd."""
        cmd = XmlCommand('sync_config')
        return cmd.to_string()

    def sync_feed_command(self):
        """Generates xml string for sync feed on gvmd."""
        cmd = XmlCommand('sync_feed')
        return cmd.to_string()

    def sync_scap_command(self):
        """Generates xml string for sync scap on gvmd."""
        cmd = XmlCommand('sync_scap')
        return cmd.to_string()

    def test_alert_command(self, alert_id):
        """Generates xml string for test alert on gvmd."""
        cmd = XmlCommand('test_alert')
        cmd.set_attribute('alert_id', alert_id)
        return cmd.to_string()

    def verify_agent_command(self, agent_id):
        """Generates xml string for verify agent on gvmd."""
        cmd = XmlCommand('verify_agent')
        cmd.set_attribute('agent_id', agent_id)
        return cmd.to_string()

    def verify_report_format_command(self, report_format_id):
        """Generates xml string for verify report format on gvmd."""
        cmd = XmlCommand('verify_report_format')
        cmd.set_attribute('report_format_id', report_format_id)
        return cmd.to_string()

    def verify_scanner_command(self, scanner_id):
        """Generates xml string for verify scanner on gvmd."""
        cmd = XmlCommand('verify_scanner')
        cmd.set_attribute('scanner_id', scanner_id)
        return cmd.to_string()
