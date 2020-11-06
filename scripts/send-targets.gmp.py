# -*- coding: utf-8 -*-
# Copyright (C) 2018-2019 Greenbone Networks GmbH
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

import sys
from gvm.protocols.gmpv9.types import get_alive_test_from_string

from lxml import etree


def check_args(args):
    len_args = len(args.script) - 1
    if len_args != 1:
        message = """
        This script pulls target data from an xml document and feeds it to \
    a desired GSM
        One parameter after the script name is required.

        1. <xml_doc>  -- .xml file containing targets

        Example:
            $ gvm-script --gmp-username name --gmp-password pass \
    ssh --hostname <gsm> scripts/send-targets.gmp.py example_file.xml
        """
        print(message)
        quit()


def error_and_exit(msg):
    print("Error: {}\n".format(msg), file=sys.stderr)
    sys.exit(1)


def yes_or_no(question):
    reply = str(input(question + ' (y/n): ')).lower().strip()
    if reply[0] == ('y'):
        return True
    if reply[0] == ('n'):
        return False
    else:
        return yes_or_no("Please enter 'y' or 'n'")


def create_xml_tree(xml_doc):
    try:
        xml_tree = etree.parse(xml_doc)
        xml_tree = xml_tree.getroot()
    except IOError as err:
        error_and_exit("Failed to read xml_file: {} (exit)".format(str(err)))
    except etree.Error as err:
        error_and_exit("Failed to parse xml_file: {} (exit)".format(str(err)))

    if len(xml_tree) == 0:
        error_and_exit("XML file is empty (exit)")

    return xml_tree


def parse_send_xml_tree(gmp, xml_tree):
    credential_options = [
        'ssh_credential',
        'smb_credential',
        'esxi_credential',
        'snmp_credential',
    ]
    counter = 1

    for target in xml_tree.xpath('target'):
        keywords = {}  # {'make_unique': True}

        keywords['name'] = target.find('name').text

        keywords['hosts'] = target.find('hosts').text.split(',')

        exclude_hosts = target.find('exclude_hosts').text
        if exclude_hosts is not None:
            keywords['exclude_hosts'] = exclude_hosts.split(',')

        comment = target.find('comment').text
        if comment is not None:
            keywords['comment'] = comment

        credentials = gmp.get_credentials()[0].xpath("//credential/@id")

        for credential in credential_options:
            cred_id = target.find(credential).xpath('@id')[0]
            if cred_id == '':
                continue
            if cred_id not in credentials:
                response = yes_or_no(
                    "\nThe credential '{}' for 'target {}' could not be "
                    "located...\nWould you like to continue?".format(
                        credential, counter
                    )
                )

                if response is False:
                    print("Terminating...\n")
                    quit()
                else:
                    continue

            key = '{}_id'.format(credential)
            keywords[key] = cred_id
            elem_path = target.find(credential)
            port = elem_path.find('port')
            if port is not None and port.text is not None:
                port_key = '{}_port'.format(credential)
                keywords[port_key] = elem_path.find('port').text

        alive_test = get_alive_test_from_string(target.find('alive_tests').text)

        if alive_test is not None:
            keywords['alive_test'] = alive_test

        reverse_lookup_only = target.find('reverse_lookup_only').text
        if reverse_lookup_only == '1':
            keywords['reverse_lookup_only'] = 1

        reverse_lookup_unify = target.find('reverse_lookup_unify').text
        if reverse_lookup_unify == '1':
            keywords['reverse_lookup_unify'] = 1

        port_range = target.find('port_range')
        if port_range is not None:
            keywords['port_range'] = port_range.text

        if target.xpath('port_list/@id') is not None:
            port_list = {}
            port_list = target.xpath('port_list/@id')[0]
            keywords['port_list_id'] = port_list

        print(keywords)

        gmp.create_target(**keywords)

        counter += 1


def main(gmp, args):
    # pylint: disable=undefined-variable

    check_args(args)

    xml_doc = args.script[1]

    print('\nSending targets...')

    xml_tree = create_xml_tree(xml_doc)
    parse_send_xml_tree(gmp, xml_tree)

    print('\n  Target(s) created!\n')


if __name__ == '__gmp__':
    main(gmp, args)  # pylint: disable=undefined-variable
