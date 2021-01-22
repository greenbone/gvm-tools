# -*- coding: utf-8 -*-
# Copyright (C) 2021 Greenbone Networks GmbH
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

from uuid import UUID
from cpe import CPE

from typing import List, Dict, Tuple
from datetime import date
import datetime
from argparse import ArgumentParser, RawTextHelpFormatter
from lxml import etree as e
from gvm.protocols.latest import InfoType
from gvm.errors import GvmResponseError, GvmError
from gvm.xml import pretty_print
from gvmtools.helper import generate_uuid, error_and_exit
import json
import csv
from pathlib import Path


HELP_TEXT = (
    'This script creates a cve report from a JSON document.'
    ' Usable with gvm-script (gvm-tools)'
)


class CPELookup:
    """Class handles the CPEs"""

    def __init__(self, filename):
        try:
            self.file = open(filename, 'r')
            self.reader = csv.reader(self.file)
        except FileNotFoundError:
            error_and_exit(
                f'There is no file "{filename}". '
                'Maybe you need to create a list first. Run with '
                f'argument "++create-list +f {filename}", to create '
                'a new list, or pass the correct location of an existing list.'
            )

    def get_cves(self, cpes):
        """Get CVEs for the CPEs"""
        d1 = datetime.datetime.now()
        print(f'Serching CVEs for {str(len(cpes))}:', end=None)
        vulns = {}
        i = 0
        for cpe in cpes:
            vulns[cpe] = {}
        for row in self.reader:  # O(n)
            for cpe in cpes:
                if cpe in row[0]:
                    vulns[cpe][row[1].strip("'")] = float(row[2].strip("'"))
                    i = i + 1
        self.file.seek(0)
        d2 = datetime.datetime.now()
        print(f'Found {str(i)} CVEs. Time consumed: {str(d2 - d1)}')

        return vulns

    def finish_lookup(self):
        self.file.close()


class ListGenerator:
    """
    Creating the initial lists for this script.
    """

    def __init__(self, gmp, filename="cpes.csv"):
        self.gmp = gmp
        self.file = open(filename, 'w')

    def get_cve_from_cpe_id(self, cpe_id):
        cves = []
        return cves

    def cpe_to_cve(self, resp):
        cve_tags = resp.findall('info')
        for cve_tag in cve_tags[:-1]:
            cve = None
            cpes = None
            if 'id' in cve_tag.attrib:
                cve = cve_tag.attrib['id']
                cpes = cve_tag.find('cve').find('products').text
                cvss = cve_tag.find('cve').find('cvss').text
                if cpes:
                    for cpe in cpes.strip().split(' '):
                        print(
                            f"'{cpe}','{cve}','{cvss}'",
                            file=self.file,
                            end='\n',
                        )

    def create_cve_list(self, step=1000):
        resp = self.gmp.get_info_list(info_type=InfoType.CVE, filter='rows=1')
        count = resp.find('info_count').text

        counter = int(count)
        print(f'Found {count} CVEs.')

        first = 0
        d1 = datetime.datetime.now()
        while counter > step:
            resp = self.gmp.get_info_list(
                info_type=InfoType.CVE, filter=f'rows={step} first={first}'
            )
            # refresh the counters
            counter = counter - step
            first = first + step

            self.cpe_to_cve(resp)
            print(
                f'CVEs left: {str(counter)}/{count} TIME CONSUMED: {str(datetime.datetime.now() - d1)}'
            )

        # find the rest
        resp = self.gmp.get_info_list(
            info_type=InfoType.CVE, filter=f'rows={counter} first={first}'
        )
        self.cpe_to_cve(resp)

    def finish_list(self):
        self.file.close()


def generate_host_detail_elem(
    name, value, source_name=None, source_description=None, source_type=None
):
    host_detail_elem = e.Element('detail')
    e.SubElement(host_detail_elem, 'name').text = name
    e.SubElement(host_detail_elem, 'value').text = value

    if source_name:
        source_elem = e.SubElement(host_detail_elem, 'source')
        e.SubElement(source_elem, 'name').text = source_name
        if source_type:
            e.SubElement(source_elem, 'type').text = source_type
        if source_description:
            e.SubElement(source_elem, 'description').text = source_description

    return host_detail_elem


class Results:
    def __init__(self, gmp):
        self.results = e.Element('results')
        self.hosts = []

        self.gmp = gmp

    def add_results(self, ip, hostname, cpes: Dict, cpeo, os):
        print("ADDING RESULTS")
        results = []
        host_elem = e.Element('host')
        host_id = generate_uuid()
        e.SubElement(host_elem, 'ip').text = ip
        e.SubElement(host_elem, 'asset', {'asset_id': host_id}).text = ''

        source_name = 'gvm-tools'
        print("ADDED HOST ELEM")
        host_elem.append(
            generate_host_detail_elem(
                name='hostname', value=hostname, source_name=source_name
            )
        )
        host_elem.append(
            generate_host_detail_elem(
                name='best_os_txt',
                value=os,
                source_name=source_name,
                source_description="Host Details",
            )
        )
        host_elem.append(
            generate_host_detail_elem(
                name='best_os_cpe',
                value=cpeo,
                source_name=source_name,
                source_description="Host Details",
            )
        )

        print("SO FAR")

        for cpe, cves in cpes.items():
            print("UNPACKED CPES")
            if cves:
                for cve, cvss in cves.items():
                    print("UNPACKED CPES")
                    result_id = generate_uuid()
                    result = e.Element('result', {'id': result_id})
                    e.SubElement(result, 'name').text = f'Result for host {ip}'
                    e.SubElement(
                        result, 'comment'
                    ).text = 'Imported with gvm-tools'
                    e.SubElement(result, 'modification_time').text = date[0]
                    e.SubElement(result, 'creation_time').text = date[1]
                    detect_elem = e.Element('detection')
                    detect_result_elem = e.SubElement(
                        detect_elem, 'result', {'id': result_id}
                    )
                    details_elem = e.SubElement(detect_result_elem, 'details')

                    host_elem = e.Element('host')
                    host_elem.text = ip
                    e.SubElement(
                        host_elem, 'asset', {'asset_id': host_id}
                    ).text = ''
                    e.SubElement(host_elem, 'hostname').text = hostname
                    result.append(host_elem)

                    nvt_elem = e.Element('nvt', {'oid': cve})
                    nvt_elem.SubElement('type').text('cve')
                    nvt_elem.SubElement('name').text(cve)
                    nvt_elem.SubElement('cvss_base').text(cvss)
                    nvt_elem.SubElement('cve').text(cve)

                    result.append(nvt_elem)

                    e.SubElement(result, 'severity').text = cvss

                    host_elem.append(
                        generate_host_detail_elem(
                            name='App',
                            value=cpe,
                            source_type='cve',
                            source_name=cve,
                            source_description='CVE Scanner',
                        )
                    )

                    results.append(result)
        pretty_print(results)
        return host_id, cvss


class Hosts:
    """Class to store the host elements"""

    def __init__(self):
        self.hosts = []

    def add_host(self):
        pass


def convert_cpe23_to_cpe22(cpe):
    """Convert a CPE v2.3 to a CPE v2.2
    returns the CPE v2.2 and True if no product
    version is given
    """
    # MAKE ME BETTER!!!
    cpe = CPE(cpe)
    any_version = False
    if cpe.get_version()[0] == '*':
        any_version = True
    return (
        str(CPE(cpe.as_uri_2_3(), CPE.VERSION_2_2)).replace('CPE v2.2: ', ''),
        any_version,
    )


def parse_args(args):  # pylint: disable=unused-argument
    """ Parsing args ... """

    parser = ArgumentParser(
        prefix_chars='+',
        add_help=False,
        formatter_class=RawTextHelpFormatter,
        description=HELP_TEXT,
    )

    parser.add_argument(
        '+h',
        '++help',
        action='help',
        help='Show this help message and exit.',
    )

    parser.add_argument(
        '++create-list',
        action='store_true',
        dest="create_list",
        help="Create the CPE to CVE helper list",
    )

    parser.add_argument(
        '+l',
        '++list',
        type=str,
        dest="list",
        help="Create the CPE to CVE helper list",
    )

    parser.add_argument(
        '+f',
        '++file',
        type=str,
        dest="json_file",
        help="File that should be parsed",
    )

    args, _ = parser.parse_known_args()

    return args


def add_cpe_dict(cpe: e.Element) -> Dict:
    cves = []
    for cve in cpe.find('cpe').find('cves').findall('cve'):
        cves.append(cve.find('*').get('id'))
    return {cpe: [cves]}


def get_cpe(gmp, cpe):
    # print("GET")
    cpe = convert_cpe23_to_cpe22(cpe)
    # print(cpe)
    if cpe[1] is False:
        print(f'Found 1 CPE with version.')
        return [cpe[0]]

    cpes = []
    d2 = datetime.datetime.now()
    # print("Jo2")
    cpe_xml = gmp.get_info_list(
        info_type=InfoType.CPE, filter='rows=-1 uuid~"{}:"'.format(cpe[0])
    )
    infos = cpe_xml.findall('info')
    for cpe in infos[:-1]:
        cpes.append(cpe.get('id'))
    d3 = datetime.datetime.now()
    print(f'Found {str(len(infos[:-1]))} CPEs without version: {str(d3 - d2)}.')
    return cpes


def parse_json(gmp, hosts_dump, cpe_list):
    """Loads an JSON file and extracts host informations:

    Args:
        host_dump

    Returns:
        hosts:       The host list
    """

    results = Results(gmp=gmp)
    hosts = Hosts()

    entries = []

    for entry in hosts_dump:
        if entry[3] is None:
            error_and_exit("The JSON format is not correct.")
        name = entry[0]
        print(f"Host {name}")
        ips = entry[1]
        ip_range = entry[2]
        os = entry[3]
        os_cpe = convert_cpe23_to_cpe22(entry[4])[0]

        objs = []
        # adding the app/apps in the host object (if there are any ...)
        # I hope this is not all to bad performing ...
        cpes = []
        # entry[7] should be cpes ...
        if entry[7] is not None:
            # print(entry[7])
            if isinstance(entry[7], str):
                cpes.extend(get_cpe(gmp, entry[7]))
            else:
                for cpe in entry[7]:
                    if cpe:
                        cpes.extend(get_cpe(gmp, cpe))

        vulns = cpe_list.get_cves(cpes)
        if vulns:
            print("WE GOT CPES")
            for ip in ips:
                results.add_results(
                    ip=ip,
                    hostname=name,
                    cpes=vulns,
                    cpeo=os_cpe,
                    os=os,
                )

    return entries


def main(gmp, args):
    # pylint: disable=undefined-variable

    parsed_args = parse_args(args=args)

    if parsed_args.create_list:
        print("Generating CVE to CPE list")
        list_generator = ListGenerator(
            gmp, filename=Path(parsed_args.list).absolute()
        )
        list_generator.create_cve_list()
        list_generator.finish_list()
        print("Done.")
    if parsed_args.json_file:
        cpe_list = CPELookup(parsed_args.list)
        print("Looking up hosts ...")
        with open(parsed_args.json_file, 'r') as fp:
            hosts = parse_json(gmp, json.load(fp)[0]['results'], cpe_list)


if __name__ == '__gmp__':
    main(gmp, args)
