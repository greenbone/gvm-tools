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

import json
import csv
import datetime
import time
from pathlib import Path

from typing import Dict, Tuple
from argparse import ArgumentParser, RawTextHelpFormatter, Namespace
from lxml import etree as e
from cpe import CPE
from gvm.protocols.gmp import Gmp
from gvm.protocols.latest import InfoType
from gvmtools.helper import generate_uuid, error_and_exit


HELP_TEXT = (
    'This script creates a cve report from a JSON document.\n'
    'The JSON document needs to be formatted like this: '
    '['
    '    {'
    '        "headings": ['
    '            "name",'
    '            "IP Address",'
    '            "IP range",'
    '            "Operating System",'
    '            "CPE String 23",'
    '            "Name",'
    '            "Full Version (version)",'
    '            "CPE String 23"'
    '        ],'
    '        ...,'
    '        "results": ['
    '            ['
    '                "foo",'
    '                "127.0.0.1",'
    '                "127.0.0.1/32",'
    '                "Some Windows",'
    '                "cpe:2.3:o:microsoft:some_windows:-:*:*:*:*:*:*:*",'
    '                ['
    '                    "Some Microsoftware",'
    '                    .'
    '                ],'
    '                ['
    '                    "0.1",'
    '                    ...'
    '                ],'
    '                ['
    '                    "cpe:2.3:a:microsoft:microsoftware:0.1:*:*:*:*:*:*:*",'
    '                    ...'
    '                ]'
    '            ],'
    '        ]'
    '    }'
    ']'
    ' Usable with gvm-script (gvm-tools). Help: gvm-script -h'
)


class ProgressBar:
    def __init__(self, length: int, count: int, pl_name: str):
        self.length = length
        self.count = count
        self.current = 0
        self.start_time = datetime.datetime.now()
        self.entities = pl_name

        self.eta = '???'
        self.seq = ''
        self.end = ''

        self._print()
        self.seq = '\r'

    def _leading_zeros(self) -> str:
        return (len(str(self.count)) - len(str(self.current))) * ' '

    def _bar(self):
        points = int(self.length * (self.current / self.count))
        return str("·" * points + " " * (self.length - points))

    def _print(self):
        print(
            f'{self.seq}[{self._bar()}] | '
            f'{self._leading_zeros()}{str(self.current)}/{str(self.count)} '
            f'{self.entities} processed. | '
            f'ETA: {self.eta}',
            flush=True,
            end=self.end,
        )

    def update(self, progressed):
        self.current = progressed
        elapsed = datetime.datetime.now() - self.start_time
        self.eta = str(elapsed / self.current * (self.count - self.current))
        self._print()

    def done(self):
        self.current = self.count
        self.eta = 'Done!         '
        self.end = '\n'
        self._print()


class ListGenerator:
    """
    Creating the CPE to CVE list used for the report generation
    in this this script.
    """

    def __init__(self, gmp: Gmp, filename: Path, recreate: bool):
        self.gmp = gmp
        if filename.exists():
            if recreate:
                filename.unlink()
            else:
                error_and_exit(
                    f'The file "{filename}" already exists. '
                    'If you want to delete the old list and '
                    'recreate the list run with "++create-list '
                    f'recreate +f {filename}"'
                )
        self.file = open(filename, 'w')

    def _cpe_to_cve(self, resp):
        """ Write the CPEs and CVEs to the list """
        cve_tags = resp.findall('info')
        for cve_tag in cve_tags[
            :-1
        ]:  # -1 because the last info tag is a wrongy. :D
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

    def create_cve_list(self, step: int = 3000):
        """Creates a CPE to CVE list in a CSV format:
        'cpe', 'cve', 'cvss'
        The CPE's have a 1-to-1-relation to the CVE's
        so CPE's can appear more then once in this
        list

        step(int): How many CVEs will be requested from the GSM
                   in one request. Be careful with higher values.
                   You will need to set the default timeout in
                   gvm-tools higher if you set step >3000. A higher
                   step will make the list generation faster.
        """
        resp = self.gmp.get_info_list(info_type=InfoType.CVE, filter='rows=1')
        count = resp.find('info_count').text

        first = 0
        count = int(count)
        print(f'Creating CPE to CVE list. Found {count} CVE\'s.')
        progress_bar = ProgressBar(length=100, count=count, pl_name='CVEs')
        print(f'[{" " * 50}] | ({str(first)}/{count})', flush=True, end='')
        while (first + step) < count:
            resp = self.gmp.get_info_list(
                info_type=InfoType.CVE, filter=f'rows={step} first={first}'
            )
            self._cpe_to_cve(resp)
            first = first + step
            progress_bar.update(progressed=first)

        # find the rest
        resp = self.gmp.get_info_list(
            info_type=InfoType.CVE,
            filter=f'rows={counter - first} first={first}',
        )
        self._cpe_to_cve(resp)
        progress_bar.done()

        self.file.close()


class Report:
    def __init__(self, gmp):
        self.results = e.Element('results', {'start': '1', 'max': '-1'})
        self.hosts = []
        self.report = None

        self.gmp = gmp

    def finish_report(self):
        report_format_id = 'd5da9f67-8551-4e51-807b-b6a873d70e34'
        self.report_id = generate_uuid()
        self.report = e.Element(
            'report',
            {
                'id': self.report_id,
                'format_id': report_format_id,
                'extension': 'xml',
                'content_type': 'text/xml',
            },
        )
        owner_elem = e.SubElement(self.report, 'owner')
        e.SubElement(owner_elem, 'name').text = ''
        e.SubElement(self.report, 'name').text = 'Report created from JSON-File'

        inner_report = e.SubElement(
            self.report, 'report', {'id': self.report_id}
        )
        ports_elem = e.SubElement(
            inner_report, 'ports', {'start': '1', 'max': '-1'}
        )

        inner_report.append(ports_elem)
        inner_report.append(self.results)
        inner_report.extend(self.hosts)
        self.report.append(inner_report)

    def send_report(self) -> str:
        the_time = time.strftime("%Y/%m/%d-%H:%M:%S")
        task_id = ''
        task_name = "CVE_Scan_Report_{}".format(the_time)

        res = self.gmp.create_container_task(
            name=task_name, comment="Created with gvm-tools."
        )

        task_id = res.xpath('//@id')[0]

        report = e.tostring(self.report)

        res = self.gmp.import_report(report, task_id=task_id, in_assets=True)

        return res.xpath('//@id')[0]

    def generate_host_detail(
        self,
        name,
        value,
        source_name=None,
        source_description=None,
        source_type=None,
    ):
        """ Generating a host details xml element """
        host_detail_elem = e.Element('detail')
        e.SubElement(host_detail_elem, 'name').text = name
        e.SubElement(host_detail_elem, 'value').text = value

        if source_name:
            source_elem = e.SubElement(host_detail_elem, 'source')
            e.SubElement(source_elem, 'name').text = source_name
            if source_type:
                e.SubElement(source_elem, 'type').text = source_type
            if source_description:
                e.SubElement(
                    source_elem, 'description'
                ).text = source_description

        return host_detail_elem

    def add_results(self, ip, hostname, cpes: Dict, cpeo, os, date_time):
        host_id = generate_uuid()
        source_name = 'gvm-tools'
        date_format = '%Y-%m-%dT%H:%M:%S'
        date_time = f'{date_time.strftime(date_format)}Z'

        host_elem = e.Element('host')
        e.SubElement(host_elem, 'ip').text = ip
        e.SubElement(host_elem, 'asset', {'asset_id': host_id})
        e.SubElement(host_elem, 'start').text = date_time
        e.SubElement(host_elem, 'end').text = date_time
        host_result_count_elem = e.SubElement(host_elem, 'result_count')
        host_elem.append(
            self.generate_host_detail(
                name='hostname', value=hostname, source_name=source_name
            )
        )
        host_elem.append(
            self.generate_host_detail(
                name='best_os_txt',
                value=os,
                source_name=source_name,
                source_description="Host Details",
            )
        )
        host_elem.append(
            self.generate_host_detail(
                name='best_os_cpe',
                value=cpeo,
                source_name=source_name,
                source_description="Host Details",
            )
        )

        host_details = 0
        for cpe, cves in cpes.items():
            if cves:
                for cve, cvss in cves.items():
                    result_id = generate_uuid()
                    result = e.Element('result', {'id': result_id})
                    e.SubElement(result, 'name').text = f'Result for host {ip}'
                    e.SubElement(
                        result, 'comment'
                    ).text = 'Imported with gvm-tools'
                    e.SubElement(result, 'modification_time').text = date_time
                    e.SubElement(result, 'creation_time').text = date_time
                    detect_elem = e.Element('detection')
                    detect_result_elem = e.SubElement(
                        detect_elem, 'result', {'id': result_id}
                    )
                    details_elem = e.SubElement(detect_result_elem, 'details')
                    # We need to add the detection details here
                    # but actually they are not imported to GSM anyways ...
                    e.SubElement(details_elem, 'detail')

                    result_host_elem = e.Element('host')
                    result_host_elem.text = ip
                    e.SubElement(
                        result_host_elem, 'asset', {'asset_id': host_id}
                    )
                    e.SubElement(result_host_elem, 'hostname').text = hostname
                    result.append(result_host_elem)

                    nvt_elem = e.Element('nvt', {'oid': cve})
                    e.SubElement(nvt_elem, 'type').text = 'cve'
                    e.SubElement(nvt_elem, 'name').text = cve
                    e.SubElement(nvt_elem, 'cvss_base').text = str(cvss)
                    e.SubElement(nvt_elem, 'cve').text = cve

                    result.append(nvt_elem)

                    e.SubElement(result, 'severity').text = str(cvss)

                    host_elem.append(
                        self.generate_host_detail(
                            name='App',
                            value=cpe,
                            source_type='cve',
                            source_name=cve,
                            source_description='CVE Scanner',
                        )
                    )
                    host_details = host_details + 1

                    self.results.append(result)
        e.SubElement(host_result_count_elem, 'page').text = str(host_details)
        self.hosts.append(host_elem)


class Parser:
    """Class handles the Parsing from JSON to a Report"""

    def __init__(self, gmp: Gmp, json_file: Path, cpe_list: Path) -> None:
        try:
            self.cpe_list = open(cpe_list, 'r')
            self.reader = csv.reader(self.cpe_list)
        except FileNotFoundError:
            error_and_exit(
                f'There is no file "{cpe_list}". '
                'Maybe you need to create a list first. Run with '
                f'argument "++create-list +f {cpe_list}", to create '
                'a new list, or pass the correct location of an existing list.'
            )
        self.gmp = gmp
        try:
            self.json_fp = open(json_file)
            self.json_dump = json.load(self.json_fp)[0]['results']
        except FileNotFoundError:
            error_and_exit(f'There is no file "{json_file}".')
        except json.JSONDecodeError as e:
            error_and_exit(f'The JSON seems to be invalid: {e.args[0]}')

    def parse(self) -> Report:
        """Loads an JSON file and extracts host informations:

        Args:
            host_dump: the dumped json results, containing a hostname,
                    host_ip, host_ip_range, host_operating_system,
                    host_os_cpe, arrays of found_app, app_version,
                    app_cpe
        """

        report = Report(gmp=gmp)

        date_time = datetime.datetime.now()

        count = len(self.json_dump)
        progressed = 0
        print(f'Found {str(count)} hosts:')

        progressbar = ProgressBar(length=100, count=count, pl_name="Hosts")

        for entry in self.json_dump:
            if entry[3] is None:
                error_and_exit("The JSON format is not correct.")
            name = entry[0]
            # print(f"Creating Results for the host {name}")
            ips = entry[1]
            if isinstance(ips, str):
                ips = [ips]
            os = entry[3]
            os_cpe = convert_cpe23_to_cpe22(entry[4])[0]

            cpes = []
            # entry[7] should be the CPEs ...
            if entry[7] is not None:
                if isinstance(entry[7], str):
                    cpes.extend(self._get_cpes(entry[7]))
                else:
                    for cpe in entry[7]:
                        if cpe:
                            cpes.extend(self._get_cpes(cpe))

            vulns = self._get_cves(cpes)
            if vulns:
                for ip in ips:
                    report.add_results(
                        ip=ip,
                        hostname=name,
                        cpes=vulns,
                        cpeo=os_cpe,
                        os=os,
                        date_time=date_time,
                    )

            progressed += 1
            progressbar.update(progressed=progressed)

        progressbar.done()
        print("Nice ...")
        print(report.results)
        return report

    def _get_cpes(self, cpe):
        """Parse and return the CPE's from the JSON.
        Convert the CPEs to v2.2 and check if they have a
        version part. If not get this CPE in all versions
        from the GSM and return them. This may result in
        a lot of false positives or false negatives.
        """
        cpe = convert_cpe23_to_cpe22(cpe)
        if cpe[1] is False:
            return [cpe[0]]

        cpes = []
        cpe_xml = self.gmp.get_info_list(
            info_type=InfoType.CPE, filter='rows=-1 uuid~"{}:"'.format(cpe[0])
        )
        infos = cpe_xml.findall('info')
        for cpe in infos[:-1]:  # -1 because the last info tag is a wrongy. :D
            cpes.append(cpe.get('id'))
        return cpes

    def _get_cves(self, cpes):
        """Get CVEs for the CPEs from the CSV List"""
        vulns = {}
        i = 0
        for row in self.reader:  # O(n)
            for cpe in cpes:
                vulns[cpe] = {}
                if cpe in row[0]:
                    vulns[cpe][row[1].strip("'")] = float(row[2].strip("'"))
                    i = i + 1
        self.cpe_list.seek(0)

        return vulns

    def finish_lookup(self):
        self.json_fp.close()
        self.cve_list.close()


def convert_cpe23_to_cpe22(cpe: str) -> Tuple[str, bool]:
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


def parse_args(args: Namespace) -> Namespace:  # pylint: disable=unused-argument
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
        nargs='?',
        type=str,
        choices=('no_creation', 'recreate', 'create'),
        const='create',
        default='no_creation',
        dest="create_list",
        help="Create the CPE to CVE helper list",
    )

    parser.add_argument(
        '+l',
        '++list',
        type=str,
        dest="list",
        required=True,
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


def main(gmp, args):
    # pylint: disable=undefined-variable

    parsed_args = parse_args(args=args)

    recreate = False
    if parsed_args.create_list == 'recreate':
        recreate = True
    if parsed_args.create_list != 'no_creation':
        print("Generating CVE to CPE list.")
        list_generator = ListGenerator(
            gmp, filename=Path(parsed_args.list).absolute(), recreate=recreate
        )
        list_generator.create_cve_list()
        print("Generation of CVE to CPE list done.")
    if parsed_args.json_file:
        report = Parser(
            gmp=gmp, json_file=parsed_args.json_file, cpe_list=parsed_args.list
        ).parse()

        report.finish_report()
        report_id = report.send_report()
        print(f"Imported Report [{report_id}]")


if __name__ == '__gmp__':
    main(gmp, args)
