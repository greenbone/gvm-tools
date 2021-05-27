# -*- coding: utf-8 -*-
# Copyright (C) 2017-2021 Greenbone Networks GmbH
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

# pylint: disable=too-many-lines

import time
import textwrap
import json

from random import randrange, choice, gauss, seed
from argparse import ArgumentParser, Namespace, RawTextHelpFormatter
from pathlib import Path
from gvm.protocols.gmp import Gmp
from lxml import etree as e

from gvmtools.helper import (
    generate_uuid,
    generate_id,
    generate_random_ips,
)

__version__ = "0.1.0"

HELP_TEXT = """
    Random Report Generation Script {version} (C) 2017-2021 Greenbone Networks GmbH

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

    This script generates randomized report data.
    """.format(
    version=__version__
)


def generate_ports(n_ports):
    protocol = ['/tcp', '/udp']
    return [str(randrange(0, 65536)) + choice(protocol) for i in range(n_ports)]


def generate_report_elem(task, **kwargs):
    rep_format_id = 'a994b278-1f62-11e1-96ac-406186ea4fc5'
    rep_id = generate_uuid()
    outer_report_elem = e.Element(
        'report',
        attrib={
            'extension': 'xml',
            'id': rep_id,
            'format_id': rep_format_id,
            'content_type': 'text/xml',
        },
    )
    owner_elem = e.SubElement(outer_report_elem, 'owner')
    e.SubElement(owner_elem, 'name').text = 'testowner'
    e.SubElement(outer_report_elem, 'name').text = 'testname'
    e.SubElement(outer_report_elem, 'writeable').text = str(0)
    e.SubElement(outer_report_elem, 'in_use').text = str(0)
    task_elem = e.SubElement(outer_report_elem, 'task', attrib={'id': task[0]})
    e.SubElement(task_elem, 'name').text = task[1]
    repform_elem = e.SubElement(
        outer_report_elem, 'report_format', attrib={'id': rep_format_id}
    )
    e.SubElement(repform_elem, 'name').text = 'XML'

    # Generating inner <report> tag
    outer_report_elem.append(generate_inner_report(rep_id, **kwargs))

    return outer_report_elem


def generate_inner_report(rep_id, n_results, n_hosts, data, **kwargs):
    report_elem = e.Element('report', attrib={'id': rep_id})
    results_elem = e.SubElement(
        report_elem, 'results', {'max': str(n_results), 'start': '1'}
    )

    # Create Hosts, Ports, Data
    hosts = generate_random_ips(n_hosts)  # Host IPs
    ports = generate_ports(n_hosts)
    oid_dict = {host: [] for host in hosts}
    asset_dict = {host: generate_uuid() for host in hosts}
    host_names = {host: generate_id() for host in hosts}
    max_sev = 0.0

    # Create <result> tags with random data
    for _ in range(n_results):
        host_ip = choice(hosts)
        host_port = choice(ports)
        result_elem, oid, severity = generate_result_elem(
            data["vulns"],
            host_ip,
            host_port,
            asset_dict[host_ip],
            host_names[host_ip],
        )
        if float(severity) > max_sev:
            max_sev = float(severity)

        oid_dict[host_ip].append(oid)
        results_elem.append(result_elem)

    e.SubElement(report_elem, "result_count").text = str(n_results)

    sev_elem = e.Element("severity")
    e.SubElement(sev_elem, "full").text = str(max_sev)
    e.SubElement(sev_elem, "filtered").text = str(max_sev)

    report_elem.append(sev_elem)

    # Create <host> tags with random data
    for host in hosts:
        if len(oid_dict[host]) > 0:
            report_elem.append(
                generate_host_elem(
                    host,
                    oid_dict[host][0],
                    asset_dict[host],
                    host_names[host],
                    data=data,
                    **kwargs,
                )
            )

    return report_elem


def generate_result_elem(vulns, host_ip, host_port, host_asset, host_name):
    result_elem = e.Element('result', {'id': generate_uuid()})

    e.SubElement(result_elem, 'name').text = "a_result" + generate_id()
    own = e.SubElement(result_elem, 'owner')
    e.SubElement(own, 'name').text = generate_id()

    elem = e.Element('modification_time')
    e.SubElement(result_elem, 'modification_time').text = (
        time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(time.time()))[:-2]
        + ':00'
    )  # Hell of a Timeformat :D
    e.SubElement(result_elem, 'comment').text = ''
    e.SubElement(result_elem, 'creation_time').text = (
        time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(time.time() - 20))[
            :-2
        ]
        + ':00'
    )

    host_elem = e.Element('host')
    host_elem.text = host_ip
    e.SubElement(host_elem, 'asset', {'asset_id': host_asset}).text = ''
    e.SubElement(host_elem, 'hostname').text = host_name
    result_elem.append(host_elem)

    port_elem = e.Element('port')
    port_elem.text = host_port
    result_elem.append(port_elem)

    nvt = vulns[randrange(len(vulns))]
    e.SubElement(result_elem, 'severity').text = nvt['severity']
    nvt_elem = e.Element('nvt', {'oid': nvt['oid']})
    result_elem.append(nvt_elem)

    e.SubElement(result_elem, 'notes').text = 'TestNotes'

    result_elem.append(elem)

    return result_elem, nvt['oid'], nvt['severity']


def generate_host_detail_elem(
    name, value, source_name=None, source_description=None
):
    host_detail_elem = e.Element('detail')
    e.SubElement(host_detail_elem, 'name').text = name
    e.SubElement(host_detail_elem, 'value').text = value

    if source_name:
        source_elem = e.SubElement(host_detail_elem, 'source')
        e.SubElement(source_elem, 'name').text = source_name

        if source_description:
            e.SubElement(source_elem, 'description').text = source_description

    return host_detail_elem


def generate_additional_host_details(
    n_details, host_details, *, not_vuln=False
):
    host_detail_elems = []

    for _ in range(n_details):
        details = None

        if not_vuln:
            details = host_details.copy()
            details["source_name"] += str(randrange(14259, 103585))
        else:
            details = choice(host_details)

        host_detail_elems.append(
            generate_host_detail_elem(
                details['name'],
                details['value'],
                source_name=details.get('source_name'),
                source_description=details.get('source_description'),
            )
        )

    return host_detail_elems


def generate_host_elem(
    host_ip, oid, host_asset, host_name, n_host_details, n_not_vuln, data
):
    host_elem = e.Element('host')
    e.SubElement(host_elem, 'ip').text = host_ip
    e.SubElement(host_elem, 'asset', {'asset_id': host_asset}).text = ''

    e.SubElement(host_elem, 'start').text = (
        time.strftime(
            "%Y-%m-%dT%H:%M:%S%z", time.localtime(time.time() - 1000)
        )[:-2]
        + ':00'
    )
    e.SubElement(host_elem, 'end').text = (
        time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(time.time() - 30))[
            :-2
        ]
        + ':00'
    )

    app = choice(list(data["apps"]))
    os = choice(list(data["oss"]))

    host_elem.append(
        generate_host_detail_elem('App', data["apps"].get(app), source_name=oid)
    )
    host_elem.append(
        generate_host_detail_elem(
            data["apps"].get(app), '/usr/bin/foo', source_name=oid
        )
    )
    host_elem.append(
        generate_host_detail_elem(
            'hostname',
            host_name,
            source_name=oid,
            source_description="Host Details",
        )
    )
    host_elem.append(
        generate_host_detail_elem(
            'best_os_txt',
            list(os)[0],
            source_name=oid,
            source_description="Host Details",
        )
    )
    host_elem.append(
        generate_host_detail_elem(
            'best_os_cpe',
            data["oss"].get(os),
            source_name=oid,
            source_description="Host Details",
        )
    )

    if n_host_details:
        host_elem.extend(
            generate_additional_host_details(
                n_host_details, data["host_details"]
            )
        )

    dev = n_not_vuln / 10
    if n_not_vuln:
        host_elem.extend(
            generate_additional_host_details(
                n_not_vuln + randrange(-dev, dev),
                data["not_vuln"],
                not_vuln=True,
            )
        )

    return host_elem


def generate_reports(task, n_reports, with_gauss, **kwargs):
    reports = []

    if with_gauss:
        n_reports = abs(int(gauss(n_reports, 1)))
        if n_reports == 0:
            n_reports += 1

    for _ in range(n_reports):
        if with_gauss:
            n_results = abs(int(gauss(n_results, 2)))

        report_elem = generate_report_elem(task, **kwargs)
        report_elem = e.tostring(report_elem)
        reports.append(report_elem)

    return reports


def generate_data(gmp, n_tasks, **kwargs):
    for i in range(n_tasks):
        index = '{{0:0>{}}}'.format(len(str(n_tasks)))
        task_name = 'Task_for_GenReport:_{}'.format(index.format(i + 1))

        gmp.create_container_task(task_name)

        task_id = gmp.get_tasks(
            filter_string='name={}'.format(task_name)
        ).xpath('//@id')[0]

        reports = generate_reports(task=(task_id, task_name), **kwargs)

        for report in reports[0:]:
            gmp.import_report(report, task_id=task_id, in_assets=True)


def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=undefined-variable, line-too-long

    parser = ArgumentParser(
        prog="random-report-gen",
        prefix_chars="-",
        description=HELP_TEXT,
        formatter_class=RawTextHelpFormatter,
        add_help=False,
        epilog=textwrap.dedent(
            """
        Example:
            $ gvm-script --gmp-username name --gmp-password pass
            ssh --hostname <gsm> scripts/gen-random-reports.gmp.py -T 5 -r 4 -R 3 --hosts 10
        """
        ),
    )

    parser.add_argument(
        "-H", action="help", help="Show this help message and exit."
    )

    parser.add_argument(
        "--datafile",
        default=Path(args.script[0]).parent / "default_report_data.json",
        help="A json file containing the following information: "
        "vulnerabilities, operating systems, applications and host details. "
        "Take the default json file as an example.",
    )

    parser.add_argument(
        "--tasks",
        "-T",
        type=int,
        default="1",
        help="Number of Tasks to be generated.",
    )

    parser.add_argument(
        "--reports",
        "-r",
        type=int,
        default="5",
        help="Number of Reports per Task.",
    )

    parser.add_argument(
        "--results",
        "-R",
        type=int,
        default="5",
        help="Number of Results per Report.",
    )

    parser.add_argument(
        "--hosts",
        type=int,
        default="5",
        help="Number of randomized hosts to select from.",
    )

    parser.add_argument(
        "--host-details",
        dest="host_details",
        type=int,
        default="2",
        help="Number of additional host details per host.",
    )

    parser.add_argument(
        "--not-vuln-details",
        dest="not_vuln",
        type=int,
        default="10",
        help="Number of 'NOT_VULN' host details per host.",
    )

    parser.add_argument(
        "--with-gauss",
        dest="with_gauss",
        action="store_true",
        help="if you would like for the number of reports/task and "
        "results/report to be randomized along a Gaussian distribution.",
    )

    parser.add_argument(
        "--seed", help="RNG Seed, in case the same data should be generated."
    )

    script_args = parser.parse_args(args.script_args)

    if not script_args.seed:
        seed()
    else:
        seed(script_args.seed)

    with open(str(script_args.datafile)) as file:
        data = json.load(file)

    print('\n  Generating randomized data(s)...\n')

    generate_data(
        gmp,
        n_tasks=script_args.tasks,
        n_reports=script_args.reports,
        n_results=script_args.results,
        n_hosts=script_args.hosts,
        n_host_details=script_args.host_details,
        n_not_vuln=script_args.not_vuln,
        data=data,
        with_gauss=script_args.with_gauss,
    )

    print('\n  Generation done.\n')


if __name__ == '__gmp__':
    main(gmp, args)
