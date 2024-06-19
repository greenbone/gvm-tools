# SPDX-FileCopyrightText: 2022 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

# List vulnerabilities with CERT-BUND IDs and severities from a report,
# per host and CERT-BUND advisory.

import os
import re
import sys
from argparse import ArgumentParser, Namespace
from itertools import zip_longest
from typing import Dict, List, Optional, Sequence, Tuple, TypeVar, overload

from gvm.errors import GvmResponseError
from gvm.protocols.gmp import Gmp

import ssv_csv

# from gvm.xml import pretty_print

sys.path.append(os.path.dirname(args.argv[0]))  # type: ignore


class _Row(Dict, total=False):
    host: str
    port: str
    hostname: str
    name: str
    severity: str
    cves: str
    cb: List[str]


class _Host(Dict, total=False):
    ip: str
    name: str
    operating_system: str


class _CBund(Dict, total=False):
    severity: str
    title: str


@overload
def _get_text(e, other: str) -> str:
    """Signature of _get_text if other is str"""


@overload
def _get_text(e, other: None = None) -> Optional[str]:
    """Signature of _get_text if other is None"""


def _get_text(e, other: Optional[str] = None) -> Optional[str]:
    """Return (recursive) inner text of element if truthy"""
    if e is not None:
        text = "".join(e.itertext())
        text = text.strip()
        if text:
            return text
    return other


@overload
def _assign(
    tgt: _Host, tgtfield: str, src: Dict[str, Optional[str]], srcfield: str
) -> None:
    """Signature of _assign for _Host targets"""


@overload
def _assign(
    tgt: Dict[str, str],
    tgtfield: str,
    src: Dict[str, Optional[str]],
    srcfield: str,
) -> None:
    """Signature of _assign for Dict[str, str] targets"""


def _assign(
    tgt, tgtfield: str, src: Dict[str, Optional[str]], srcfield: str
) -> None:
    """Assign src[srcfield] to tgt[tgtfield] if extant and truthy"""
    if srcfield in src:
        srcval = src[srcfield]
        if srcval:
            tgt[tgtfield] = srcval


def _info(string: str) -> None:
    print("I:", string, file=sys.stderr)


def _warn(string: str) -> None:
    print("W:", string, file=sys.stderr)


def _err(string: str) -> None:
    print("E:", string, file=sys.stderr)


T = TypeVar("T")


def _group_batch(
    tutti: Sequence[T], batch_size: int
) -> Sequence[Tuple[Optional[T], ...]]:
    iterlist = [iter(tutti)] * batch_size
    return list(zip_longest(*iterlist))


# validate CERT-BUND ID
_cb_id_match = re.compile("CB-K[0-9]+/[0-9]+")


# encode for filter_string
def _cb_fmt(cbid: str) -> str:
    if _cb_id_match.fullmatch(cbid) is not None:
        return "uuid=" + cbid
    _warn(f"invalid CERT-BUND ID: {cbid}")
    return ""


def main(gmp: Gmp, args: Namespace) -> None:
    raw_args = [] + args.argv[1:] + args.script_args
    parser = ArgumentParser(
        prog="certbund-report.gmp.py",
        description="Displays CERT-Bund advisories for vulnerabilities.",
        epilog=(
            "Usage: gvm-script [opts] connection_type "
            "certbund-report.gmp.py [Options] ID"
        ),
        add_help=False,
    )
    ogroup = parser.add_argument_group("Options")
    ogroup.add_argument(
        "-H", action="help", help="show this help message and exit"
    )
    ogroup.add_argument(
        "-o",
        "--output",
        metavar="outfile",
        help='write to this CSV file, "-" for stdout (default)',
        default="-",
    )
    ogroup.add_argument(
        "-r",
        "--report",
        action="store_true",
        help="ID is a report ID, not a task ID",
    )
    agroup = parser.add_argument_group("Arguments")
    agroup.add_argument("ID", help="task (or report) ID to analyse")
    script_args = parser.parse_args(raw_args)
    if script_args.report:
        report_id = script_args.ID
    else:
        task_id = script_args.ID
        _info("obtaining task")
        try:
            task = gmp.get_task(task_id)
        except GvmResponseError as e:
            if e.status != "404":
                raise e
            _err(f"task {task_id} not found")
            sys.exit(1)
        try:
            task_report = task.xpath(
                "/get_tasks_response/task[1]/last_report/report[1]"
            )
            report_id = task_report[0].get("id")
        except IndexError:
            _err("task does not have any (finished) report")
            sys.exit(1)
    _info("obtaining report")
    try:
        report = gmp.get_report(report_id, ignore_pagination=True, details=True)
    except GvmResponseError as e:
        if e.status != "404":
            raise e
        _err(f"report {report_id} not found")
        sys.exit(1)
    # with open("report.xml", "w", encoding="utf-8") as rf:
    #    pretty_print(report, file=rf)

    ### gather data
    # + host IP       hosts[row['host']]['ip']
    # - vuln port     row['port']
    # - host name     row.get('hostname',
    #                     hosts[row['host']].get('name', 'N/A'))
    # - host OS       hosts[row['host']].get('os', 'N/A')
    # + vuln name     row['name']
    # + vuln severity row['severity']
    # + vuln CVEs     row['cves']
    # + bund ID       row['cb'] : list(str)
    # + bund severity cbund[…].get('severity', 'N/A')
    # - bund title    cbund[…].get('title', 'N/A')

    orows: List[_Row] = []
    hosts: Dict[str, _Host] = {}
    cbund: Dict[str, _CBund] = {}
    results = report.xpath(
        "/get_reports_response/report/report/results/"
        'result[./nvt/refs/ref/@type="cert-bund"]'
    )
    # pretty_print(results)
    _info(f"processing {len(results)} results")
    for result in results:
        orow: _Row = {}
        r_host = result.find("host")
        asset = r_host.find("asset").attrib["asset_id"]
        hosts[asset] = {"ip": r_host.text}  # more filled in later
        orow["host"] = asset
        r_hostname = _get_text(r_host.find("hostname"))
        if r_hostname:
            orow["hostname"] = r_hostname
        orow["port"] = _get_text(result.find("port"), "N/A")
        orow["name"] = _get_text(result.find("name"), "N/A")
        orow["severity"] = _get_text(result.find("severity"), "N/A")
        r_cve: List[str] = []
        r_cb: List[str] = []
        for ref in result.find("nvt").find("refs").findall("ref"):
            if ref.attrib["type"] == "cve":
                r_cve.append(ref.attrib["id"])
            elif ref.attrib["type"] == "cert-bund":
                cbid = ref.attrib["id"]
                r_cb.append(cbid)
                cbund[cbid] = {}  # more filled in later
        orow["cves"] = ", ".join(r_cve)
        orow["cb"] = r_cb
        orows.append(orow)
    hostdatas = report.xpath("/get_reports_response/report/report/host")
    # pretty_print(hostdatas)
    _info(f"processing {len(hosts)}/{len(hostdatas)} hosts")
    for hostdata in hostdatas:
        asset = hostdata.find("asset").attrib["asset_id"]
        if asset not in hosts:
            continue
        details: Dict[str, Optional[str]] = {}
        details["ip"] = _get_text(hostdata.find("ip"))
        for detail in hostdata.findall("detail"):
            dname = _get_text(detail.find("name"))
            if dname in ("best_os_cpe", "hostname", "OS"):
                details[dname] = _get_text(detail.find("value"))
        hostent: _Host = hosts[asset]
        _assign(hostent, "ip", details, "ip")
        _assign(hostent, "name", details, "hostname")
        # try best_os_cpe first but overwrite with OS if better
        _assign(hostent, "os", details, "best_os_cpe")
        _assign(hostent, "os", details, "OS")

    ### retrieve CERT-BUND Advisories

    _info(f"retrieving {len(cbund)} CERT-BUND advisories")
    # one-by-one
    # cb_retrieve_problem = False
    # for id, cbdata in cbund.items():
    #    try:
    #        cb = gmp.get_cert_bund_advisory(id).find(
    #            'info'
    #        ).find('cert_bund_adv')
    #        cbdata['severity'] = _get_text(cb.find('severity'), 'N/A')
    #        cbdata['title'] = _get_text(cb.find('title'), 'N/A')
    #    except GvmResponseError as e:
    #        if e.status != '404':
    #            raise e
    #        cb_retrieve_problem = True
    # batched
    for cb_batch in _group_batch(list(cbund.keys()), 50):
        actual_batch = [x for x in cb_batch if x is not None]
        fstr = " ".join(map(_cb_fmt, actual_batch)) + " first=1 rows=-1"
        try:
            cbs = gmp.get_cert_bund_advisories(filter_string=fstr)
        except GvmResponseError as e:
            if e.status != "404":
                raise e
            # warn below
            continue
        for cbi in cbs.findall("info"):
            if "id" not in cbi.attrib:
                # we have both <info id="CB-K14/1304"> (which we want)
                # and, for some reason, <info start="1" max="10"/>
                continue
            cbid = cbi.attrib["id"]
            if cbid in cbund:
                cb = cbi.find("cert_bund_adv")
                cbund[cbid]["severity"] = _get_text(cb.find("severity"), "N/A")
                cbund[cbid]["title"] = _get_text(cb.find("title"), "N/A")
    cb_retrieve_problem = {}

    ### output

    _info("emitting CSV")
    if script_args.o == "-":
        outfile = sys.stdout
    else:
        outfile = open(script_args.o, "w", encoding="utf-8")
    writer = ssv_csv.CSVWriter(outfile, sep=",")
    writer.writeln("sep=,")
    writer.write(
        "IP",
        "Port",
        "Hostname",
        "OS",
        "Vulnerability",
        "Severity",
        "CVEs",
        "CertBUND-ID",
        "CertBUND-Severity",
        "CertBUND-Title",
    )
    for row in orows:
        ip = hosts[row["host"]]["ip"]
        port = row["port"]
        hname = row.get("hostname", hosts[row["host"]].get("name", "N/A"))
        operating_system = hosts[row["host"]].get("os", "N/A")
        vname = row["name"]
        vsev = row["severity"]
        cves = row["cves"]
        for cb in row["cb"]:
            if "severity" in cbund[cb]:
                cbsev = cbund[cb]["severity"]
                cbtitle = cbund[cb]["title"]
            else:
                cb_retrieve_problem[cb] = 1
                cbsev = "N/A"
                cbtitle = "N/A (could not be retrieved)"
            writer.write(
                ip,
                port,
                hname,
                operating_system,
                vname,
                vsev,
                cves,
                cb,
                cbsev,
                cbtitle,
            )
    cb_nproblems = len(cb_retrieve_problem)
    if cb_nproblems > 0:
        _warn(f"{cb_nproblems} CERT-BUND advisories could not be obtained")
    else:
        _info("done")


if __name__ == "__gmp__":
    main(gmp, args)  # type: ignore
