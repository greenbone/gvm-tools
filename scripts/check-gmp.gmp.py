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

import logging
import os
import re
import signal
import sqlite3
import sys
import tempfile
from argparse import ArgumentParser, Namespace, RawTextHelpFormatter
from datetime import datetime, timedelta, tzinfo
from decimal import Decimal
from pathlib import Path
from gvm.protocols.gmp import Gmp

from lxml import etree

__version__ = "2.0.0"

logger = logging.getLogger(__name__)

HELP_TEXT = """
    Check-GMP Nagios Command Plugin {version} (C) 2017-2021 Greenbone Networks GmbH

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
    """.format(
    version=__version__
)

NAGIOS_OK = 0
NAGIOS_WARNING = 1
NAGIOS_CRITICAL = 2
NAGIOS_UNKNOWN = 3

NAGIOS_MSG = ["OK", "WARNING", "CRITICAL", "UNKNOWN"]

MAX_RUNNING_INSTANCES = 10


class InstanceManager:
    """Class for managing instances of this plugin

    All new reports will be cached in a sqlite database.
    The first call with a unknown host takes longer,
    because the remote gvmd/openvasmd has to generate the report.
    The second call will retrieve the data from the database if the scan
    duration does not differ.

    Additionally this class handles all instances of check-gmp. No more than
    MAX_RUNNING_INSTANCES can run simultaneously. Other instances are stopped
    and wait for continuation.
    """

    def __init__(self, path, parser):
        """Initialise the sqlite database.

        Create it if it does not exist else connect to it.

        Arguments:
            path (string): Path to the database.
        """
        self.cursor = None
        self.con_db = None
        self.db = Path(path)
        self.pid = os.getpid()

        # Try to read file with information about cached reports
        # First check whether the file exist or not
        try:
            exist = self.db.is_file()
            logger.debug("DB file exist?: %s ", exist)

            if not exist:
                if not self.db.parent.is_dir():
                    self.db.parent.mkdir(parents=True, exist_ok=True)
                else:
                    self.db.touch()
                # Connect to db
                self.connect_db()

                # Create the tables
                self.cursor.execute(
                    """CREATE TABLE Report(
                    host text,
                    scan_end text,
                    params_used text,
                    report text
                )"""
                )

                self.cursor.execute(
                    """CREATE TABLE Instance(
                    created_at text,
                    pid integer,
                    pending integer default 0
                )"""
                )

                logger.debug("Tables created")
            else:
                self.connect_db()

        except PermissionError:
            parser.error(
                "The selected temporary database file {} or the parent dir has"
                " not the correct permissions.".format(self.db)
            )

    @staticmethod
    def _to_sql_bool(pending):
        """Replace True/False with 1/0."""
        return '1' if pending else '0'

    def connect_db(self):
        """Connect to the database

        Simply connect to the database at location <path>
        """
        try:
            logger.debug("connect db: %s", self.db)
            self.con_db = sqlite3.connect(str(self.db))
            self.cursor = self.con_db.cursor()
            logger.debug(sqlite3.sqlite_version)
        except Exception as e:  # pylint: disable=broad-except
            logger.debug(e)

    def close_db(self):
        """Close database"""
        self.con_db.close()

    def set_host(self, host):
        """Sets the host variable

        Arguments:
            host (string): Given ip or hostname of target.
        """
        self.host = host

    def is_old_report(self, last_scan_end, params_used):
        """Decide whether the current report is old or not

        At first the last scanend and the params that were used are fetched
        from the database. If no report is fetched, then True will be returned.
        The next step is to compare the old and the new scanend.
        If the scanends matches, then return False, because it is the same
        report. Else the old report will be deleted.

        Arguments:
            last_scan_end (string): Last scan end of report
            params_used (string): Params used for this check

        Returns:
            True if it is an old report or empty. False if it is the same
            report.
        """

        # Before we do anything here, check existing instance

        # Retrieve the scan_end value
        self.cursor.execute(
            "SELECT scan_end, params_used FROM Report WHERE" " host=?",
            (self.host,),
        )
        db_entry = self.cursor.fetchone()

        logger.debug("%s %s", db_entry, last_scan_end)

        if not db_entry:
            return True
        else:
            old = parse_date(db_entry[0])
            new = parse_date(last_scan_end)

            logger.debug(
                "Old time (from db): %s\n" "New time (from rp): %s", old, new
            )

            if new <= old and params_used == db_entry[1]:
                return False
            else:
                # Report is newer. Delete old entry.
                logger.debug("Delete old report for host %s", self.host)
                self.delete_report()
                return True

    def load_local_report(self):
        """Load report from local database

        Select the report from the database according due the hostname or ip.

        Returns:
            An lxml ElementTree
        """
        self.cursor.execute(
            "SELECT report FROM Report WHERE host=?", (self.host,)
        )
        db_entry = self.cursor.fetchone()

        if db_entry:
            return etree.fromstring(db_entry[0])
        else:
            logger.debug("Report from host %s is not in the db", self.host)

    def add_report(self, scan_end, params_used, report):
        """Create new entry with the lxml report

        Create a string from the lxml object and add it to the database.
        Additional data is the scanend and the params used.

        Arguments:
            scan_end (string): Scan end of the report
            params_used (string): Params used for this check
            report (obj): An lxml ElementTree
        """

        data = etree.tostring(report)

        logger.debug("add_report: %s, %s, %s", self.host, scan_end, params_used)

        # Insert values
        self.cursor.execute(
            "INSERT INTO Report VALUES (?, ?, ?, ?)",
            (self.host, scan_end, params_used, data),
        )

        # Save the changes
        self.con_db.commit()

    def delete_report(self):
        """Delete report from database"""
        self.cursor.execute("DELETE FROM Report WHERE host=?", (self.host,))

        # Save the changes
        self.con_db.commit()

    def delete_entry_with_ip(self, ip):
        """Delete report from database with given ip

        Arguments:
            ip (string): IP-Adress
        """
        logger.debug("Delete entry with ip: %s", ip)
        self.cursor.execute("DELETE FROM Report WHERE host=?", (ip,))
        self.con_db.isolation_level = None
        self.cursor.execute("VACUUM")
        self.con_db.isolation_level = ''  # see: https://github.com/CxAalto/gtfspy/commit/8d05c3c94a6d4ca3ed675d88af93def7d5053bfe # pylint: disable=line-too-long
        # Save the changes
        self.con_db.commit()

    def delete_older_entries(self, days):
        """Delete reports from database older than given days

        Arguments:
            days (int): Number of days in past
        """
        logger.debug("Delete entries older than: %s days", days)
        self.cursor.execute(
            "DELETE FROM Report WHERE scan_end <= "
            'date("now", "-%s day")' % days
        )
        self.cursor.execute("VACUUM")

        # Save the changes
        self.con_db.commit()

    def has_entries(self, pending):
        """Return number of instance entries
        Arguments:
            pending (bool): True for pending instances. False for running
                           instances.

        Returns:
            The number of pending or non pending instances entries.
        """
        self.cursor.execute(
            "SELECT count(*) FROM Instance WHERE pending=?",
            (self._to_sql_bool(pending),),
        )

        res = self.cursor.fetchone()

        return res[0]

    def check_instances(self):
        """This method checks the status of check-gmp instances.

        Checks whether instances are pending or not and start instances
        according to the number saved in the MAX_RUNNING_INSTANCES variable.
        """

        # Need to check whether any instances are in the database that were
        # killed f.e. because a restart of nagios
        self.clean_orphaned_instances()

        # How many processes are currently running?
        number_instances = self.has_entries(pending=False)

        # How many pending entries are waiting?
        number_pending_instances = self.has_entries(pending=True)

        logger.debug(
            "check_instances: %i %i", number_instances, number_pending_instances
        )

        if (
            number_instances < MAX_RUNNING_INSTANCES
            and number_pending_instances == 0
        ):
            # Add entry for running process and go on
            logger.debug("Fall 1")
            self.add_instance(pending=False)

        elif (
            number_instances < MAX_RUNNING_INSTANCES
            and number_pending_instances > 0
        ):
            # Change pending entries and wake them up until enough instances
            # are running
            logger.debug("Fall 2")

            while (
                number_instances < MAX_RUNNING_INSTANCES
                and number_pending_instances > 0
            ):
                pending_entries = self.get_oldest_pending_entries(
                    MAX_RUNNING_INSTANCES - number_instances
                )

                logger.debug("Oldest pending pids: %s", pending_entries)

                for entry in pending_entries:
                    created_at = entry[0]
                    pid = entry[1]

                    # Change status to not pending and continue the process
                    self.update_pending_status(created_at, False)
                    self.start_process(pid)

                # Refresh number of instances for next while loop
                number_instances = self.has_entries(pending=False)
                number_pending_instances = self.has_entries(pending=True)

            # TODO: Check if this is really necessary
            # self.add_instance(pending=False)
            # if number_instances >= MAX_RUNNING_INSTANCES:
            # self.stop_process(self.pid)

        elif (
            number_instances >= MAX_RUNNING_INSTANCES
            and number_pending_instances == 0
        ):
            # There are running enough instances and no pending instances
            # Add new entry with pending status true and stop this instance
            logger.debug("Fall 3")
            self.add_instance(pending=True)
            self.stop_process(self.pid)

        elif (
            number_instances >= MAX_RUNNING_INSTANCES
            and number_pending_instances > 0
        ):
            # There are running enough instances and there are min one
            # pending instance
            # Add new entry with pending true and stop this instance
            logger.debug("Fall 4")
            self.add_instance(pending=True)
            self.stop_process(self.pid)

        # If an entry is pending and the same params at another process is
        # starting, then exit with gmp pending since data
        # if self.has_pending_entries():
        # Check if an pending entry is the same as this process
        # If hostname
        #    date = datetime.now()
        #    end_session('GMP PENDING: since %s' % date, NAGIOS_OK)
        #    end_session('GMP RUNNING: since', NAGIOS_OK)

    def add_instance(self, pending):
        """Add new instance entry to database

        Retrieve the current time in ISO 8601 format. Create a new entry with
        pending status and the dedicated pid

        Arguments:
            pending (bool): State of instance
        """
        current_time = datetime.now().isoformat()

        # Insert values
        self.cursor.execute(
            "INSERT INTO Instance VALUES (?, ?, ?)",
            (current_time, self.pid, self._to_sql_bool(pending)),
        )

        # Save the changes
        self.con_db.commit()

    def get_oldest_pending_entries(self, number):
        """Return the oldest last entries of pending entries from database

        Return:
            the oldest instances with status pending limited by the variable
            <number>
        """
        self.cursor.execute(
            "SELECT * FROM Instance WHERE pending=1 ORDER BY "
            "created_at LIMIT ? ",
            (number,),
        )
        return self.cursor.fetchall()

    def update_pending_status(self, date, pending):
        """Update pending status of instance

        The date variable works as a primary key for the instance table.
        The entry with date get his pending status updated.

        Arguments:
            date (string):  Date of creation for entry
            pending (bool): Status of instance
        """
        self.cursor.execute(
            "UPDATE Instance SET pending=? WHERE created_at=?",
            (self._to_sql_bool(pending), date),
        )

        # Save the changes
        self.con_db.commit()

    def delete_instance(self, pid=None):
        """Delete instance from database

        If a pid different from zero is given, then delete the entry with
        given pid. Else delete the entry with the pid stored in this class
        instance.

        Keyword Arguments:
            pid (number): Process Indentificattion Number (default: {0})
        """
        if not pid:
            pid = self.pid

        logger.debug("Delete entry with pid: %i", pid)
        self.cursor.execute("DELETE FROM Instance WHERE pid=?", (pid,))

        # Save the changes
        self.con_db.commit()

    def clean_orphaned_instances(self):
        """Delete non existing instance entries

        This method check whether a pid exist on the os and if not then delete
        the orphaned entry from database.
        """
        self.cursor.execute("SELECT pid FROM Instance")

        pids = self.cursor.fetchall()

        for pid in pids:
            if not self.check_pid(pid[0]):
                self.delete_instance(pid[0])

    def wake_instance(self):
        """Wake up a pending instance

        This method is called at the end of any session from check_gmp.
        Get the oldest pending entries and wake them up.
        """
        # How many processes are currently running?
        number_instances = self.has_entries(pending=False)

        # How many pending entries are waiting?
        number_pending_instances = self.has_entries(pending=True)

        if (
            number_instances < MAX_RUNNING_INSTANCES
            and number_pending_instances > 0
        ):

            pending_entries = self.get_oldest_pending_entries(
                MAX_RUNNING_INSTANCES - number_instances
            )

            logger.debug(
                "wake_instance: %i %i",
                number_instances,
                number_pending_instances,
            )

            for entry in pending_entries:
                created_at = entry[0]
                pid = entry[1]
                # Change status to not pending and continue the process
                self.update_pending_status(created_at, False)
                self.start_process(pid)

    def start_process(self, pid):
        """Continue a stopped process

        Send a continue signal to the process with given pid

        Arguments:
            pid (int): Process Identification Number
        """
        logger.debug("Continue pid: %i", pid)
        os.kill(pid, signal.SIGCONT)

    def stop_process(self, pid):
        """Stop a running process

        Send a stop signal to the process with given pid

        Arguments:
            pid (int): Process Identification Number
        """
        os.kill(pid, signal.SIGSTOP)

    def check_pid(self, pid):
        """Check for the existence of a process.

        Arguments:
            pid (int): Process Identification Number
        """
        try:
            os.kill(pid, 0)
        except OSError:
            return False
        else:
            return True


def ping(gmp, im):
    """Checks for connectivity

    This function sends the get_version command and checks whether the status
    is ok or not.
    """
    version = gmp.get_version()
    version_status = version.xpath("@status")

    if "200" in version_status:
        end_session(im, "GMP OK: Ping successful", NAGIOS_OK)
    else:
        end_session(im, "GMP CRITICAL: Machine dead?", NAGIOS_CRITICAL)


def status(gmp, im, script_args):
    """Returns the current status of a host

    This functions return the current state of a host.
    Either directly over the host management or within a task.

    For a task you can explicitly ask for the trend.
    Otherwise the last report of the task will be filtered.

    In the host management the report id in the details is taken
    as report for the filter.
    If the host information contains any vulnerabilities, then will the
    report be filtered too. With additional parameters it is possible to add
    more information about the vulnerabilities.

    * DFN-Certs
    * Logs
    * Autofp
    * Scanend
    * Overrides
    """
    params_used = "task=%s autofp=%i overrides=%i apply_overrides=%i" % (
        script_args.task,
        script_args.autofp,
        int(script_args.overrides),
        int(script_args.apply_overrides),
    )

    if script_args.task:
        task = gmp.get_tasks(
            filter_string="permission=any owner=any rows=1 "
            'name="%s"' % script_args.task
        )
        if script_args.trend:
            trend = task.xpath("task/trend/text()")

            if not trend:
                end_session(
                    im, "GMP UNKNOWN: Trend is not available.", NAGIOS_UNKNOWN
                )

            trend = trend[0]

            if trend in ["up", "more"]:
                end_session(
                    im, "GMP CRITICAL: Trend is %s." % trend, NAGIOS_CRITICAL
                )
            elif trend in ["down", "same", "less"]:
                end_session(im, "GMP OK: Trend is %s." % trend, NAGIOS_OK)
            else:
                end_session(
                    im,
                    "GMP UNKNOWN: Trend is unknown: %s" % trend,
                    NAGIOS_UNKNOWN,
                )
        else:
            last_report_id = task.xpath("task/last_report/report/@id")

            if not last_report_id:
                end_session(
                    im, "GMP UNKNOWN: Report is not available", NAGIOS_UNKNOWN
                )

            last_report_id = last_report_id[0]
            last_scan_end = task.xpath(
                "task/last_report/report/scan_end/text()"
            )

            if last_scan_end:
                last_scan_end = last_scan_end[0]
            else:
                last_scan_end = ""

            if im.is_old_report(last_scan_end, params_used):
                host = script_args.hostaddress

                full_report = gmp.get_report(
                    report_id=last_report_id,
                    filter_string="sort-reverse=id result_hosts_only=1 "
                    "min_cvss_base= min_qod= levels=hmlgd autofp={} "
                    "notes=0 apply_overrides={} overrides={} first=1 rows=-1 "
                    "delta_states=cgns host={}".format(
                        script_args.autofp,
                        int(script_args.overrides),
                        int(script_args.apply_overrides),
                        host,
                    ),
                    details=True,
                )

                im.add_report(last_scan_end, params_used, full_report)
                logger.debug("Report added to db")
            else:
                full_report = im.load_local_report()

            filter_report(
                im, full_report.xpath("report/report")[0], script_args
            )


def filter_report(im, report, script_args):
    """Filter out the information in a report

    This function filters the results of a given report.

    Arguments:
        report (obj): Report as lxml ElementTree.
    """
    report_id = report.xpath("@id")
    if report_id:
        report_id = report_id[0]
    results = report.xpath("//results")
    if not results:
        end_session(
            im, "GMP UNKNOWN: Failed to get results list", NAGIOS_UNKNOWN
        )

    results = results[0]
    # Init variables
    any_found = False
    high_count = 0
    medium_count = 0
    low_count = 0
    log_count = 0
    error_count = 0

    nvts = {"high": [], "medium": [], "low": [], "log": []}

    all_results = results.xpath("result")

    for result in all_results:
        if script_args.hostaddress:
            host = result.xpath("host/text()")
            if not host:
                end_session(
                    im,
                    "GMP UNKNOWN: Failed to parse result host",
                    NAGIOS_UNKNOWN,
                )

            if script_args.hostaddress != host[0]:
                continue
            any_found = True

        threat = result.xpath("threat/text()")
        if not threat:
            end_session(
                im,
                "GMP UNKNOWN: Failed to parse result threat.",
                NAGIOS_UNKNOWN,
            )

        threat = threat[0]
        if threat in "High":
            high_count += 1
            if script_args.oid:
                nvts["high"].append(retrieve_nvt_data(result))
        elif threat in "Medium":
            medium_count += 1
            if script_args.oid:
                nvts["medium"].append(retrieve_nvt_data(result))
        elif threat in "Low":
            low_count += 1
            if script_args.oid:
                nvts["low"].append(retrieve_nvt_data(result))
        elif threat in "Log":
            log_count += 1
            if script_args.oid:
                nvts["log"].append(retrieve_nvt_data(result))
        else:
            end_session(
                im,
                "GMP UNKNOWN: Unknown result threat: %s" % threat,
                NAGIOS_UNKNOWN,
            )

    errors = report.xpath("errors")

    if errors:
        errors = errors[0]
        if script_args.hostaddress:
            for error in errors.xpath("error"):
                host = error.xpath("host/text()")
                if script_args.hostaddress == host[0]:
                    error_count += 1
        else:
            error_count = errors.xpath("count/text()")[0]

    ret = 0
    if high_count > 0:
        ret = NAGIOS_CRITICAL
    elif medium_count > 0:
        ret = NAGIOS_WARNING

    if script_args.empty_as_unknown and (
        not all_results or (not any_found and script_args.hostaddress)
    ):
        ret = NAGIOS_UNKNOWN

    print(
        "GMP %s: %i vulnerabilities found - High: %i Medium: %i "
        "Low: %i"
        % (
            NAGIOS_MSG[ret],
            (high_count + medium_count + low_count),
            high_count,
            medium_count,
            low_count,
        )
    )

    if not all_results:
        print("Report did not contain any vulnerabilities")

    elif not any_found and script_args.hostaddress:
        print(
            "Report did not contain vulnerabilities for IP %s"
            % script_args.hostaddress
        )

    if int(error_count) > 0:
        if script_args.hostaddress:
            print_without_pipe(
                "Report did contain %i errors for IP %s"
                % (error_count, script_args.hostaddress)
            )
        else:
            print_without_pipe(
                "Report did contain %i errors" % int(error_count)
            )

    if script_args.report_link:
        print(
            "https://%s/omp?cmd=get_report&report_id=%s"
            % (script_args.hostname, report_id)
        )

    if script_args.oid:
        print_nvt_data(
            nvts,
            show_log=script_args.showlog,
            show_ports=script_args.show_ports,
            descr=script_args.descr,
            dfn=script_args.dfn,
        )

    if script_args.scanend:
        end = report.xpath("//end/text()")
        end = end[0] if end else "Timestamp of scan end not given"
        print("SCAN_END: %s" % end)

    if script_args.details:
        if script_args.hostname:
            print("GSM_Host: %s:%d" % (script_args.hostname, script_args.port))
        if script_args.gmp_username:
            print("GMP_User: %s" % script_args.gmp_username)
        if script_args.task:
            print_without_pipe("Task: %s" % script_args.task)

    end_session(
        im,
        "|High=%i Medium=%i Low=%i" % (high_count, medium_count, low_count),
        ret,
    )


def retrieve_nvt_data(result):
    """Retrieve the nvt data out of the result object

    This function parse the xml tree to find the important nvt data.

    Arguments:
        result (obj): Result as lxml ElementTree

    Returns:
        Tuple -- List with oid, name, desc, port and dfn
    """
    oid = result.xpath("nvt/@oid")
    name = result.xpath("nvt/name/text()")
    desc = result.xpath("description/text()")
    port = result.xpath("port/text()")

    if oid:
        oid = oid[0]

    if name:
        name = name[0]

    if desc:
        desc = desc[0]
    else:
        desc = ""

    if port:
        port = port[0]
    else:
        port = ""

    certs = result.xpath("nvt/cert/cert_ref")

    dfn_list = []
    for ref in certs:
        ref_type = ref.xpath("@type")[0]
        ref_id = ref.xpath("@id")[0]

        if ref_type in "DFN-CERT":
            dfn_list.append(ref_id)

    return (oid, name, desc, port, dfn_list)


def print_nvt_data(
    nvts, show_log=False, show_ports=False, descr=False, dfn=False
):
    """Print nvt data

    Prints for each nvt found in the array the relevant data

    Arguments:
        nvts (obj): Object holding all nvts
    """
    for key, nvt_data in nvts.items():
        if key == "log" and not show_log:
            continue
        for nvt in nvt_data:
            print_without_pipe("NVT: %s (%s) %s" % (nvt[0], key, nvt[1]))
            if show_ports:
                print_without_pipe("PORT: %s" % (nvt[3]))
            if descr:
                print_without_pipe("DESCR: %s" % nvt[2])

            if dfn and nvt[4]:
                dfn_list = ", ".join(nvt[4])
                if dfn_list:
                    print_without_pipe("DFN-CERT: %s" % dfn_list)


def end_session(im, msg, nagios_status):
    """End the session

    Close the socket if open and print the last msg

    Arguments:
        msg string): Message to print
        nagios_status (int): Exit status
    """
    print(msg)

    # Delete this instance
    im.delete_instance()

    # Activate some waiting instances if possible
    im.wake_instance()

    # Close the connection to database
    im.close_db()

    sys.exit(nagios_status)


def print_without_pipe(msg):
    """Prints the message, but without any pipe symbol

    If any pipe symbol is in the msg string, then it will be replaced with
    broken pipe symbol.

    Arguments:
        msg (string): Message to print
    """
    if "|" in msg:
        msg = msg.replace("|", "¦")

    print(msg)


# ISO 8601 date time string parsing

# Copyright (c) 2007 - 2015 Michael Twomey

# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:

# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
# OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
# CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

__all__ = ["parse_date", "ParseError", "UTC"]

_basestring = str


# Adapted from http://delete.me.uk/2005/03/iso8601.html
ISO8601_REGEX = re.compile(
    r"""
    (?P<year>[0-9]{4})
    (
        (
            (-(?P<monthdash>[0-9]{1,2}))
            |
            (?P<month>[0-9]{2})
            (?!$)  # Don't allow YYYYMM
        )
        (
            (
                (-(?P<daydash>[0-9]{1,2}))
                |
                (?P<day>[0-9]{2})
            )
            (
                (
                    (?P<separator>[ T])
                    (?P<hour>[0-9]{2})
                    (:{0,1}(?P<minute>[0-9]{2})){0,1}
                    (
                        :{0,1}(?P<second>[0-9]{1,2})
                        ([.,](?P<second_fraction>[0-9]+)){0,1}
                    ){0,1}
                    (?P<timezone>
                        Z
                        |
                        (
                            (?P<tz_sign>[-+])
                            (?P<tz_hour>[0-9]{2})
                            :{0,1}
                            (?P<tz_minute>[0-9]{2}){0,1}
                        )
                    ){0,1}
                ){0,1}
            )
        ){0,1}  # YYYY-MM
    ){0,1}  # YYYY only
    $
    """,
    re.VERBOSE,
)


class ParseError(Exception):
    """Raised when there is a problem parsing a date string"""


# Yoinked from python docs
ZERO = timedelta(0)


class Utc(tzinfo):
    """UTC Timezone"""

    def utcoffset(self, dt):
        return ZERO

    def tzname(self, dt):
        return "UTC"

    def dst(self, dt):
        return ZERO

    def __repr__(self):
        return "<iso8601.Utc>"


UTC = Utc()


class FixedOffset(tzinfo):
    """Fixed offset in hours and minutes from UTC"""

    def __init__(self, offset_hours, offset_minutes, name):
        self.__offset_hours = offset_hours  # Keep for later __getinitargs__
        # Keep for later __getinitargs__
        self.__offset_minutes = offset_minutes
        self.__offset = timedelta(hours=offset_hours, minutes=offset_minutes)
        self.__name = name

    def __eq__(self, other):
        if isinstance(other, FixedOffset):
            # pylint: disable=protected-access
            return (other.__offset == self.__offset) and (
                other.__name == self.__name
            )
        if isinstance(other, tzinfo):
            return other == self
        return False

    def __getinitargs__(self):
        return (self.__offset_hours, self.__offset_minutes, self.__name)

    def utcoffset(self, dt):
        return self.__offset

    def tzname(self, dt):
        return self.__name

    def dst(self, dt):
        return ZERO

    def __repr__(self):
        return "<FixedOffset %r %r>" % (self.__name, self.__offset)


def to_int(
    source_dict, key, default_to_zero=False, default=None, required=True
):
    """Pull a value from the dict and convert to int

    :param default_to_zero: If the value is None or empty, treat it as zero
    :param default: If the value is missing in the dict use this default

    """

    value = source_dict.get(key)
    if value in [None, ""]:
        value = default
    if (value in ["", None]) and default_to_zero:
        return 0
    if value is None:
        if required:
            raise ParseError("Unable to read %s from %s" % (key, source_dict))
        return value
    else:
        return int(value)


def parse_timezone(matches, default_timezone=UTC):
    """Parses ISO 8601 time zone specs into tzinfo offsets"""

    if matches["timezone"] == "Z":
        return UTC
    # This isn't strictly correct, but it's common to encounter dates without
    # timezones so I'll assume the default (which defaults to UTC).
    # Addresses issue 4.
    if matches["timezone"] is None:
        return default_timezone
    sign = matches["tz_sign"]
    hours = to_int(matches, "tz_hour")
    minutes = to_int(matches, "tz_minute", default_to_zero=True)
    description = "%s%02d:%02d" % (sign, hours, minutes)
    if sign == "-":
        hours = -1 * hours
        minutes = -1 * minutes
    return FixedOffset(hours, minutes, description)


def parse_date(datestring, default_timezone=UTC):
    """Parses ISO 8601 dates into datetime objects

    The timezone is parsed from the date string. However it is quite common to
    have dates without a timezone (not strictly correct). In this case the
    default timezone specified in default_timezone is used. This is UTC by
    default.

    Arguments
        datestring: The date to parse as a string
        default_timezone: A datetime tzinfo instance to use when no timezone
                          is specified in the datestring. If this is set to
                          None then a naive datetime object is returned.
    Returns:
        A datetime.datetime instance
    Raises:
        ParseError when there is a problem parsing the date or
        constructing the datetime instance.

    """
    if not isinstance(datestring, _basestring):
        raise ParseError("Expecting a string %r" % datestring)

    match = ISO8601_REGEX.match(datestring)
    if not match:
        raise ParseError("Unable to parse date string %r" % datestring)

    groups = match.groupdict()

    tz = parse_timezone(groups, default_timezone=default_timezone)

    groups["second_fraction"] = int(
        Decimal("0.%s" % (groups["second_fraction"] or 0))
        * Decimal("1000000.0")
    )

    try:
        return datetime(
            year=to_int(groups, "year"),
            month=to_int(
                groups,
                "month",
                default=to_int(groups, "monthdash", required=False, default=1),
            ),
            day=to_int(
                groups,
                "day",
                default=to_int(groups, "daydash", required=False, default=1),
            ),
            hour=to_int(groups, "hour", default_to_zero=True),
            minute=to_int(groups, "minute", default_to_zero=True),
            second=to_int(groups, "second", default_to_zero=True),
            microsecond=groups["second_fraction"],
            tzinfo=tz,
        )
    except Exception as e:
        raise ParseError(e) from None


def main(gmp: Gmp, args: Namespace) -> None:
    tmp_path = "%s/check_gmp/" % tempfile.gettempdir()
    tmp_path_db = tmp_path + "reports.db"

    parser = ArgumentParser(
        prog="check-gmp",
        prefix_chars="-",
        description=HELP_TEXT,
        formatter_class=RawTextHelpFormatter,
        add_help=False,
        epilog="""
        usage: gvm-script [connection_type] check-gmp.gmp.py ...
        or: gvm-script [connection_type] check-gmp.gmp.py -H
        or: gvm-script connection_type --help""",
    )

    parser.add_argument(
        "-H", action="help", help="Show this help message and exit."
    )

    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version="%(prog)s {version}".format(version=__version__),
        help="Show program's version number and exit",
    )

    parser.add_argument(
        "--cache",
        nargs="?",
        default=tmp_path_db,
        help="Path to cache file. Default: %s." % tmp_path_db,
    )

    parser.add_argument(
        "--clean", action="store_true", help="Activate to clean the database."
    )

    parser.add_argument(
        "-u", "--gmp-username", help="GMP username.", required=False
    )

    parser.add_argument(
        "-w", "--gmp-password", help="GMP password.", required=False
    )

    parser.add_argument(
        "-F",
        "--hostaddress",
        required=False,
        default="",
        help="Report last report status of host <ip>.",
    )

    parser.add_argument(
        "-T", "--task", required=False, help="Report status of task <task>."
    )

    parser.add_argument(
        "--apply-overrides", action="store_true", help="Apply overrides."
    )

    parser.add_argument(
        "--overrides", action="store_true", help="Include overrides."
    )

    parser.add_argument(
        "-d",
        "--details",
        action="store_true",
        help="Include connection details in output.",
    )

    parser.add_argument(
        "-l",
        "--report-link",
        action="store_true",
        help="Include URL of report in output.",
    )

    parser.add_argument(
        "--dfn",
        action="store_true",
        help="Include DFN-CERT IDs on vulnerabilities in output.",
    )

    parser.add_argument(
        "--oid",
        action="store_true",
        help="Include OIDs of NVTs finding vulnerabilities in output.",
    )

    parser.add_argument(
        "--descr",
        action="store_true",
        help="Include descriptions of NVTs finding vulnerabilities in output.",
    )

    parser.add_argument(
        "--showlog", action="store_true", help="Include log messages in output."
    )

    parser.add_argument(
        "--show-ports",
        action="store_true",
        help="Include port of given vulnerable nvt in output.",
    )

    parser.add_argument(
        "--scanend",
        action="store_true",
        help="Include timestamp of scan end in output.",
    )

    parser.add_argument(
        "--autofp",
        type=int,
        choices=[0, 1, 2],
        default=0,
        help="Trust vendor security updates for automatic false positive"
        " filtering (0=No, 1=full match, 2=partial).",
    )

    parser.add_argument(
        "-e",
        "--empty-as-unknown",
        action="store_true",
        help="Respond with UNKNOWN on empty results.",
    )

    parser.add_argument(
        "-I",
        "--max-running-instances",
        default=10,
        type=int,
        help="Set the maximum simultaneous processes of check-gmp",
    )

    parser.add_argument("--hostname", nargs="?", required=False)

    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument(
        "--ping", action="store_true", help="Ping the gsm appliance."
    )

    group.add_argument(
        "--status", action="store_true", help="Report status of task."
    )

    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument(
        "--days",
        type=int,
        help="Delete database entries that are older than" " given days.",
    )
    group.add_argument("--ip", help="Delete database entry for given ip.")

    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument(
        "--trend", action="store_true", help="Report status by trend."
    )
    group.add_argument(
        "--last-report",
        action="store_true",
        help="Report status by last report.",
    )

    script_args = parser.parse_args(args.script_args)

    aux_parser = ArgumentParser(
        prefix_chars="-", formatter_class=RawTextHelpFormatter
    )
    aux_parser.add_argument("--hostname", nargs="?", required=False)
    gvm_tool_args, _ = aux_parser.parse_known_args(sys.argv)
    if "hostname" in gvm_tool_args:
        script_args.hostname = gvm_tool_args.hostname

    # Set the max running instances variable
    if script_args.max_running_instances:
        # TODO should be passed as local variable instead of using a global one
        # pylint: disable=global-statement
        global MAX_RUNNING_INSTANCES
        MAX_RUNNING_INSTANCES = script_args.max_running_instances

    # Set the report manager
    if script_args.cache:
        tmp_path_db = script_args.cache
    im = InstanceManager(tmp_path_db, parser)

    # Check if command holds clean command
    if script_args.clean:
        if script_args.ip:
            logger.info("Delete entry with ip %s", script_args.ip)
            im.delete_entry_with_ip(script_args.ip)
        elif script_args.days:
            logger.info("Delete entries older than %s days", script_args.days)
            im.delete_older_entries(script_args.days)
        sys.exit(1)

    # Set the host
    im.set_host(script_args.hostaddress)

    # Check if no more than 10 instances of check-gmp runs simultaneously
    im.check_instances()

    try:
        gmp.get_version()
    except Exception as e:  # pylint: disable=broad-except
        end_session(im, "GMP CRITICAL: %s" % str(e), NAGIOS_CRITICAL)

    if script_args.ping:
        ping(gmp, im)

    if "status" in script_args:
        status(gmp, im, script_args)


if __name__ == "__gmp__":
    main(gmp, args)
