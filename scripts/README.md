![Greenbone Logo](https://www.greenbone.net/wp-content/uploads/gb_logo_resilience_horizontal.png)

# GVM Example Scripts

## `application-detection.gmp.py`

This script will search the reports and display all hosts with the requested applications!

### Arguments

* `<application>`: Name of the application

### Example

  `$ gvm-script --gmp-username name --gmp-password pass ssh --hostname <gsm> scripts/application-detection.gmp.py <application>`

---

## `cfg-gen-for-certs.gmp.py`

This script creates a new scan config with nvts from a given CERT-Bund!

### Arguments

* `<cert>`: Name or ID of the CERT-Bund

### Example

`$ gvm-script --gmp-username name --gmp-password pass ssh --hostname <gsm> scripts/cfg-gen-for-certs.gmp.py CB-K16/0943`

---

## `check-gmp.gmp.py`

This script can test different methods of the gmp API.

| Optional argument | Description |
| --- | --- |
|`-H`:      |              Show this help message and exit
|`-V`, `--version`: |        Show program's version number and exit
|`--cache [CACHE]`:  |   Path to cache file. Default: `/var/folders/mk/ dfxkj16j4779x98r26n21qnr0000gn/ T/check_gmp/reports.db`
| `--clean` | Activate to clean the database
| `-u GMP_USERNAME`, `--gmp-username GMP_USERNAME` | GMP username
| `-w GMP_PASSWORD`, `--gmp-password GMP_PASSWORD` | GMP password
|`-F HOSTADDRESS`, `--hostaddress HOSTADDRESS` | Report last report status of host `<ip>`.
|`-T TASK`, `--task TASK` | Report status of task `<task>`.
|`--apply-overrides`    | Apply overrides.
|`--overrides`          | Include overrides.
|`-d`, `--details`       |  Include connection details in output.
|`-l`, `--report-link`   |  Include URL of report in output.
|`--dfn`               |  Include DFN-CERT IDs on vulnerabilities in output.
|`--oid`               |  Include OIDs of NVTs finding vulnerabilities in output.
|`--descr`             |  Include descriptions of NVTs finding vulnerabilities in output.
|`--showlog`           |  Include log messages in output.
| `--show-ports`       |   Include port of given vulnerable nvt in output.
| `--scanend`          |   Include timestamp of scan end in output.
| `--autofp {0,1,2}`  |    Trust vendor security updates for automatic false positive filtering (`0=No`, `1=full match`, `2=partial`).
| `-e`, `--empty-as-unknown` | Respond with `UNKNOWN` on empty results.
| `-I MAX_RUNNING_INSTANCES`, `--max-running-instances MAX_RUNNING_INSTANCES` | Set the maximum simultaneous processes of check-gmp
| `--hostname [HOSTNAME]`
| `--ping`               | Ping the gsm appliance.
| `--status`            |  Report status of task.
| `--days DAYS`        |   Delete database entries that are older than given days.
| `--ip IP`             |  Delete database entry for given ip.
| `--trend`             |  Report status by trend.
| `--last-report`      |   Report status by last report.

### Example

`$ gvm-script --gmp-username name --gmp-password pass ssh --hostname <gsm> scripts/check-gmp.gmp.py --ip 127.0.0.1 --ping`

---

## `clean-sensor.gmp.py`

This script removes all resources from a sensor, except active tasks.

### Example

`$ gvm-script --gmp-username name --gmp-password pass ssh --hostname <gsm> scripts/clean-sensor.gmp.py`

---

## `combine-reports.gmp.py`

This script will combine desired reports into a single report. The combined report will then be sent to a desired container task. This script will create a container task for the combined report to be sent to, however, if you would like the report to be sent to an existing task, place the report of the desired task first and add the argument 'first_task'.

### Arguments

* `<report_1_uuid>, ..., <report_n_uuid>`: UUIDs of the reports to be combined

### Example

`$ gvm-script --gmp-username=namessh --gmp-password=pass ssh --hostname=hostname scripts/combine-reports.gmp.py "d15a337c-56f3-4208-a462-afeb79eb03b7" "303fa0a6-aa9b-43c4-bac0-66ae0b2d1698" 'first_task'`

---

## `create-dummy-data.gmp.py`

This script will create random data in the given GVM database.

### Arguments

* `<count>`: Number of datasets to create

### Example

`$ gvm-script --gmp-username name --gmp-password pass ssh --hostname <gsm> scripts/create-dummy-data.gmp.py <count>`

---

## `create-targets-from-host-list.gmp.py`

This script pulls hostnames from a text file and creates a target for each.

### Arguments

* `<hostname>`: IP of the GVM host
* `<hosts_textfile>`: text file containing hostnames

### Example

`$ gvm-script --gmp-username name --gmp-password pass ssh --hostname <gsm> scripts/create_targets_from_host_list.gmp.py <hostname> <hosts_textfile>`

---

## `delete-overrides-by-filter.gmp.py`

This script deletes overrides with a specific filter value.

### Arguments

* `<filter>`: the parameter for the filter.

### Example

`$ gvm-script --gmp-username name --gmp-password pass ssh --hostname <gsm> scripts/delete-overrides-by-filter.gmp.py <filter>`

---

## `generate-random-reports.gmp.py`

This script generates randomized report data.

### Arguments

* `-T <number of tasks>`:   number of tasks to be generated
* `-r <number of reports>`: number of reports per task
* `-R <number of results>`: number of results per report
* `--hosts <number of hosts>`:   number of randomized hosts to select from
* `'with-gauss'`: if you would like for the number of reports/task and results/report to be randomized along a Gaussian distribution
* `--task-type {container,scan}`: Type of Task(s) to store the generated Reports. Can either be 'container' or 'scan', default: 'container'.

### Example

`$ gvm-script --gmp-username name --gmp-password pass ssh --hostname <gsm> scripts/gen-random-reports.gmp.py -T 5 -r 4 -R 3 --hosts 10 --with-gauss`

---

## `gen-random-targets.gmp.py`

This script generates random task data and feeds it to a desired GSM database.

### Arguments

* `<host_number>`: number of dummy hosts to select from
* `<number>`: number of targets to be generated
* `'with-gauss'`: (optional), if you would like for the number of targets generated
    to be randomized on a Gaussian distribution

### Example

`$ gvm-script --gmp-username name --gmp-password pass ssh --hostname <gsm> scripts/gen-random-targets.gmp.py 3 40 with-gauss`

---

## `list-tasks.gmp.py`

Lists the tasks stored in an GSM Database

### Example

`$ gvm-script --gmp-username name --gmp-password pass ssh --hostname <gsm> scripts/list-tasks.gmp.py`

---

## `monthly-report.gmp.py`

This script will display all vulnerabilities from the hosts of the reports in a given month!

### Arguments

* `<month>`: month of the monthly report
* `<year>`: year of the monthly report
* `'with-tables'`: (optional), parameter to activate a verbose output of hosts.

### Example

`$ gvm-script --gmp-username name --gmp-password pass ssh --hostname <gsm> scripts/monthly-report.gmp.py 05 2019 with-tables`

---

## `monthly-report2.gmp.py`

This script will display all vulnerabilities from the hosts of the reports in a given month!

### Arguments

* `<month>`: month of the monthly report
* `<year>`: year of the monthly report

### Example

`$ gvm-script --gmp-username name --gmp-password pass ssh --hostname <gsm> scripts/monthly-report2.gmp.py 05 2019`

---

## `nvt-scan.gmp.py`

This script creates a new task with specific host and nvt!

### Arguments
* `<oid>`:   oid of the nvt
* `<target>`: scan target.

### Example

`$ gvm-script --gmp-username name --gmp-password pass ssh --hostname <gsm> 1.3.6.1.4.1.25623.1.0.106223 localhost`

---

## `pdf-report.gmp.py`

This script requests the given report and saves it as a pdf file locally.

### Arguments

* `<report_id>`: ID of the report
* `<pdf_filename>`: (optional), pdf file name

### Example

`$ gvm-script --gmp-username name --gmp-password pass ssh --hostname <gsm> scripts/pdf-report.gmp.py <report_id> <pdf_file>`

---

## `scan-new-system.gmp.py`

This script starts a new scan on the given host.

### Arguments

* `<host_ip>`  IP Address of the host system

### Example

`$ gvm-script --gmp-username name --gmp-password pass ssh --hostname <gsm> scripts/scan-new-system.gmp.py <host_ip>`

---

## `send-delta-emails.gmp.py`

This script, once started, will continuously send delta reports via email for selected tasks. The routine follows this procedure:

Every `<interval>` minutes do:
* Get all tasks where the tag `<task_tag>` is attached.
* For each of these tasks get the finished reports:
  * If less than 2 reports, continue with next task
  * If latest report has tag "delta_alert_sent", continue with next task
  * Create a CSV report from the delta of latest vs. previous report where filtered for only the new results.
  * Send the CSV as an attachment to the configured email address.

> You may edit the scripts hardcoded variables like `from_address`, `to_address`, etc.

### Example

`$ gvm-script --gmp-username name --gmp-password pass ssh --hostname <gsm> scripts/send-delta-emails.gmp.py`

---

## `send-schedules.gmp.py`

This script pulls schedule data from an xml document and feeds it to a desired GSM.

### Arguments

* `<xml_doc>`:   .xml file containing schedules

### Example

`$ gvm-script --gmp-username name --gmp-password pass ssh --hostname <gsm> scripts/send-schedules.gmp.py example_file.xml`

---

## `send-targets.gmp.py`

This script pulls target data from an xml document and feeds it to a desired GSM.

### Arguments

* `<xml_doc>`:   .xml file containing schedules

### Example

`$ gvm-script --gmp-username name --gmp-password pass ssh --hostname <gsm> scripts/send-targets.gmp.py example_file.xml`

---

## `send-tasks.gmp.py`

This script pulls tasks data from an xml document and feeds it to a desired GSM.

### Arguments

* `<xml_doc>`:   .xml file containing schedules

### Example

`$ gvm-script --gmp-username name --gmp-password pass ssh --hostname <gsm> scripts/send-tasks.gmp.py example_file.xml`

---

## `start-alert-scan.gmp.py`

This script makes an alert scan and sends the report via email.

### Arguments

* `<sender_email>`:      E-Mail of the sender
* `<receiver_email>`:    E-Mail of the receiver

### Example

`$ gvm-script --gmp-username name --gmp-password pass ssh --hostname <gsm> scripts/start-alert-scan.gmp.py <sender_email> <receiver_email>`

---

## `start-multiple-alerts-scan.gmp.py`

This script makes an alert scan and sends the report via email.

### Arguments

* `<sender_email>`:      E-Mail of the sender
* `<receiver_email>`:    E-Mail of the receiver

### Example

`$ gvm-script --gmp-username name --gmp-password pass ssh --hostname <gsm> scripts/start-multiple-alerts-scan.gmp.py <sender_email> <receiver_email>`

---

## `start-nvt-scan.gmp.py`

This script creates a new task (if the target is not existing) with specific host and nvt!

### Arguments
* `<oid>`:   oid of the nvt
* `<target>`: scan target.

### Example

`$ gvm-script --gmp-username name --gmp-password pass ssh --hostname <gsm> scripts/start-nvt-scan.gmp.py 1.3.6.1.4.1.25623.1.0.106223 localhost`

---

## `sync-assets.gmp.py`

This script reads asset data from a csv file and sync it with the gsm.

### Arguments

* `<csv_file>`:    should contain a table of IP-addresses with an optional a comment

### Example

`$ gvm-script --gmp-username name --gmp-password pass ssh --hostname <gsm> scripts/sync-assets.gmp.py <csv_file>`

---

## `update-task-target.gmp.py`

This script will update target hosts information for a desired task.

### Arguments

* `<hosts_file>`:   .csv file containing desired target hosts separated by ','
* `<task_uuid>`:    uuid of task to be modified

### Example

`$ gvm-script --gmp-username name --gmp-password pass ssh --hostname <gsm> scripts/update-task-target.gmp.py hosts_file.csv "303fa0a6-aa9b-43c4-bac0-66ae0b2d1698"`

## `create-alerts-from-csv.gmp.py`

Creates alerts as specified in a csv-file. See alerts.csv for file format/contents.

### Example

`$ gvm-script --gmp-username *admin-user* --gmp-password *password* socket create-alerts-from-csv.gmp.py alerts.csv `

- For SMB Alerts use something like %N_%CT%z in the naming of the report, as shown in the example alerts.csv
- %N is the name for the object or the associated task for reports, %C is the creation date in the format YYYYMMDD, and %c is the creation time in the format HHMMSS.
- The script only support EMAIL and SMB Alerts, please note that the fields are quite different between the two alert types, but refer to the sample alerts.csv
- The CSV must starts with name, type (EMAIL or SMB). The remaining fields then depend on the type chosen, specifically:
- EMAIL; *senders email*, *recipients email*, *mail subject*, *message body*, *notice type* (0=Report in message 1=Simple Notice or 2=Attach Report), *Report Type* (e.g. CSV Results), *Status* (Done, Requested)
- SMB; *SMB Credentials*,*SMB Share Path*,*Report Name*, *Report Folder* (if not stored in the root of the share), *Not used*, *Report Type* (e.g. CSV Results), *Status* (Done, Requested)
- A simple example below with 1 EMAIL alert and 1 SMB Alert.
Alert_EMAIL_Stop,EMAIL,"martin@example.org","noc@example.org","Message Subject","Message Body",1,"CSV Results","Stop Requested"
Alert_SMB_Done,SMB,"Cred_Storage_SMB","\\smbserver\share","%N_%CT%cZ","Reports",,"CSV Results","Done"

**Note**: This script relies on credentials as/if specified in alerts.csv as well as a working SMTP server on the Greenbone primary server. If you're using SMB add the required credentials first using [create-credentials-from-csv.gmp.py](#create-credentials-from-csvgmppy).

## `create-schedules-from-csv.gmp.py`

Creates schedules as specified in a csv-file. See schedules.csv for file format/contents.

### Example
`$ gvm-script --gmp-username *admin-user* --gmp-password *password* socket create-schedules-from-csv.gmp.py ./schedules.csv`

**Note**: create schedules, then credentials, then targets, then tasks and make sure to use the same names between the input csv-files.
The sample files should serve as examples, however a short explanation of a VCALENDAR stream exported from Greenbone below¹.

```
Example Key:Value pair | Comment
---|---
BEGIN:VCALENDAR | Begin VCalendar Entry
VERSION:2.0 | iCalendar Version number
PRODID:-//Greenbone.net//NONSGML Greenbone Security Manager 23.1.0//EN | As generated by Greenbone replace with something else if you want to
BEGIN:VEVENT | Start of Vevent
DTSTART:20231125T220000Z | Start date
DURATION:PT1H | Duration of scan. PT0S means "Entire Operation". S = seconds, M = minutes, H = hours
RRULE:FREQ=HOURLY;INTERVAL=4 | Frequency; Yearly, Monthly, Weekly, Hourly. Optionally Interval withs same unit
DTSTAMP:20231125T212042Z | Date stamp created
END:VEVENT | End Vevent
END:VCALENDAR | End VCalendar Entry
```

¹ See also https://www.rfc-editor.org/rfc/rfc5545.txt Internet Calendaring and Scheduling Core Object Specification (iCalendar)

## `create-credentials-from-csv.gmp.py`

Creates credentials as specified in a csv-file. See credentials.csv for file format/contents.

### Example

`$ gvm-script --gmp-username *admin-user* --gmp-password *password* socket create-credentials-from-csv.gmp.py ./credentials.csv`

**Note**: create schedules, then credentials, then targets, then tasks and make sure to use the same names between the input csv-files.
The sample files should serve as an example.

## `create-filters-from-csv.gmp.py`

Creates filters as specified in a csv-file. See filters.csv for file format/contents.

### Example

`$ gvm-script --gmp-username *admin-user* --gmp-password *password* socket create-filters-from-csv.gmp.py ./filters.csv`

- CSV-file; filterType, filterName, filterDescription, filterTerm, where
    - filterType is one of Alert, Config (scan-config), Credential, Report, Scanner, Schedule, Target, or Task.
    - filterName is the name of the filter.
    - filterDescription is your description of the filter.
    - FilterTerm is the actual term used to define the filter, such as \~Labnet.

## `create-tags-from-csv.gmp.py`

Creates tags as specified in a csv-file. See tags.csv for file format/contents.

### Example

`$ gvm-script --gmp-username *admin-user* --gmp-password *password* socket create-tags-from-csv.gmp.py ./tags.csv`

- May contain up to 10 resources to assign to tag. Currently only creates tags for Credential, Target, and Tasks
- Use tag:*searchforthis* as filter. Example: *tag:bsecure*
- Will add reports when I've figured out if tags are really dynamic and a filter will do it for new reports.

## `create-targets-from-csv.gmp.py`

Creates targets as specified in a csv-file. See targets.csv for file format/contents.

### Example

`$ gvm-script --gmp-username *admin-user* --gmp-password *password* socket create-targets-from-csv.gmp.py ./targets.csv`

- Alive test can be:

```
No | Alive Test | Notes
---|---|---
1 | Scan Config Default | ICMP Ping is used by default with the Built-in Scan Configurations
2 | ICMP Ping | ICMP echo request and echo reply messages
3 | TCP-ACK Service Ping | Sends TCP packets with only the ACK bit set. Target is required by [RFC 793](http://www.rfc-editor.org/rfc/rfc793.txt) to respond with a RST packet
4 | TCP-SYN Service Ping | SYN only scans (never sends an ACK even if target replies with SYN/ACK)
5 | ICMP & TCP-ACK Service Ping | ICMP & TCP-ACK tests combined
6 | ICMP & ARP Ping | ICMP Ping & sends a broadcast ARP request to solicit a reply from the host that uses the specified IP address
7 | TCP-ACK Service & ARP Ping | TCP-ACK and ARP Ping combined
8 | ICMP, TCP-ACK Service & ARP Ping | ICMP, TCP-ACK, and ARP Ping combined
9 | Consider Alive | Consider the target alive. This may take considerably longer to finish.
```

## `create-tasks-from-csv.gmp.py`

Creates tasks as specified in a csv-file. See tasks.csv for file format/contents

### Example

`$ gvm-script --gmp-username *admin-user* --gmp-password *password* socket create-tasks-from-csv.gmp.py ./task.csv`

- Change Hosts Scan Ordering by changing #5 within CSV to Random, Sequential or Reverse in script.
- Specify up to 5 alerts in CSV, blanks will be discarded.

**Note**: Make sure that all other configurations that the tasks may rely on are already created, including alerts, schedules, credentials, and targets,
in other words if it is referenced in tasks.csv it must already exist.

## `empty-trash.gmp.py`

- Does what is says on the tin, empties the trashcan in Greenbone.
- Use it when you're testing like crazy and have a trashcan with ~ a gazillion objects
- You can also just use `gvm-cli --gmp-username *admin-user* --gmp-password *password* socket --pretty --xml "<empty_trashcan/>"`

## `export-csv-report.gmp.py`

Requests the report specified and exports it as a csv formatted report locally.

### Example
`$ gvm-script --gmp-username *admin-user* --gmp-password *password* socket export-csv-report.gmp.py *report_uuid* ./output.csv`

- Get the *report_uuid* with list-reports.gmp.py or find it in the UI. If the output is not specified it will be named *report_uuid.csv*
- Note the only changes to this script is an added ignore_pagination=True, details=True to get the full report.

## `export-pdf-report.gmp.py`

Requests the report specified and exports it as a pdf formatted report locally.

### Example

`$ gvm-script --gmp-username *admin-user* --gmp-password *password* socket export-pdf-report.gmp.py *report_uuid* ./output.pdf`

- Get the *report_uuid* with list-reports.gmp.py or find it in the UI. If the output is not specified it will be named *report_uuid.pdf*

**Note**: the only changes to this script is an added ignore_pagination=True, details=True to get the full report.

## `list-alerts.gmp.py`

Lists all alerts configured with name and uuid.

### Example

`$ gvm-script --gmp-username *admin-user* --gmp-password *password* socket list-alerts.gmp.py`

## `list-credentials.gmp.py`

Lists all credentials configured with name and uuid.

`$ gvm-script --gmp-username *admin-user* --gmp-password *password* socket list-credentials.gmp.py`

Returns Credential uuid, Name, Type, & if insecure use is allowed

## `list-feeds.gmp.py`

Lists feeds and their status.

### Example

`$ gvm-script --gmp-username *admin-user* --gmp-password *password* socket list-feeds.gmp.py`

## `list-filters.gmp.py`

Lists filters.

### Example
`$ gvm-script --gmp-username *admin-user* --gmp-password *password* socket list-filters.gmp.py`

Returns Filter Name, uuid, type, and the term (filter)

## `list-groups.gmp.py`

Lists all groups

### Example

`$ gvm-script --gmp-username *admin-user* --gmp-password *password* socket list-groups.gmp.py`

Returns Group Name, uuid, members

## `list-policies.gmp.py`

Lists compliance policies.

### Example

`$ gvm-script --gmp-username *admin-user* --gmp-password *password* socket list-policies.gmp.py`

## `list-portlists.gmp.py`

Lists port lists.

### Example

`$ gvm-script --gmp-username *admin-user* --gmp-password *password* socket list-portlists.gmp.py`

## `list-report-formats.gmp.py`

Lists all report formats with name and uuid.

### Example
`$ gvm-script --gmp-username *admin-user* --gmp-password *password* socket list-report-formats.gmp.py`

## `list-reports.gmp.py`

Lists all reports that have specified status

### Example
`$ gvm-script --gmp-username *admin-user* --gmp-password *password* socket list-reports.gmp.py *Status*`

where status is "All", "Requested", "Queued", "Interrupted", "Running", "Stop Requested", "Stopped", or "Done"

- Case matters, so "Done" or "Stopped" will work while "done" or "stopped" will not.
- Script now shows, in percentage, how far the scan/report is.
- There are no reports generated before at least one scan task has been started.

## `list-roles.gmp.py`

Lists all roles

### Example
`$ gvm-script --gmp-username *admin-user* --gmp-password *password* socket list-roles.gmp.py`

Returns Role Name, uuid, members

## `list-scan-configs.gmp.py`

Lists all scan configs.

### Example

`$ gvm-script --gmp-username *admin-user* --gmp-password *password* socket list-scan-configs.gmp.py`

## `list-scanners.gmp.py`

Lists all scanners currently configured.

### Example

`$ gvm-script --gmp-username *admin-user* --gmp-password *password* socket list-scanners.gmp.py`

Returns the scanners Name, uuid, & the host on which it resides (note CVE scanner does not return a host and sockets are local)

## `list-schedules.gmp.py`

Lists all schedules configured with name, uuid, timezone, and iCalendar information.

### Example

`$ gvm-script --gmp-username *admin-user* --gmp-password *password* socket list-schedules.gmp.py`

## `list-tags.gmp.py`

Lists all tags currently configured.

### Example

`$ gvm-script --gmp-username *admin-user* --gmp-password *password* socket list-tags.gmp.py`

Returns Tag name, uuid, Modified Date, Value, Type, and Count of ressources assigned to tag.

## `list-targets.gmp.py`

Lists all targets currently configured.

### Example

`$ gvm-script --gmp-username *admin-user* --gmp-password *password* socket list-targets.gmp.py`

- No targets configured by default, however using the provided files in this repo, you should now have a few (5).
- Returns targets Name, uuid, number of Hosts, and credentials (SSH, SMB, ESXi, & SNMP Credentials)

## `list-tickets.gmp.py`

Lists all tickets created

### Example

`$ gvm-script --gmp-username *admin-user* --gmp-password *password* socket list-tickets.gmp.py`

Returns the tickets name, Host, Associated Task, Status, and Note (depending on status either Open-, Fixed-, or Closed note).

## `list-users.gmp.py`

Lists all users

### Example

`$ gvm-script --gmp-username *admin-user* --gmp-password *password* socket list-users.gmp.py`

Returns user Name, uuid, role, groups

¹ The default order is "None" which equals sequential, meaning that if this field is empty scanning will be sequential as it will be if specifically set to sequential. Possible results are None, Sequential, Reverse, or Random.

## `start-scans-from-csv.gmp.py`

Starts scans (tasks) specified in csv file

### Example

`$ gvm-script --gmp-username *admin-user* --gmp-password *password* socket start-scans-from-csv.gmp.py *csv-file with task names*`

Returns the number of tasks started.

## `stop-all-scans.gmp.py`

Stops scans (tasks) that are in status running, queued, or requested

### Example

`$ gvm-script --gmp-username *admin-user* --gmp-password *password* socket stop-all-scans.gmp.py`

- Stops all scans
- Returns the number of tasks stopped.

## `stop-scans-from-csv.gmp.py`

Stops scans (tasks) specified in csv file

### Example

`$ gvm-script --gmp-username *admin-user* --gmp-password *password* socket stop-scans-from-csv.gmp.py *csv-file with task names*`

- Stops the tasks specified in the file (example startscan.csv works for both scripts)
- Returns the number of tasks stopped.
