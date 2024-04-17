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

## `random-report-gen.gmp.py`

This script generates randomized report data.

### Arguments

* `<number of tasks>`:   number of tasks to be generated
* `<number of reports>`: number of reports per task
* `<number of results>`: number of results per report
* `<number of hosts>`:   number of randomized hosts to select from
* `'with-gauss'`: if you would like for the number of reports/task and results/report to be randomized along a Gaussian distribution

### Example

`$ gvm-script --gmp-username name --gmp-password pass ssh --hostname <gsm> scripts/random-report-gen.gmp.py 10 50 2500 256 with-gauss`

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
