.. _scripting:

Scripting
=========

.. _xml_scripting:

XML Scripting
-------------

.. note:: XML scripting via :program:`gvm-cli` should only be considered for
  simpler use cases. :ref:`GMP or OSP scripts <gvm_scripting>` are often more
  powerful and easier to write.

Scripting via :program:`gvm-cli` is directly based on the `Greenbone Management
Protocol <https://docs.greenbone.net/API/GMP/gmp.html>`_ and `Open Scanner
Protocol <https://docs.greenbone.net/API/OSP/osp.html>`_. Both protocols make
use of XML command requests and corresponding responses.

A typical example for using the GMP protocol is the automatic scan of a new
system. Below we assume that an Intrusion Detection System is in use that
monitors the systems in the DMZ and immediately discovers new systems and
unusual TCP ports not used up to now. If such an event is being discovered,
the IDS should automatically initiate a scan of the new system. This can be
done with the help of a script.

Starting point is the IP address of the new suspected system. For this IP
address, a target needs to be created in the :term:`GSM`.
If the IP address is saved in the environment variable :envvar:`IPADDRESS` by
the IDS, the respective target can be created with the following command:

.. code-block:: shell

  > gvm-cli socket --xml "<create_target><name>Suspect Host</name><hosts>"$IPADDRESS"</hosts></create_target>"
  <create_target_response status="201" status_text="OK, resource created" id="e5adc10c-71d0-49fe-aacf-a442ee31d387"/>

See :command:`create_target` command for all `details
<https://docs.greenbone.net/API/OMP/omp.html#command_create_target>`__.


Now a task can be created using the default *Full and Fast* scan config with
UUID :token:`daba56c8-73ec-11df-a475-002264764cea` and the previously generated
target.

.. code-block:: shell

  > gvm-cli socket --xml "<create_task><name>Scan Suspect Host</name><target id=\"e5adc10c-71d0-49fe-aacf-a442ee31d387\"/><config id=\"daba56c8-73ec-11df-a475-002264764cea\"/><scanner id=\"08b69003-5fc2-4037-a479-93b440211c73\"/></create_task>"
  <create_task_response status="201" status_text="OK, resource created" id="7249a07c-03e1-4197-99e4-a3a9ab5b7c3b"/>

See :command:`create_task` command for all `details
<https://docs.greenbone.net/API/OMP/omp.html#command_create_task>`__.


Afterwards the task can be started using the UUID return from the last response.

.. code-block:: shell

  > gvm-cli socket --xml "<start_task task_id=\"7249a07c-03e1-4197-99e4-a3a9ab5b7c3b\"/>"
  <start_task_response status="202" status_text="OK, request submitted"><report_id>0f9ea6ca-abf5-4139-a772-cb68937cdfbb</report_id></start_task_response>

See :command:`start_task` command for all `details
<https://docs.greenbone.net/API/OMP/omp.html#command_start_task>`__.


Now the task is running. The response returned the UUID of the report which will
contain the results of the scan. The current status of the task can be displayed
with the following command:

.. code-block:: shell

  > gvm-cli socket --xml "<get_tasks task_id=\"7249a07c-03e1-4197-99e4-a3a9ab5b7c3b\"/>"
  <get_tasks_response status="200" status_text="OK">
  ...
  <status>Running</status><progress>98 ... </progress>
  ...
  <get_tasks_response/>

See :command:`get_tasks` command for all `details
<https://docs.greenbone.net/API/OMP/omp.html#command_get_tasks>`__.


As soon as the scan is completed, the full report is available and can be
displayed via

.. code-block:: shell

  > gvm-cli socket --xml "<get_reports report_id=\"0f9ea6ca-abf5-4139-a772-cb68937cdfbb\"/>"
  <get_reports_response status="200" status_text="OK"><report type="scan" id="0f9ea6ca-abf5-4139-a772-cb68937cdfbb" format_id="a994b278-1f62-11e1-96ac-406186ea4fc5" extension="xml" content_type="text/xml">
  ...
  </get_reports_response>

See :command:`get_reports` command for all `details
<https://docs.greenbone.net/API/OMP/omp.html#command_get_reports>`__.


Additionally, the report could be downloaded in a specific report format instead
of plain XML. All report formats can be listed with

.. code-block:: shell

  > gvm-cli socket --xml "<get_report_formats/>"
  <get_report_formats_response status="200" status_text="OK"><report_format id="5057e5cc-b825-11e4-9d0e-28d24461215b">
  ...
  </get_report_formats_response>

See :command:`get_report_formats` command for all `details
<https://docs.greenbone.net/API/OMP/omp.html#command_get_report_formats>`__.

E.g. to download the report in a PDF format the following command can be used:

.. code-block:: shell

  > gvm-cli socket --xml "<get_reports report_id=\"0f9ea6ca-abf5-4139-a772-cb68937cdfbb\" format_id=\"c402cc3e-b531-11e1-9163-406186ea4fc5\"/>"

.. note:: Please be aware that the PDF is returned as `base64 encoded
  <https://en.wikipedia.org/wiki/Base64>`_ content of the
  *<get_report_response><report>* element in the XML response.


.. _gvm_scripting:

GVM Scripts
-----------

.. versionchanged:: 2.0

Scripting of :term:`GMP (Greenbone Management Protocol) <GMP>` and :term:`OSP
(Open Scanner Protocol) <OSP>` via :program:`gvm-script` or interactively via
:program:`gvm-pyshell` is based on the `python-gvm`_ library. Please take a look
at `python-gvm`_ for further details about the API.

.. note:: By convention, scripts using :term:`GMP` are called *GMP scripts* and
  are files with a :file:`.gmp` ending. Accordingly, *OSP scripts* with the
  ending :file:`.osp` are using :term:`OSP`. Technically both protocols could be
  used in one single script file.

The following sections are using the same example as in
:ref:`XML scripting <xml_scripting>` where we assume that an Intrusion Detection
System is in use that monitors the systems in the DMZ and immediately discovers
new systems and unusual TCP ports not used up until now. The IDS will provide the
IP address of a new system to the GMP script.

We start with defining the function to be called when the script is
started. For this, we add the following code to a file named
:file:`scan-new-system.gmp`.

.. code-block:: python3

  if __name__ == '__gmp__':
    main(gmp, args)

This ensures the script is only called when being run as a GMP script. The
:dfn:`gmp` and :dfn:`args` variables are provided by :program:`gvm-cli` or
:program:`gvm-pyshell`. :dfn:`args` contains arguments for the script, e.g. the
username and password for the GMP connection. Most important for our example
script, it contains the argv property with the list of additional script
specific arguments. The :dfn:`gmp` variable contains a connected and
authenticated instance of a `Greenbone Management Protocol class
<https://python-gvm.readthedocs.io/en/latest/api/protocols.html#gvm.protocols.gmpv7.Gmp>`_.

The main function begins with the following code lines:

.. code-block:: python3

  def main(gmp, args):
    # check if IP address is provided to the script
    # argv[0] contains the script name
    if len(args.argv) <= 1:
      print('Missing IP address argument')
      return 1

    ipaddress = args.argv[1]

The main function stores the first argument passed to the script as :envvar:`ipaddress`
variable. Going further, we add the logic to create a target, create a new scan
task for the target, start the task and print the corresponding report ID.

.. code-block:: python3

    ipaddress = args.argv[1]

    target_id = create_target(gmp, ipaddress)

    full_and_fast_scan_config_id = 'daba56c8-73ec-11df-a475-002264764cea'
    openvas_scanner_id = '08b69003-5fc2-4037-a479-93b440211c73'
    task_id = create_task(
        gmp,
        ipaddress,
        target_id,
        full_and_fast_scan_config_id,
        openvas_scanner_id,
    )

    report_id = start_task(gmp, task_id)

    print(
        "Started scan of host {}. Corresponding report ID is {}".format(
            ipaddress, report_id
        )
    )

For creating the target from an IP address (DNS name is also possible) the
following is used. Since target names must be unique, the current datetime in
ISO 8601 format (YYYY-MM-DDTHH:MM:SS.mmmmmm) is added.

.. code-block:: python3

  def create_target(gmp, ipaddress):
      import datetime

      # create a unique name by adding the current datetime
      name = "Suspect Host {} {}".format(ipaddress, str(datetime.datetime.now()))
      response = gmp.create_target(name=name, hosts=[ipaddress])
      return response.get('id')


The function for creating the task is defined as:

.. code-block:: python3

  def create_task(gmp, ipaddress, target_id, scan_config_id, scanner_id):
      name = "Scan Suspect Host {}".format(ipaddress)
      response = gmp.create_task(
          name=name,
          config_id=scan_config_id,
          target_id=target_id,
          scanner_id=scanner_id,
      )
      return response.get('id')


And finally, the function to start the task and get the report ID:

.. code-block:: python3

  def start_task(gmp, task_id):
      response = gmp.start_task(task_id)
      # the response is
      # <start_task_response><report_id>id</report_id></start_task_response>
      return response[0].text


For getting a PDF document of the report, a second script :file:`pdf-report.gmp`
can be used.

.. code-block:: python3

  from base64 import b64decode
  from pathlib import Path


  def main(gmp, args):
      # check if report id and PDF filename are provided to the script
      # argv[0] contains the script name
      if len(args.argv) <= 2:
          print('Please provide report ID and PDF file name as script arguments')
          return 1

      report_id = args.argv[1]
      pdf_filename = args.argv[2]

      pdf_report_format_id = "c402cc3e-b531-11e1-9163-406186ea4fc5"
      response = gmp.get_report(
          report_id=report_id, report_format_id=pdf_report_format_id
      )

      report_element = response[0]
      # get the full content of the report element
      content = "".join(report_element.itertext())

      # convert content to 8-bit ASCII bytes
      binary_base64_encoded_pdf = content.encode('ascii')
      # decode base64
      binary_pdf = b64decode(binary_base64_encoded_pdf)

      # write to file and support ~ in filename path
      pdf_path = Path(pdf_filename).expanduser()
      pdf_path.write_bytes(binary_pdf)

      print('Done.')


  if __name__ == '__gmp__':
      main(gmp, args)



.. _python-gvm: https://python-gvm.readthedocs.io/

Example Scripts
---------------

All example scripts can be found at `GitHub
<https://github.com/greenbone/gvm-tools/tree/master/scripts>`_
