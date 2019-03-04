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
address a target needs to be created in the :term:`GSM`.
If the IP address is saved in the environment variable :envvar:`IPADDRESS` by
the IDS the respective target can be created with the following command:

.. code-block:: shell

  > gvm-cli socket --xml "<create_target><name>Suspect Host</name><hosts>"$IPADDRESS"</hosts></create_target>"
  <create_target_response status="201" status_text="OK, resource created" id="e5adc10c-71d0-49fe-aacf-a442ee31d387"/>

See :command:`create_target` command for all `details
<https://docs.greenbone.net/API/OMP/omp.html#command_create_target>`__.


Now a task can be created using the default *Full and Fast* scan config with
UUID :token:`daba56c8-73ec-11df-a475-002264764cea` and the previously generated
target.

.. code-block:: shell

  > gvm-cli socket --xml "<create_task><name>Scan Suspect Host</name><target id=\"e5adc10c-71d0-49fe-aacf-a442ee31d387\"/><config id=\"daba56c8-73ec-11df-a475-002264764cea\"/></create_task>" 
  <create_task_response status="201" status_text="OK, resource created" id="7249a07c-03e1-4197-99e4-a3a9ab5b7c3b"/>

See :command:`create_task` command for all `details
<https://docs.greenbone.net/API/OMP/omp.html#command_create_task>`__.


Afterwards the task can be stated using the UUID return from the last response.

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


Additionally the report could be downloaded in a specific report format instead
of plain XML. Therefore all report formats can be listed with

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

.. note:: Please be aware the PDF is returned as `base64 encoded
  <https://en.wikipedia.org/wiki/Base64>`_ content of the
  *<get_report_response><report>* element in the XML response.


.. _gvm_scripting:

GVM Scripts
-----------

Scripting of :term:`GMP (Greenbone Management Protocol) <GMP>` and :term:`OSP
(Open Scanner Protocol) <OSP>` via :program:`gvm-script` is based on the
`python-gvm <https://python-gvm.readthedocs.io/en/latest/>`_ library.

Example Scripts
---------------

All example scripts can be found at `GitHub
<https://github.com/greenbone/gvm-tools/tree/master/scripts>`_
