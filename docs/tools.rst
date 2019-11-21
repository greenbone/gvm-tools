.. _tools:

Provided Tools
==============

Currently, :program:`gvm-tools` comes with three command line interface
programs:

* :ref:`gvm-cli <gvm_cli>`
* :ref:`gvm-script <gvm_script>`
* :ref:`gvm-pyshell <gvm_pyshell>`

All of these programs are clients communicating either via
:term:`Greenbone Management Protocol (GMP) <GMP>`
or :term:`Open Scanner Protocol (OSP) <OSP>`. The
:ref:`connection <connection_types>` is established using a
:ref:`TLS <tls_connection_type>`, :ref:`SSH <ssh_connection_type>` or
:ref:`Unix Domain Socket <socket_connection_type>` communication channel.

All tools take several arguments and parameters. :program:`gvm-tools` allows
setting defaults for most of these in a configuration file. See :doc:`config`
for details about the possible settings and capabilities.

.. _gvm_cli:

gvm-cli
-------

:program:`gvm-cli` is a low level tool which offers sending and receiving 
commands and responses for the XML-based :term:`GMP <GMP>` and :term:`OSP <OSP>` 
directly via the command line. It is intended for :ref:`simple scripting <xml_scripting>`
via shell.

.. code-block:: shell

  > gvm-cli --help
  usage: gvm-cli [-h] [-c [CONFIG]]
                [--log [{DEBUG,INFO,WARNING,ERROR,CRITICAL}]]
                [--timeout TIMEOUT] [--gmp-username GMP_USERNAME]
                [--gmp-password GMP_PASSWORD] [-V]
                CONNECTION_TYPE ...

  optional arguments:
    -h, --help            show this help message and exit
    -c [CONFIG], --config [CONFIG]
                          Configuration file path (default: ~/.config/gvm-
                          tools.conf)
    --log [{DEBUG,INFO,WARNING,ERROR,CRITICAL}]
                          Activate logging (default level: None)
    --timeout TIMEOUT     Response timeout in seconds, or -1 to wait
                          indefinitely (default: 60)
    --gmp-username GMP_USERNAME
                          Username for GMP service (default: '')
    --gmp-password GMP_PASSWORD
                          Password for GMP service (default: '')
    -V, --version         Show version information and exit

  connections:
    valid connection types

    CONNECTION_TYPE       Connection type to use
      ssh                 Use SSH to connect to service
      tls                 Use TLS secured connection to connect to service
      socket              Use UNIX Domain socket to connect to service


Examples:

.. code-block:: shell

  > gvm-cli socket --xml "<get_version/>"
  <get_version_response status="200" status_text="OK"><version>7.0</version></get_version_response>

  > gvm-cli socket --xml "<get_tasks/>"
  <get_tasks_response status="200" status_text="OK">
  ...
  </get_tasks_response>

  > gvm-cli socket < commands.xml


.. _gvm_script:

gvm-script
----------

.. versionadded:: 2.0

:program:`gvm-script` allows running :ref:`gvm scripts <gvm_scripting>`
which are Python based scripts calling the `Python based GVM API
<https://python-gvm.readthedocs.io/en/latest/>`_. Depending on the
:command:`--protocol` argument a global gmp or osp object is passed to the
script.

.. note:: :program:`gvm-script` is only available with :program:`gvm-tools` version 2.0 and beyond.

.. code-block:: shell

  usage: gvm-script [-h] [-c [CONFIG]]
                    [--log [{DEBUG,INFO,WARNING,ERROR,CRITICAL}]]
                    [--timeout TIMEOUT] [--gmp-username GMP_USERNAME]
                    [--gmp-password GMP_PASSWORD] [-V] [--protocol {GMP,OSP}]
                    CONNECTION_TYPE ...

  optional arguments:
    -h, --help            show this help message and exit
    -c [CONFIG], --config [CONFIG]
                          Configuration file path (default: ~/.config/gvm-
                          tools.conf)
    --log [{DEBUG,INFO,WARNING,ERROR,CRITICAL}]
                          Activate logging (default level: None)
    --timeout TIMEOUT     Response timeout in seconds, or -1 to wait
                          indefinitely (default: 60)
    --gmp-username GMP_USERNAME
                          Username for GMP service (default: '')
    --gmp-password GMP_PASSWORD
                          Password for GMP service (default: '')
    -V, --version         Show version information and exit
    --protocol {GMP,OSP}  Service protocol to use (default: GMP)

  connections:
    valid connection types

    CONNECTION_TYPE       Connection type to use
      ssh                 Use SSH to connect to service
      tls                 Use TLS secured connection to connect to service
      socket              Use UNIX Domain socket to connect to service


.. _gvm_pyshell:

gvm-pyshell
-----------

:program:`gvm-pyshell` is a tool to use the `Python GVM API
<https://python-gvm.readthedocs.io/en/latest/>`_ interactively. Running the tool
will open a Python interpreter in the `interactive mode
<https://docs.python.org/3/tutorial/interpreter.html#interactive-mode>`_
providing a global gmp or osp object depending on the :command:`--protocol`
argument.

The interactive shell can be exited with:

  * :kbd:`Ctrl + D` on Linux  or
  * :kbd:`Ctrl + Z` on Windows

.. code-block:: shell

  > gvm-pyshell --help
  usage: gvm-pyshell [-h] [-c [CONFIG]]
                    [--log [{DEBUG,INFO,WARNING,ERROR,CRITICAL}]]
                    [--timeout TIMEOUT] [--gmp-username GMP_USERNAME]
                    [--gmp-password GMP_PASSWORD] [-V] [--protocol {GMP,OSP}]
                    CONNECTION_TYPE ...

  optional arguments:
    -h, --help            show this help message and exit
    -c [CONFIG], --config [CONFIG]
                          Configuration file path (default: ~/.config/gvm-
                          tools.conf)
    --log [{DEBUG,INFO,WARNING,ERROR,CRITICAL}]
                          Activate logging (default level: None)
    --timeout TIMEOUT     Response timeout in seconds, or -1 to wait
                          indefinitely (default: 60)
    --gmp-username GMP_USERNAME
                          Username for GMP service (default: '')
    --gmp-password GMP_PASSWORD
                          Password for GMP service (default: '')
    -V, --version         Show version information and exit
    --protocol {GMP,OSP}  Service protocol to use (default: GMP)

  connections:
    valid connection types

    CONNECTION_TYPE       Connection type to use
      ssh                 Use SSH to connect to service
      tls                 Use TLS secured connection to connect to service
      socket              Use UNIX Domain socket to connect to service


Example:

.. code-block:: python

  > gvm-pyshell socket
  GVM Interactive Console 2.0.0 API 1.0.0. Type "help" to get information about functionality.
  >>> gmp.get_protocol_version()
  '7'
  >>> gmp.get_version().get('status')
  '200'
  >>> gmp.get_version()[0].text
  '7.0'
  >>> [t.find('name').text for t in tasks.xpath('task')]
  ['Scan Task', 'Simple Scan', 'Host Discovery']
