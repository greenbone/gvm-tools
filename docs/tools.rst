.. _tools:

Provided Tools
==============

Currently, :program:`gvm-tools` ships with three console line interface programs.

* :ref:`gvm-cli <gvm_cli>`
* :ref:`gvm-pyshell <gvm_pyshell>`
* :ref:`gvm-script <gvm_script>`

All of these programs are clients to communicate either via
:term:`GMP (Greenbone Management Protocol) <GMP>`
or :term:`OSP (Open Scanner Protocol) <OSP>`.

.. _connection_types:

Currently three different connection types are supported:

  * TLS - *tls*
  * SSH - *ssh*
  * Unix Domain socket - *socket*

The user has to decide to use one of these connection types establish a
communication channel. Most of the time the **socket** connection should be
chosen. The other connection types require some setup and possible adjustments
at the server side.

All tools take several arguments and parameters. :program:`gvm-tools` allows
setting defaults for most of these in a configuration file. See :doc:`config`
for details about the possible settings and capabilities.

.. _gvm_cli:

gvm-cli
-------

:program:`gvm-cli` is a low level tool which offers sending and receiving of
commands and responses for the XML-based :term:`GMP (Greenbone Management
Protocol) <GMP>` and :term:`OSP (Open Scanner Protocol) <OSP>` directly via the
command line. It's intended for simple scripting via the shell.

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


.. _gvm_pyshell:

gvm-pyshell
-----------

.. _gvm_script:

gvm-script
----------

.. versionadded:: 2.0

.. note:: :program:`gvm-script` is only available with gvm-tools version 2.0 and
  later
