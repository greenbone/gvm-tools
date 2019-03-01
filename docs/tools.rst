.. _tools:

Provided Tools
==============

Currently :program:`gvm-tools` ships with three console line interface programs.

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
  * Unix Socket - *socket*

The user has to decide to use one of these connection types establish a
communication channel. Most of the time the **socket** connection should be
chosen. The other connection types require some setup and possible adjustments
at the server side.

All tools take several arguments and parameters. :program:`gvm-tools` allows to
set defaults for most of these in a configuration file. See :doc:`config` for
details about the possible settings and capabilities.

.. _gvm_cli:

gvm-cli
-------

.. _gvm_pyshell:

gvm-pyshell
-----------

.. _gvm_script:

gvm-script
----------

.. versionadded:: 2.0

.. note:: :program:`gvm-script` is only available with gvm-tools version 2.0 and
  later
