================
GVM-Tools
================

.. contents:: Table of contents

Introduction
~~~~~~~~~~~~

*GVM-Tools* is a collection of tools that help with remote controlling
a Greenbonse Security Manager (GSM) appliance and its underlying Greenbone
Vulnerability Manager (GVM). The tools essentially aid accessing
the communication protocols GMP (Greenbone Management Protocol) and
OSP (Open Scanner Protocol).

**Current Version: 1.1.0**

This module is comprised of interactive and non-interactive clients
as well as supporting libraries. The programming language Python
is supported directly for interactive scripting and library use.
But it is also possible to issue remote GMP/OSP commands without
programming in Python.

Installing
~~~~~~~~~~~~

To install it, after downloading the repository, you can use ``pip`` like that::

    pip install .

Otherwise you can use python itself to install it::

    # System
    python3 setup.py install

    # Local
    python3 setup.py install --user

Requirements
~~~~~~~~~~~~
- python3-paramiko
- python3-lxml
- python3-dialog

Some scripts need additional requirements.

Clients
~~~~~~~
There are several clients to communicate via GMP/OSP.

All clients have the ability to build a connection in various ways::

* Unix Socket
* TLS Connection
* SSH Connection

gvm-cli
#######
This little tool sends plain GMP/OSP commands and prints the result to the standard output. When the program is used without any parameters, it asks for an XML command and for the user credentials.

Example program use
-------------------
Returns the current version.

.. code-block:: bash

    gvm-cli --xml "<get_version/>"

Return all tasks.

.. code-block:: bash

    gvm-cli --xml "<commands><authenticate><credentials><username>myuser</username><password>mypass</password></credentials></authenticate><get_tasks/></commands>"


Reads a file with GMP commands and return the result.

.. code-block:: bash

    gvm-cli < myfile.gmp

gvm-pyshell
###########
This tool has a lot more features than the simple gvm-cli client. You have the possibility to create your own custom scripts with commands from the gvm-lib and from python3 itself. The scripts can be pre-loaded in the program through an additional argument.

Example program use
-------------------
Open script.gmp over TLS connection.

.. code-block:: bash

    gvm-pyshell tls --hostname=127.0.0.1 script.gmp

Connect with given credentials and as unixsocket. Opens an interactive shell.

.. code-block:: bash

    gvm-pyshell socket --gmp-username=user --gmp-password=pass -i

Connect through SSH connection. Opens an interactive shell.

.. code-block:: bash

    gvm-pyshell ssh --hostname=127.0.0.1 -i


Example script
---------------

.. code-block:: python

    # Retrieve current GMP version
    version = gmp.get_version()

    # Prints the XML in beautiful form
    pretty(version)

    # Retrieve all tasks
    tasks = gmp.get_tasks()

    # Get names of tasks
    task_names = tasks.xpath('task/name/text()')
    pretty(task_names)

gvm-dialog
##########
With gvm-dialog you'll get a terminal-based dialog.

This client is **experimental**.

Example:

.. code-block:: bash

    gvm-dialog socket