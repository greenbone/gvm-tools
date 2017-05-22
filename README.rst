================
GVM-Tools
================

.. contents:: Table of contents

Introduction
~~~~~~~~~~~~

*GVM-Tools* are comprised of three clients and one library.
The proper purpose for this tools is simply communication with some
GVM (Greenbone Vulnerability Manager) over GMP (Greenbone Management Protocol) or OSP (Open Scanner Protocol).

Current Version: 0.2.dev1

Installing
~~~~~~~~~~~~


To install it, after downloading the repository, you can use ``pip`` like that::

    pip install .

Clients
~~~~~~~
Currently there are three different clients to communicate with the GVM.
Only the gvm-dialog is under development and not accessible.
All clients have the ability to build a connection in various ways.

These three ways are:

* Unix Socket
* TLS Connection
* SSH Connection

gvm-cli
#######
This little tool sends plain GMP commands and prints the result to the standard output. When program is used without any parameters, it asks for an XML command and user credentials.

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
