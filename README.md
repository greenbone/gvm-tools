<img src="https://www.greenbone.net/wp-content/uploads/01_Logo-mit-Schriftzug_500px_on_white_horiz1.jpg" alt="Greenbone Logo" width="400px">

# Greenbone Vulnerability Management Tools

[![GitHub release](https://img.shields.io/github/release/greenbone/gvm-tools.svg)](https://github.com/greenbone/gvm-tools/releases)
[![PyPI](https://img.shields.io/pypi/v/gvm-tools.svg)](https://pypi.org/project/gvm-tools/)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/greenbone/gvm-tools/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/greenbone/gvm-tools/?branch=master)
[![codecov](https://codecov.io/gh/greenbone/gvm-tools/branch/master/graph/badge.svg)](https://codecov.io/gh/greenbone/gvm-tools)
[![CircleCI](https://circleci.com/gh/greenbone/gvm-tools/tree/master.svg?style=svg)](https://circleci.com/gh/greenbone/gvm-tools/tree/master)

## Introduction

The Greenbone Vulnerability Management Tools or GVM-Tools in short are a collection of tools that help with remote controlling a
Greenbone Security Manager (GSM) appliance and its underlying Greenbone
Vulnerability Manager (GVM). The tools essentially aid accessing the
communication protocols GMP (Greenbone Management Protocol) and OSP
(Open Scanner Protocol).

**Current Version: 1.4.1**

This module is comprised of interactive and non-interactive clients as
well as supporting libraries. The programming language Python is
supported directly for interactive scripting and library use. But it is
also possible to issue remote GMP/OSP commands without programming in
Python.

## Requirements

GVM-Tools requires Python >= 3 along with the following libraries:

    - python3-paramiko
    - python3-lxml
    - python3-dialog
    - python3-defusedxml

The file `requirements.txt` is used for CI tests to ensure the CI tests
happen in a defined known-good environment and are not affected by
sudden changes in the dependent modules.

Some scripts need additional requirements.

## Installing

You can install the latest stable release of gvm-tools from the Python Package Index using [pip](https://pip.pypa.io/):

    pip install gvm-tools

alternatively download or clone this repository and install the latest development version:

    pip install .

## Clients

There are several clients to communicate via GMP/OSP.

All clients have the ability to build a connection in various ways:

    * Unix Socket
    * TLS Connection
    * SSH Connection

### gvm-cli

This little tool sends plain GMP/OSP commands and prints the result to
the standard output. When the program is used without any parameters, it
asks for an XML command and for the user credentials.

#### Example program use

Returns the current version.

```
gvm-cli socket --xml "<get_version/>"
```

Returns the current version using a TLS connection with certificates.

```
gvm-cli tls --hostname 192.168.0.10 --port 1234 --certfile '/tmp/certs/cert.pem' --keyfile '/tmp/certs/key.pem' --cafile '/tmp/certs/cert.pem' --xml "<get_version/>"
```

Return all
tasks.

```
gvm-cli socket --xml "<commands><authenticate><credentials><username>myuser</username><password>mypass</password></credentials></authenticate><get_tasks/></commands>"
```

Reads a file with GMP commands and return the result.

```
gvm-cli socket --gmp-username foo --gmp-password bar < myfile.gmp
```

Note that `gvm-cli` will by default raise an exception when a command is
rejected by the server. If this kind of error handling is not desired, the
unparsed XML response can be requested using the `--raw` parameter:

```
gvm-cli socket --raw --xml "<authenticate/>"
```

### gvm-pyshell

This tool has a lot more features than the simple gvm-cli client. You
have the possibility to create your own custom scripts with commands
from the gvm-lib and from python3 itself. The scripts can be pre-loaded
in the program through an additional argument.

#### Example program use

Open script.gmp over TLS connection.

```
gvm-pyshell tls --hostname=127.0.0.1 script.gmp
```

Connect with given credentials and as unixsocket. Opens an interactive
shell.

```
gvm-pyshell socket --gmp-username=user --gmp-password=pass -i
```

Connect through SSH connection. Opens an interactive shell.

```
gvm-pyshell ssh --hostname=127.0.0.1 -i
```

#### Example script

```
# Retrieve current GMP version
version = gmp.get_version()

# Prints the XML in beautiful form
pretty(version)

# Retrieve all tasks
tasks = gmp.get_tasks()

# Get names of tasks
task_names = tasks.xpath('task/name/text()')
pretty(task_names)
```

#### More example scripts

There is a growing collection of gmp-scripts in the folder "scripts/".
Some of them might be exactly what you need and all of them help writing
your own gmp scripts.

### gvm-dialog

With gvm-dialog you'll get a terminal-based dialog.

This client is **experimental**.

Example:

```
gvm-dialog socket
```
