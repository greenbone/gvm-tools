![Greenbone Logo](https://www.greenbone.net/wp-content/uploads/gb_logo_resilience_horizontal.png)

# Greenbone Vulnerability Management Tools

[![GitHub releases](https://img.shields.io/github/release/greenbone/gvm-tools.svg)](https://github.com/greenbone/gvm-tools/releases)
[![PyPI release](https://img.shields.io/pypi/v/gvm-tools.svg)](https://pypi.org/project/gvm-tools/)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/greenbone/gvm-tools/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/greenbone/gvm-tools/?branch=master)
[![code test coverage](https://codecov.io/gh/greenbone/gvm-tools/branch/master/graph/badge.svg)](https://codecov.io/gh/greenbone/gvm-tools)
[![CircleCI](https://circleci.com/gh/greenbone/gvm-tools/tree/master.svg?style=svg)](https://circleci.com/gh/greenbone/gvm-tools/tree/master)

The Greenbone Vulnerability Management Tools or gvm-tools in short
are a collection of tools that help with remote controlling a
Greenbone Security Manager (GSM) appliance and its underlying Greenbone
Vulnerability Manager (GVM). The tools essentially aid accessing the
communication protocols GMP (Greenbone Management Protocol) and OSP
(Open Scanner Protocol).

This module is comprised of interactive and non-interactive clients.
The programming language Python is supported directly for interactive scripting.
But it is also possible to issue remote GMP/OSP commands without programming in
Python.

## Table of Contents

* [Installation](#installation)
  * [Requirements](#requirements)
  * [Install using pip](#install-using-pip)
* [Usage](#usage)
  * [gvm-cli](#gvm-cli)
     * [Example program use](#example-program-use)
  * [gvm-pyshell](#gvm-pyshell)
     * [Example program use](#example-program-use-1)
     * [Example script](#example-script)
     * [More example scripts](#more-example-scripts)
* [Support](#support)
* [Maintainer](#maintainer)
* [Contributing](#contributing)
* [License](#license)

## Installation

### Requirements

Python 3.5 and later is supported.

### Install using pip

You can install the latest stable release of gvm-tools from the Python Package
Index using [pip](https://pip.pypa.io/):

    pip install gvm-tools

alternatively download or clone this repository and install the latest
development version:

    pip install .

## Usage

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
from the [python-gvm library](https://github.com/greenbone/python-gvm) and from
python3 itself. The scripts can be pre-loaded in the program through an
additional argument.

#### Example program use

Open script.gmp over TLS connection.

```
gvm-pyshell tls --hostname=127.0.0.1 script.gmp
```

Connect with given credentials and as unix socket. Opens an interactive
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
from gvmtools.helper import pretty_print
pretty_print(version)

# Retrieve all tasks
tasks = gmp.get_tasks()

# Get names of tasks
task_names = tasks.xpath('task/name/text()')
pretty_print(task_names)
```

#### More example scripts

There is a growing collection of gmp-scripts in the
["scripts/"](https://github.com/greenbone/python-gvm/master/scripts) folder.
Some of them might be exactly what you need and all of them help writing
your own gmp scripts.

## Support

For any question on the usage of gvm-tools or gmp scripts please use the
[Greenbone Community Portal](https://community.greenbone.net/c/gmp). If you
found a problem with the software, please
[create an issue](https://github.com/greenbone/gvm-tools/issues) on GitHub.

## Maintainer

This project is maintained by [Greenbone Networks GmbH](https://www.greenbone.net/).

## Contributing

Your contributions are highly appreciated. Please
[create a pull request](https://github.com/greenbone/gvm-tools/pulls) on GitHub.
For bigger changes, please discuss it first in the
[issues](https://github.com/greenbone/gvm-tools/issues).

For development you should use [pipenv](https://pipenv.readthedocs.io/en/latest/)
to keep you python packages separated in different environments. First install
pipenv via pip

    pip install --user pipenv

Afterwards run

    pipenv install --dev

in the checkout directory of gvm-tools (the directory containing the Pipfile) to
install all dependencies including the packages only required for development.

## License

Copyright (C) 2017-2018 [Greenbone Networks GmbH](https://www.greenbone.net/)

Licensed under the [GNU General Public License v3.0 or later](LICENSE).
