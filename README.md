![Greenbone Logo](https://www.greenbone.net/wp-content/uploads/gb_new-logo_horizontal_rgb_small.png)

# Greenbone Vulnerability Management Tools <!-- omit in toc -->
[![GitHub releases](https://img.shields.io/github/release-pre/greenbone/gvm-tools.svg)](https://github.com/greenbone/gvm-tools/releases)
[![PyPI release](https://img.shields.io/pypi/v/gvm-tools.svg)](https://pypi.org/project/gvm-tools/)
[![code test coverage](https://codecov.io/gh/greenbone/gvm-tools/branch/master/graph/badge.svg)](https://codecov.io/gh/greenbone/gvm-tools)
[![Build and test](https://github.com/greenbone/gvm-tools/actions/workflows/ci-python.yml/badge.svg)](https://github.com/greenbone/gvm-tools/actions/workflows/ci-python.yml)

The Greenbone Vulnerability Management Tools `gvm-tools` are a collection of
tools that help with remote controlling a Greenbone Enterprise Appliance and
Greenbone Community Edition installations. The tools aid in accessing the
communication protocols GMP (Greenbone Management Protocol) and OSP
(Open Scanner Protocol).

This module is comprised of interactive and non-interactive clients.
The programming language Python is supported directly for interactive scripting.
But it is also possible to issue remote GMP/OSP commands without programming in
Python.


## Table of Contents <!-- omit in toc -->
- [Documentation](#documentation)
- [Installation](#installation)
  - [Requirements](#requirements)
  - [Version](#version)
- [Usage](#usage)
  - [gvm-cli](#gvm-cli)
    - [Examples](#examples)
  - [gvm-script](#gvm-script)
    - [Example script](#example-script)
    - [More example scripts](#more-example-scripts)
  - [gvm-pyshell](#gvm-pyshell)
    - [Example program use](#example-program-use)
- [Support](#support)
- [Maintainer](#maintainer)
- [Contributing](#contributing)
- [License](#license)

## Documentation

The documentation for `gvm-tools` can be found at
[https://greenbone.github.io/gvm-tools/](https://greenbone.github.io/gvm-tools/).
Please refer to the documentation for more details as this README just
gives a short overview.

## Installation

See the [documentation](https://greenbone.github.io/gvm-tools/install.html)
for all supported installation options.

### Requirements

Python 3.9 and later is supported.

### Version

Please consider to always use the **newest** version of `gvm-tools` and `python-gvm`.
We frequently update this projects to add features and keep them free from bugs.
This is why installing `gvm-tools` using pip is recommended.

**To use `gvm-tools` with an old GMP version (7, 8, 9) you must use a release version**
**that is `<21.06`, combined with an `python-gvm` version `<21.05`.**
**In the `21.06` release the support of these older versions has been dropped.**

## Usage

There are several clients to communicate via GMP/OSP.

All clients have the ability to build a connection in various ways:

* Unix Socket
* TLS Connection
* SSH Connection

### gvm-cli

This tool sends plain GMP/OSP commands and prints the result to the standard
output.

#### Examples

Return the current protocol version used by the server:

```bash
gvm-cli socket --xml "<get_version/>"
```

Return all tasks visible to the GMP user with the provided credentials:

```bash
gvm-cli --gmp-username foo --gmp-password bar socket --xml "<get_tasks/>"
```

Read a file with GMP commands and return the result:

```bash
gvm-cli --gmp-username foo --gmp-password bar socket myfile.xml
```

Note that `gvm-cli` will by default print an error message and exit with a
non-zero exit code when a command is rejected by the server. If this kind of
error handling is not desired, the unparsed XML response can be requested using
the `--raw` parameter:

```bash
gvm-cli socket --raw --xml "<authenticate/>"

```

### gvm-script

This tool has a lot more features than the simple `gvm-cli` client. You
have the possibility to create your own custom gmp or osp scripts with commands
from the [python-gvm library](https://github.com/greenbone/python-gvm) and from
Python 3 itself.

#### Example script

```python
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
["scripts/"](scripts/) folder.
Some of them might be exactly what you need and all of them help writing
your own gmp scripts.

### gvm-pyshell

This tool is for running gmp or osp scripts interactively. It provides the same
API as [gvm-script](#gvm-script) using the
[python-gvm library](https://github.com/greenbone/python-gvm).

#### Example program use

Connect with given credentials via a unix domain socket and open an interactive
shell:

```bash
gvm-pyshell --gmp-username user --gmp-password pass socket
```

Connect through SSH connection and open the interactive shell:

```bash
gvm-pyshell --hostname 127.0.0.1 ssh
```

## Support

For any question on the usage of `gvm-tools` or gmp scripts please use the
[Greenbone Community Portal](https://community.greenbone.net/c/gmp). If you
found a problem with the software, please
[create an issue](https://github.com/greenbone/gvm-tools/issues) on GitHub.

## Maintainer

This project is maintained by [Greenbone AG](https://www.greenbone.net/).

## Contributing

Your contributions are highly appreciated. Please
[create a pull request](https://github.com/greenbone/gvm-tools/pulls) on GitHub.
For bigger changes, please discuss it first in the
[issues](https://github.com/greenbone/gvm-tools/issues).

For development you should use [poetry](https://python-poetry.org/)
to keep you python packages separated in different environments. First install
poetry via pip

    python3 -m pip install --user poetry

Afterwards run

    poetry install

in the checkout directory of `gvm-tools` (the directory containing the
`pyproject.toml` file) to install all dependencies including the packages only
required for development.

Afterwards active the git hooks for auto-formatting and linting via
[autohooks](https://github.com/greenbone/autohooks).

    poetry run autohooks activate --force

## License

Copyright (C) 2017-2024 [Greenbone AG](https://www.greenbone.net/)

Licensed under the [GNU General Public License v3.0 or later](LICENSE).
