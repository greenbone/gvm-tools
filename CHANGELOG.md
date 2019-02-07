SUMMARY OF RELEASE CHANGES FOR GVM-TOOLS
=======================================

For detailed code changes, please visit
https://github.com/greenbone/gvm-tools/commits/master
or get the entire source code repository and view log history:
$ git clone https://github.com/greenbone/gvm-tools.git
$ cd gvm-tools && git log

# gvm-tools 2.0.0.beta2 (unreleased)

# Configfile

- The structure for the config file (default is ~/.config/gvm-tools.conf) has
  changed. It's possible to set defaults for nearly all command line arguments.

## Other

- The commandline help for `gvm-cli` and `gvm-pyshell` has been updated and
  made more consistent.
- Fix a bug which caused `gvm-pyshell` to immediately re-enter interactive mode
  upon exiting it for the first time.
- Renamed --ssh-user switch to --ssh-username
- Added --ssh-password switch for ssh connection
- Update `gvmtools.get_version` to return a fully compliant PEP 440 version
  string.

# gvm-tools 2.0.0.beta1 (13.11.2018)

gvm-tools got split into the command line interfaces (*gvm-cli* and
*gvm-pyshell*) including the [gmp (example) scripts](https://github.com/greenbone/gvm-tools/tree/master/scripts)
and the Python API. The Python API can now be found at
[python-gvm](https://github.com/greenbone/python-gvm). During this split the
python package name for the API got changed from **gmp** to **gvm**. The API
has also been refactored and stabilized. For details please take a look at
[python-gvm](https://github.com/greenbone/python-gvm).

## Scripts

- It's now possible to write OSP scripts. Using the --protocol=OSP switch
  gvm-pyshell adds a global **osp** object instead of the **gmp** one.
- The `__name__` variable is set to `__gmp__` for GMP scripts and to `__osp__`
  for OSP scripts *(Remember: for normal Python scripts `__name__` is set to
  [`__main__`](https://docs.python.org/3/library/__main__.html))*.
- Scripts are only getting two global variables now: **gmp** (or **osp**)
  and **args**. **gmp** and **osp** are the global objects to communicate with
  the remote *gvmd* or *ospd* daemon. **args** contains the parsed arguments for
  the script.
- The global **args** object only contains script related parameters now. These
  username and password from the --gmp-username and --gmp-password switches and
  the additional scripts parameters as `args.argv`.
- GMPError got renamed to GvmError and must be imported from gvm.errors module.
  ```python
  from gvm.errors import GvmError as GMPError
  ```
- Added new client helper module.
- pretty function isn't available as a global function in the scripts anymore.
  It must be imported separately like
  ```python
  from gvmtools.helper import pretty_print as pretty
  ```
- The included [gmp scripts](https://github.com/greenbone/gvm-tools/tree/master/scripts)
  have been cleaned up and adjusted for the new API.
- It's possible to get the current versions of gvm-tools via `__version__` and
  python-gvm via `__api_version__`.

## Other

- Removed experimental gvm-dialog application.
- Use pipenv for development.

# gvm-tools 1.4.1 (2018-08-10)

This is the first maintenance release of the gvm-tools module 1.4 for
the Greenbone Vulnerability Management (GVM) framework.

This release covers bug fixes in 'create' and 'modify' methods.

Many thanks to everyone who has contributed to this release: Raphael
Grewe, Juan Jose Nicola and Jan-Oliver Wagner

Main changes compared to gvm-tools-1.4.0:

- Fix bugs for create and modify command methods.
- Improve unit tests.
- Improve documentation.

# gvm-tools 1.4.0 (2018-08-09)

This is the first release of the gvm-tools module 1.4 for the Greenbone
Vulnerability Management (GVM) framework.

This release covers bug fixes, robustness improvements and an extended
GMP scripts collection.

Many thanks to everyone who has contributed to this release: Raphael
Grewe, Mirko Hansen, Henning Häcker, David Kleuker, Juan Jose Nicola,
Timo Pollmeier, Bjoern Ricks, Joshua Schwartz, Jan-Oliver Wagner and
Michael Wiegand.

Main changes compared to gvm-tools-1.3.1:

- Correct XML encoding for commands
- Fix bug for long GMP commands through SSHConnection
- Add new GMP scripts: create\_targets\_from\_host\_list.gmp,
  gen-random-targets.gmp, send-schedules.gmp, send-targets.gmp,
  send-tasks.gmp, send\_delta\_emails.gmp, startAlertScan.gmp,
  update-task-target.gmp.
- Improve and extend 'create' and 'modify' command methods
- Add support for accessing the raw response
- Improve unit tests
- Allow anonymous connections
- Require lxml and defusedxml python modules
- Improve documentation
- Several code improvements

# 1.3.1 - 2017-12-14

- Improved stability with ssh connections again

# 1.3.0 - 2017-12-12

- Improved stability with ssh connections
- Fixed bugs for create\_target command
- Fixed some typos
- Added correct license file
- Improved setup (Only Python3 is allowed)

# 1.2.0 - 2017-08-04

- Improved feature to read from config file for gvm-cli
- Added feature to read from config file for gvm-pyshell
- Added feature to disable timeout on sockets for all clients
- Added new script to delete overrides by filter
- Removed requirement for username in gvm-cli
- Minor code improvement

# 1.1.0 - 2017-06-28

- Fixed hgignore file (Ignored important file)
- Fixed choice decision for the connectiontype
- Fixed quote bug in gvm\_connection.py
- Changed quit function to sys.exit of non interactively used python
  files (f.e. scripts)
- Changed path of unixsocket from openvasmd.sock to gvmd.sock
- Added timeout functionality to all connection types
- Added GPL v3 licenses in all relevant files
- Added function create\_report
- Added new script to sync tasks between to gsm
- Added new script to sync assets from a csv list
- Added experimental client gvm-dialog again

# 1.0.3 - 2017-06-01

- Fixed wrong library path

# 1.0.2 - 2017-06-01

- Changed directory structure and names, because of the generic names
  for python modules
- Directory libs is named gmp
- Directory clients is copied into gmp

# 1.0.1 - 2017-06-01

- Changed name to gvm-tools
- Bugfixes at the scripts
- Added new script to create dummy data for gsm

# 1.0 - 2017-05-31

- First stable release of gvm-tools
