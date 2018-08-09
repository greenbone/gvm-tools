SUMMARY OF RELEASE CHANGES FOR GVM-TOOLS
=======================================

For detailed code changes, please visit
https://github.com/greenbone/gvm-tools/commits/master
or get the entire source code repository and view log history:
$ git clone https://github.com/greenbone/gvm-tools.git
$ cd gvm-tools && git log

gvm-tools 1.4.0 (2018-08-09)
----------------------------

This is the first release of the gvm-tools module 1.4 for the
Greenbone Vulnerability Management (GVM) framework.

This release covers bug fixes, robustness improvements and an extended GMP
scripts collection.

Many thanks to everyone who has contributed to this release:
Raphael Grewe, Mirko Hansen, Henning Häcker, David Kleuker, Juan Jose Nicola,
Timo Pollmeier, Bjoern Ricks, Joshua Schwartz, Jan-Oliver Wagner and
Michael Wiegand.

Main changes compared to gvm-tools-1.4.0:

* Correct XML encoding for commands
* Fix bug for long GMP commands through SSHConnection
* Add new GMP scripts: create_targets_from_host_list.gmp,
  gen-random-targets.gmp, send-schedules.gmp, send-targets.gmp,
  send-tasks.gmp, send_delta_emails.gmp, startAlertScan.gmp,
  update-task-target.gmp.
* Improve and extend 'create' and 'modify' command methods
* Add support for accessing the raw response
* Improve unit tests
* Allow anonymous connections
* Require lxml and defusedxml python modules
* Improve documentation
* Several code improvements

1.3.1 - 2017-12-14
------------------
* Improved stability with ssh connections again

1.3.0 - 2017-12-12
------------------
* Improved stability with ssh connections
* Fixed bugs for create_target command
* Fixed some typos
* Added correct license file
* Improved setup (Only Python3 is allowed)

1.2.0 - 2017-08-04
------------------
* Improved feature to read from config file for gvm-cli
* Added feature to read from config file for gvm-pyshell
* Added feature to disable timeout on sockets for all clients
* Added new script to delete overrides by filter
* Removed requirement for username in gvm-cli

* Minor code improvement

1.1.0 - 2017-06-28
------------------
* Fixed hgignore file (Ignored important file)
* Fixed choice decision for the connectiontype
* Fixed quote bug in gvm_connection.py

* Changed quit function to sys.exit of non interactively used python files (f.e. scripts)
* Changed path of unixsocket from openvasmd.sock to gvmd.sock

* Added timeout functionality to all connection types
* Added GPL v3 licenses in all relevant files
* Added function create_report
* Added new script to sync tasks between to gsm
* Added new script to sync assets from a csv list
* Added experimental client gvm-dialog again

1.0.3 - 2017-06-01
------------------
* Fixed wrong library path

1.0.2 - 2017-06-01
------------------
* Changed directory structure and names, because of the generic names for python modules
* Directory libs is named gmp
* Directory clients is copied into gmp

1.0.1 - 2017-06-01
------------------
* Changed name to gvm-tools
* Bugfixes at the scripts
* Added new script to create dummy data for gsm 

1.0 - 2017-05-31
----------------
* First stable release of gvm-tools


