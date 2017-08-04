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


