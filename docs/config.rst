.. _config:

Configuration
=============

.. versionchanged:: 2.0

By default, :program:`gvm-tools` :ref:`programs <tools>` are evaluating the
:file:`~/.config/gvm-tools.conf`
`ini style <https://docs.python.org/3/library/configparser.html#supported-ini-file-structure>`_
config file since version 2.0. The name of the used config file can be set using the
:command:`-c/--config` command line switch.

Settings
--------

The configuration file consists of sections, each led by a :code:`[section]`
header, followed by key/value entries separated by a :code:`=` character.
Whitespaces between key and value are ignored, i.e., :code:`key = value` is the
same as :code:`key=value`.

Currently five sections are evaluated:

* :ref:`Main section <main_section>`
* :ref:`GMP section <gmp_section>`
* :ref:`Socket section <socket_config_section>`
* :ref:`TLS section <tls_config_section>`
* :ref:`SSH section <ssh_config_section>`

.. _main_section:

.. rubric:: Main Section

The main section allows changing the default connection timeout besides
defining variables for :ref:`interpolation`.

.. code-block:: ini

  [main]
  timeout = 60


.. _gmp_section:

.. rubric:: GMP Section

The GMP section allows setting the default user name and password for
`Greenbone Management Protocol (GMP)
<https://community.greenbone.net/t/about-the-greenbone-management-protocol-gmp-category/83>`_
based communication.

.. code-block:: ini

  [gmp]
  username=gmpuser
  password=gmppassword


.. _socket_config_section:

.. rubric:: Socket Section

This section is only relevant if the :ref:`socket connection type 
<socket_connection_type>` is used.

The socket section allows setting the default path to the Unix Domain socket of
:term:`gvmd` or :term:`openvasmd` respectively. It must not be confused with the
socket path to the redis server used by :term:`openvassd`. 

.. code-block:: ini

  [unixsocket]
  socketpath=/var/run/gvmd.sock


.. _tls_config_section:

.. rubric:: TLS Section

This section is only relevant if the :ref:`TLS connection type 
<tls_connection_type>` is used (default for accessing :term:`openvasmd` 
on :term:`GOS` 3.1).

The TLS section allows setting the default port, TLS certificate file, TLS key
file and TLS certificate authority file.

.. code-block:: ini

  [tls]
  port=1234
  certfile=/path/to/tls.cert
  keyfile=/path/to/tls.key
  cafile=/path/to/tls.ca


.. _ssh_config_section:

.. rubric:: SSH Section

This section is only relevant if the :ref:`SSH connection type <ssh_connection_type>`
is used (default for accessing :term:`openvasmd` on :term:`GOS` 4 and beyond).

The SSH section allows setting the default SSH port, SSH user name and SSH
password. 

.. code-block:: ini

  [ssh]
  username=sshuser
  password=sshpassword
  port=2222

.. rubric:: Comments

Configuration files may also contain comments by using the special character
:code:`#`. A comment should be placed on a separate line above or below the
setting.

.. code-block:: ini

  [main]
  # connection timeout of 120 seconds
  timeout=120


.. _interpolation:

.. rubric:: Interpolation

The configuration file also supports the `interpolation of values
<https://docs.python.org/3/library/configparser.html#interpolation-of-values>`_.
It is possible to define values in the :code:`[main]` section and reference
them via a :code:`%(<variablename>)s` syntax. Additionally, values of the
same section can be referenced.

.. code-block:: ini

  [main]
  my_first_name=John

  [gmp]
  my_last_name=Smith
  username=%(my_first_name)s%(my_last_name)s

Using this syntax will set the gmp user name setting to `JohnSmith`.

Example
-------

Full example configuration:

.. code-block:: ini

  [main]
  # increased timeout to 5 minutes
  timeout = 300
  tls_path=/data/tls
  default_user=johnsmith

  [gmp]
  username=%(default_user)s
  password=choo4Gahdi2e

  [unixsocket]
  socketpath=/var/run/gvmd.sock

  [tls]
  port=1234
  certfile=%(tls_path)s/tls.cert
  keyfile=%(tls_path)s/tls.key
  cafile=%(tls_path)s/tls.ca

  [ssh]
  username=%(default_user)s
  password=Poa8Ies1iJee
