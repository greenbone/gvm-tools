.. _connection_types:

Connection Types
================

Before being able to talk to a remote :term:`GMP` or :term:`OSP` server using
one of the :ref:`provided command line clients <tools>`, the user
has to choose a connection type for establishing a communication channel.
Currently three different connection types are supported for being used as
transport protocol:

  * :ref:`TLS – tls <tls_connection_type>`
  * :ref:`SSH – ssh <ssh_connection_type>`
  * :ref:`Unix Domain Socket – socket <socket_connection_type>`

For the most common use case (querying :term:`openvasmd`/:term:`gvmd` via
:term:`GMP` on the same host) the :ref:`socket connection
<socket_connection_type>` should be chosen. The other connection types require
some setup and possible adjustments at the server side, if no :term:`Greenbone OS <GOS>` 
based system is used.


.. _socket_connection_type:

Using a Unix Domain Socket
--------------------------

The Unix Domain Socket is the default connection type of :term:`gvmd` in the
:term:`Greenbone Source Edition <GSE>`. It is only usable when running the
client tool on the same host as the daemon.

The location and name of the Unix Domain Socket provided by
:term:`gvmd`/:term:`openvasmd` highly depends on the environment and
:term:`GVM` installation. Additionally, its name changed from :file:`openvasmd.sock` in
:term:`GVM 9 <GVM9>` to :file:`gvmd.sock` in :term:`GVM 10 <GVM10>`.

For :term:`GOS 4 <GOS>` the path is either :file:`/run/openvas/openvasmd.sock` or
:file:`/usr/share/openvas/gsa/classic/openvasmd.sock` and for
:term:`GOS 5 <GOS>` the path is either :file:`/run/gvm/gvmd.sock` or
:file:`/usr/share/gvm/gsad/web/gvmd.sock`.

:term:`OSPd based scanners <OSPd>` may be accessed via Unix Domain Sockets as well.
The location and name of these sockets is configurable and depends on the used
OSPd scanner implementation.

.. _don_t_use_sudo:

.. warning::

  Accessing a Unix Domain Socket requires sufficient Unix file permissions for
  the user running the :ref:`command line interface tool <tools>`.
  
  Please do not start a tool as **root** user via :command:`sudo` or :command:`su` only to
  be able to access the socket path. Instead, adjust the
  socket file permissions, e.g. by setting the :command:`--listen-owner`,
  :command:`--listen-group` or :command:`--listen-mode` arguments of
  :term:`gvmd`.


.. _tls_connection_type:

Using TLS
---------

The TLS connection type was the default connection type for remote and local
communication in :term:`GOS 3.1 <GOS>` and before. It is used to secure the
transport protocol connection of :term:`GMP` or :term:`OSP`. It requires to
provide a TLS certificate file, TLS key file and TLS certificate authority file.


.. _ssh_connection_type:

Using SSH
---------

Since :term:`GOS 4 <GOS>`, SSH is the default connection type for secure remote
communication with the manager daemon via :term:`GMP`. The :term:`Greenbone
Management Protocol <GMP>` is tunneled through SSH and forwarded to
:term:`gvmd`/:term:`openvasmd`.
