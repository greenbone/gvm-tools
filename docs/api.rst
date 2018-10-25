.. _api:

Developer Interface
===================

.. module:: gmp

This part of the documentation covers all public interfaces of gvm-tools.


Main Interface
--------------

.. autoclass:: Gmp
   :inherited-members:

.. autofunction:: get_version

Connections
-----------

.. module:: gmp.connection

.. autoclass:: SSHConnection
   :inherited-members:

.. autoclass:: TLSConnection
   :inherited-members:

.. autoclass:: UnixSocketConnection
   :inherited-members:

Transforms
----------

.. automodule:: gmp.transform
    :members:
