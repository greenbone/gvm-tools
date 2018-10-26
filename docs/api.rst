.. _api:

Developer Interface
===================

This part of the documentation covers all public interfaces of gvm-tools.


Main Interface
--------------

.. automodule:: gmp

.. autoclass:: Gmp
   :inherited-members:

.. autofunction:: get_version

Connections
-----------

.. automodule:: gmp.connection

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
