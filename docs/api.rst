.. _api:

Developer Interface
===================

This part of the documentation covers all public interfaces of gvm-tools.


Main
----

.. automodule:: gmp

.. autodata:: VERSION

.. autofunction:: get_version

Connections
-----------

.. automodule:: gmp.connection

.. autoclass:: GmpConnection
   :members:

.. autoclass:: SSHConnection
   :members:
   :inherited-members:

.. autoclass:: TLSConnection
   :members:
   :inherited-members:

.. autoclass:: UnixSocketConnection
   :members:
   :inherited-members:

Transforms
----------

.. automodule:: gmp.transform
    :members:

Protocols
---------

.. automodule:: gmp.protocols

Latest
^^^^^^

.. automodule:: gmp.protocols.latest

GMP v7
^^^^^^

.. automodule:: gmp.protocols.gmpv7

.. autoclass:: Gmp
    :members:

Errors
------

.. automodule:: gmp.error
    :members:
