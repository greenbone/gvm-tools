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

.. automodule:: gmp.connections

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

.. automodule:: gmp.transforms
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
    :inherited-members:

Errors
------

.. automodule:: gmp.errors
    :members:
