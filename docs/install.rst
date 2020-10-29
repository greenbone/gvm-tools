.. _installation:

Installation of gvm-tools
=========================

The current universally applicable installation process for Python is using
the `pip`_ installer tool in conjunction with the `pypi`_ package repository.

Installing the Latest Stable Release of gvm-tools
-------------------------------------------------

For installing the latest stable release of :program:`gvm-tools` from the
`Python Package Index <https://pypi.org/>`_, `pip`_ or `poetry`_ can be used.

Using pip
^^^^^^^^^

The following command installs :program:`gvm-tools` system wide:

.. code-block:: shell

  python3 -m pip install gvm-tools

A system wide installation usually requires admin permissions. Therefore, 
:program:`gvm-tools` may only be installed for the
`current user <https://docs.python.org/3/library/site.html#site.USER_BASE>`_
via:

.. code-block:: shell

  python3 -m pip install --user gvm-tools

For further details and additional installation options, please take a look at
the documentation of `pip`_.

Using poetry
^^^^^^^^^^^^

To avoid polluting the system and user namespaces with Python packages and to
allow installing different versions of the same package at the same time,
`python virtual environments <https://docs.python.org/3/library/venv.html>`_
have been introduced.

`poetry`_ is a tool combining the use of virtual environments and handling
dependencies elegantly.

Please follow the `poetry documentation <https://python-poetry.org/docs/#installation>`_
to install the tool.

To install :program:`gvm-tools` into a virtual environment, the following
commands need to be executed:

.. code-block:: shell

  mkdir path/to/venv/dir
  cd path/to/venv/dir
  poetry install gvm-tools

Afterwards, the environment containing the installed :program:`gvm-tools` can be
activated by running:

.. code-block:: shell

  cd path/to/venv/dir
  poetry shell

Getting the Source
------------------

The source code of **python-gvm** can be found at
`GitHub <https://github.com/greenbone/python-gvm>`_.

To clone the public repository run::

    git clone git://github.com/greenbone/gvm-tools

Once there is a copy of the source, it can be installed into the current Python
`environment <https://docs.python.org/3/library/venv.html#venv-def>`_:

.. code-block:: shell

    python3 -m pip install -e /path/to/gvm-tools

.. _pip: https://pip.pypa.io/en/stable/
.. _poetry: https://python-poetry.org/
.. _pypi: https://pypi.org/
