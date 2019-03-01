.. _installation:

Installation of gvm-tools
=========================

The current universally applicable installation process for Python is using
the `pip`_ installer tool in conjunction with the `pypi`_ package repository.

.. note:: All commands listed here use the general tool names. If some of these
  tools are provided from your distribution you may need to use the explicit
  python 3 version of the tool e.g. :program:`pip3`.

Using pip
---------

You can install the latest stable release of :program:`gvm-tools` from the
`Python Package Index <https://pypi.org/>`_ using `pip`_.

The following command installs :program:`gvm-tools` system wide:

.. code-block:: shell

  pip install gvm-tools

A system wide installation requires admin permissions normally. Therefore you
may need install :program:`gvm-tools` only for the
`current user <https://docs.python.org/3/library/site.html#site.USER_BASE>`_
via:

.. code-block:: shell

  pip install --user gvm-tools

For further details and additional installation options please take a look at
the documentation of `pip`_.

Using pipenv
------------

To avoid polluting the system and user namespaces with python packages and to
allow to install different versions of the same package at the same time
`python virtual environments <https://docs.python.org/3/library/venv.html>`_
have been introduced. `pipenv`_ is a tool to combine using virtual environments
and `pip`_ in an elegant fashion.

Please follow the `pipenv documentation <https://pipenv.readthedocs.io/en/latest/install/#pragmatic-installation-of-pipenv>`_
to install the tool.

To install :program:`gvm-tools` into a virtual environment the following
commands needs to be executed:

.. code-block:: shell

  mkdir path/to/venv/dir
  cd path/to/venv/dir
  pipenv install gvm-tools

Afterwards the environment containing the installed :program:`gvm-tools` can be
activated by running:

.. code-block:: shell

  cd path/to/venv/dir
  pipenv shell

Getting the Source
------------------

The source code of python-gvm can be found at
`GitHub <https://github.com/greenbone/python-gvm>`_.

To clone the public repository run::

    git clone git://github.com/greenbone/gvm-tools

Once you have a copy of the source, you can install it into your current python
`environment <https://docs.python.org/3/library/venv.html#venv-def>`_:

.. code-block:: shell

    pip install -e /path/to/gvm-tools

.. _pip: https://pip.pypa.io/
.. _pipenv: http://pipenv.org/
.. _pypi: https://pypi.org/
