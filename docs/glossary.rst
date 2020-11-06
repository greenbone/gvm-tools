Glossary
========

.. glossary::

  gvmd
    Management daemon shipped with :term:`GVM 10 <GVM10>` and later.
    Abbreviation for **G**\reenbone **V**\ulnerability **M**\anager
    **D**\aemon.

  openvasmd
    Management daemon shipped with :term:`GVM 9 <GVM9>` and before.
    Abbreviation for **OpenVAS** **M**\anager **D**\aemon.

  openvassd
    Scanner daemon used by :term:`GVM 10 <GVM10>` and before. It listens for
    incoming connections via :term:`OTP` and starts scan processes to run the
    actual vulnerability tests. It collects the results and reports them to the
    management daemon. With :term:`GVM 11 <GVM11>` it has been converted into
    the :term:`openvas` application by removing the daemon and OTP parts.
    Abbreviation for **OpenVAS** **S**\canner **D**\aemon.

  openvas
    Scanner application executable to run vulnerability tests against targets
    and to store scan results into a redis database. Used in
    :term:`GVM 11 <GVM11>` and later. It has originated from the
    :term:`openvassd` daemon.

  OSPd
    A `framework <https://github.com/greenbone/ospd>`_ for several scanner
    daemons speaking the :term:`Open Scanner Protocol (OSP) <OSP>`.

  ospd-openvas
    A :term:`OSP <OSP>` scanner daemon managing the :term:`openvas <openvas>`
    executable for reporting scan results to the management daemon :term:`gvmd`.
    Used in :term:`GVM 11 <GVM11>` and later.

  GOS
    Greenbone Operating System, the operating system of the
    :term:`GSM appliances <GSM>`. It provides the commercial version of the
    :term:`GVM framework <GVM>` with enterprise support and features.

  GSM
    The commercial product line `Greenbone Security Manager
    <https://www.greenbone.net/en/product-comparison/>`_ available as appliances
    or virtual machines.

  GMP
    The `Greenbone Management Protocol
    <https://community.greenbone.net/t/about-the-greenbone-management-protocol-gmp-category/83>`_.
    An XML-based communication protocol provided by :term:`openvasmd` and
    :term:`gvmd`. In the past it was also known as OMP.

  OSP
    The `Open Scanner Protocol
    <https://community.greenbone.net/t/about-the-open-scanner-protocol-osp-category/98>`_.
    An XML-based communication protocol provided by
    `OSPd <https://github.com/greenbone/ospd>`_ based scanners.

  OTP
    The OpenVAS Transfer Protocol was inherited from pre-:term:`OpenVAS <GVM>`
    times. It is used by :term:`openvassd` to communicate with the manager
    daemon and got replaced by :term:`OSP` in :term:`GVM 11 <GVM11>`. See the
    `announcement <https://community.greenbone.net/t/goodbye-otp/1739>`_ for
    some background.

  GVM
    The `Greenbone Vulnerability Management (GVM)
    <https://community.greenbone.net/t/about-gvm-architecture/1231>`_ is a
    framework of several services. It is developed as part of the commercial
    product line :term:`Greenbone Security Manager <GSM>`. Formerly known as
    OpenVAS.

  GVM9
    `Version 9 <https://community.greenbone.net/t/gvm-9-end-of-life-initial-release-2017-03-07/211>`_
    of the :term:`GVM` framework. Also known as **OpenVAS 9**. Used in the
    :term:`GOS 4 <GOS>` series.

  GVM10
    `Version 10 <https://community.greenbone.net/t/gvm-10-old-stable-initial-release-2019-04-05/208>`_ of the
    :term:`GVM` framework. Used in :term:`GOS 5 <GOS>`.

  GVM11
    `Version 11 <https://community.greenbone.net/t/gvm-11-stable-initial-release-2019-10-14/3674>`_ of the
    :term:`GVM` framework. Used in :term:`GOS 6 <GOS>`.

  GSE
    The `Greenbone Source Edition (GSE)
    <https://community.greenbone.net/t/about-the-greenbone-source-edition-gse-category/176>`_
    covers the actual source codes of the Greenbone application stack
    for vulnerability scanning and vulnerability management :term:`GVM`.
    The source edition is adopted by external third parties, e.g., if the
    :term:`GVM` stack is provided by a Linux distribution, it is build from
    the Greenbone Source Edition.
