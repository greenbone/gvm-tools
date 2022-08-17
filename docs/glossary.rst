Glossary
========

.. glossary::

  gvmd
    Management daemon shipped with :term:`GVM 10 <GVM10>` and later.
    Abbreviation for **G**\reenbone **V**\ulnerability **M**\anager
    **D**\aemon.

  openvassd
    Scanner daemon used by :term:`GVM 10 <GVM10>` and before. It listens for
    incoming connections via OTP and starts scan processes to run the
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
    :term:`Greenbone Enterprise` Appliance. It provides the commercial version
    of the :term:`Greenbone Community Edition` with enterprise support and
    features.

  GSM
    Greenbone Security Manager (GSM) is the former name of our commercial
    product line :term:`Greenbone Enterprise` as hardware or virtual appliances.

  GMP
    The Greenbone Management Protocol (GMP) is an XML-based communication
    protocol provided by :term:`gvmd`. It provides an API to create, read, update
    and delete scans and vulnerability information.

  OSP
    The Open Scanner Protocol is an XML-based communication protocol provided by
    :term:`ospd-openvas`. It provides an API to start scans, get :term:`VT`
    information and to receive scan results.

  GVM
    The :term:`Greenbone Community Edition` consists of several services. This
    software framework has been named Greenbone Vulnerability Management (GVM)
    in the past.

  Greenbone Community Edition
    The Greenbone Community Edition covers the actual releases of the Greenbone
    application framework for vulnerability scanning and vulnerability
    management provided as open-source software to the community. The Greenbone
    Community Edition is adopted by external third parties, e.g., if the
    software framework is provided by a Linux distribution, it is build from the
    Greenbone Community Edition. It is developed as part of the commercial
    :term:`Greenbone Enterprise` product line. Sometimes referred to as the
    OpenVAS framework.

  GVM9
    `Version 9 <https://community.greenbone.net/t/gvm-9-end-of-life-initial-release-2017-03-07/211>`_
    of the :term:`Greenbone Community Edition`. Also known as **OpenVAS 9**.
    Used in the :term:`GOS 4 <GOS>` series.

  GVM10
    `Version 10 <https://community.greenbone.net/t/gvm-10-old-stable-initial-release-2019-04-05/208>`_ of the
    :term:`Greenbone Community Edition`. Used in :term:`GOS 5 <GOS>`.

  GVM11
    `Version 11 <https://community.greenbone.net/t/gvm-11-stable-initial-release-2019-10-14/3674>`_ of the
    :term:`Greenbone Community Edition`. Used in :term:`GOS 6 <GOS>`.

  GVM20.08
    `Version 20.08 <https://community.greenbone.net/t/gvm-20-08-stable-initial-release-2020-08-12/6312>`_ of the
    :term:`Greenbone Community Edition`. Used in :term:`GOS 20.08 <GOS>`. First
    version using `Calendar Versioning <https://calver.org/>`_

  GVM21.4
    `Version 21.4 <https://community.greenbone.net/t/gvm-21-04-oldstable-initial-release-2021-04-16/8942>`_ of the
    :term:`Greenbone Community Edition`. Used in :term:`GOS 21.04 <GOS>`.

  GVM22.4
    `Version 22.4 <https://community.greenbone.net/t/greenbone-community-edition-22-4-stable-initial-release-2022-07-25/12638>`_ of the
    :term:`Greenbone Community Edition`. Used in :term:`GOS 22.04 <GOS>`.

  Greenbone Enterprise
    Greenbone Enterprise is the `Greenbone product line for on-premises solutions
    <https://www.greenbone.net/en/product-comparison/>`_.
    Included are virtual or hardware Greenbone Enterprise Appliances with the
    :term:`Greenbone Operating System (GOS)<GOS>`, the
    :term:`Greenbone Community Edition` framework, and the
    :term:`Greenbone Enterprise Feed`.

  Greenbone Community Feed
    The Greenbone Community Feed is the freely available feed for vulnerability
    information licensed as open-source. It contains basic scan configurations,
    report formats, port lists and the most important vulnerability tests. The
    provided data is updated on a daily basis with no warranty or promises for
    fixes or completeness.

  Greenbone Enterprise Feed
    The Greenbone Enterprise Feed is the commercial feed provided by
    Greenbone Networks containing additional enterprise features like
    vulnerability tests for enterprise products, policy and compliance checks,
    extensive reports formats and special scan configurations.
    The feed comes with a service-level agreement ensuring support, quality
    assurance and availability.

  VT
    Vulnerability Tests (VTs), also known as Network Vulnerability Tests
    (NVTs), are scripts written in the NASL programming language to detect
    vulnerabilities at remote hosts.
