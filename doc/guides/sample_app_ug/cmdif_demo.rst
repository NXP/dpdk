..  SPDX-License-Identifier: BSD-3-Clause
    Copyright 2018 NXP

CMDIF DEMO Application
======================

DPDK based CMDIF demo application is a simple application that demonstrates the communication between GPP & AIOP using DPDK API’s and Command Interface library.
Command Interface library is provided as a lib module within the "examples/cmdif/" (examples/cmdif/lib/librte_cmdif.a).

This application requires a corresponding process running on AIOP core/s which will read and respond to this application.

The application verifies :
  a) CMDIF client (where GPP is the client and AIOP is the server)
  b) CMDIF server (where GPP is the server and AIOP is the client)

Note: Any user writing application over DPAA2 CMDIF based raw device should also include the library 'librte_cmdif.a'

Supported SoCs
--------------

This application is only supported on NXP SoC's

- LS2084A/LS2044A
- LS2088A/LS2048A
- LS1088A/LS1048A

Overview
--------

CMDIF Client (GPP is client):

In the CMDIF client, the GPP is the client and the AIOP is the server.
Requests are initiated by the GPP and are sent to the AIOP core.
The AIOP responds back with the response.

.. code-block:: console

  +-----------------------+
  |             APP(DPDK) |
  |     ^     |           |
  +-----|-----|-----------+
  |     |     | CMDIF LIB |    *GPP*
  |     |     |           |
  +-----|-----|-----------+
  |     |     | CMDIF DRV |
  |     |     |           |
  +-----|-----|-----------+
        |     |
        |     |
        |     |
  +-----|-----|-----------+
  |     |     |           |
  |     |_____|  AIOP FW  |    *AIOP*
  |                       |
  +-----------------------+

The CMDIF client (demo) is responsible for the following:
  - Opens a CI communication channel using a single DPCI device, defined in container used by application.
  - Sends multiple messages from GPP to AIOP using synchronous commands.
  - Sends and receive response for multiple messages from GPP to AIOP using asynchronous commands.
  - Application Validates the response received from the AIOP Server application and prints the result on console.
  - Closes the opened CI communication channels.

CMDIF Server (GPP is server):
`
In the CMDIF server, the GPP is the server and the AIOP is the client.
Requests are initiated by the AIOP and are sent to the GPP core.
The GPP responds back to the AIOP with success or error.

.. code-block:: console

  +-----------------------+
  |      _____  APP(DPDK) |
  |     |     |           |
  +-----|-----|-----------+
  |     |     | CMDIF LIB |    *GPP*
  |     |     |           |
  +-----|-----|-----------+
  |     |     | CMDIF DRV |
  |     |     |           |
  +-----|-----|-----------+
        |     |
        |     |
        |     |
  +-----|-----|-----------+
  |     |     |           |
  |     |     V  AIOP FW  |    *AIOP*
  |                       |
  +-----------------------+

The CMDIF server (demo) is responsible for the following:
  - Registers the server module
  - Opens the Sever session
  - Initiates the client open on the AIOP client
  - Receives requests/commands from the AIOP
  - Closes the server session
  - Unregisters the module

Compiling the Application
-------------------------

To compile the sample application see :doc:`compiling`.

The application is located in the ``cmdif_demo`` sub-directory.

Running the Application
-----------------------

The application has a number of command line options::

    ./cmdif_demo [EAL options]

The demo application showcases only a single thread/core use-case, thus supporting the coremask with single core.
Running the example also requires
  - running dynamic_AIOP_dpl.sh
  - Loading the cmdif_integ_dbg.elf (provided in AIOPSL - https://bitbucket.sw.nxp.com/projects/DPAA2/repos/aiopsl/browse/demos/images/LS2085A/cmdif_integ_dbg.elf?at=develop) using the aiop_tool which is to be run in background

For example,

.. code-block:: console

    ./dynamic_AIOP_dpl.sh
    export DPRC = <dprc container created for GPP>
    aiop_tool load -g dprc.3 -f cmdif_integ_dbg.elf &
    ./cmdif_demo -c 0x2"

In this command:

*   The -c option enables cores 2

Refer to the *DPDK Getting Started Guide* for general information on running applications and
the Environment Abstraction Layer (EAL) options.

Expected Output
---------------

The application should prints below logs on console in case of CMDIF client:
  - PASSED open commands
  - PASSED synchronous send commands
  - PASSED asynchronous send/receive commands
  - PASSED: close commands

Also verify that application prints below logs in console in case of CMDIF server:
  - PASSED cmdif session open
  - PASSED sync command
  - PASSED Async commands
  - PASSED Isolation context test
  - PASSED cmdif session close
