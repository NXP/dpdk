..  SPDX-License-Identifier: BSD-3-Clause
    Copyright 2021 NXP

NXP LA12xx Poll Mode Driver
=======================================

The BBDEV LA12xx poll mode driver (PMD) supports an implementation of a
LDPC Encode / Decode 5GNR wireless acceleration function, using NXP's
PCI based LA12xx Software defined radio.
More information can be found at `NXP Official Website
<https://www.nxp.com/products/processors-and-microcontrollers/arm-processors/layerscape-processors/layerscape-access-la1200-programmable-baseband-processor:LA1200>`_.

Features
--------

LA12xx PMD supports the following features:

- LDPC Encode in the DL
- LDPC Decode in the UL
- Maximum of 8 UL queues
- Maximum of 8 DL queues
- PCIe Gen-3 x8 Interface
- MSI-X

LA12xx PMD supports the following BBDEV capabilities:

* For the LDPC encode operation:
   - ``RTE_BBDEV_LDPC_CRC_24B_ATTACH`` :  set to attach CRC24B to CB(s)
   - ``RTE_BBDEV_LDPC_RATE_MATCH`` :  if set then do not do Rate Match bypass

* For the LDPC decode operation:
   - ``RTE_BBDEV_LDPC_CRC_TYPE_24B_CHECK`` :  check CRC24B from CB(s)
   - ``RTE_BBDEV_LDPC_CRC_TYPE_24B_DROP`` :  drops CRC24B bits appended while decoding
   - ``RTE_BBDEV_LDPC_DEC_SCATTER_GATHER`` :  supports scatter-gather for input/output data

Installation
------------

Section 3 of the DPDK manual provides instructions on installing and compiling DPDK.

DPDK requires hugepages to be configured as detailed in section 2 of the DPDK manual.

Initialization
--------------

The device can be listed on the host console with:


Use the following lspci command to get the multiple LA12xx processor ids. The
device ID of the LA12xx baseband processor
is "1c30".

.. code-block:: console

  sudo lspci -nn

...
0001:01:00.0 Power PC [0b20]: Freescale Semiconductor Inc Device [1957:1c30] (
rev 10)
...
0002:01:00.0 Power PC [0b20]: Freescale Semiconductor Inc Device [1957:1c30] (
rev 10)


Test Application
----------------

BBDEV provides a test application, ``test-bbdev.py`` and range of test data for testing
the functionality of LA12xx FEC encode and decode, depending on the device's
capabilities. The test application is located under app->test-bbdev folder and has the
following options:

.. code-block:: console

  "-p", "--testapp-path": specifies path to the bbdev test app.
  "-e", "--eal-params"	: EAL arguments which are passed to the test app.
  "-t", "--timeout"	: Timeout in seconds (default=300).
  "-c", "--test-cases"	: Defines test cases to run. Run all if not specified.
  "-v", "--test-vector"	: Test vector path (default=dpdk_path+/app/test-bbdev/test_vectors/bbdev_null.data).
  "-n", "--num-ops"	: Number of operations to process on device (default=32).
  "-b", "--burst-size"	: Operations enqueue/dequeue burst size (default=32).
  "-s", "--snr"		: SNR in dB used when generating LLRs for bler tests.
  "-s", "--iter_max"	: Number of iterations for LDPC decoder.
  "-l", "--num-lcores"	: Number of lcores to run (default=16).
  "-i", "--init-device" : Initialise PF device with default values.


To execute the test application tool using simple decode or encode data,
type one of the following:

.. code-block:: console

  ./test-bbdev.py -c validation -n 64 -b 1 -v ./ldpc_dec_default.data
  ./test-bbdev.py -c validation -n 64 -b 1 -v ./ldpc_enc_default.data

The test application ``test-bbdev.py``, supports the ability to configure the PF device with
a default set of values, if the "-i" or "- -init-device" option is included. The default values
are defined in test_bbdev_perf.c.


Test Vectors
~~~~~~~~~~~~

In addition to the simple LDPC decoder and LDPC encoder tests, bbdev also provides
a range of additional tests under the test_vectors folder, which may be useful. The results
of these tests will depend on the LA12xx FEC capabilities which may cause some
testcases to be skipped, but no failure should be reported.
