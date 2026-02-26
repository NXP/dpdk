..  SPDX-License-Identifier: BSD-3-Clause
    Copyright 2026 NXP


NXP V2X Fast Crypto Engine (v2x_fce)
====================================

The v2x_fce PMD provides poll mode crypto driver support for NXP i.MX943 (V2X FCE)
hardware accelerator.


Architecture
------------

i.MX 943 use cases (TLS, IPsec, …) requires high performance cryptographic solution.
For this reason NXP as designed the i.MX 943 with new crypto accelerators:
-- A new AHB-DMA to V2X-FH subsystem.
-- Faster AES engine (LTC-AES) that interacts with the DMA directly
-- A prefetcher to remove DRAM memory accesses latency

This engine allow users to use the hardware cryptographic accelerators
so that they can achieve fast cryptographic operations (AES, AES GCM, SHA).
This provides significant improvement to system level performance.

v2x_fce PMD uses UIO interface to interact with
Linux kernel for configure and destroy the device instance (ring).


Implementation
--------------

The FCE is a feature implemented in the V2X i.mx943 firmware.
The FCE is started once the firmware is authenticated.
The SHE0 MU is reused for this purpose.
The Core writes the FCE requests inside the SHE0 MU buffer slots.
The Core then signals V2X to process the pushed request via a single word MU message.


Features
--------

The V2X_FCE PMD has support for:

Cipher algorithms:

* ``RTE_CRYPTO_CIPHER_AES256_CBC``
* ``RTE_CRYPTO_CIPHER_AES256_ECB``

Hash algorithms:

* ``RTE_CRYPTO_AUTH_SHA256_HMAC``
* ``RTE_CRYPTO_AUTH_SHA384_HMAC``
* ``RTE_CRYPTO_AUTH_SHA512_HMAC``

AEAD algorithms:


Supported SoCs
--------------------

* i.MX943

Limitations
-----------

* Hash followed by Cipher mode is not supported
* Only supports the session-oriented API implementation (session-less APIs are not supported).

Prerequisites
-------------

v2x_fce driver has following dependencies are not part of DPDK and must be installed separately:

* **NXP Linux SDK**

  NXP Linux software development kit (SDK) includes support for the family
  of iMX9 ARM-Architecture-based system on chip (SoC) processors
  and corresponding boards.

  It includes the Linux board support packages (BSPs) for NXP SoCs,
  a fully operational tool chain, kernel and board specific modules.


Currently supported by DPDK:

* Supported architectures:  **arm64 LE**.

* Follow the DPDK :ref:`Getting Started Guide for Linux <linux_gsg>` to setup the basic DPDK environment.
