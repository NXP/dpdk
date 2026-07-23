.. SPDX-License-Identifier: BSD-3-Clause
   Copyright 2024-2026 NXP

ENETC4 Poll Mode Driver
=======================

The ENETC4 NIC PMD (**librte_net_enetc**) provides poll mode driver
support for the inbuilt NIC found in multiple NXP new generation SoCs.

More information can be found at `NXP Official Website
<https://www.nxp.com/products/processors-and-microcontrollers/arm-processors/i-mx-applications-processors/i-mx-9-processors/i-mx-95-applications-processor-family-high-performance-safety-enabled-platform-with-eiq-neutron-npu:iMX95>`_.

This section provides an overview of the NXP ENETC4
and how it is integrated into the DPDK.


ENETC4 Overview
---------------

ENETC4 is a PCI Integrated End Point (IEP).
IEP implements peripheral devices in a SoC
such that software sees them as PCIe device.
ENETC4 is an evolution of BDR (Buffer Descriptor Ring) based networking IPs.

This infrastructure simplifies adding support for IEP and facilitates in following:

- Device discovery and location
- Resource requirement discovery and allocation
  (e.g. interrupt assignment, device register address)
- Event reporting


Supported ENETC4 SoCs
---------------------

- i.MX95
- i.MX943


NIC Driver (PMD)
----------------

The ENETC4 PMD is a traditional DPDK PMD
that bridges the DPDK framework and ENETC4 internal drivers,
supporting both Virtual Functions (VFs) and Physical Functions (PF).
Key functionality includes:

- Driver registration: The device vendor table is registered in the PCI subsystem.
- Device discovery: The DPDK framework scans the PCI bus for connected devices,
  triggering the ENETC4 driver's probe function.
- Initialization: The probe function configures basic device registers
  and sets up Buffer Descriptor (BD) rings.
- Receive processing: Upon packet reception, the BD Ring status bit is set,
  facilitating packet processing.
- Transmission: Packet transmission precedes reception, ensuring efficient data transfer.
- TCP and UDP segmentation offload (TSO) on VFs, enabled per Tx queue
  when the TSO offload flag is requested.
- Large receive offload (LRO) on the receive path via hardware Receive
  Segment Coalesce (RSC), enabled when the TCP LRO Rx offload flag is
  requested. RSC requires the FCS to be stripped, so it cannot be combined
  with the KEEP_CRC Rx offload.
- Per-queue Rx interrupts on VFs (cacheable Rx path only), enabling
  interrupt-driven receive with ``vfio-pci``. Applications set
  ``intr_conf.rxq = 1`` in ``rte_eth_conf`` to activate this feature.
  See `Rx Interrupt Mode (VF)`_ for setup details.
- Firmware version: The NETC IP version is reported via ``rte_eth_dev_fw_version_get``.
- Registers dump: The station interface, port (PF only) and BD ring registers are dumped via ``rte_eth_dev_get_reg_info``.
- SI-based port VLAN (pvid): Hardware VLAN tag insertion on Tx and removal on Rx, configured
  via ``rte_eth_dev_set_vlan_pvid``. On a PF the registers are written directly; on a privileged
  VF the request is forwarded to the kernel PF through the VSI-PSI mailbox (class 0x24).
  Use the testpmd command ``tx_vlan set pvid <port_id> <vlan_id> on|off`` to enable or disable.


Prerequisites
-------------

There are three main pre-requisites for executing ENETC4 PMD
on ENETC4 compatible boards:

#. **ARM64 Toolchain**

   For example, the `*aarch64* ARM toolchain
   <https://developer.arm.com/-/media/Files/downloads/gnu/13.3.rel1/binrel/arm-gnu-toolchain-13.3.rel1-x86_64-aarch64-none-linux-gnu.tar.xz>`_.

#. **Linux Kernel**

   It can be obtained from `NXP's Github hosting <https://github.com/nxp-imx/linux-imx>`_.

The following dependencies are not part of DPDK and must be installed separately:

- **NXP Linux LF**

  NXP Linux LF refers to NXP's Linux Factory releases,
  which are specific Linux distributions and Board Support Packages (BSPs)
  provided by NXP for their i.MX family of applications processors
  and other embedded platforms.

  i.MX LF release and related information can be obtained from: `LF
  <https://www.nxp.com/design/design-center/software/embedded-software/i-mx-software/embedded-linux-for-i-mx-applications-processors:IMXLINUX>`_
  Refer section: Linux Current Release.


Driver compilation and testing
------------------------------

Follow instructions available in the document
:ref:`compiling and testing a PMD for a NIC <pmd_build_and_test>`
to launch **testpmd**.


Rx Interrupt Mode (VF)
----------------------

The ENETC4 VF PMD supports per-queue MSI-X Rx interrupts on the cacheable
(default) Rx path. This allows applications to block in ``epoll_wait``
instead of busy-polling, reducing CPU utilization when traffic is absent.

**MSI-X vector assignment**

ENETC4 VF MSI-X vector 0 is reserved for the PSI-to-VSI mailbox interrupt
(link status notifications). Rx queue ``i`` is mapped to vector ``i + 1``.
The driver allocates all required eventfds before calling
``rte_intr_enable()`` so that ``vfio-pci`` can wire each MSI-X vector to
its eventfd when it programs the MSI-X table.

**Kernel and driver requirements**

- ``vfio-pci`` kernel module with no-IOMMU mode enabled (no SMMU required).
- The non-cacheable memory mode (``nc=1`` devarg) does **not** support
  Rx interrupts and returns ``-ENOTSUP`` from ``rx_queue_intr_enable``.

**Host setup**

.. code-block:: console

   # Enable vfio-pci no-IOMMU mode (if SMMU is not available)
   modprobe vfio enable_unsafe_noiommu_mode=1
   modprobe vfio-pci

   # Bind the VF to vfio-pci
   echo vfio-pci > /sys/bus/pci/devices/<vf_pci_addr>/driver_override
   echo <vf_pci_addr> > /sys/bus/pci/drivers_probe

**Running l3fwd-power with a single queue and core**

The ``l3fwd-power`` sample application demonstrates interrupt-driven Rx.
It sets ``intr_conf.rxq = 1`` in ``rte_eth_conf``, which triggers the VF
interrupt setup in the driver. The ``--vfio-intr=msix`` EAL flag instructs
DPDK to use MSI-X eventfds for interrupt signalling.

.. code-block:: console

   ./dpdk-l3fwd-power -l 0-1 -n 1 --vfio-intr=msix \
       -a <vf_pci_addr> -- \
       -p 0x1 --config="(0,0,1)" --no-numa --interrupt-only

Where:

- ``-l 0-1`` assigns the main thread to core 0 and the forwarding lcore to
  core 1.
- ``-a <vf_pci_addr>`` specifies the VF PCI address (e.g. ``0000:01:00.1``).
- ``--config="(0,0,1)"`` maps port 0, queue 0 to lcore 1.
- ``--interrupt-only`` enables pure interrupt mode (no busy-poll fallback).

With no incoming traffic the forwarding lcore sleeps in ``epoll_wait``;
CPU utilization drops to near zero. On the first arriving packet the MSI-X
interrupt fires, the lcore wakes, drains the ring, disables the interrupt,
processes the burst, then re-enables and re-arms the interrupt before
returning to sleep.
