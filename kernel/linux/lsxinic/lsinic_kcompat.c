/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018-2021 NXP
 */

#include "lsinic_kcompat.h"

#if (KERNEL_VERSION(2, 6, 35) > LINUX_VERSION_CODE)
#ifdef HAVE_TX_MQ
#ifndef CONFIG_NETDEVICES_MULTIQUEUE
void __lsinic_netif_set_real_num_tx_queues(struct net_device *dev,
					   unsigned int txq)
{
	unsigned int real_num = dev->real_num_tx_queues;
	struct Qdisc *qdisc;
	int i;

	if (unlikely(txq > dev->num_tx_queues))
		;
	else if (txq > real_num)
		dev->real_num_tx_queues = txq;
	else if (txq < real_num) {
		dev->real_num_tx_queues = txq;
		for (i = txq; i < dev->num_tx_queues; i++) {
			qdisc = netdev_get_tx_queue(dev, i)->qdisc;
			if (qdisc) {
				spin_lock_bh(qdisc_lock(qdisc));
				qdisc_reset(qdisc);
				spin_unlock_bh(qdisc_lock(qdisc));
			}
		}
	}
}
#endif /* CONFIG_NETDEVICES_MULTIQUEUE */
#endif /* HAVE_TX_MQ */
#endif /* < 2.6.35 */

#if (KERNEL_VERSION(3, 7, 0) > LINUX_VERSION_CODE || \
	(RHEL_RELEASE_CODE && RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(6, 5)))

static inline int __lsinic_pcie_cap_version(struct pci_dev *dev)
{
	int pos;
	u16 reg16;

	pos = pci_find_capability(dev, PCI_CAP_ID_EXP);
	if (!pos)
		return 0;
	pci_read_config_word(dev, pos + PCI_EXP_FLAGS, &reg16);
	return reg16 & PCI_EXP_FLAGS_VERS;
}

static inline bool __lsinic_pcie_cap_has_devctl(const struct pci_dev
						__always_unused *dev)
{
	return true;
}

static inline bool __lsinic_pcie_cap_has_lnkctl(struct pci_dev *dev)
{
	int type = pci_pcie_type(dev);

	return __lsinic_pcie_cap_version(dev) > 1 ||
		type == PCI_EXP_TYPE_ROOT_PORT ||
		type == PCI_EXP_TYPE_ENDPOINT ||
		type == PCI_EXP_TYPE_LEG_END;
}

static inline bool __lsinic_pcie_cap_has_sltctl(struct pci_dev *dev)
{
	int type = pci_pcie_type(dev);
	int pos;
	u16 pcie_flags_reg;

	pos = pci_find_capability(dev, PCI_CAP_ID_EXP);
	if (!pos)
		return 0;
	pci_read_config_word(dev, pos + PCI_EXP_FLAGS, &pcie_flags_reg);

	return __lsinic_pcie_cap_version(dev) > 1 ||
		type == PCI_EXP_TYPE_ROOT_PORT ||
		(type == PCI_EXP_TYPE_DOWNSTREAM &&
		pcie_flags_reg & PCI_EXP_FLAGS_SLOT);
}

static inline bool __lsinic_pcie_cap_has_rtctl(struct pci_dev *dev)
{
	int type = pci_pcie_type(dev);

	return __lsinic_pcie_cap_version(dev) > 1 ||
		type == PCI_EXP_TYPE_ROOT_PORT ||
		type == PCI_EXP_TYPE_RC_EC;
}

static bool __lsinic_pcie_capability_reg_implemented(struct pci_dev *dev,
						     int pos)
{
	if (!pci_is_pcie(dev))
		return false;

	switch (pos) {
	case PCI_EXP_FLAGS_TYPE:
		return true;
	case PCI_EXP_DEVCAP:
	case PCI_EXP_DEVCTL:
	case PCI_EXP_DEVSTA:
		return __lsinic_pcie_cap_has_devctl(dev);
	case PCI_EXP_LNKCAP:
	case PCI_EXP_LNKCTL:
	case PCI_EXP_LNKSTA:
		return __lsinic_pcie_cap_has_lnkctl(dev);
	case PCI_EXP_SLTCAP:
	case PCI_EXP_SLTCTL:
	case PCI_EXP_SLTSTA:
		return __lsinic_pcie_cap_has_sltctl(dev);
	case PCI_EXP_RTCTL:
	case PCI_EXP_RTCAP:
	case PCI_EXP_RTSTA:
		return __lsinic_pcie_cap_has_rtctl(dev);
	case PCI_EXP_DEVCAP2:
	case PCI_EXP_DEVCTL2:
	case PCI_EXP_LNKCTL2:
		return __lsinic_pcie_cap_version(dev) > 1;
	default:
		return false;
	}
}

 /*
  * Note that these accessor functions are only for the "PCI Express
  * Capability" (see PCIe spec r3.0, sec 7.8).	They do not apply to the
  * other "PCI Express Extended Capabilities" (AER, VC, ACS, MFVC, etc.)
  */
int __lsinic_pcie_capability_read_word(struct pci_dev *dev, int pos, u16 *val)
{
	int ret;

	*val = 0;
	if (pos & 1)
		return -EINVAL;

	if (__lsinic_pcie_capability_reg_implemented(dev, pos)) {
		ret = pci_read_config_word(dev, pci_pcie_cap(dev) + pos, val);
		/*
		 * Reset *val to 0 if pci_read_config_word() fails, it may
		 * have been written as 0xFFFF if hardware error happens
		 * during pci_read_config_word().
		 */
		if (ret)
			*val = 0;
		return ret;
	}

	/*
	 * For Functions that do not implement the Slot Capabilities,
	 * Slot Status, and Slot Control registers, these spaces must
	 * be hardwired to 0b, with the exception of the Presence Detect
	 * State bit in the Slot Status register of Downstream Ports,
	 * which must be hardwired to 1b.  (PCIe Base Spec 3.0, sec 7.8)
	 */
	if (pci_is_pcie(dev) && pos == PCI_EXP_SLTSTA &&
		pci_pcie_type(dev) == PCI_EXP_TYPE_DOWNSTREAM) {
		*val = PCI_EXP_SLTSTA_PDS;
	}

	return 0;
}

int __lsinic_pcie_capability_write_word(struct pci_dev *dev, int pos, u16 val)
{
	if (pos & 1)
		return -EINVAL;

	if (!__lsinic_pcie_capability_reg_implemented(dev, pos))
		return 0;

	return pci_write_config_word(dev, pci_pcie_cap(dev) + pos, val);
}

int __lsinic_pcie_capability_clear_and_set_word(struct pci_dev *dev, int pos,
					     u16 clear, u16 set)
{
	int ret;
	u16 val;

	ret = __lsinic_pcie_capability_read_word(dev, pos, &val);
	if (!ret) {
		val &= ~clear;
		val |= set;
		ret = __lsinic_pcie_capability_write_word(dev, pos, val);
	}

	return ret;
}
#endif

#if (KERNEL_VERSION(3, 10, 0) > LINUX_VERSION_CODE)
#ifdef CONFIG_PCI_IOV
int __lsinic_pci_vfs_assigned(struct pci_dev *dev)
{
	unsigned int vfs_assigned = 0;
#ifdef HAVE_PCI_DEV_FLAGS_ASSIGNED
	int pos;
	struct pci_dev *vfdev;
	unsigned short dev_id;

	/* only search if we are a PF */
	if (!dev->is_physfn)
		return 0;

	/* find SR-IOV capability */
	pos = pci_find_ext_capability(dev, PCI_EXT_CAP_ID_SRIOV);
	if (!pos)
		return 0;

	/*
	 ** determine the device ID for the VFs, the vendor ID will be the
	 ** same as the PF so there is no need to check for that one
	 **/
	pci_read_config_word(dev, pos + PCI_SRIOV_VF_DID, &dev_id);

	/* loop through all the VFs to see if we own any that are assigned */
	vfdev = pci_get_device(dev->vendor, dev_id, NULL);
	while (vfdev) {
		/*
		 ** It is considered assigned if it is a virtual function with
		 ** our dev as the physical function and the assigned bit is set
		 **/
		if (vfdev->is_virtfn && (vfdev->physfn == dev) &&
			(vfdev->dev_flags & PCI_DEV_FLAGS_ASSIGNED))
			vfs_assigned++;

		vfdev = pci_get_device(dev->vendor, dev_id, vfdev);
	}

#endif /* HAVE_PCI_DEV_FLAGS_ASSIGNED */
	return vfs_assigned;
}
#endif /* CONFIG_PCI_IOV */
#endif /* 3.10.0 */

#if (KERNEL_VERSION(3, 14, 0) > LINUX_VERSION_CODE || \
	(RHEL_RELEASE_CODE && RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(6, 3)))
int __lsinic_pci_enable_msi_range(struct pci_dev *dev, int minvec, int maxvec)
{
	int nvec = maxvec;
	int rc;

	if (maxvec < minvec)
		return -ERANGE;

	do {
		rc = pci_enable_msi_block(dev, nvec);
		if (rc < 0) {
			return rc;
		} else if (rc > 0) {
			if (rc < minvec)
				return -ENOSPC;
			nvec = rc;
		}
	} while (rc);

	return nvec;
}
#endif
