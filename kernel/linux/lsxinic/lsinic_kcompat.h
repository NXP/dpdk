/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018-2021 NXP
 */

#ifndef _LSINIC_KCOMPAT_H_
#define _LSINIC_KCOMPAT_H_

#include <linux/device.h>
#include <linux/pci.h>
#include <linux/types.h>
#include <linux/pci.h>
#include <linux/netdevice.h>

#ifndef LINUX_VERSION_CODE
#include <linux/version.h>
#else
#ifndef KERNEL_VERSION
#define KERNEL_VERSION(a, b, c) (((a) << 16) + ((b) << 8) + (c))
#endif
#endif

#ifndef RHEL_RELEASE_VERSION
#define RHEL_RELEASE_VERSION(a, b) (((a) << 8) + (b))
#endif

#ifndef RHEL_RELEASE_CODE
#define RHEL_RELEASE_CODE 0
#endif

/*****************************************************************************/
#if (KERNEL_VERSION(2, 6, 27) > LINUX_VERSION_CODE)
	#ifdef CONFIG_NETDEVICES_MULTIQUEUE
		#define HAVE_TX_MQ
	#endif
#else
	#define HAVE_TX_MQ
#endif

#if (KERNEL_VERSION(2, 6, 37) > LINUX_VERSION_CODE)
#error Too old Kernel version to support LS/LX EP host driver.
#endif

#define HAVE_NDO_GET_STATS64

#if (KERNEL_VERSION(2, 6, 39) <= LINUX_VERSION_CODE)
#define HAVE_HW_FEATURES
#endif

/*****************************************************************************/
#if (KERNEL_VERSION(3, 0, 0) <= LINUX_VERSION_CODE || \
	(RHEL_RELEASE_CODE && RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(6, 3)))
#define HAVE_FREE_RCU
#endif

#if (KERNEL_VERSION(3, 2, 0) > LINUX_VERSION_CODE)
	#if (RHEL_RELEASE_CODE && \
	     RHEL_RELEASE_VERSION(6, 3) <= RHEL_RELEASE_CODE)
		#ifndef HAVE_PCI_DEV_FLAGS_ASSIGNED
			#define HAVE_PCI_DEV_FLAGS_ASSIGNED
		#endif
	#endif
#else /* < 3.2.0 */
	#ifndef HAVE_PCI_DEV_FLAGS_ASSIGNED
		#define HAVE_PCI_DEV_FLAGS_ASSIGNED
		#define	HAVE_VF_SPOOFCHK_CONFIGURE
	#endif
#endif /* < 3.2.0 */

#ifdef HAVE_VF_SPOOFCHK_CONFIGURE
	#define HAVE_SPOOFCHK
#else
	#if (RHEL_RELEASE_CODE && \
	     RHEL_RELEASE_VERSION(6, 6) <= RHEL_RELEASE_CODE)
		#define HAVE_SPOOFCHK
	#endif
#endif

#if (KERNEL_VERSION(3, 3, 0) > LINUX_VERSION_CODE)
#define netdev_tx_reset_queue(q) do {} while (0)
#endif

/*****************************************************************************/
#if (KERNEL_VERSION(3, 7, 0) > LINUX_VERSION_CODE || \
	(RHEL_RELEASE_CODE && RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(6, 5)))
#define pci_pcie_type(dev) ((dev)->pcie_type)
extern int __lsinic_pcie_capability_clear_and_set_word(
						struct pci_dev *dev, int pos,
						u16 clear, u16 set);

extern int __lsinic_pcie_capability_read_word(struct pci_dev *dev,
					      int pos,
					      u16 *val);

extern int __lsinic_pcie_capability_write_word(struct pci_dev *dev,
					       int pos,
					       u16 val);

#define pcie_capability_read_word(d, p, v) \
		__lsinic_pcie_capability_read_word(d, p, v)

#define pcie_capability_clear_and_set_word(d, p, c, s) \
		__lsinic_pcie_capability_clear_and_set_word(d, p, c, s)

#define pcie_capability_write_word(d, p, v) \
		__lsinic_pcie_capability_write_word(d, p, v)
#endif

/*****************************************************************************/
#if (KERNEL_VERSION(3, 10, 0) > LINUX_VERSION_CODE)
	#ifdef CONFIG_PCI_IOV
		extern int __lsinic_pci_vfs_assigned(struct pci_dev *dev);
	#else
		static inline int __lsinic_pci_vfs_assigned(struct pci_dev *dev)
		{
			return 0;
		}
	#endif
#define pci_vfs_assigned(dev) __lsinic_pci_vfs_assigned(dev)
#endif

/*****************************************************************************/
#if (KERNEL_VERSION(3, 11, 0) > LINUX_VERSION_CODE)
	#include <net/ip.h>
	#if (RHEL_RELEASE_CODE && \
	     RHEL_RELEASE_VERSION(6, 7) > RHEL_RELEASE_CODE)
		#define skb_mark_napi_id(skb, napi) do {} while (0)
	#else
		#include <net/busy_poll.h>
	#endif
#else
	#include <net/busy_poll.h>
#endif

/*****************************************************************************/
#if (KERNEL_VERSION(3, 14, 0) > LINUX_VERSION_CODE || \
	(RHEL_RELEASE_CODE && RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(6, 3)))
extern int __lsinic_pci_enable_msi_range(struct pci_dev *dev,
					 int minvec,
					 int maxvec);
#define pci_enable_msi_range(pdev, minvec, maxvec) \
		__lsinic_pci_enable_msi_range(pdev, minvec, maxvec)

#endif

/*****************************************************************************/

#if (KERNEL_VERSION(3, 15, 0) <= LINUX_VERSION_CODE || \
	(RHEL_RELEASE_CODE && RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(6, 6)))
#define INIC_U64_STATS_FETCH_BEGIN(syncp) \
		u64_stats_fetch_begin_irq((syncp))
#define INIC_U64_STATS_FETCH_RETRY(syncp, start) \
		u64_stats_fetch_retry_irq((syncp), (start))
#else
#define INIC_U64_STATS_FETCH_BEGIN(syncp) \
		u64_stats_fetch_begin_bh((syncp))
#define INIC_U64_STATS_FETCH_RETRY(syncp, start) \
		u64_stats_fetch_retry_bh((syncp), (start))
#endif

#if (KERNEL_VERSION(3, 18, 0) < LINUX_VERSION_CODE)
#define INIC_READ_ONCE(a) READ_ONCE((a))
#else
#define INIC_READ_ONCE(a) ACCESS_ONCE((a))
#endif

/*****************************************************************************/
#if (KERNEL_VERSION(4, 8, 0) <= LINUX_VERSION_CODE)
#define HAVE_PCI_ALLOC_IRQ_VECTORS
#endif

#ifdef HAVE_NDO_GET_STATS64
	#if (KERNEL_VERSION(4, 9, 62) <= LINUX_VERSION_CODE)
		#define HAVE_NEW_INTERFACE
	#endif
#endif

#if (KERNEL_VERSION(4, 15, 0) <= LINUX_VERSION_CODE)
#define HAVE_TIMER_SETUP
#endif

/*****************************************************************************/

#endif /* LSINIC_KCOMPAT_H */
