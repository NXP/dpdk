/* SPDX-License-Identifier: GPL-2.0
 * Copyright 2018-2023 NXP
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

#define LSINIC_HOST_KERNEL_VER LINUX_VERSION_CODE

/*****************************************************************************/
#if (KERNEL_VERSION(2, 6, 27) > LSINIC_HOST_KERNEL_VER)
#ifdef CONFIG_NETDEVICES_MULTIQUEUE
#define HAVE_TX_MQ
#endif
#else
#define HAVE_TX_MQ
#endif

#if (KERNEL_VERSION(2, 6, 37) > LSINIC_HOST_KERNEL_VER)
#error Too old Kernel version to support LS/LX EP host driver.
#endif

#define HAVE_NDO_GET_STATS64

#if (KERNEL_VERSION(2, 6, 39) <= LSINIC_HOST_KERNEL_VER)
#define HAVE_HW_FEATURES
#endif

/*****************************************************************************/
#if (KERNEL_VERSION(3, 0, 0) <= LSINIC_HOST_KERNEL_VER || \
	(RHEL_RELEASE_CODE && \
	RHEL_RELEASE_VERSION(6, 3) < RHEL_RELEASE_CODE))
#define HAVE_FREE_RCU
#endif

#if (KERNEL_VERSION(3, 2, 0) > LSINIC_HOST_KERNEL_VER)
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

#if (KERNEL_VERSION(3, 3, 0) > LSINIC_HOST_KERNEL_VER)
#define netdev_tx_reset_queue(q) do {} while (0)
#endif

/*****************************************************************************/
#if (KERNEL_VERSION(3, 11, 0) > LSINIC_HOST_KERNEL_VER)
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

#if (KERNEL_VERSION(3, 15, 0) <= LSINIC_HOST_KERNEL_VER || \
	(RHEL_RELEASE_CODE && \
	RHEL_RELEASE_VERSION(6, 6) <= RHEL_RELEASE_CODE))
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

#if (KERNEL_VERSION(3, 18, 0) < LSINIC_HOST_KERNEL_VER)
#define INIC_READ_ONCE(a) READ_ONCE((a))
#else
#define INIC_READ_ONCE(a) ACCESS_ONCE((a))
#endif

/*****************************************************************************/
#if (KERNEL_VERSION(4, 8, 0) <= LSINIC_HOST_KERNEL_VER)
#define HAVE_PCI_ALLOC_IRQ_VECTORS
#endif

#ifdef HAVE_NDO_GET_STATS64
#if (KERNEL_VERSION(3, 10, 0) <= LSINIC_HOST_KERNEL_VER)
#define HAVE_NEW_INTERFACE
#endif
#endif

#if (KERNEL_VERSION(4, 15, 0) <= LSINIC_HOST_KERNEL_VER)
#define HAVE_TIMER_SETUP
#endif
#endif /* LSINIC_KCOMPAT_H */
