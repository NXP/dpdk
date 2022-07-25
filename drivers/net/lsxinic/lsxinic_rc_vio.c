/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2016 Intel Corporation
 * Copyright 2022 NXP
 */

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>

#include <rte_ethdev_driver.h>
#include <rte_ethdev_pci.h>
#include <rte_memcpy.h>
#include <rte_string_fns.h>
#include <rte_memzone.h>
#include <rte_malloc.h>
#include <rte_branch_prediction.h>
#include <rte_pci.h>
#include <rte_bus_pci.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_arp.h>
#include <rte_common.h>
#include <rte_errno.h>
#include <rte_cpuflags.h>

#include <rte_memory.h>
#include <rte_eal.h>
#include <rte_dev.h>
#include <rte_cycles.h>
#include <rte_kvargs.h>
#include <rte_io.h>

#include "virtio_ethdev.h"
#include "virtio_pci.h"
#include "virtio_logs.h"
#include "virtqueue.h"
#include "virtio_rxtx.h"
#include "virtio_user/virtio_user_dev.h"

#include "lsxinic_vio_common.h"

struct lsxvio_pci_cfg {
	struct lsxvio_common_cfg common_cfg;
	struct lsxvio_queue_cfg queue_cfg[LSXVIO_MAX_QUEUE_PAIRS * 2];
} __attribute__((__packed__));

struct lsxvio_rc_pci_hw {
	struct virtio_hw common_cfg;
	struct lsxvio_pci_cfg *lsx_cfg;
	uint8_t *ring_base;
	uint16_t last_avail_idx[LSXVIO_MAX_QUEUE_PAIRS * 2];
};

#define LSXVIO_HW(COMMON_VIO_HW) \
	(void *)((char *)(COMMON_VIO_HW) - \
	offsetof(struct lsxvio_rc_pci_hw, common_cfg))

static int
lsxvio_rc_eth_uninit(struct rte_eth_dev *eth_dev);
static int
lsxvio_rc_eth_configure(struct rte_eth_dev *dev);
static int
lsxvio_rc_eth_start(struct rte_eth_dev *dev);
static void
lsxvio_rc_eth_stop(struct rte_eth_dev *dev);
static int
lsxvio_rc_eth_prom_enable(struct rte_eth_dev *dev);
static int
lsxvio_rc_eth_prom_disable(struct rte_eth_dev *dev);
static int
lsxvio_rc_eth_mcast_enable(struct rte_eth_dev *dev);
static int
lsxvio_rc_eth_mcast_disable(struct rte_eth_dev *dev);
static int
lsxvio_rc_eth_info_get(struct rte_eth_dev *dev,
	struct rte_eth_dev_info *dev_info);
static int
lsxvio_rc_eth_link_update(struct rte_eth_dev *dev,
	int wait_to_complete);

static void
lsxvio_rc_set_hwaddr(struct virtio_hw *hw);
static void
lsxvio_rc_get_hwaddr(struct virtio_hw *hw);

static int
lsxvio_rc_eth_stats_get(struct rte_eth_dev *dev,
	struct rte_eth_stats *stats);
static int
lsxvio_rc_eth_xstats_get(struct rte_eth_dev *dev,
	struct rte_eth_xstat *xstats, uint32_t n);
static int
lsxvio_rc_eth_xstats_get_names(struct rte_eth_dev *dev,
	struct rte_eth_xstat_name *xstats_names,
	uint32_t limit);
static int
lsxvio_rc_eth_stats_reset(struct rte_eth_dev *dev);
static void
lsxvio_rc_free_mbufs(struct rte_eth_dev *dev);

int lsxvio_rc_logtype_init;
int lsxvio_rc_logtype_driver;

static int s_lsxvio_rc_sim;

static const struct rte_pci_id lsxvio_pci_id_map[] = {
	{ RTE_PCI_DEVICE(VIRTIO_PCI_VENDORID, VIRTIO_PCI_LEGACY_DEVICEID_NET) },
	{ RTE_PCI_DEVICE(VIRTIO_PCI_VENDORID, VIRTIO_PCI_MODERN_DEVICEID_NET) },
	{ .vendor_id = 0, /* sentinel */ },
};

struct lsxvio_rc_eth_xstats_name_off {
	char name[RTE_ETH_XSTATS_NAME_SIZE];
	uint32_t offset;
};

/* [rt]x_qX_ is prepended to the name string here */
static const
struct lsxvio_rc_eth_xstats_name_off s_lsxvio_rc_rxq_stat_str[] = {
	{
		"good_packets",
		offsetof(struct virtnet_rx, stats.packets)
	},
	{
		"good_bytes",
		offsetof(struct virtnet_rx, stats.bytes)
	},
	{
		"errors",
		offsetof(struct virtnet_rx, stats.errors)
	},
	{
		"multicast_packets",
		offsetof(struct virtnet_rx, stats.multicast)
	},
	{
		"broadcast_packets",
		offsetof(struct virtnet_rx, stats.broadcast)
	},
	{
		"undersize_packets",
		offsetof(struct virtnet_rx, stats.size_bins[0])
	},
	{
		"size_64_packets",
		offsetof(struct virtnet_rx, stats.size_bins[1])
	},
	{
		"size_65_127_packets",
		offsetof(struct virtnet_rx, stats.size_bins[2])
	},
	{
		"size_128_255_packets",
		offsetof(struct virtnet_rx, stats.size_bins[3])
	},
	{
		"size_256_511_packets",
		offsetof(struct virtnet_rx, stats.size_bins[4])
	},
	{
		"size_512_1023_packets",
		offsetof(struct virtnet_rx, stats.size_bins[5])
	},
	{
		"size_1024_1518_packets",
		offsetof(struct virtnet_rx, stats.size_bins[6])
	},
	{
		"size_1519_max_packets",
		offsetof(struct virtnet_rx, stats.size_bins[7])
	},
};

/* [rt]x_qX_ is prepended to the name string here */
static const
struct lsxvio_rc_eth_xstats_name_off s_lsxvio_rc_txq_stat_str[] = {
	{
		"good_packets",
		offsetof(struct virtnet_tx, stats.packets)
	},
	{
		"good_bytes",
		offsetof(struct virtnet_tx, stats.bytes)
	},
	{
		"multicast_packets",
		offsetof(struct virtnet_tx, stats.multicast)
	},
	{
		"broadcast_packets",
		offsetof(struct virtnet_tx, stats.broadcast)
	},
	{
		"undersize_packets",
		offsetof(struct virtnet_tx, stats.size_bins[0])
	},
	{
		"size_64_packets",
		offsetof(struct virtnet_tx, stats.size_bins[1])
	},
	{
		"size_65_127_packets",
		offsetof(struct virtnet_tx, stats.size_bins[2])
	},
	{
		"size_128_255_packets",
		offsetof(struct virtnet_tx, stats.size_bins[3])
	},
	{
		"size_256_511_packets",
		offsetof(struct virtnet_tx, stats.size_bins[4])
	},
	{
		"size_512_1023_packets",
		offsetof(struct virtnet_tx, stats.size_bins[5])
	},
	{
		"size_1024_1518_packets",
		offsetof(struct virtnet_tx, stats.size_bins[6])
	},
	{
		"size_1519_max_packets",
		offsetof(struct virtnet_tx, stats.size_bins[7])
	},
};

static int s_lsxvio_rc_2nd_proc_standalone;

static struct rte_eth_dev_data *s_lsxvio_rc_eth_data;
static rte_spinlock_t s_lsxvio_rc_lock = RTE_SPINLOCK_INITIALIZER;

#define LSXVIO_NB_RXQ_XSTATS (sizeof(s_lsxvio_rc_rxq_stat_str) / \
			    sizeof(s_lsxvio_rc_rxq_stat_str[0]))
#define LSXVIO_NB_TXQ_XSTATS (sizeof(s_lsxvio_rc_txq_stat_str) / \
			    sizeof(s_lsxvio_rc_txq_stat_str[0]))

static inline void
lsxvio_write64_twopart(uint64_t val,
	uint32_t *lo, uint32_t *hi)
{
	rte_write32(val & ((1ULL << 32) - 1), lo);
	rte_write32(val >> 32, hi);
}

static inline uint64_t
lsxvio_priv_feature(struct lsxvio_rc_pci_hw *lsx_hw)
{
	struct lsxvio_pci_cfg *lsx_cfg = lsx_hw->lsx_cfg;
	struct lsxvio_common_cfg *c_cfg = &lsx_cfg->common_cfg;
	uint64_t lsx_feature = rte_read64(&c_cfg->lsx_feature);

	return lsx_feature;
}

static void
lsxvio_rc_eth_queue_release(void *queue __rte_unused)
{
	/* do nothing */
}

static uint16_t
lsxvio_rc_get_nr_vq(struct virtio_hw *hw)
{
	uint16_t nr_vq = hw->max_queue_pairs * 2;

	if (vtpci_with_feature(hw, VIRTIO_NET_F_CTRL_VQ))
		nr_vq += 1;

	return nr_vq;
}

static inline void
lsxvio_rc_init_split_desc(struct vring *vr, uint8_t *p)
{
	vr->desc = (void *)p;
}

static inline void
lsxvio_rc_init_split_avail_used(struct vring *vr,
	uint8_t *p, unsigned long align, unsigned int num)
{
	vr->num = num;
	vr->avail = (void *)p;
	vr->used = (void *)
		RTE_ALIGN_CEIL((uintptr_t)(&vr->avail->ring[num]),
			align);
	vr->used = (void *)((uint8_t *)vr->used +
		offsetof(struct vring_used, ring[0]));
}

static inline void
lsxvio_rc_init_split(struct vring *vr, uint8_t *pdesc,
	uint8_t *p, unsigned long align, unsigned int num)
{
	if (pdesc) {
		lsxvio_rc_init_split_desc(vr, pdesc);
		lsxvio_rc_init_split_avail_used(vr, p, align, num);
	} else {
		lsxvio_rc_init_split_desc(vr, p);
		lsxvio_rc_init_split_avail_used(vr,
			(p + num * sizeof(struct vring_desc)), align, num);
	}
}

static void
lsxvio_rc_init_vring(struct virtqueue *vq, int queue_type)
{
	int size = vq->vq_nentries;
	uint8_t *ring_mem = vq->vq_ring_virt_mem;
	struct lsxvio_rc_pci_hw *lsx_hw = LSXVIO_HW(vq->hw);
	uint64_t lsx_feature = lsxvio_priv_feature(lsx_hw);
	uint8_t *remote_ring_base = lsx_hw->ring_base;
	struct vring *vr = &vq->vq_split.ring;

	PMD_INIT_FUNC_TRACE();

	memset(ring_mem, 0, vq->vq_ring_size);

	vq->vq_used_cons_idx = 0;
	vq->vq_desc_head_idx = 0;
	vq->vq_avail_idx = 0;
	vq->vq_desc_tail_idx = (uint16_t)(vq->vq_nentries - 1);
	vq->vq_free_cnt = vq->vq_nentries;
	memset(vq->vq_descx, 0,
		sizeof(struct vq_desc_extra) * vq->vq_nentries);
	if (vtpci_packed_queue(vq->hw)) {
		vring_init_packed(&vq->vq_packed.ring, ring_mem,
				  VIRTIO_PCI_VRING_ALIGN, size);
		vring_desc_init_packed(vq, size);
	} else if (queue_type == VTNET_RQ &&
		(lsx_feature & LSX_VIO_EP2RC_PACKED)) {
		vring_init_packed(&vq->vq_packed.ring, ring_mem,
				  VIRTIO_PCI_VRING_ALIGN, size);
		vring_desc_init_packed(vq, size);
	} else if (queue_type == VTNET_TQ) {
		remote_ring_base += vq->vq_queue_index *
			LSXVIO_PER_RING_NOTIFY_MAX_SIZE;
		lsxvio_rc_init_split(vr, remote_ring_base,
			ring_mem, VIRTIO_PCI_VRING_ALIGN, size);
		vring_desc_init_split(vr->desc, size);
	} else {
		lsxvio_rc_init_split(vr, NULL, ring_mem,
			VIRTIO_PCI_VRING_ALIGN, size);
		vring_desc_init_split(vr->desc, size);
	}

	virtqueue_disable_intr(vq);
}

static int
lsxvio_rc_init_queue(struct rte_eth_dev *dev,
	uint16_t vtpci_queue_idx)
{
	char vq_name[VIRTQUEUE_MAX_NAME_SZ];
	char vq_hdr_name[VIRTQUEUE_MAX_NAME_SZ];
	const struct rte_memzone *mz = NULL, *hdr_mz = NULL;
	uint32_t vq_size, size;
	struct lsxvio_rc_pci_hw *lsx_hw = dev->data->dev_private;
	struct virtio_hw *hw = &lsx_hw->common_cfg;
	uint64_t lsx_feature = lsxvio_priv_feature(lsx_hw);
	struct virtnet_rx *rxvq = NULL;
	struct virtnet_tx *txvq = NULL;
	struct virtnet_ctl *cvq = NULL;
	struct virtqueue *vq;
	size_t sz_hdr_mz = 0;
	void *sw_ring = NULL;
	int queue_type = virtio_get_queue_type(hw, vtpci_queue_idx);
	int ret;
	int numa_node = dev->device->numa_node;

	PMD_INIT_LOG(INFO, "setting up queue: %u on NUMA node %d",
			vtpci_queue_idx, numa_node);

	vq_size = VTPCI_OPS(hw)->get_queue_num(hw, vtpci_queue_idx);
	PMD_INIT_LOG(DEBUG, "vq_size: %u", vq_size);
	if (vq_size == 0) {
		PMD_INIT_LOG(ERR, "virtqueue does not exist");
		return -EINVAL;
	}

	if (!vtpci_packed_queue(hw) && !rte_is_power_of_2(vq_size)) {
		PMD_INIT_LOG(ERR, "split virtqueue size is not power of 2");
		return -EINVAL;
	}

	snprintf(vq_name, sizeof(vq_name), "port%d_vq%d",
		 dev->data->port_id, vtpci_queue_idx);

	size = RTE_ALIGN_CEIL(sizeof(*vq) +
				vq_size * sizeof(struct vq_desc_extra),
				RTE_CACHE_LINE_SIZE);
	if (queue_type == VTNET_TQ) {
		sz_hdr_mz = vq_size * sizeof(struct virtio_tx_region);
	} else if (queue_type == VTNET_CQ) {
		/* Allocate a page for control vq command, data and status */
		sz_hdr_mz = PAGE_SIZE;
	}

	vq = rte_zmalloc_socket(vq_name, size, RTE_CACHE_LINE_SIZE,
				numa_node);
	if (!vq) {
		PMD_INIT_LOG(ERR, "can not allocate vq");
		return -ENOMEM;
	}
	hw->vqs[vtpci_queue_idx] = vq;

	vq->hw = hw;
	vq->vq_queue_index = vtpci_queue_idx;
	vq->vq_nentries = vq_size;
	if (vtpci_packed_queue(hw)) {
		vq->vq_packed.used_wrap_counter = 1;
		vq->vq_packed.cached_flags = VRING_PACKED_DESC_F_AVAIL;
		vq->vq_packed.event_flags_shadow = 0;
		if (queue_type == VTNET_RQ)
			vq->vq_packed.cached_flags |= VRING_DESC_F_WRITE;
	} else if (queue_type == VTNET_RQ &&
		(lsx_feature & LSX_VIO_EP2RC_PACKED)) {
		vq->vq_packed.used_wrap_counter = 1;
		vq->vq_packed.cached_flags = VRING_PACKED_DESC_F_AVAIL;
		vq->vq_packed.event_flags_shadow = 0;
		vq->vq_packed.cached_flags |= VRING_DESC_F_WRITE;
	}

	vq->vq_ring_size = LSXVIO_PER_RING_MEM_MAX_SIZE;

	mz = rte_memzone_reserve_aligned(vq_name, vq->vq_ring_size,
			numa_node, RTE_MEMZONE_IOVA_CONTIG,
			vq->vq_ring_size);
	if (!mz) {
		if (rte_errno == EEXIST)
			mz = rte_memzone_lookup(vq_name);
		if (!mz) {
			ret = -ENOMEM;
			goto fail_q_alloc;
		}
	}

	memset(mz->addr, 0, mz->len);

	vq->vq_ring_mem = mz->iova;
	vq->vq_ring_virt_mem = mz->addr;
	PMD_INIT_LOG(DEBUG, "vq->vq_ring_mem: 0x%lx",
		     (uint64_t)mz->iova);
	PMD_INIT_LOG(DEBUG, "vq->vq_ring_virt_mem: 0x%lx",
		     (uint64_t)mz->addr);

	lsxvio_rc_init_vring(vq, queue_type);

	if (sz_hdr_mz) {
		snprintf(vq_hdr_name, sizeof(vq_hdr_name), "port%d_vq%d_hdr",
			 dev->data->port_id, vtpci_queue_idx);
		hdr_mz = rte_memzone_reserve_aligned(vq_hdr_name, sz_hdr_mz,
				numa_node, RTE_MEMZONE_IOVA_CONTIG,
				RTE_CACHE_LINE_SIZE);
		if (!hdr_mz) {
			if (rte_errno == EEXIST)
				hdr_mz = rte_memzone_lookup(vq_hdr_name);
			if (!hdr_mz) {
				ret = -ENOMEM;
				goto fail_q_alloc;
			}
		}
	}

	if (queue_type == VTNET_RQ) {
		size_t sz_sw = (RTE_PMD_VIRTIO_RX_MAX_BURST + vq_size) *
			       sizeof(vq->sw_ring[0]);

		sw_ring = rte_zmalloc_socket("sw_ring", sz_sw,
				RTE_CACHE_LINE_SIZE, numa_node);
		if (!sw_ring) {
			PMD_INIT_LOG(ERR, "can not allocate RX soft ring");
			ret = -ENOMEM;
			goto fail_q_alloc;
		}

		vq->sw_ring = sw_ring;
		rxvq = &vq->rxq;
		rxvq->vq = vq;
		rxvq->port_id = dev->data->port_id;
		rxvq->mz = mz;
	} else if (queue_type == VTNET_TQ) {
		txvq = &vq->txq;
		txvq->vq = vq;
		txvq->port_id = dev->data->port_id;
		txvq->mz = mz;
		txvq->virtio_net_hdr_mz = hdr_mz;
		txvq->virtio_net_hdr_mem = hdr_mz->iova;
	} else if (queue_type == VTNET_CQ) {
		cvq = &vq->cq;
		cvq->vq = vq;
		cvq->mz = mz;
		cvq->virtio_net_hdr_mz = hdr_mz;
		cvq->virtio_net_hdr_mem = hdr_mz->iova;
		memset(cvq->virtio_net_hdr_mz->addr, 0, PAGE_SIZE);

		hw->cvq = cvq;
	}

	/* For virtio_user case (that is when hw->virtio_user_dev is not NULL),
	 * we use virtual address. And we need properly set _offset_, please see
	 * VIRTIO_MBUF_DATA_DMA_ADDR in virtqueue.h for more information.
	 */
	if (!hw->virtio_user_dev) {
		vq->offset = offsetof(struct rte_mbuf, buf_iova);
	} else {
		vq->vq_ring_mem = (uintptr_t)mz->addr;
		vq->offset = offsetof(struct rte_mbuf, buf_addr);
		if (queue_type == VTNET_TQ)
			txvq->virtio_net_hdr_mem = (uintptr_t)hdr_mz->addr;
		else if (queue_type == VTNET_CQ)
			cvq->virtio_net_hdr_mem = (uintptr_t)hdr_mz->addr;
	}

	if (queue_type == VTNET_TQ) {
		struct virtio_tx_region *txr;
		uint32_t i;

		txr = hdr_mz->addr;
		memset(txr, 0, vq_size * sizeof(*txr));
		for (i = 0; i < vq_size; i++) {
			struct vring_desc *start_dp = txr[i].tx_indir;

			/* first indirect descriptor is always the tx header */
			if (!vtpci_packed_queue(hw) &&
				!(queue_type == VTNET_RQ &&
				(lsx_feature & LSX_VIO_EP2RC_PACKED))) {
				vring_desc_init_split(start_dp,
						      RTE_DIM(txr[i].tx_indir));
				start_dp->addr = txvq->virtio_net_hdr_mem
					+ i * sizeof(*txr)
					+ offsetof(struct virtio_tx_region,
						   tx_hdr);
				start_dp->len = hw->vtnet_hdr_size;
				start_dp->flags = VRING_DESC_F_NEXT;
			}
		}
	}

	if (VTPCI_OPS(hw)->setup_queue(hw, vq) < 0) {
		PMD_INIT_LOG(ERR, "setup_queue failed");
		return -EINVAL;
	}

	return 0;

fail_q_alloc:
	rte_free(sw_ring);
	rte_memzone_free(hdr_mz);
	rte_memzone_free(mz);
	rte_free(vq);

	return ret;
}

static void
lsxvio_rc_free_queues(struct virtio_hw *hw)
{
	uint16_t nr_vq = lsxvio_rc_get_nr_vq(hw);
	struct virtqueue *vq;
	int queue_type;
	uint16_t i;

	if (!hw->vqs)
		return;

	for (i = 0; i < nr_vq; i++) {
		vq = hw->vqs[i];
		if (!vq)
			continue;

		queue_type = virtio_get_queue_type(hw, i);
		if (queue_type == VTNET_RQ) {
			rte_free(vq->sw_ring);
			rte_memzone_free(vq->rxq.mz);
		} else if (queue_type == VTNET_TQ) {
			rte_memzone_free(vq->txq.mz);
			rte_memzone_free(vq->txq.virtio_net_hdr_mz);
		} else {
			rte_memzone_free(vq->cq.mz);
			rte_memzone_free(vq->cq.virtio_net_hdr_mz);
		}

		rte_free(vq);
		hw->vqs[i] = NULL;
	}

	rte_free(hw->vqs);
	hw->vqs = NULL;
}

static int
lsxvio_rc_alloc_queues(struct rte_eth_dev *dev)
{
	struct virtio_hw *hw = dev->data->dev_private;
	uint16_t nr_vq = lsxvio_rc_get_nr_vq(hw);
	uint16_t i;
	int ret;

	hw->vqs = rte_zmalloc(NULL, sizeof(struct virtqueue *) * nr_vq, 0);
	if (!hw->vqs) {
		PMD_INIT_LOG(ERR, "failed to allocate vqs");
		return -ENOMEM;
	}

	for (i = 0; i < nr_vq; i++) {
		ret = lsxvio_rc_init_queue(dev, i);
		if (ret < 0) {
			lsxvio_rc_free_queues(hw);
			return ret;
		}
	}

	return 0;
}

static void
lsxvio_rc_eth_close(struct rte_eth_dev *dev)
{
	struct virtio_hw *hw = dev->data->dev_private;

	PMD_INIT_LOG(DEBUG, "lsxvio_rc_eth_close");

	if (!hw->opened)
		return;
	hw->opened = false;

	vtpci_reset(hw);
	lsxvio_rc_free_mbufs(dev);
	lsxvio_rc_free_queues(hw);

#ifdef RTE_VIRTIO_USER
	if (hw->virtio_user_dev) {
		virtio_user_dev_uninit(hw->virtio_user_dev);
	} else if (dev->device && !s_lsxvio_rc_sim) {
		rte_pci_unmap_device(RTE_ETH_DEV_TO_PCI(dev));
		if (!hw->modern)
			rte_pci_ioport_unmap(VTPCI_IO(hw));
	}
#else
	if (dev->device && !s_lsxvio_rc_sim) {
		rte_pci_unmap_device(RTE_ETH_DEV_TO_PCI(dev));
		if (!hw->modern)
			rte_pci_ioport_unmap(VTPCI_IO(hw));
	}
#endif
}

static int
lsxvio_rc_eth_prom_enable(__rte_unused struct rte_eth_dev *dev)
{
	/* TBD always support.*/

	return 0;
}

static int
lsxvio_rc_eth_prom_disable(__rte_unused struct rte_eth_dev *dev)
{
	/* TBD always support.*/

	return 0;
}

static int
lsxvio_rc_eth_mcast_enable(__rte_unused struct rte_eth_dev *dev)
{
	/* TBD always support.*/

	return 0;
}

static int
lsxvio_rc_eth_mcast_disable(__rte_unused struct rte_eth_dev *dev)
{
	/* TBD always support.*/

	return 0;
}

#define VLAN_TAG_LEN           4    /* 802.3ac tag (not DMA'd) */
static int
lsxvio_rc_mtu_set(struct rte_eth_dev *dev, uint16_t mtu)
{
	struct virtio_hw *hw = dev->data->dev_private;
	uint32_t ether_hdr_len = RTE_ETHER_HDR_LEN + VLAN_TAG_LEN +
				 hw->vtnet_hdr_size;
	uint32_t frame_size = mtu + ether_hdr_len;
	uint32_t max_frame_size = hw->max_mtu + ether_hdr_len;

	max_frame_size = RTE_MIN(max_frame_size, VIRTIO_MAX_RX_PKTLEN);

	if (mtu < RTE_ETHER_MIN_MTU || frame_size > max_frame_size) {
		PMD_INIT_LOG(ERR, "MTU should be between %d and %d",
			RTE_ETHER_MIN_MTU, max_frame_size - ether_hdr_len);
		return -EINVAL;
	}
	return 0;
}

static int
lsxvio_rc_eth_rxq_intr_enable(struct rte_eth_dev *dev,
	uint16_t queue_id)
{
	struct lsxvio_rc_pci_hw *lsx_hw = dev->data->dev_private;
	struct virtio_hw *hw = &lsx_hw->common_cfg;
	struct virtnet_rx *rxvq = dev->data->rx_queues[queue_id];
	struct virtqueue *vq = rxvq->vq;
	uint64_t lsx_feature = lsxvio_priv_feature(lsx_hw);

	if (lsx_feature & LSX_VIO_EP2RC_PACKED)
		virtqueue_enable_intr_packed(vq);
	virtqueue_enable_intr(vq);
	virtio_mb(hw->weak_barriers);
	return 0;
}

static int
lsxvio_rc_eth_rxq_intr_disable(struct rte_eth_dev *dev,
	uint16_t queue_id)
{
	struct virtnet_rx *rxvq = dev->data->rx_queues[queue_id];
	struct virtqueue *vq = rxvq->vq;

	virtqueue_disable_intr(vq);
	return 0;
}

static const struct eth_dev_ops lsxvio_rc_eth_dev_ops = {
	.dev_configure           = lsxvio_rc_eth_configure,
	.dev_start               = lsxvio_rc_eth_start,
	.dev_stop                = lsxvio_rc_eth_stop,
	.dev_close               = lsxvio_rc_eth_close,
	.promiscuous_enable      = lsxvio_rc_eth_prom_enable,
	.promiscuous_disable     = lsxvio_rc_eth_prom_disable,
	.allmulticast_enable     = lsxvio_rc_eth_mcast_enable,
	.allmulticast_disable    = lsxvio_rc_eth_mcast_disable,
	.mtu_set                 = lsxvio_rc_mtu_set,
	.dev_infos_get           = lsxvio_rc_eth_info_get,
	.stats_get               = lsxvio_rc_eth_stats_get,
	.xstats_get              = lsxvio_rc_eth_xstats_get,
	.xstats_get_names        = lsxvio_rc_eth_xstats_get_names,
	.stats_reset             = lsxvio_rc_eth_stats_reset,
	.xstats_reset            = lsxvio_rc_eth_stats_reset,
	.link_update             = lsxvio_rc_eth_link_update,
	.rx_queue_setup          = virtio_dev_rx_queue_setup,
	.rx_queue_intr_enable    = lsxvio_rc_eth_rxq_intr_enable,
	.rx_queue_intr_disable   = lsxvio_rc_eth_rxq_intr_disable,
	.rx_queue_release        = lsxvio_rc_eth_queue_release,
	.rx_descriptor_done      = virtio_dev_rx_queue_done,
	.tx_queue_setup          = virtio_dev_tx_queue_setup,
	.tx_queue_release        = lsxvio_rc_eth_queue_release,
};

static void
lsxvio_rc_update_stats(struct rte_eth_dev *dev,
	struct rte_eth_stats *stats)
{
	uint32_t i;

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		const struct virtnet_tx *txvq = dev->data->tx_queues[i];

		if (!txvq)
			continue;

		stats->opackets += txvq->stats.packets;
		stats->obytes += txvq->stats.bytes;

		if (i < RTE_ETHDEV_QUEUE_STAT_CNTRS) {
			stats->q_opackets[i] = txvq->stats.packets;
			stats->q_obytes[i] = txvq->stats.bytes;
		}
	}

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		const struct virtnet_rx *rxvq = dev->data->rx_queues[i];

		if (!rxvq)
			continue;

		stats->ipackets += rxvq->stats.packets;
		stats->ibytes += rxvq->stats.bytes;
		stats->ierrors += rxvq->stats.errors;

		if (i < RTE_ETHDEV_QUEUE_STAT_CNTRS) {
			stats->q_ipackets[i] = rxvq->stats.packets;
			stats->q_ibytes[i] = rxvq->stats.bytes;
		}
	}

	stats->rx_nombuf = dev->data->rx_mbuf_alloc_failed;
}

static int
lsxvio_rc_eth_xstats_get_names(struct rte_eth_dev *dev,
	struct rte_eth_xstat_name *xstats_names,
	__rte_unused uint32_t limit)
{
	uint32_t i;
	uint32_t count = 0;
	uint32_t t;

	uint32_t nstats = dev->data->nb_tx_queues * LSXVIO_NB_TXQ_XSTATS +
		dev->data->nb_rx_queues * LSXVIO_NB_RXQ_XSTATS;

	if (!xstats_names) {
		/* Note: limit checked in rte_eth_xstats_names() */

		for (i = 0; i < dev->data->nb_rx_queues; i++) {
			struct virtnet_rx *rxvq = dev->data->rx_queues[i];

			if (!rxvq)
				continue;
			for (t = 0; t < LSXVIO_NB_RXQ_XSTATS; t++) {
				snprintf(xstats_names[count].name,
					sizeof(xstats_names[count].name),
					"rx_q%u_%s", i,
					s_lsxvio_rc_rxq_stat_str[t].name);
				count++;
			}
		}

		for (i = 0; i < dev->data->nb_tx_queues; i++) {
			struct virtnet_tx *txvq = dev->data->tx_queues[i];

			if (!txvq)
				continue;
			for (t = 0; t < LSXVIO_NB_TXQ_XSTATS; t++) {
				snprintf(xstats_names[count].name,
					sizeof(xstats_names[count].name),
					"tx_q%u_%s", i,
					s_lsxvio_rc_txq_stat_str[t].name);
				count++;
			}
		}
		return count;
	}
	return nstats;
}

static int
lsxvio_rc_eth_xstats_get(struct rte_eth_dev *dev,
	struct rte_eth_xstat *xstats, uint32_t n)
{
	uint32_t i, t;
	uint32_t count = 0;

	uint32_t nstats = dev->data->nb_tx_queues * LSXVIO_NB_TXQ_XSTATS +
		dev->data->nb_rx_queues * LSXVIO_NB_RXQ_XSTATS;

	if (n < nstats)
		return nstats;

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		struct virtnet_rx *rxvq = dev->data->rx_queues[i];

		if (!rxvq)
			continue;

		for (t = 0; t < LSXVIO_NB_RXQ_XSTATS; t++) {
			xstats[count].value = *(uint64_t *)(((char *)rxvq) +
				s_lsxvio_rc_rxq_stat_str[t].offset);
			xstats[count].id = count;
			count++;
		}
	}

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		struct virtnet_tx *txvq = dev->data->tx_queues[i];

		if (!txvq)
			continue;

		for (t = 0; t < LSXVIO_NB_TXQ_XSTATS; t++) {
			xstats[count].value = *(uint64_t *)(((char *)txvq) +
				s_lsxvio_rc_txq_stat_str[t].offset);
			xstats[count].id = count;
			count++;
		}
	}

	return count;
}

static int
lsxvio_rc_eth_stats_get(struct rte_eth_dev *dev,
	struct rte_eth_stats *stats)
{
	lsxvio_rc_update_stats(dev, stats);

	return 0;
}

static int
lsxvio_rc_eth_stats_reset(struct rte_eth_dev *dev)
{
	uint32_t i;

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		struct virtnet_tx *txvq = dev->data->tx_queues[i];

		if (!txvq)
			continue;

		txvq->stats.packets = 0;
		txvq->stats.bytes = 0;
		txvq->stats.multicast = 0;
		txvq->stats.broadcast = 0;
		memset(txvq->stats.size_bins, 0,
		       sizeof(txvq->stats.size_bins[0]) * 8);
	}

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		struct virtnet_rx *rxvq = dev->data->rx_queues[i];

		if (!rxvq)
			continue;

		rxvq->stats.packets = 0;
		rxvq->stats.bytes = 0;
		rxvq->stats.errors = 0;
		rxvq->stats.multicast = 0;
		rxvq->stats.broadcast = 0;
		memset(rxvq->stats.size_bins, 0,
		       sizeof(rxvq->stats.size_bins[0]) * 8);
	}

	return 0;
}

static void
lsxvio_rc_set_hwaddr(struct virtio_hw *hw)
{
	vtpci_write_dev_config(hw,
			offsetof(struct virtio_net_config, mac),
			&hw->mac_addr, RTE_ETHER_ADDR_LEN);
}

static void
lsxvio_rc_get_hwaddr(struct virtio_hw *hw)
{
	if (vtpci_with_feature(hw, VIRTIO_NET_F_MAC)) {
		vtpci_read_dev_config(hw,
			offsetof(struct virtio_net_config, mac),
			&hw->mac_addr, RTE_ETHER_ADDR_LEN);
	} else {
		rte_eth_random_addr(&hw->mac_addr[0]);
		lsxvio_rc_set_hwaddr(hw);
	}
}

static int
lsxvio_rc_negotiate_features(struct virtio_hw *hw,
	uint64_t req_features)
{
	uint64_t host_features;

	/* Prepare guest_features: feature that driver wants to support */
	PMD_INIT_LOG(DEBUG, "guest_features before negotiate: 0x%lx",
		req_features);

	/* Read device(host) feature bits */
	host_features = VTPCI_OPS(hw)->get_features(hw);
	PMD_INIT_LOG(DEBUG, "host_features before negotiate: 0x%lx",
		host_features);

	/* If supported, ensure MTU value is valid before acknowledging it. */
	if (host_features & req_features & (1ULL << VIRTIO_NET_F_MTU)) {
		struct virtio_net_config config;

		vtpci_read_dev_config(hw,
			offsetof(struct virtio_net_config, mtu),
			&config.mtu, sizeof(config.mtu));

		if (config.mtu < RTE_ETHER_MIN_MTU)
			req_features &= ~(1ULL << VIRTIO_NET_F_MTU);
	}

	hw->guest_features = req_features;
	hw->guest_features = vtpci_negotiate_features(hw, host_features);
	PMD_INIT_LOG(DEBUG, "features after negotiate: 0x%lx",
		hw->guest_features);

	if (hw->modern) {
		if (!vtpci_with_feature(hw, VIRTIO_F_VERSION_1)) {
			if (!s_lsxvio_rc_sim) {
				PMD_INIT_LOG(ERR,
					"VIRTIO_F_VERSION_1 features is not enabled.");
				return -EINVAL;
			}
		}
		vtpci_set_status(hw, VIRTIO_CONFIG_STATUS_FEATURES_OK);
		if (!(vtpci_get_status(hw) &
			VIRTIO_CONFIG_STATUS_FEATURES_OK)) {
			PMD_INIT_LOG(ERR,
				"failed to set FEATURES_OK status!");
			return -EINVAL;
		}
	}

	hw->req_guest_features = req_features;

	return 0;
}

static inline void
lsxvio_rc_xmit_help(struct rte_mbuf **tx_pkts,
	uint16_t nb_pkts)
{
	uint16_t i, len;
	char *src_complete;
	struct rte_mbuf *pkt;

	for (i = 0; i < nb_pkts; i++) {
		pkt = tx_pkts[i];
		len = pkt->pkt_len;
		src_complete = rte_pktmbuf_mtod_offset(pkt, char *, len);
		*(src_complete) = LSINIC_XFER_COMPLETE_DONE_FLAG;
	}
}

static uint16_t
lsxvio_rc_xmit_pkts_inorder_help(void *tx_queue,
	struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	lsxvio_rc_xmit_help(tx_pkts, nb_pkts);
	return virtio_xmit_pkts_inorder(tx_queue, tx_pkts, nb_pkts);
}

static uint16_t
lsxvio_rc_xmit_pkts_help(void *tx_queue,
	struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	lsxvio_rc_xmit_help(tx_pkts, nb_pkts);
	return virtio_xmit_pkts(tx_queue, tx_pkts, nb_pkts);
}

/* set rx and tx handlers according to what is supported */
static void
lsxvio_rc_set_rxtx_funcs(struct rte_eth_dev *eth_dev)
{
	struct lsxvio_rc_pci_hw *lsx_hw = eth_dev->data->dev_private;
	struct virtio_hw *hw = &lsx_hw->common_cfg;
	uint64_t lsx_feature = lsxvio_priv_feature(lsx_hw);

	eth_dev->tx_pkt_prepare = virtio_xmit_pkts_prepare;

	if (lsx_feature & LSX_VIO_RC2EP_DMA_NORSP) {
		RTE_LOG(INFO, PMD, "%s: LSX VIO RC2EP help\n",
			eth_dev->data->name);
		if (hw->use_inorder_tx) {
			eth_dev->tx_pkt_burst =
				lsxvio_rc_xmit_pkts_inorder_help;
		} else {
			eth_dev->tx_pkt_burst =
				lsxvio_rc_xmit_pkts_help;
		}
	} else {
		if (hw->use_inorder_tx) {
			eth_dev->tx_pkt_burst =
				virtio_xmit_pkts_inorder;
		} else {
			eth_dev->tx_pkt_burst = virtio_xmit_pkts;
		}
	}

	if (lsx_feature & LSX_VIO_EP2RC_PACKED)
		eth_dev->rx_pkt_burst = virtio_recv_pkts_packed;
	else
		eth_dev->rx_pkt_burst = virtio_recv_pkts;
}

/* reset device and renegotiate features if needed */
static int
lsxvio_rc_init_device(struct rte_eth_dev *eth_dev,
	uint64_t req_features)
{
	struct lsxvio_rc_pci_hw *lsx_hw = eth_dev->data->dev_private;
	struct virtio_hw *hw = &lsx_hw->common_cfg;
	struct virtio_net_config *config;
	struct virtio_net_config local_config;
	struct rte_pci_device *pci_dev = NULL;
	int ret;

	/* Reset the device although not necessary at startup */
	vtpci_reset(hw);

	if (hw->vqs) {
		lsxvio_rc_free_mbufs(eth_dev);
		lsxvio_rc_free_queues(hw);
	}

	/* Tell the host we've noticed this device. */
	vtpci_set_status(hw, VIRTIO_CONFIG_STATUS_ACK);

	/* Tell the host we've known how to drive the device. */
	vtpci_set_status(hw, VIRTIO_CONFIG_STATUS_DRIVER);
	ret = lsxvio_rc_negotiate_features(hw, req_features);
	if (ret)
		return ret;

	hw->weak_barriers = !vtpci_with_feature(hw, VIRTIO_F_ORDER_PLATFORM);

	if (!hw->virtio_user_dev)
		pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);

	/* If host does not support both status and MSI-X then disable LSC */
	if (vtpci_with_feature(hw, VIRTIO_NET_F_STATUS) &&
	    hw->use_msix != VIRTIO_MSIX_NONE)
		eth_dev->data->dev_flags |= RTE_ETH_DEV_INTR_LSC;
	else
		eth_dev->data->dev_flags &= ~RTE_ETH_DEV_INTR_LSC;

	/* Setting up rx_header size for the device */
	if (vtpci_with_feature(hw, VIRTIO_NET_F_MRG_RXBUF) ||
	    vtpci_with_feature(hw, VIRTIO_F_VERSION_1) ||
	    vtpci_with_feature(hw, VIRTIO_F_RING_PACKED))
		hw->vtnet_hdr_size = sizeof(struct virtio_net_hdr_mrg_rxbuf);
	else
		hw->vtnet_hdr_size = sizeof(struct virtio_net_hdr);

	/* Overwrite previous setting, to support header size in the future.*/
	hw->vtnet_hdr_size = 0;

	/* Copy the permanent MAC address to: virtio_hw */
	lsxvio_rc_get_hwaddr(hw);
	rte_ether_addr_copy((struct rte_ether_addr *)hw->mac_addr,
		&eth_dev->data->mac_addrs[0]);
	PMD_INIT_LOG(DEBUG,
		"PORT MAC: %02X:%02X:%02X:%02X:%02X:%02X",
		hw->mac_addr[0], hw->mac_addr[1], hw->mac_addr[2],
		hw->mac_addr[3], hw->mac_addr[4], hw->mac_addr[5]);

	if (vtpci_with_feature(hw, VIRTIO_NET_F_CTRL_VQ)) {
		config = &local_config;

		vtpci_read_dev_config(hw,
			offsetof(struct virtio_net_config, mac),
			&config->mac, sizeof(config->mac));

		if (vtpci_with_feature(hw, VIRTIO_NET_F_STATUS)) {
			vtpci_read_dev_config(hw,
				offsetof(struct virtio_net_config, status),
				&config->status, sizeof(config->status));
		} else {
			PMD_INIT_LOG(DEBUG,
				"VIRTIO_NET_F_STATUS is not supported");
			config->status = 0;
		}

		if (vtpci_with_feature(hw, VIRTIO_NET_F_MQ)) {
			vtpci_read_dev_config(hw,
				offsetof(struct virtio_net_config,
					max_virtqueue_pairs),
				&config->max_virtqueue_pairs,
				sizeof(config->max_virtqueue_pairs));
		} else {
			PMD_INIT_LOG(DEBUG,
				"VIRTIO_NET_F_MQ is not supported");
			config->max_virtqueue_pairs = 1;
		}

		hw->max_queue_pairs = config->max_virtqueue_pairs;

		if (vtpci_with_feature(hw, VIRTIO_NET_F_MTU)) {
			vtpci_read_dev_config(hw,
				offsetof(struct virtio_net_config, mtu),
				&config->mtu,
				sizeof(config->mtu));

			if (config->mtu < RTE_ETHER_MIN_MTU) {
				PMD_INIT_LOG(ERR, "invalid max MTU value (%u)",
					config->mtu);
				return -EINVAL;
			}

			hw->max_mtu = config->mtu;
			/* Set initial MTU to maximum one supported by vhost */
			eth_dev->data->mtu = config->mtu;

		} else {
			hw->max_mtu = VIRTIO_MAX_RX_PKTLEN - RTE_ETHER_HDR_LEN -
				VLAN_TAG_LEN - hw->vtnet_hdr_size;
		}

		PMD_INIT_LOG(DEBUG, "config->max_virtqueue_pairs=%d",
			config->max_virtqueue_pairs);
		PMD_INIT_LOG(DEBUG, "config->status=%d", config->status);
		PMD_INIT_LOG(DEBUG,
			"PORT MAC: %02X:%02X:%02X:%02X:%02X:%02X",
			config->mac[0], config->mac[1],
			config->mac[2], config->mac[3],
			config->mac[4], config->mac[5]);
	} else {
		PMD_INIT_LOG(DEBUG, "config->max_virtqueue_pairs=1");
		hw->max_queue_pairs = 1;
		hw->max_mtu = VIRTIO_MAX_RX_PKTLEN - RTE_ETHER_HDR_LEN -
			VLAN_TAG_LEN - hw->vtnet_hdr_size;
	}

	ret = lsxvio_rc_alloc_queues(eth_dev);
	if (ret < 0)
		return ret;

	if (eth_dev->data->dev_conf.intr_conf.rxq) {
		PMD_INIT_LOG(ERR, "Not support interrupt");
		return -ENOTSUP;
	}

	vtpci_reinit_complete(hw);

	if (pci_dev)
		PMD_INIT_LOG(DEBUG, "port %d vendorID=0x%x deviceID=0x%x",
			eth_dev->data->port_id, pci_dev->id.vendor_id,
			pci_dev->id.device_id);

	return 0;
}

static int
lsxvio_rc_remap_pci(struct rte_pci_device *pci_dev,
	struct virtio_hw *hw)
{
	if (hw->modern) {
		if (rte_pci_map_device(pci_dev)) {
			PMD_INIT_LOG(DEBUG, "failed to map pci device!");
			return -EINVAL;
		}
	} else {
		if (rte_pci_ioport_map(pci_dev, 0, VTPCI_IO(hw)) < 0)
			return -EINVAL;
	}

	return 0;
}

static void
lsxvio_rc_modern_read_dev_config(struct virtio_hw *hw,
	size_t offset, void *dst, int length)
{
	int i;
	uint8_t *p;
	uint8_t old_gen, new_gen;
	struct lsxvio_rc_pci_hw *lsx_hw = LSXVIO_HW(hw);
	struct lsxvio_common_cfg *cfg = &lsx_hw->lsx_cfg->common_cfg;

	do {
		old_gen = rte_read8(&cfg->config_generation);

		p = dst;
		for (i = 0; i < length; i++)
			*p++ = rte_read8((uint8_t *)hw->dev_cfg + offset + i);

		new_gen = rte_read8(&cfg->config_generation);
	} while (old_gen != new_gen);
}

static void
lsxvio_rc_modern_write_dev_config(struct virtio_hw *hw,
	size_t offset, const void *src, int length)
{
	int i;
	const uint8_t *p = src;

	for (i = 0;  i < length; i++)
		rte_write8((*p++), (((uint8_t *)hw->dev_cfg) + offset + i));
}

static uint64_t
lsxvio_rc_modern_get_features(struct virtio_hw *hw)
{
	uint64_t features;
	struct lsxvio_rc_pci_hw *lsx_hw = LSXVIO_HW(hw);
	struct lsxvio_common_cfg *cfg = &lsx_hw->lsx_cfg->common_cfg;

	features = rte_read64(&cfg->device_feature);

	return features;
}

static void
lsxvio_rc_modern_set_features(__rte_unused struct virtio_hw *hw,
	__rte_unused uint64_t features)
{
}

static uint8_t
lsxvio_rc_modern_get_status(struct virtio_hw *hw)
{
	struct lsxvio_rc_pci_hw *lsx_hw = LSXVIO_HW(hw);
	struct lsxvio_common_cfg *cfg = &lsx_hw->lsx_cfg->common_cfg;

	return rte_read8(&cfg->device_status);
}

static void
lsxvio_rc_modern_set_status(struct virtio_hw *hw, uint8_t status)
{
	struct lsxvio_rc_pci_hw *lsx_hw = LSXVIO_HW(hw);
	struct lsxvio_common_cfg *cfg = &lsx_hw->lsx_cfg->common_cfg;

	rte_write8(status, &cfg->device_status);
}

static uint8_t
lsxvio_rc_modern_get_isr(struct virtio_hw *hw)
{
	return rte_read8(hw->isr);
}

static uint16_t
lsxvio_rc_modern_set_config_irq(struct virtio_hw *hw,
	uint16_t vec)
{
	struct lsxvio_rc_pci_hw *lsx_hw = LSXVIO_HW(hw);
	struct lsxvio_common_cfg *cfg = &lsx_hw->lsx_cfg->common_cfg;

	rte_write16(vec, &cfg->msix_config);
	return rte_read16(&cfg->msix_config);
}

static uint16_t
lsxvio_rc_modern_set_queue_irq(struct virtio_hw *hw,
	struct virtqueue *vq, uint16_t vec)
{
	struct lsxvio_rc_pci_hw *lsx_hw = LSXVIO_HW(hw);
	struct lsxvio_queue_cfg *qcfg = lsx_hw->lsx_cfg->queue_cfg;
	uint16_t q_idx = vq->vq_queue_index;

	rte_write16(vec, &qcfg[q_idx].queue_msix_vector);
	return rte_read16(&qcfg[q_idx].queue_msix_vector);
}

static uint16_t
lsxvio_rc_modern_get_queue_num(struct virtio_hw *hw,
	uint16_t queue_id)
{
	struct lsxvio_rc_pci_hw *lsx_hw = LSXVIO_HW(hw);
	struct lsxvio_queue_cfg *qcfg = lsx_hw->lsx_cfg->queue_cfg;

	return rte_read16(&qcfg[queue_id].queue_size);
}

static int
lsxvio_rc_modern_setup_queue(struct virtio_hw *hw,
	struct virtqueue *vq)
{
	uint64_t desc_addr, avail_addr, used_addr;
	uint64_t avail_offset, used_offset;
	uint16_t notify_off;
	uint16_t q_idx = vq->vq_queue_index;
	struct lsxvio_rc_pci_hw *lsx_hw = LSXVIO_HW(hw);
	struct lsxvio_queue_cfg *qcfg = lsx_hw->lsx_cfg->queue_cfg;
	struct vring *sp_ring = &vq->vq_split.ring;

	desc_addr = vq->vq_ring_mem;
	avail_offset = (uint64_t)sp_ring->avail -
		(uint64_t)vq->vq_ring_virt_mem;
	used_offset = (uint64_t)sp_ring->used -
		(uint64_t)vq->vq_ring_virt_mem;
	avail_addr = desc_addr + avail_offset;
	used_addr = desc_addr + used_offset;

	lsxvio_write64_twopart(desc_addr, &qcfg[q_idx].queue_desc_lo,
		&qcfg[q_idx].queue_desc_hi);
	lsxvio_write64_twopart(avail_addr, &qcfg[q_idx].queue_avail_lo,
		&qcfg[q_idx].queue_avail_hi);
	lsxvio_write64_twopart(used_addr, &qcfg[q_idx].queue_used_lo,
		&qcfg[q_idx].queue_used_hi);

	notify_off = rte_read16(&qcfg[q_idx].queue_notify_off);
	vq->notify_addr = (void *)((uint8_t *)hw->notify_base +
					notify_off * hw->notify_off_multiplier);

	rte_write16(1, &qcfg[q_idx].queue_enable);

	return 0;
}

static void
lsxvio_rc_modern_del_queue(struct virtio_hw *hw,
	struct virtqueue *vq)
{
	uint16_t q_idx = vq->vq_queue_index;
	struct lsxvio_rc_pci_hw *lsx_hw = LSXVIO_HW(hw);
	struct lsxvio_queue_cfg *qcfg = lsx_hw->lsx_cfg->queue_cfg;

	lsxvio_write64_twopart(0, &qcfg[q_idx].queue_desc_lo,
		&qcfg[q_idx].queue_desc_hi);
	lsxvio_write64_twopart(0, &qcfg[q_idx].queue_avail_lo,
		&qcfg[q_idx].queue_avail_hi);
	lsxvio_write64_twopart(0, &qcfg[q_idx].queue_used_lo,
		&qcfg[q_idx].queue_used_hi);

	rte_write16(0, &qcfg[q_idx].queue_enable);
}

static void
lsxvio_rc_modern_notify_queue(struct virtio_hw *hw,
	struct virtqueue *vq)
{
	struct lsxvio_rc_pci_hw *lsx_hw = LSXVIO_HW(hw);
	uint8_t *ring_base = lsx_hw->ring_base;
	struct vring_avail *avail_ring;
	int queue_type = virtio_get_queue_type(hw, vq->vq_queue_index);
	uint64_t lsx_feature = lsxvio_priv_feature(lsx_hw);

	if (queue_type == VTNET_RQ &&
		lsx_feature & LSX_VIO_EP2RC_PACKED) {
		struct lsxvio_packed_notify *pnotify;
		uint16_t last_avail_idx =
			lsx_hw->last_avail_idx[vq->vq_queue_index];

		pnotify = (void *)(ring_base +
			vq->vq_queue_index *
			LSXVIO_PER_RING_NOTIFY_MAX_SIZE);

		while (last_avail_idx != vq->vq_avail_idx) {
			pnotify->addr[last_avail_idx] =
				vq->vq_packed.ring.desc[last_avail_idx].addr;
			last_avail_idx = (last_avail_idx + 1) &
				(vq->vq_nentries - 1);
		}

		rte_wmb();

		lsx_hw->last_avail_idx[vq->vq_queue_index] =
			vq->vq_avail_idx;
		rte_write16(vq->vq_avail_idx, &pnotify->last_avail_idx);
	} else if (queue_type == VTNET_TQ) {
		avail_ring = (void *)(ring_base +
			vq->vq_queue_index *
			LSXVIO_PER_RING_NOTIFY_MAX_SIZE +
			sizeof(struct vring_desc) * vq->vq_nentries);
		rte_write16(vq->vq_split.ring.avail->idx, &avail_ring->idx);
		rte_write16(vq->vq_queue_index, vq->notify_addr);
	} else {
		avail_ring = (void *)(ring_base +
			vq->vq_queue_index *
			LSXVIO_PER_RING_NOTIFY_MAX_SIZE);
		rte_write16(vq->vq_split.ring.avail->idx, &avail_ring->idx);
		rte_write16(vq->vq_queue_index, vq->notify_addr);
	}
}

static const struct virtio_pci_ops lsxvio_rc_modern_ops = {
	.read_dev_cfg	= lsxvio_rc_modern_read_dev_config,
	.write_dev_cfg	= lsxvio_rc_modern_write_dev_config,
	.get_status	= lsxvio_rc_modern_get_status,
	.set_status	= lsxvio_rc_modern_set_status,
	.get_features	= lsxvio_rc_modern_get_features,
	.set_features	= lsxvio_rc_modern_set_features,
	.get_isr	= lsxvio_rc_modern_get_isr,
	.set_config_irq	= lsxvio_rc_modern_set_config_irq,
	.set_queue_irq  = lsxvio_rc_modern_set_queue_irq,
	.get_queue_num	= lsxvio_rc_modern_get_queue_num,
	.setup_queue	= lsxvio_rc_modern_setup_queue,
	.del_queue	= lsxvio_rc_modern_del_queue,
	.notify_queue	= lsxvio_rc_modern_notify_queue,
};

static int
lsxvio_rc_pci_set_ops(struct virtio_hw *hw)
{
	int ret = 0;

#ifdef RTE_VIRTIO_USER
	if (hw->virtio_user_dev)
		VTPCI_OPS(hw) = &virtio_user_ops;
	else if (hw->modern)
		VTPCI_OPS(hw) = &lsxvio_rc_modern_ops;
	else
		ret = -EINVAL;
#else
	if (hw->modern)
		VTPCI_OPS(hw) = &lsxvio_rc_modern_ops;
	else
		ret = -EINVAL;
#endif

	return ret;
}

static int
lsxvio_rc_read_caps(struct rte_pci_device *dev,
	struct lsxvio_rc_pci_hw *lsx_hw)
{
	struct virtio_hw *hw = &lsx_hw->common_cfg;
	uint8_t *reg_base, *ring_base;

	reg_base = dev->mem_resource[LSXVIO_REG_BAR_IDX].addr;
	ring_base = dev->mem_resource[LSXVIO_RING_BAR_IDX].addr;

	lsx_hw->lsx_cfg = (void *)(reg_base + LSXVIO_COMMON_OFFSET);
	hw->isr = reg_base + LSXVIO_ISR_OFFSET;
	hw->notify_base = (void *)(reg_base + LSXVIO_NOTIFY_OFFSET);
	hw->dev_cfg = (void *)(reg_base + LSXVIO_DEVICE_OFFSET);
	hw->notify_off_multiplier = LSXVIO_NOTIFY_OFF_MULTI;

	lsx_hw->ring_base = ring_base;
	memset(lsx_hw->last_avail_idx, 0,
		LSXVIO_MAX_QUEUE_PAIRS * 2 * sizeof(uint16_t));

	if (!s_lsxvio_rc_sim) {
		if (rte_pci_map_device(dev)) {
			PMD_INIT_LOG(DEBUG, "failed to map pci device!");
			return -EIO;
		}
	}
	virtio_hw_internal[hw->port_id].vtpci_ops = &lsxvio_rc_modern_ops;

	return 0;
}

static int
lsxvio_rc_pci_eth_dev_init(struct rte_eth_dev *eth_dev)
{
	struct lsxvio_rc_pci_hw *lsx_hw = eth_dev->data->dev_private;
	struct virtio_hw *hw = &lsx_hw->common_cfg;
	int ret;

	if (sizeof(struct virtio_net_hdr_mrg_rxbuf) >
		RTE_PKTMBUF_HEADROOM) {
		PMD_INIT_LOG(ERR,
			"Not sufficient headroom required = %d, avail = %d",
			(int)sizeof(struct virtio_net_hdr_mrg_rxbuf),
			RTE_PKTMBUF_HEADROOM);

		return -EINVAL;
	}

	eth_dev->dev_ops = &lsxvio_rc_eth_dev_ops;

	if (rte_eal_process_type() == RTE_PROC_SECONDARY &&
		!s_lsxvio_rc_2nd_proc_standalone) {
		if (!hw->virtio_user_dev) {
			ret = lsxvio_rc_remap_pci(RTE_ETH_DEV_TO_PCI(eth_dev),
				hw);
			if (ret)
				return ret;
		}

		lsxvio_rc_pci_set_ops(hw);
		lsxvio_rc_set_rxtx_funcs(eth_dev);

		return 0;
	}

	eth_dev->data->dev_flags |= RTE_ETH_DEV_CLOSE_REMOVE;

	/* Allocate memory for storing MAC addresses */
	eth_dev->data->mac_addrs = rte_zmalloc("virtio",
		VIRTIO_MAX_MAC_ADDRS * RTE_ETHER_ADDR_LEN, 0);
	if (!eth_dev->data->mac_addrs) {
		PMD_INIT_LOG(ERR,
			"Failed to allocate MAC addresses buffer size(%d)",
			VIRTIO_MAX_MAC_ADDRS * RTE_ETHER_ADDR_LEN);
		return -ENOMEM;
	}

	hw->port_id = eth_dev->data->port_id;

	if (!hw->virtio_user_dev) {
		ret = lsxvio_rc_read_caps(RTE_ETH_DEV_TO_PCI(eth_dev),
			lsx_hw);
		if (ret)
			goto err_vtpci_init;
		hw->modern = 1;
	}

	rte_spinlock_init(&hw->state_lock);

	/* reset device and negotiate default features */
	ret = lsxvio_rc_init_device(eth_dev, VIRTIO_PMD_DEFAULT_GUEST_FEATURES);
	if (ret < 0)
		goto err_virtio_init;

	hw->opened = true;

	return 0;

err_virtio_init:
	if (!hw->virtio_user_dev) {
		rte_pci_unmap_device(RTE_ETH_DEV_TO_PCI(eth_dev));
		if (!hw->modern)
			rte_pci_ioport_unmap(VTPCI_IO(hw));
	}
err_vtpci_init:
	rte_free(eth_dev->data->mac_addrs);
	eth_dev->data->mac_addrs = NULL;
	return ret;
}

static int
lsxvio_rc_eth_uninit(struct rte_eth_dev *eth_dev)
{
	PMD_INIT_FUNC_TRACE();

	if (rte_eal_process_type() == RTE_PROC_SECONDARY)
		return 0;

	lsxvio_rc_eth_stop(eth_dev);
	lsxvio_rc_eth_close(eth_dev);

	eth_dev->dev_ops = NULL;
	eth_dev->tx_pkt_burst = NULL;
	eth_dev->rx_pkt_burst = NULL;

	PMD_INIT_LOG(DEBUG, "dev_uninit completed");

	return 0;
}

static int
lsxvio_rc_sim_pci_resource_set(struct rte_pci_device *dev)
{
	int i, map_idx = 0;
	void *mapaddr;

	RTE_LOG(INFO, EAL, "LSXVIO Simulator: vendor: 0x%04x\n",
		dev->id.vendor_id);

	/* Map all BARs */
	for (i = 0; i != PCI_MAX_RESOURCE; i++) {
		/* skip empty BAR */
		if (dev->mem_resource[i].phys_addr == 0)
			continue;

		mapaddr = rte_mem_iova2virt(dev->mem_resource[i].phys_addr);
		dev->mem_resource[i].addr = mapaddr;
		map_idx++;
	}

	return 0;
}

static uint16_t
lsxvio_rc_2nd_proc_find_free_port(void)
{
	uint32_t i;

	for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
		if (!rte_eth_devices[i].data)
			return i;
	}
	return RTE_MAX_ETHPORTS;
}

static struct rte_eth_dev *
lsxvio_rc_2nd_proc_eth_dev_allocate(const char *name)
{
	const struct rte_memzone *mz;
	struct rte_eth_dev *eth_dev = NULL;
	size_t name_len, size;
	uint16_t port_id;

	name_len = strnlen(name, RTE_ETH_NAME_MAX_LEN);
	if (name_len == 0) {
		RTE_ETHDEV_LOG(ERR, "Zero length LSINIC RC device name\n");
		return NULL;
	}

	if (name_len >= RTE_ETH_NAME_MAX_LEN) {
		RTE_ETHDEV_LOG(ERR, "LSINIC RC device name is too long\n");
		return NULL;
	}

	rte_spinlock_lock(&s_lsxvio_rc_lock);

	if (!s_lsxvio_rc_eth_data) {
		size = sizeof(struct rte_eth_dev_data);
		size = size * RTE_MAX_ETHPORTS;
		mz = rte_memzone_reserve("lsxvio_rc_eth_dev_data",
				size, rte_socket_id(), 0);
		if (!mz) {
			RTE_ETHDEV_LOG(ERR, "data alloc failed\n");
			rte_spinlock_unlock(&s_lsxvio_rc_lock);
			return NULL;
		}
		s_lsxvio_rc_eth_data = mz->addr;
	}

	port_id = lsxvio_rc_2nd_proc_find_free_port();
	eth_dev = &rte_eth_devices[port_id];
	eth_dev->data = &s_lsxvio_rc_eth_data[port_id];

	strlcpy(eth_dev->data->name, name, sizeof(eth_dev->data->name));
	eth_dev->data->port_id = port_id;
	eth_dev->data->mtu = RTE_ETHER_MTU;

	rte_spinlock_unlock(&s_lsxvio_rc_lock);

	return eth_dev;
}

static int
lsxvio_rc_eth_2nd_proc_probe(struct rte_pci_device *pci_dev)
{
	struct rte_eth_dev *eth_dev;
	int ret;

	eth_dev = lsxvio_rc_2nd_proc_eth_dev_allocate(pci_dev->name);
	if (!eth_dev)
		return -ENOMEM;
	eth_dev->data->dev_private = rte_zmalloc_socket(pci_dev->name,
		sizeof(struct lsxvio_rc_pci_hw),
		RTE_CACHE_LINE_SIZE,
		pci_dev->device.numa_node);
	if (!eth_dev->data->dev_private) {
		rte_eth_dev_release_port(eth_dev);
		return -ENOMEM;
	}
	eth_dev->device = &pci_dev->device;
	rte_eth_copy_pci_info(eth_dev, pci_dev);
	ret = lsxvio_rc_pci_eth_dev_init(eth_dev);
	if (ret)
		rte_eth_dev_pci_release(eth_dev);
	else
		rte_eth_dev_probing_finish(eth_dev);

	return ret;
}

static int
lsxvio_rc_eth_pci_probe(struct rte_pci_driver *pci_drv __rte_unused,
	struct rte_pci_device *pci_dev)
{
	if (s_lsxvio_rc_sim)
		lsxvio_rc_sim_pci_resource_set(pci_dev);

	if (s_lsxvio_rc_2nd_proc_standalone)
		return lsxvio_rc_eth_2nd_proc_probe(pci_dev);

	return rte_eth_dev_pci_generic_probe(pci_dev,
		sizeof(struct lsxvio_rc_pci_hw),
		lsxvio_rc_pci_eth_dev_init);
}

static int
lsxvio_rc_eth_pci_remove(struct rte_pci_device *pci_dev)
{
	int ret;

	ret = rte_eth_dev_pci_generic_remove(pci_dev,
		lsxvio_rc_eth_uninit);
	/* Port has already been released by close. */
	if (ret == -ENODEV)
		ret = 0;
	return ret;
}

static struct rte_pci_driver rte_lsxvio_pci_pmd = {
	.driver = {
		.name = RTE_STR(lsxvio_net),
	},
	.id_table = lsxvio_pci_id_map,
	.drv_flags = RTE_PCI_DRV_NEED_MAPPING,
	.probe = lsxvio_rc_eth_pci_probe,
	.remove = lsxvio_rc_eth_pci_remove,
};

RTE_INIT(rte_lsxvio_pci_pmd_init)
{
	rte_eal_iopl_init();
	rte_pci_register(&rte_lsxvio_pci_pmd);
}

static bool
lsxvio_rc_rx_offload_enabled(struct virtio_hw *hw)
{
	return vtpci_with_feature(hw, VIRTIO_NET_F_GUEST_CSUM) ||
		vtpci_with_feature(hw, VIRTIO_NET_F_GUEST_TSO4) ||
		vtpci_with_feature(hw, VIRTIO_NET_F_GUEST_TSO6);
}

static bool
lsxvio_rc_tx_offload_enabled(struct virtio_hw *hw)
{
	return vtpci_with_feature(hw, VIRTIO_NET_F_CSUM) ||
		vtpci_with_feature(hw, VIRTIO_NET_F_HOST_TSO4) ||
		vtpci_with_feature(hw, VIRTIO_NET_F_HOST_TSO6);
}

static int
lsxvio_rc_eth_configure(struct rte_eth_dev *dev)
{
	const struct rte_eth_rxmode *rxmode = &dev->data->dev_conf.rxmode;
	const struct rte_eth_txmode *txmode = &dev->data->dev_conf.txmode;
	struct lsxvio_rc_pci_hw *lsx_hw = dev->data->dev_private;
	struct virtio_hw *hw = &lsx_hw->common_cfg;
	uint32_t ether_hdr_len = RTE_ETHER_HDR_LEN + VLAN_TAG_LEN +
		hw->vtnet_hdr_size;
	uint64_t rx_offloads = rxmode->offloads;
	uint64_t tx_offloads = txmode->offloads;
	uint64_t req_features, lsx_feature;
	int ret;

	PMD_INIT_LOG(DEBUG, "configure");
	req_features = VIRTIO_PMD_DEFAULT_GUEST_FEATURES;

	if (dev->data->dev_conf.intr_conf.rxq) {
		PMD_INIT_LOG(ERR, "Not support interrupt");
		return -ENOTSUP;
	}

	if (rxmode->max_rx_pkt_len > hw->max_mtu + ether_hdr_len)
		req_features &= ~(1ULL << VIRTIO_NET_F_MTU);

	if (rx_offloads & (DEV_RX_OFFLOAD_UDP_CKSUM |
			   DEV_RX_OFFLOAD_TCP_CKSUM))
		req_features |= (1ULL << VIRTIO_NET_F_GUEST_CSUM);

	if (rx_offloads & DEV_RX_OFFLOAD_TCP_LRO)
		req_features |=
			(1ULL << VIRTIO_NET_F_GUEST_TSO4) |
			(1ULL << VIRTIO_NET_F_GUEST_TSO6);

	if (tx_offloads & (DEV_TX_OFFLOAD_UDP_CKSUM |
			   DEV_TX_OFFLOAD_TCP_CKSUM))
		req_features |= (1ULL << VIRTIO_NET_F_CSUM);

	if (tx_offloads & DEV_TX_OFFLOAD_TCP_TSO)
		req_features |=
			(1ULL << VIRTIO_NET_F_HOST_TSO4) |
			(1ULL << VIRTIO_NET_F_HOST_TSO6);

	/* if request features changed, reinit the device */
	if (req_features != hw->req_guest_features) {
		ret = lsxvio_rc_init_device(dev, req_features);
		if (ret < 0)
			return ret;
	}

	if ((rx_offloads & (DEV_RX_OFFLOAD_UDP_CKSUM |
			DEV_RX_OFFLOAD_TCP_CKSUM)) &&
		!vtpci_with_feature(hw, VIRTIO_NET_F_GUEST_CSUM)) {
		PMD_DRV_LOG(ERR,
			"rx checksum not available on this host");
		return -ENOTSUP;
	}

	if ((rx_offloads & DEV_RX_OFFLOAD_TCP_LRO) &&
		(!vtpci_with_feature(hw, VIRTIO_NET_F_GUEST_TSO4) ||
		 !vtpci_with_feature(hw, VIRTIO_NET_F_GUEST_TSO6))) {
		PMD_DRV_LOG(ERR,
			"Large Receive Offload not available on this host");
		return -ENOTSUP;
	}

	/* start control queue */
	if (vtpci_with_feature(hw, VIRTIO_NET_F_CTRL_VQ))
		virtio_dev_cq_start(dev);

	if (rx_offloads & DEV_RX_OFFLOAD_VLAN_STRIP)
		hw->vlan_strip = 1;

	hw->has_tx_offload = lsxvio_rc_tx_offload_enabled(hw);
	hw->has_rx_offload = lsxvio_rc_rx_offload_enabled(hw);

	if (dev->data->dev_flags & RTE_ETH_DEV_INTR_LSC)
		/* Enable vector (0) for Link State Intrerrupt */
		if (VTPCI_OPS(hw)->set_config_irq(hw, 0) ==
				VIRTIO_MSI_NO_VECTOR) {
			PMD_DRV_LOG(ERR, "failed to set config vector");
			return -EBUSY;
		}

	hw->use_simple_rx = 1;
	lsx_feature = lsxvio_priv_feature(lsx_hw);

	if (vtpci_with_feature(hw, VIRTIO_F_IN_ORDER)) {
		hw->use_inorder_tx = 1;
		hw->use_inorder_rx = 1;
		hw->use_simple_rx = 0;
	} else if (lsx_feature & LSX_VIO_RC2EP_IN_ORDER) {
		hw->use_inorder_tx = 1;
	}

	if (vtpci_packed_queue(hw)) {
		hw->use_simple_rx = 0;
		hw->use_inorder_rx = 0;
	} else if (lsx_feature & LSX_VIO_EP2RC_PACKED) {
		hw->use_simple_rx = 0;
		hw->use_inorder_rx = 0;
	}

#if defined RTE_ARCH_ARM64 || defined RTE_ARCH_ARM
	if (!rte_cpu_get_flag_enabled(RTE_CPUFLAG_NEON) ||
		vtpci_with_feature(hw, VIRTIO_NET_F_MRG_RXBUF) ||
		s_lsxvio_rc_sim ||
		(rx_offloads & (DEV_RX_OFFLOAD_UDP_CKSUM |
			DEV_RX_OFFLOAD_TCP_CKSUM |
			DEV_RX_OFFLOAD_TCP_LRO |
			DEV_RX_OFFLOAD_VLAN_STRIP)))
		hw->use_simple_rx = 0;
#else
	if (vtpci_with_feature(hw, VIRTIO_NET_F_MRG_RXBUF) ||
		s_lsxvio_rc_sim ||
		(rx_offloads & (DEV_RX_OFFLOAD_UDP_CKSUM |
			DEV_RX_OFFLOAD_TCP_CKSUM |
			DEV_RX_OFFLOAD_TCP_LRO |
			DEV_RX_OFFLOAD_VLAN_STRIP)))
		hw->use_simple_rx = 0;
#endif

	return 0;
}

static inline int
lsxvio_rc_recv_refill(struct virtqueue *vq,
	struct rte_mbuf **cookie, uint16_t num)
{
	struct vq_desc_extra *dxp;
	struct virtio_hw *hw = vq->hw;
	struct vring_desc *start_dp = vq->vq_split.ring.desc;
	uint16_t idx, i;

	if (unlikely(vq->vq_free_cnt == 0))
		return -ENOSPC;
	if (unlikely(vq->vq_free_cnt < num))
		return -EMSGSIZE;

	if (unlikely(vq->vq_desc_head_idx >= vq->vq_nentries))
		return -EFAULT;

	for (i = 0; i < num; i++) {
		idx = vq->vq_desc_head_idx;
		dxp = &vq->vq_descx[idx];
		dxp->cookie = (void *)cookie[i];
		dxp->ndescs = 1;

		start_dp[idx].addr =
			VIRTIO_MBUF_ADDR(cookie[i], vq) +
			RTE_PKTMBUF_HEADROOM - hw->vtnet_hdr_size;
		start_dp[idx].len =
			cookie[i]->buf_len - RTE_PKTMBUF_HEADROOM +
			hw->vtnet_hdr_size;
		start_dp[idx].flags = VRING_DESC_F_WRITE;
		vq->vq_desc_head_idx = start_dp[idx].next;
		vq_update_avail_ring(vq, idx);
		if (vq->vq_desc_head_idx == VQ_RING_DESC_CHAIN_END) {
			vq->vq_desc_tail_idx = vq->vq_desc_head_idx;
			break;
		}
	}

	vq->vq_free_cnt = (uint16_t)(vq->vq_free_cnt - num);

	return 0;
}

static inline int
lsxvio_rc_recv_refill_packed(struct virtqueue *vq,
	struct rte_mbuf **cookie, uint16_t num)
{
	struct vring_packed_desc *start_dp = vq->vq_packed.ring.desc;
	uint16_t flags = vq->vq_packed.cached_flags;
	struct virtio_hw *hw = vq->hw;
	struct vq_desc_extra *dxp;
	uint16_t idx;
	int i;

	if (unlikely(vq->vq_free_cnt == 0))
		return -ENOSPC;
	if (unlikely(vq->vq_free_cnt < num))
		return -EMSGSIZE;

	for (i = 0; i < num; i++) {
		idx = vq->vq_avail_idx;
		dxp = &vq->vq_descx[idx];
		dxp->cookie = (void *)cookie[i];
		dxp->ndescs = 1;

		start_dp[idx].addr = VIRTIO_MBUF_ADDR(cookie[i], vq) +
				RTE_PKTMBUF_HEADROOM - hw->vtnet_hdr_size;
		start_dp[idx].len = cookie[i]->buf_len - RTE_PKTMBUF_HEADROOM
					+ hw->vtnet_hdr_size;

		vq->vq_desc_head_idx = dxp->next;
		if (vq->vq_desc_head_idx == VQ_RING_DESC_CHAIN_END)
			vq->vq_desc_tail_idx = vq->vq_desc_head_idx;

		virtqueue_store_flags_packed(&start_dp[idx], flags,
					     hw->weak_barriers);

		if (++vq->vq_avail_idx >= vq->vq_nentries) {
			vq->vq_avail_idx -= vq->vq_nentries;
			vq->vq_packed.cached_flags ^=
				VRING_PACKED_DESC_F_AVAIL_USED;
			flags = vq->vq_packed.cached_flags;
		}
	}
	vq->vq_free_cnt = (uint16_t)(vq->vq_free_cnt - num);
	return 0;
}

static int
lsxvio_rc_rx_queue_setup_finish(struct rte_eth_dev *dev,
	uint16_t queue_idx)
{
	uint16_t vtpci_queue_idx = 2 * queue_idx + VTNET_SQ_RQ_QUEUE_IDX;
	struct lsxvio_rc_pci_hw *lsx_hw = dev->data->dev_private;
	struct virtio_hw *hw = &lsx_hw->common_cfg;
	uint64_t lsx_feature = lsxvio_priv_feature(lsx_hw);
	struct virtqueue *vq = hw->vqs[vtpci_queue_idx];
	struct virtnet_rx *rxvq = &vq->rxq;
	struct rte_mbuf *m;
	uint16_t desc_idx;
	int error, nbufs;

	PMD_INIT_FUNC_TRACE();

	/* Allocate blank mbufs for the each rx descriptor */
	nbufs = 0;

	memset(&rxvq->fake_mbuf, 0, sizeof(rxvq->fake_mbuf));
	for (desc_idx = 0; desc_idx < RTE_PMD_VIRTIO_RX_MAX_BURST;
	     desc_idx++) {
		vq->sw_ring[vq->vq_nentries + desc_idx] =
			&rxvq->fake_mbuf;
	}

	while (!virtqueue_full(vq)) {
		m = rte_mbuf_raw_alloc(rxvq->mpool);
		if (!m)
			break;

		/* Enqueue allocated buffers */
		if (lsx_feature & LSX_VIO_EP2RC_PACKED)
			error = lsxvio_rc_recv_refill_packed(vq, &m, 1);
		else
			error = lsxvio_rc_recv_refill(vq, &m, 1);
		if (error) {
			rte_pktmbuf_free(m);
			break;
		}
		nbufs++;
	}

	if (lsx_feature & LSX_VIO_EP2RC_PACKED)
		virtqueue_enable_intr_packed(vq);
	else
		vq_update_avail_idx(vq);

	PMD_INIT_LOG(DEBUG, "Allocated %d bufs", nbufs);

	VIRTQUEUE_DUMP(vq);

	return 0;
}

static int
lsxvio_rc_eth_start(struct rte_eth_dev *dev)
{
	uint16_t i;
	struct virtnet_rx *rxvq;
	struct virtnet_tx *txvq;
	struct virtio_hw *hw = dev->data->dev_private;
	int ret;

	/* Finish the initialization of the queues */
	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		ret = lsxvio_rc_rx_queue_setup_finish(dev, i);
		if (ret < 0)
			return ret;
	}
	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		ret = virtio_dev_tx_queue_setup_finish(dev, i);
		if (ret < 0)
			return ret;
	}

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		rxvq = dev->data->rx_queues[i];
		/* Flush the old packets */
		virtqueue_rxvq_flush(rxvq->vq);
		virtqueue_notify(rxvq->vq);
	}

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		txvq = dev->data->tx_queues[i];
		virtqueue_notify(txvq->vq);
	}

	PMD_INIT_LOG(DEBUG, "Notified backend at initialization");

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		rxvq = dev->data->rx_queues[i];
		VIRTQUEUE_DUMP(rxvq->vq);
	}

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		txvq = dev->data->tx_queues[i];
		VIRTQUEUE_DUMP(txvq->vq);
	}

	lsxvio_rc_set_rxtx_funcs(dev);
	hw->started = true;

	/* Initialize Link state */
	lsxvio_rc_eth_link_update(dev, 0);

	return 0;
}

static void
lsxvio_rc_free_mbufs(struct rte_eth_dev *dev)
{
	struct virtio_hw *hw = dev->data->dev_private;
	uint16_t nr_vq = lsxvio_rc_get_nr_vq(hw);
	uint32_t i, mbuf_num = 0;
	struct virtqueue *vq;
	struct rte_mbuf *buf;
	int queue_type;

	if (!hw->vqs)
		return;

	for (i = 0; i < nr_vq; i++) {
		vq = hw->vqs[i];
		if (!vq)
			continue;

		queue_type = virtio_get_queue_type(hw, i);
		if (queue_type != VTNET_RQ && queue_type != VTNET_TQ)
			continue;

		VIRTQUEUE_DUMP(vq);

		while ((buf = virtqueue_detach_unused(vq)) != NULL) {
			rte_pktmbuf_free(buf);
			mbuf_num++;
		}

		VIRTQUEUE_DUMP(vq);
	}

	PMD_INIT_LOG(DEBUG, "%d mbufs freed", mbuf_num);
}

static void
lsxvio_rc_eth_stop(struct rte_eth_dev *dev)
{
	struct virtio_hw *hw = dev->data->dev_private;
	struct rte_eth_link link;

	PMD_INIT_LOG(DEBUG, "stop");

	rte_spinlock_lock(&hw->state_lock);
	if (!hw->started)
		goto out_unlock;
	hw->started = false;

	memset(&link, 0, sizeof(link));
	rte_eth_linkstatus_set(dev, &link);
out_unlock:
	rte_spinlock_unlock(&hw->state_lock);
}

static int
lsxvio_rc_eth_link_update(struct rte_eth_dev *dev,
	__rte_unused int wait_to_complete)
{
	struct rte_eth_link link;
	uint16_t status;
	struct virtio_hw *hw = dev->data->dev_private;

	memset(&link, 0, sizeof(link));
	link.link_duplex = ETH_LINK_FULL_DUPLEX;
	link.link_speed  = ETH_SPEED_NUM_10G;
	link.link_autoneg = ETH_LINK_FIXED;

	if (!hw->started) {
		link.link_status = ETH_LINK_DOWN;
	} else if (vtpci_with_feature(hw, VIRTIO_NET_F_STATUS)) {
		PMD_INIT_LOG(DEBUG, "Get link status from hw");
		vtpci_read_dev_config(hw,
			offsetof(struct virtio_net_config, status),
			&status, sizeof(status));
		if ((status & VIRTIO_NET_S_LINK_UP) == 0) {
			link.link_status = ETH_LINK_DOWN;
			PMD_INIT_LOG(DEBUG, "Port %d is down",
				dev->data->port_id);
		} else {
			link.link_status = ETH_LINK_UP;
			PMD_INIT_LOG(DEBUG, "Port %d is up",
				dev->data->port_id);
		}
	} else {
		link.link_status = ETH_LINK_UP;
	}

	return rte_eth_linkstatus_set(dev, &link);
}

static int
lsxvio_rc_eth_info_get(struct rte_eth_dev *dev,
	struct rte_eth_dev_info *dev_info)
{
	uint64_t tso_mask, host_features;
	struct virtio_hw *hw = dev->data->dev_private;

	dev_info->speed_capa = ETH_LINK_SPEED_10G; /* fake value */

	dev_info->max_rx_queues =
		RTE_MIN(hw->max_queue_pairs, VIRTIO_MAX_RX_QUEUES);
	dev_info->max_tx_queues =
		RTE_MIN(hw->max_queue_pairs, VIRTIO_MAX_TX_QUEUES);
	dev_info->min_rx_bufsize = VIRTIO_MIN_RX_BUFSIZE;
	dev_info->max_rx_pktlen = VIRTIO_MAX_RX_PKTLEN;
	dev_info->max_mac_addrs = VIRTIO_MAX_MAC_ADDRS;

	host_features = VTPCI_OPS(hw)->get_features(hw);
	dev_info->rx_offload_capa = DEV_RX_OFFLOAD_VLAN_STRIP;
	dev_info->rx_offload_capa |= DEV_RX_OFFLOAD_JUMBO_FRAME;
	if (host_features & (1ULL << VIRTIO_NET_F_GUEST_CSUM)) {
		dev_info->rx_offload_capa |=
			DEV_RX_OFFLOAD_TCP_CKSUM |
			DEV_RX_OFFLOAD_UDP_CKSUM;
	}
	if (host_features & (1ULL << VIRTIO_NET_F_CTRL_VLAN))
		dev_info->rx_offload_capa |= DEV_RX_OFFLOAD_VLAN_FILTER;
	tso_mask = (1ULL << VIRTIO_NET_F_GUEST_TSO4) |
		(1ULL << VIRTIO_NET_F_GUEST_TSO6);
	if ((host_features & tso_mask) == tso_mask)
		dev_info->rx_offload_capa |= DEV_RX_OFFLOAD_TCP_LRO;

	dev_info->tx_offload_capa = DEV_TX_OFFLOAD_MULTI_SEGS |
				    DEV_TX_OFFLOAD_VLAN_INSERT;
	if (host_features & (1ULL << VIRTIO_NET_F_CSUM)) {
		dev_info->tx_offload_capa |=
			DEV_TX_OFFLOAD_UDP_CKSUM |
			DEV_TX_OFFLOAD_TCP_CKSUM;
	}
	tso_mask = (1ULL << VIRTIO_NET_F_HOST_TSO4) |
		(1ULL << VIRTIO_NET_F_HOST_TSO6);
	if ((host_features & tso_mask) == tso_mask)
		dev_info->tx_offload_capa |= DEV_TX_OFFLOAD_TCP_TSO;

	return 0;
}

static void
lsxvio_rc_eth_construct(void)
{
	char *penv = getenv("LSXVIO_PCI_SIM");

	if (penv)
		s_lsxvio_rc_sim = atoi(penv);
	if (s_lsxvio_rc_sim)
		rte_lsxvio_pci_pmd.drv_flags &= (~RTE_PCI_DRV_NEED_MAPPING);

	penv = getenv("LSXVIO_RC_PROC_SECONDARY_STANDALONE");
	if (penv)
		s_lsxvio_rc_2nd_proc_standalone = atoi(penv);

	rte_lsxvio_pci_pmd.driver.name = RTE_STR(lsxvio_net);
	rte_pci_register(&rte_lsxvio_pci_pmd);
}

RTE_INIT(lsxvio_rc_eth_construct);
RTE_PMD_EXPORT_NAME(lsxvio_net, __COUNTER__);
RTE_PMD_REGISTER_PCI_TABLE(lsxvio_net, lsxvio_pci_id_map);

RTE_INIT(virtio_init_log)
{
	lsxvio_rc_logtype_init = rte_log_register("pmd.net.lsxvio.init");
	if (lsxvio_rc_logtype_init >= 0)
		rte_log_set_level(lsxvio_rc_logtype_init, RTE_LOG_NOTICE);
	lsxvio_rc_logtype_driver = rte_log_register("pmd.net.lsxvio.driver");
	if (lsxvio_rc_logtype_driver >= 0)
		rte_log_set_level(lsxvio_rc_logtype_driver, RTE_LOG_NOTICE);
}
