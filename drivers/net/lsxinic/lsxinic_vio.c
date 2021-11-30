// SPDX-License-Identifier: BSD-3-Clause
/* Copyright 2020-2021 NXP  */

#include <stdio.h>
#include <linux/virtio_ids.h>
#include <generic/rte_cycles.h>
#include <rte_malloc.h>

#include <rte_interrupts.h>
#include <dpaa2_hw_pvt.h>
#include <rte_lsx_pciep_bus.h>

#include "lsxinic_common_pmd.h"
#include "lsxinic_vio_common.h"
#include "lsxinic_vio_net.h"
#include "lsxinic_vio_rxtx.h"
#include "lsxinic_vio.h"

int lsxvio_virtio_check_driver_feature(struct lsxvio_common_cfg *common)
{
	return ((common->driver_feature[0] ==
		(common->device_feature[0] & common->driver_feature[0])) &&
		(common->driver_feature[1] ==
		(common->device_feature[1] & common->driver_feature[1])));
}

void lsxvio_virtio_config_fromrc(struct rte_lsx_pciep_device *dev)
{
	struct lsxvio_adapter *adapter = dev->eth_dev->data->dev_private;
	struct lsxvio_common_cfg *common = BASE_TO_COMMON(adapter->cfg_base);
	struct lsxvio_queue_cfg *queue;
	struct lsxvio_queue *vq;
	uint64_t desc_addr;
	int i, size;
	uint8_t *virt;

	/* Get common config from bar.
	 * Currently vdpa driver use MSI-X interrupts.
	 */
	dev->mmsi_flag = LSX_PCIEP_MSIX_INT;
	/* Init msix before start queues. */
	if (!lsx_pciep_hw_sim_get(adapter->pcie_idx)) {
		lsx_pciep_msix_init(dev);

		adapter->msix_config = common->msix_config;
		adapter->msix_cfg_addr = lsx_pciep_msix_get_vaddr(dev,
			adapter->msix_config);
		adapter->msix_cfg_cmd = lsx_pciep_msix_get_cmd(dev,
			adapter->msix_config);
	}

	/* Check queue_used_num, which needs rc to set it. */
	if (adapter->num_queues < common->queue_used_num)
		LSXINIC_PMD_INFO("Max %d queues are supported, %d are used",
			adapter->num_queues, common->queue_used_num);
	else if (common->queue_used_num > 0)
		adapter->num_queues = common->queue_used_num;

	/* When DRIOVER_OK is set, this will be called. */
	for (i = 0; i < LSXVIO_MAX_QUEUE_PAIRS * 2; i++) {
		queue = BASE_TO_QUEUE(adapter->cfg_base, i);
		if (!queue->queue_enable)
			continue;

		vq = adapter->vqs[i];
		if (queue->queue_size <= LSXVIO_MAX_RING_DESC)
			/* It is better to set configs related to num_desc. */
			vq->nb_desc = queue->queue_size;

		vq->notify_addr = (uint16_t *)(BASE_TO_NOTIFY(adapter->cfg_base)
			+ queue->queue_notify_off * LSXVIO_NOTIFY_OFF_MULTI);
		vq->shadow_avail =
			(struct vring_avail *)(adapter->ring_base +
			queue->queue_notify_off *
			(sizeof(struct vring_avail) +
			(vq->nb_desc * sizeof(uint16_t))));
		desc_addr =
			(queue->queue_desc_lo |
			((uint64_t)(queue->queue_desc_hi) << 32));
		size = RTE_MAX(CFG_1M_SIZE,
			vring_size(LSXVIO_MAX_RING_DESC, RTE_CACHE_LINE_SIZE));
		if (!lsx_pciep_hw_sim_get(adapter->pcie_idx))
			virt = lsx_pciep_set_ob_win(dev,
				desc_addr, size);
		else
			virt = DPAA2_IOVA_TO_VADDR(desc_addr);
		vq->desc = (struct vring_desc *)virt;
		vq->avail = (struct vring_avail *)(virt - desc_addr +
				(queue->queue_avail_lo
				| ((uint64_t)(queue->queue_avail_hi) << 32)));
		vq->used = (struct vring_used *)(virt - desc_addr +
				(queue->queue_used_lo
				| ((uint64_t)(queue->queue_used_hi) << 32)));
		vq->shadow_used_split = rte_zmalloc_socket("q->shadow_used",
			sizeof(struct vring_used) +
			(vq->nb_desc * sizeof(struct vring_used_elem)),
			RTE_CACHE_LINE_SIZE, rte_socket_id());
		LSXINIC_PMD_INFO("desc_addr=%lx, avail_addr=%lx,"
				" used_addr=%lx, size=%lx, desc=%p"
				" avail=%p, used=%p, shadow_used_split=%p",
				desc_addr,
				queue->queue_avail_lo |
				((uint64_t)(queue->queue_avail_hi) << 32),
				queue->queue_used_lo |
				((uint64_t)(queue->queue_used_hi) << 32),
				vring_size(LSXVIO_MAX_RING_DESC,
				RTE_CACHE_LINE_SIZE),
				vq->desc, vq->avail, vq->used,
				vq->shadow_used_split);

		if (queue->queue_msix_vector != VIRTIO_MSI_NO_VECTOR &&
			!lsx_pciep_hw_sim_get(adapter->pcie_idx)) {
			vq->msix_irq = queue->queue_msix_vector;
			vq->msix_vaddr = lsx_pciep_msix_get_vaddr(dev,
				vq->msix_irq);
			vq->msix_cmd = lsx_pciep_msix_get_cmd(dev,
				vq->msix_irq);
		}

		vq->status = LSXVIO_QUEUE_START;
	}
}

void lsxvio_virtio_reset_dev(struct rte_eth_dev *dev)
{
	struct lsxvio_adapter *adapter = dev->data->dev_private;
	struct lsxvio_common_cfg *common = BASE_TO_COMMON(adapter->cfg_base);
	struct lsxvio_queue_cfg *queue;
	int i;

	/* Set queeu_enable to 0. */
	for (i = 0; i < LSXVIO_MAX_QUEUE_PAIRS * 2; i++) {
		queue = BASE_TO_QUEUE(adapter->cfg_base, i);
		queue->queue_enable = 0;
	}

	/* Set device_status to 0 after reset. */
	adapter->status = 0;
	common->device_status = 0;
}

static void
lsxvio_virtio_common_init(uint64_t virt, uint64_t features)
{
	struct lsxvio_common_cfg *common;
	struct lsxvio_queue_cfg *queue;
	uint16_t i;

	/* Init common cfg. */
	common = (struct lsxvio_common_cfg *)(virt + LSXVIO_COMMON_OFFSET);
	common->device_feature[0] = features & 0xffffffff;
	common->device_feature[1] = features >> 32;
	common->num_queues = LSXVIO_MAX_QUEUE_PAIRS * 2;
	common->device_status = VIRTIO_CONFIG_STATUS_NEEDS_RESET;

	for (i = 0; i < LSXVIO_MAX_QUEUE_PAIRS * 2; i++) {
		queue = (struct lsxvio_queue_cfg *)(virt
				+ sizeof(struct lsxvio_common_cfg)
				+ i * sizeof(struct lsxvio_queue_cfg));

		queue->queue_size = LSXVIO_MAX_RING_DESC;
		queue->queue_notify_off = i;
	}
}

static void
lsxvio_virtio_blk_init(uint64_t virt)
{
	struct lsxvio_common_cfg *common;
	struct virtio_blk_config *blk;

	common = (struct lsxvio_common_cfg *)(virt + LSXVIO_COMMON_OFFSET);
	blk = (struct virtio_blk_config *)(virt + LSXVIO_DEVICE_OFFSET);
	/* TBD */
	blk->capacity = 0x10000000;
	if (common->device_feature[0] & VIRTIO_NET_F_MQ)
		blk->num_queues = LSXVIO_MAX_QUEUE_PAIRS;
}

static void
lsxvio_virtio_net_init(uint64_t virt)
{
	struct lsxvio_common_cfg *common;
	struct virtio_net_config *net;

	common = (struct lsxvio_common_cfg *)(virt + LSXVIO_COMMON_OFFSET);
	net = (struct virtio_net_config *)(virt + LSXVIO_DEVICE_OFFSET);
	/* Init device cfg. */
	if (common->device_feature[0] & VIRTIO_NET_F_MAC) {
		net->mac[0] = 0x00;
		net->mac[1] = 0xe0;
		net->mac[2] = 0x0c;
		net->mac[3] = 0x0;
		net->mac[4] = 0x0;
		net->mac[5] = 0x0;
	}

	if (common->device_feature[0] & VIRTIO_NET_F_STATUS)
		net->status = VIRTIO_NET_S_LINK_UP;

	if (common->device_feature[0] & VIRTIO_NET_F_MQ)
		net->max_virtqueue_pairs = LSXVIO_MAX_QUEUE_PAIRS;

	if (common->device_feature[0] & VIRTIO_NET_F_MTU)
		net->mtu = 10 * 1024 - VLAN_ETH_HLEN;
}

void
lsxvio_virtio_init(uint64_t virt, uint16_t id)
{
	switch (id) {
	case VIRTIO_ID_NET:
	case VIRTIO_PCI_MODERN_NET:
	case VIRTIO_PCI_FSL:
		lsxvio_virtio_common_init(virt, LSX_VIRTIO_NET_FEATURES);
		lsxvio_virtio_net_init(virt);
		break;
	case VIRTIO_ID_BLOCK:
	case VIRTIO_PCI_BLK:
		lsxvio_virtio_common_init(virt, LSX_VIRTIO_BLK_FEATURES_TEST);
		lsxvio_virtio_blk_init(virt);
		break;
	default:
		LSXINIC_PMD_ERR("The device type is not supported!");
	}
}
