// SPDX-License-Identifier: BSD-3-Clause
/* Copyright 2020-2022 NXP  */

#include <stdio.h>

#include <generic/rte_cycles.h>
#include <rte_malloc.h>

#include <rte_interrupts.h>
#include <rte_lsx_pciep_bus.h>
#include <ethdev_driver.h>
#include <dpaa2_hw_pvt.h>

#include "lsxinic_common_pmd.h"
#include "lsxinic_vio_common.h"
#include "lsxinic_ep_vio_net.h"
#include "lsxinic_ep_vio_rxtx.h"
#include "lsxinic_ep_vio.h"
#include "lsxinic_ep_dma.h"

int lsxvio_virtio_check_driver_feature(struct lsxvio_common_cfg *common)
{
	return (common->driver_feature ==
		(common->device_feature & common->driver_feature));
}

int
lsxvio_virtio_config_fromrc(struct rte_lsx_pciep_device *dev)
{
	struct lsxvio_adapter *adapter = dev->eth_dev->data->dev_private;
	struct lsxvio_common_cfg *common = BASE_TO_COMMON(adapter->cfg_base);
	struct lsxvio_queue_cfg *queue;
	struct lsxvio_queue *vq;
	struct lsinic_dma_job *e2r_jobs, *r2e_jobs, *r2e_idx_jobs;
	uint64_t desc_addr;
	uint64_t src, dst;
	uint32_t i, j;
	uint8_t *virt;
	char name[RTE_MEMZONE_NAMESIZE];

	/* Get common config from bar.
	 * Currently vdpa driver use MSI-X interrupts.
	 */
	dev->mmsi_flag = LSX_PCIEP_MSIX_INT;
	/* Init msix before start queues. */
	if (!lsx_pciep_hw_sim_get(adapter->pcie_idx)) {
		lsx_pciep_multi_msix_init(dev, LSXVIO_MAX_QUEUES);

		adapter->msix_config = common->msix_config;
		if (common->msix_config != VIRTIO_MSI_NO_VECTOR) {
			adapter->msix_cfg_addr =
				dev->msix_addr[adapter->msix_config];
			adapter->msix_cfg_cmd =
				dev->msix_data[adapter->msix_config];
		} else {
			adapter->msix_cfg_addr = NULL;
			adapter->msix_cfg_cmd = 0;
		}
	}

	/* Check queue_used_num, which needs rc to set it. */
	if (adapter->num_queues < common->queue_used_num)
		LSXINIC_PMD_INFO("Max %d queues are supported, %d are used",
			adapter->num_queues, common->queue_used_num);
	else if (common->queue_used_num > 0)
		adapter->num_queues = common->queue_used_num;

	/* When DRIOVER_OK is set, this will be called. */
	for (i = 0; i < adapter->num_queues; i++) {
		queue = BASE_TO_QUEUE(adapter->cfg_base, i);
		if (!queue->queue_enable)
			continue;

		vq = adapter->vqs[i];
		if (queue->queue_size <= LSXVIO_MAX_RING_DESC)
			/* It is better to set configs related to num_desc. */
			vq->nb_desc = queue->queue_size;

		vq->notify_addr = (uint16_t *)(BASE_TO_NOTIFY(adapter->cfg_base)
			+ queue->queue_notify_off * LSXVIO_NOTIFY_OFF_MULTI);

		desc_addr =
			(queue->queue_desc_lo |
			((uint64_t)(queue->queue_desc_hi) << 32));
		if (!lsx_pciep_hw_sim_get(adapter->pcie_idx))
			virt = lsx_pciep_set_ob_win(dev,
				desc_addr, LSXVIO_PER_RING_MEM_MAX_SIZE);
		else
			virt = DPAA2_IOVA_TO_VADDR(desc_addr);
		if (!virt) {
			LSXINIC_PMD_ERR("OB map host phy(0x%lx) failed\n",
				desc_addr);
			return -ENOMEM;
		}
		vq->desc_addr = virt;

		if (vq->type == LSXVIO_QUEUE_TX) {
			vq->mem_base = 0;
			if (vq->flag & LSXVIO_QUEUE_PKD_INORDER_FLAG) {
				vq->mem_base = queue->queue_mem_base;
				vq->packed_notify = (void *)
					(adapter->ring_base +
					queue->queue_notify_off *
					LSXVIO_PER_RING_MEM_MAX_SIZE);
				vq->shadow_phy = (adapter->ring_phy_base +
					queue->queue_notify_off *
					LSXVIO_PER_RING_MEM_MAX_SIZE);
				vq->shadow_avail = NULL;
				vq->pdesc = vq->desc_addr;
				vq->vdesc = NULL;
			} else {
				vq->shadow_avail = (void *)
					(adapter->ring_base +
					queue->queue_notify_off *
					LSXVIO_PER_RING_MEM_MAX_SIZE);
				vq->packed_notify = NULL;
				vq->vdesc = vq->desc_addr;
				vq->pdesc = NULL;
			}
			vq->shadow_vdesc = NULL;
		} else {
			if (queue->queue_mem_base) {
				vq->mem_base = queue->queue_mem_base;
				vq->shadow_sdesc = (void *)(adapter->ring_base +
					queue->queue_notify_off *
					LSXVIO_PER_RING_MEM_MAX_SIZE);
				memset(vq->shadow_sdesc, 0,
					sizeof(struct lsxvio_short_desc) *
					vq->nb_desc);
				vq->shadow_phy = (adapter->ring_phy_base +
					queue->queue_notify_off *
					LSXVIO_PER_RING_MEM_MAX_SIZE);
				vq->shadow_avail = (void *)
					((char *)vq->shadow_sdesc +
					sizeof(struct lsxvio_short_desc) *
					vq->nb_desc);
				vq->shadow_vdesc = NULL;
			} else {
				vq->mem_base = 0;
				vq->shadow_vdesc = (void *)
					(adapter->ring_base +
					queue->queue_notify_off *
					LSXVIO_PER_RING_MEM_MAX_SIZE);
				vq->shadow_avail = (void *)
					((char *)vq->shadow_vdesc +
					sizeof(struct vring_desc) *
					vq->nb_desc);
				vq->shadow_sdesc = NULL;
			}
			vq->vdesc = vq->desc_addr;
			vq->pdesc = NULL;
			vq->packed_notify = NULL;
		}

		if (vq->shadow_avail) {
			for (j = 0; j < vq->nb_desc; j++)
				vq->shadow_avail->ring[j] = j;
		}

		vq->avail = (struct vring_avail *)(virt - desc_addr +
				(queue->queue_avail_lo
				| ((uint64_t)(queue->queue_avail_hi) << 32)));
		vq->used = (struct vring_used *)(virt - desc_addr +
				(queue->queue_used_lo
				| ((uint64_t)(queue->queue_used_hi) << 32)));
		vq->shadow_used_split = rte_zmalloc_socket("q->shadow_used",
			sizeof(struct vring_used) + RTE_CACHE_LINE_SIZE +
			(vq->nb_desc * sizeof(struct vring_used_elem)),
			RTE_CACHE_LINE_SIZE, rte_socket_id());
		if (!vq->shadow_used_split) {
			LSXINIC_PMD_ERR("shadow_used_split alloc failed\n");

			return -ENOMEM;
		}
		vq->shadow_used_split =
			(void *)((char *)vq->shadow_used_split +
			offsetof(struct vring_used, ring[0]));
		sprintf(name, "shadow_pdesc_%d_%d_%d_%d_%d",
			dev->pcie_id, dev->pf, dev->is_vf, dev->vf, i);
		vq->shadow_pdesc_mz = rte_memzone_reserve_aligned(name,
			vq->nb_desc * sizeof(struct vring_packed_desc),
			SOCKET_ID_ANY, RTE_MEMZONE_IOVA_CONTIG,
			RTE_CACHE_LINE_SIZE);
		if (vq->shadow_pdesc_mz) {
			vq->shadow_pdesc = vq->shadow_pdesc_mz->addr;
			vq->shadow_pdesc_phy = vq->shadow_pdesc_mz->iova;
		} else {
			LSXINIC_PMD_ERR("RSV %s (size = %ld) failed\n",
				name,
				vq->nb_desc * sizeof(struct vring_packed_desc));

			return -ENOMEM;
		}

		e2r_jobs = &vq->dma_jobs[LSXVIO_E2R_BD_DMA_START];
		r2e_jobs = &vq->dma_jobs[LSXVIO_R2E_BD_DMA_START];
		r2e_idx_jobs = &vq->dma_jobs[LSXVIO_R2E_IDX_BD_DMA_START];

		if (vq->type == LSXVIO_QUEUE_TX &&
			vq->flag & LSXVIO_QUEUE_PKD_INORDER_FLAG &&
			vq->shadow_pdesc_mz) {
			for (j = 0; j < vq->nb_desc; j++) {
				vq->shadow_pdesc[j].id = j;
				e2r_jobs[j].src = vq->shadow_pdesc_phy +
					j * sizeof(struct vring_packed_desc);
				e2r_jobs[j].dst = vq->ob_base + desc_addr +
					j * sizeof(struct vring_packed_desc);
			}
		}

		if (vq->type == LSXVIO_QUEUE_TX &&
			vq->flag & LSXVIO_QUEUE_DMA_ADDR_NOTIFY_FLAG) {
			for (j = 0; j < vq->nb_desc; j++) {
				if (vq->mem_base) {
					src = queue->queue_rc_shadow_base +
						vq->ob_base +
						j * sizeof(uint32_t);
					dst = vq->shadow_phy +
					offsetof(struct lsxvio_packed_notify,
					addr[0]) + j * sizeof(uint32_t);
				} else {
					src = queue->queue_rc_shadow_base +
						vq->ob_base +
						j * sizeof(uint64_t);
					dst = vq->shadow_phy +
					offsetof(struct lsxvio_packed_notify,
					addr[0]) + j * sizeof(uint64_t);
				}
				r2e_jobs[j].src = src;
				r2e_jobs[j].dst = dst;

				src = queue->queue_rc_shadow_base +
					vq->ob_base +
					sizeof(uint64_t) * vq->nb_desc +
					j * sizeof(uint16_t);
				dst = vq->shadow_phy +
					offsetof(struct lsxvio_packed_notify,
					last_avail_idx);
				r2e_idx_jobs[j].src = src;
				r2e_idx_jobs[j].dst = dst;
				r2e_idx_jobs[j].len = sizeof(uint16_t);

				vq->dma_bd_cntx[j].cntx_type =
					LSXVIO_DMA_TX_CNTX_DATA;
			}
		}

		if (vq->type == LSXVIO_QUEUE_RX &&
			(vq->flag & LSXVIO_QUEUE_IDX_INORDER_FLAG) &&
			queue->queue_rc_shadow_base) {
			for (j = 0; j < vq->nb_desc; j++) {
				if (vq->mem_base) {
					src = queue->queue_rc_shadow_base +
					vq->ob_base +
					j *
					sizeof(struct lsxvio_short_desc);
					dst = vq->shadow_phy +
					j *
					sizeof(struct lsxvio_short_desc);
				} else {
					src = queue->queue_rc_shadow_base +
						vq->ob_base +
						j * sizeof(struct vring_desc);
					dst = vq->shadow_phy +
						j * sizeof(struct vring_desc);
				}

				r2e_jobs[j].src = src;
				r2e_jobs[j].dst = dst;

				vq->dma_bd_cntx[j].cntx_type =
					LSXVIO_DMA_RX_CNTX_DATA;
			}
		}

		LSXINIC_PMD_INFO("PHY desc=%lx, avail=%lx, used_addr=%lx",
			desc_addr,
			queue->queue_avail_lo |
			((uint64_t)(queue->queue_avail_hi) << 32),
			queue->queue_used_lo |
			((uint64_t)(queue->queue_used_hi) << 32));

		LSXINIC_PMD_INFO("VIR desc=%p, avail=%p, used=%p, split=%p",
			vq->desc_addr, vq->avail, vq->used,
			vq->shadow_used_split);

		if (queue->queue_msix_vector != VIRTIO_MSI_NO_VECTOR &&
			!lsx_pciep_hw_sim_get(adapter->pcie_idx)) {
			vq->msix_irq = queue->queue_msix_vector;
			vq->msix_vaddr = dev->msix_addr[vq->msix_irq];
			vq->msix_cmd = dev->msix_data[vq->msix_irq];
		}

		vq->status = LSXVIO_QUEUE_START;
	}

	return 0;
}

void lsxvio_virtio_reset_dev(struct rte_eth_dev *dev)
{
	struct lsxvio_adapter *adapter = dev->data->dev_private;
	struct lsxvio_common_cfg *common = BASE_TO_COMMON(adapter->cfg_base);
	struct lsxvio_queue_cfg *queue;
	int i;

	/* Set queeu_enable to 0. */
	for (i = 0; i < LSXVIO_MAX_QUEUES; i++) {
		queue = BASE_TO_QUEUE(adapter->cfg_base, i);
		queue->queue_enable = 0;
	}

	/* Set device_status to 0 after reset. */
	adapter->status = 0;
	common->device_status = 0;
}

static void
lsxvio_virtio_common_init(uint64_t virt,
	uint64_t features, uint64_t lsx_feature)
{
	struct lsxvio_common_cfg *common;
	struct lsxvio_queue_cfg *queue;
	uint16_t i;

	/* Init common cfg. */
	common = (struct lsxvio_common_cfg *)(virt + LSXVIO_COMMON_OFFSET);
	common->device_feature = features;
	common->num_queues = LSXVIO_MAX_QUEUES;
	common->device_status = VIRTIO_CONFIG_STATUS_NEEDS_RESET;
	common->lsx_feature = lsx_feature;
	common->msix_config = VIRTIO_MSI_NO_VECTOR;

	for (i = 0; i < LSXVIO_MAX_QUEUES; i++) {
		queue = (struct lsxvio_queue_cfg *)(virt
				+ sizeof(struct lsxvio_common_cfg)
				+ i * sizeof(struct lsxvio_queue_cfg));

		queue->queue_size = LSXVIO_MAX_RING_DESC;
		queue->queue_notify_off = i;
		queue->queue_msix_vector = VIRTIO_MSI_NO_VECTOR;
	}
}

static void
lsxvio_virtio_net_init(uint64_t virt)
{
	struct lsxvio_common_cfg *common;
	struct virtio_net_config *net;

	common = (struct lsxvio_common_cfg *)(virt + LSXVIO_COMMON_OFFSET);
	net = (struct virtio_net_config *)(virt + LSXVIO_DEVICE_OFFSET);
	/* Init device cfg. */
	if (common->device_feature & (1ULL << VIRTIO_NET_F_MAC)) {
		net->mac[0] = 0x00;
		net->mac[1] = 0xe0;
		net->mac[2] = 0x0c;
		net->mac[3] = 0x0;
		net->mac[4] = 0x0;
		net->mac[5] = 0x0;
	}

	if (common->device_feature & (1ULL << VIRTIO_NET_F_STATUS))
		net->status = VIRTIO_NET_S_LINK_UP;

	if (common->device_feature & (1ULL << VIRTIO_NET_F_MQ))
		net->max_virtqueue_pairs = LSXVIO_MAX_QUEUE_PAIRS;

	if (common->device_feature & (1ULL << VIRTIO_NET_F_MTU)) {
		net->mtu = 10 * 1024 - sizeof(struct rte_ether_hdr) -
			sizeof(struct rte_vlan_hdr);
	}
}

void
lsxvio_virtio_init(uint64_t virt, uint16_t id, uint64_t lsx_feature)
{
	switch (id) {
	case VIRTIO_ID_NETWORK:
	case VIRTIO_PCI_MODERN_NET:
	case VIRTIO_PCI_FSL:
		lsxvio_virtio_common_init(virt,
			LSX_VIRTIO_NET_FEATURES, lsx_feature);
		lsxvio_virtio_net_init(virt);
		break;
	case VIRTIO_ID_BLOCK:
	case VIRTIO_PCI_BLK:
		lsxvio_virtio_common_init(virt,
			lsxvio_virtio_get_blk_feature(), lsx_feature);
		lsxvio_virtio_blk_init(virt);
		break;
	default:
		LSXINIC_PMD_ERR("The device type is not supported!");
	}
}
