// SPDX-License-Identifier: GPL-2.0
/*
 * NXP LSX NIC driver for virtio dataplane offloading
 *
 * Copyright 2020-2021 NXP
 *
 * Code was mostly borrowed from linux/drivers/vdpa/ifcvf/ifcvf_base.c
 * See linux/drivers/vdpa/ifcvf/ifcvf_base.c for additional Copyrights.
 */
#include <linux/interrupt.h>
#include <linux/pci.h>
#include <linux/sysfs.h>
#include <linux/delay.h>
#include "lsxinic_base.h"

static int s_lsx_pci_vio_cap;

static void iowrite64_twopart(u64 val,
	__le32 __iomem *lo, __le32 __iomem *hi)
{
	writel((u32)val, lo);
	writel(val >> 32, hi);
}

static struct lsxvdpa_adapter *
hw_vf_to_adapter(struct lsxvdpa_hw *hw)
{
	return container_of(hw, struct lsxvdpa_adapter, vf);
}

static struct lsxvio_queue_cfg *
lsxvdpa_hw_queue_cfg(struct lsxvio_common_cfg __iomem *cfg,
	int i)
{
	return (struct lsxvio_queue_cfg *)((u8 *)cfg +
			sizeof(struct lsxvio_common_cfg) +
			i * sizeof(struct lsxvio_queue_cfg));
}

static void __iomem *
lsxvdpa_hw_get_cap_addr(struct lsxvdpa_hw *hw,
	struct virtio_pci_cap *cap)
{
	struct lsxvdpa_adapter *lsxinic;
	struct pci_dev *pdev;
	u32 length, offset;
	u8 bar;

	length = le32_to_cpu(cap->length);
	offset = le32_to_cpu(cap->offset);
	bar = cap->bar;

	lsxinic = hw_vf_to_adapter(hw);
	pdev = lsxinic->pdev;

	if (bar >= PCI_STD_NUM_BARS) {
		LSX_DBG(pdev,
			"Invalid bar number %u to get capabilities\n", bar);
		return NULL;
	}

	if (offset + length > pci_resource_len(pdev, bar)) {
		LSX_DBG(pdev,
			"offset(%u) + len(%u) overflows bar%u's capability\n",
			offset, length, bar);
		return NULL;
	}

	return hw->bar_addr[bar] + offset;
}

static int
lsxvdpa_hw_read_config_range(struct pci_dev *dev,
	uint32_t *val, int size, int where)
{
	int ret, i;

	for (i = 0; i < size; i += 4) {
		ret = pci_read_config_dword(dev, where + i, val + i / 4);
		if (ret < 0)
			return ret;
	}

	return 0;
}

void
lsxvdpa_hw_dump_cfg_addr(struct lsxvdpa_hw *hw,
	struct pci_dev *dev)
{
	LSX_INFO(dev, "######## PCI capability mapping: ########\n");
	LSX_INFO(dev, "--------common cfg: %px\n", hw->common_cfg);
	LSX_INFO(dev, "--------isr cfg: %px\n", hw->isr);
	LSX_INFO(dev, "--------device cfg: %px\n", hw->device_cfg);
	LSX_INFO(dev, "--------notify base: %px\n", hw->notify_base);
	LSX_INFO(dev, "--------notify_off_multiplier: %x\n",
						hw->notify_off_multiplier);
}

void
lsxvdpa_hw_dump_common_cfgs(struct lsxvdpa_hw *hw,
	struct pci_dev *dev)
{
	struct lsxvio_common_cfg __iomem *common = hw->common_cfg;
	struct lsxvio_queue_cfg *queue;
	int i, num = common->num_queues;

	LSX_INFO(dev, "######## common config ########\n");
	LSX_INFO(dev, "device_feature_lo=%x\n", common->device_feature[0]);
	LSX_INFO(dev, "device_feature_hi=%x\n", common->device_feature[1]);
	LSX_INFO(dev, "driver_feature_lo=%x\n", common->driver_feature[0]);
	LSX_INFO(dev, "driver_feature_hi=%x\n", common->driver_feature[1]);
	LSX_INFO(dev, "msix_config=%x\n", common->msix_config);
	LSX_INFO(dev, "num_queues=%x\n", common->num_queues);
	LSX_INFO(dev, "device_status=%x\n", common->device_status);
	LSX_INFO(dev, "config_generation=%x\n", common->config_generation);

	for (i = 0; i < num; i++) {
		queue = lsxvdpa_hw_queue_cfg(common, i);
		LSX_INFO(dev, "queue config, id=%x :\n", i);
		LSX_INFO(dev, "queue_size=%x\n", queue->queue_size);
		LSX_INFO(dev, "queue_msix_vector=%x\n",
					queue->queue_msix_vector);
		LSX_INFO(dev, "queue_enable=%x\n", queue->queue_enable);
		LSX_INFO(dev, "queue_notify_off=%x\n",
					queue->queue_notify_off);
		LSX_INFO(dev, "queue_desc_lo=%x\n", queue->queue_desc_lo);
		LSX_INFO(dev, "queue_desc_hi=%x\n", queue->queue_desc_hi);
		LSX_INFO(dev, "queue_avail_lo=%x\n", queue->queue_avail_lo);
		LSX_INFO(dev, "queue_avail_hi=%x\n", queue->queue_avail_hi);
		LSX_INFO(dev, "queue_used_lo=%x\n", queue->queue_used_lo);
		LSX_INFO(dev, "queue_used_hi=%x\n", queue->queue_used_hi);
	}
}

int lsxvdpa_hw_init_hw(struct lsxvdpa_hw *hw, struct pci_dev *pdev)
{
	int i;
	struct virtio_pci_cap cap;
	int ret;
	u8 pos;

	if (s_lsx_pci_vio_cap) {
		ret = pci_read_config_byte(pdev, PCI_CAPABILITY_LIST, &pos);
		if (ret < 0) {
			LSX_ERR(pdev, "Failed to read PCI capability list\n");
			return -EIO;
		}

		while (pos) {
			ret = lsxvdpa_hw_read_config_range(pdev, (u32 *)&cap,
					sizeof(cap), pos);
			if (ret < 0) {
				LSX_ERR(pdev,
					  "Failed to get PCI capability at %x\n", pos);
				break;
			}

			if (cap.cap_vndr != PCI_CAP_ID_VNDR)
				goto next;

			switch (cap.cfg_type) {
			case VIRTIO_PCI_CAP_COMMON_CFG:
				hw->common_cfg = lsxvdpa_hw_get_cap_addr(hw, &cap);
				LSX_DBG(pdev, "hw->common_cfg = %p\n",
					hw->common_cfg);
				break;
			case VIRTIO_PCI_CAP_NOTIFY_CFG:
				pci_read_config_dword(pdev, pos + sizeof(cap),
					&hw->notify_off_multiplier);
				hw->notify_base = lsxvdpa_hw_get_cap_addr(hw, &cap);
				LSX_DBG(pdev, "hw->notify_base = %p\n",
					hw->notify_base);
				break;
			case VIRTIO_PCI_CAP_ISR_CFG:
				hw->isr = lsxvdpa_hw_get_cap_addr(hw, &cap);
				LSX_DBG(pdev, "hw->isr = %p\n", hw->isr);
				break;
			case VIRTIO_PCI_CAP_DEVICE_CFG:
				hw->device_cfg = lsxvdpa_hw_get_cap_addr(hw, &cap);
				LSX_DBG(pdev, "hw->device_cfg = %p\n", hw->device_cfg);
				break;
			}
next:
			pos = cap.cap_next;
		}
	} else {
		hw->common_cfg = hw->bar_addr[LSXVIO_CONFIG_BAR_IDX] +
			LSXVIO_COMMON_OFFSET;
		hw->isr = hw->bar_addr[LSXVIO_CONFIG_BAR_IDX] +
			LSXVIO_ISR_OFFSET;
		hw->notify_base = hw->bar_addr[LSXVIO_CONFIG_BAR_IDX] +
			LSXVIO_NOTIFY_OFFSET;
		hw->device_cfg = hw->bar_addr[LSXVIO_CONFIG_BAR_IDX] +
			LSXVIO_DEVICE_OFFSET;
		hw->notify_off_multiplier = LSXVIO_NOTIFY_OFF_MULTI;
		hw->ring_base = hw->bar_addr[LSXVIO_RING_BAR_IDX];
	}

	/* Init for update rc desc/avail to ep in future. */
	for (i = 0; i < LSXVIO_MAX_QUEUE_PAIRS * 2; i++) {
		hw->shadow_vring[i] = hw->bar_addr[LSXVIO_RING_BAR_IDX]
					+ sizeof(struct shadow_vring);
	}

	if (hw->common_cfg == NULL || hw->notify_base == NULL ||
	    hw->isr == NULL || hw->device_cfg == NULL) {
		LSX_ERR(pdev, "Incomplete PCI capabilities\n");
		return -EIO;
	}

	lsxvdpa_hw_dump_cfg_addr(hw, pdev);

	return 0;
}

u8 lsxvdpa_hw_get_status(struct lsxvdpa_hw *hw)
{
	return readb(&hw->common_cfg->device_status);
}

void lsxvdpa_hw_set_status(struct lsxvdpa_hw *hw, u8 status)
{
	writeb(status, &hw->common_cfg->device_status);
}

void lsxvdpa_hw_reset(struct lsxvdpa_hw *hw)
{
	struct lsxvdpa_adapter *lsxinic = hw_vf_to_adapter(hw);
	struct pci_dev *pdev = lsxinic->pdev;
	uint16_t timeout = 0;

	hw->config_cb.callback = NULL;
	hw->config_cb.private = NULL;

	lsxvdpa_hw_set_status(hw, VIRTIO_CONFIG_STATUS_SEND_RESET);

	/* wait until the reset is completed.
	 * Pay attention that before reset is completed, we cannot
	 * access the device, for example, writing the bar.
	 */
	LSX_INFO(pdev, "wait status=0x%x to be 0\n", lsxvdpa_hw_get_status(hw));
	do {
		msleep(VIRTIO_READ_STATUS_DELAY);
	} while ((lsxvdpa_hw_get_status(hw) != 0)
			&& (timeout++ < VIRTIO_READ_STATUS_TIMEOUT));

	LSX_INFO(pdev, "device reset ok!\n");
}

static void lsxvdpa_hw_add_status(struct lsxvdpa_hw *hw, u8 status)
{
	if (status != 0)
		status |= lsxvdpa_hw_get_status(hw);

	lsxvdpa_hw_set_status(hw, status);
	lsxvdpa_hw_get_status(hw);
}

u64 lsxvdpa_hw_get_features(struct lsxvdpa_hw *hw)
{
	struct lsxvio_common_cfg __iomem *cfg = hw->common_cfg;
	u32 features_lo, features_hi;

	features_lo = readl(&cfg->device_feature[0]);
	features_hi = readl(&cfg->device_feature[1]);

	return ((u64)features_hi << 32) | features_lo;
}

void lsxvdpa_hw_read_net_config(struct lsxvdpa_hw *hw, u64 offset,
			   void *dst, int length)
{
	u8 old_gen, new_gen, *p;
	int i;

	WARN_ON(offset + length > sizeof(struct virtio_net_config));
	do {
		old_gen = readb(&hw->common_cfg->config_generation);
		p = dst;
		for (i = 0; i < length; i++)
			*p++ = readb(hw->device_cfg + offset + i);

		new_gen = readb(&hw->common_cfg->config_generation);
	} while (old_gen != new_gen);
}

void lsxvdpa_hw_write_net_config(struct lsxvdpa_hw *hw, u64 offset,
			    const void *src, int length)
{
	const u8 *p;
	int i;

	p = src;
	WARN_ON(offset + length > sizeof(struct virtio_net_config));
	for (i = 0; i < length; i++)
		writeb(*p++, hw->device_cfg + offset + i);
}

void lsxvdpa_hw_set_features(struct lsxvdpa_hw *hw, u64 features)
{
	struct lsxvio_common_cfg __iomem *cfg = hw->common_cfg;

	writel((u32)features, &cfg->driver_feature[0]);
	writel(features >> 32, &cfg->driver_feature[1]);
}

static int lsxvdpa_hw_config_features(struct lsxvdpa_hw *hw)
{
	struct lsxvdpa_adapter *lsx = hw_vf_to_adapter(hw);

	lsxvdpa_hw_set_features(hw, hw->req_features);
	lsxvdpa_hw_add_status(hw, VIRTIO_CONFIG_S_FEATURES_OK);

	if (!(lsxvdpa_hw_get_status(hw) & VIRTIO_CONFIG_S_FEATURES_OK)) {
		LSX_ERR(lsx->pdev, "Failed to set FEATURES_OK status\n");
		return -EIO;
	}

	return 0;
}

u16 lsxvdpa_hw_get_vq_state(struct lsxvdpa_hw *hw, u16 qid)
{
	return readw(&hw->shadow_vring[qid]->last_avail_idx);
}

int lsxvdpa_hw_set_vq_state(struct lsxvdpa_hw *hw, u16 qid, u16 num)
{
	hw->vring[qid].last_avail_idx = num;
	writew(num, &hw->shadow_vring[qid]->last_avail_idx);

	return 0;
}

static int lsxvdpa_hw_hw_enable(struct lsxvdpa_hw *hw)
{
	struct lsxvio_common_cfg __iomem *cfg = hw->common_cfg;
	struct lsxvdpa_adapter *lsxinic = hw_vf_to_adapter(hw);
	struct pci_dev *pdev = lsxinic->pdev;
	struct lsxvio_queue_cfg *queue;
	struct vring_info *vring;
	u16 notify_off;
	u32 i, num = hw->nr_vring;

	writew(LSXINIC_MSI_CONFIG_OFF, &cfg->msix_config);

	if (readw(&cfg->msix_config) == VIRTIO_MSI_NO_VECTOR) {
		LSX_ERR(pdev, "No msix vector for device config\n");
		return -EINVAL;
	}

	for (i = 0; i < num; i++) {
		vring = &(hw->vring[i]);
		if (!vring->ready)
			break;

		queue = lsxvdpa_hw_queue_cfg(cfg, i);
		notify_off = readw(&queue->queue_notify_off);
		vring->notify_addr = hw->notify_base
			+ notify_off * hw->notify_off_multiplier;
		LSX_INFO(pdev, "id:%d notfiy addr: %px\n",
			i, vring->notify_addr);
		iowrite64_twopart(vring->desc, &queue->queue_desc_lo,
			&queue->queue_desc_hi);
		iowrite64_twopart(vring->avail, &queue->queue_avail_lo,
			&queue->queue_avail_hi);
		iowrite64_twopart(vring->used, &queue->queue_used_lo,
			&queue->queue_used_hi);
		writew(vring->size, &queue->queue_size);
		writew(i + LSXINIC_MSI_QUEUE_OFF,
			&queue->queue_msix_vector);

		if (readw(&queue->queue_msix_vector) ==
		    VIRTIO_MSI_NO_VECTOR) {
			LSX_ERR(pdev, "No msix vector for queue %u\n", i);
			return -EINVAL;
		}

		lsxvdpa_hw_set_vq_state(hw, i, hw->vring[i].last_avail_idx);
		writew(1, &queue->queue_enable);
	}

	lsxvdpa_hw_dump_common_cfgs(hw, pdev);

	return 0;
}

static void lsxvdpa_hw_hw_disable(struct lsxvdpa_hw *hw)
{
	struct lsxvio_common_cfg __iomem *cfg;
	struct lsxvio_queue_cfg *queue;
	u32 i;

	cfg = hw->common_cfg;
	writew(VIRTIO_MSI_NO_VECTOR, &cfg->msix_config);

	for (i = 0; i < hw->nr_vring; i++) {
		queue = lsxvdpa_hw_queue_cfg(cfg, i);
		writew(VIRTIO_MSI_NO_VECTOR, &queue->queue_msix_vector);
	}

	readw(&queue->queue_msix_vector);
}

int lsxvdpa_hw_start_hw(struct lsxvdpa_hw *hw)
{
	lsxvdpa_hw_reset(hw);
	lsxvdpa_hw_add_status(hw, VIRTIO_CONFIG_S_ACKNOWLEDGE);
	lsxvdpa_hw_add_status(hw, VIRTIO_CONFIG_S_DRIVER);

	if (lsxvdpa_hw_config_features(hw) < 0)
		return -EINVAL;

	if (lsxvdpa_hw_hw_enable(hw) < 0)
		return -EINVAL;

	lsxvdpa_hw_add_status(hw, VIRTIO_CONFIG_S_DRIVER_OK);

	return 0;
}

void lsxvdpa_hw_stop_hw(struct lsxvdpa_hw *hw)
{
	lsxvdpa_hw_hw_disable(hw);
	lsxvdpa_hw_reset(hw);
}

void lsxvdpa_hw_notify_queue(struct lsxvdpa_hw *hw, u16 qid)
{
	struct vring_info *vring = &hw->vring[qid];
	struct vring_avail *shadow_avail_ring;
	struct vring_avail *local_avail_ring =
			(struct vring_avail *)__va(vring->avail);

	shadow_avail_ring =
		(struct vring_avail *)
		(hw->ring_base + qid * (sizeof(struct vring_avail) +
		(vring->size * sizeof(uint16_t))));
	writew(local_avail_ring->idx, &shadow_avail_ring->idx);
	if (lsxvdpa_hw_get_status(hw) & VIRTIO_CONFIG_S_DRIVER_OK)
		writew(qid, hw->vring[qid].notify_addr);
}
