/* SPDX-License-Identifier: GPL-2.0 */
/*
 * NXP LSX NIC driver for virtio dataplane offloading
 *
 * Copyright 2020-2021 NXP
 *
 * Code was mostly borrowed from linux/drivers/vdpa/ifcvf/ifcvf_base.h
 * See linux/drivers/vdpa/ifcvf/ifcvf_base.h for additional Copyrights.
 */

#ifndef _LSXINIC_H_
#define _LSXINIC_H_

#include <linux/pci.h>
#include <linux/pci_regs.h>
#include <linux/vdpa.h>
#include <uapi/linux/virtio_net.h>
#include <uapi/linux/virtio_config.h>
#include <uapi/linux/virtio_pci.h>
#include <uapi/linux/virtio_ring.h>

#include "lsxinic_vio_common.h"

#define LSXINIC_SUBSYS_VENDOR_ID	0x1957
#define LSXINIC_SUBSYS_DEVICE_ID	0x8d80

#define LSXINIC_SUPPORTED_FEATURES \
		((1ULL << VIRTIO_NET_F_MAC)			| \
		 (1ULL << VIRTIO_F_ANY_LAYOUT)			| \
		 (1ULL << VIRTIO_F_VERSION_1)			| \
		 (1ULL << VIRTIO_NET_F_STATUS)			| \
		 (1ULL << VIRTIO_F_ORDER_PLATFORM)		| \
		 (1ULL << VIRTIO_F_ACCESS_PLATFORM)		| \
		 (1ULL << VIRTIO_NET_F_MRG_RXBUF))

#define LSXINIC_QUEUE_ALIGNMENT	PAGE_SIZE
#define LSXINIC_QUEUE_MAX		512
#define LSXINIC_MSI_CONFIG_OFF	0
#define LSXINIC_MSI_QUEUE_OFF	1

#define LSXINIC_LM_CFG_SIZE		0x40
#define LSXINIC_LM_RING_STATE_OFFSET	0x20
#define LSXINIC_LM_BAR			4

#define LSX_ERR(pdev, fmt, ...)	dev_err(&pdev->dev, fmt, ##__VA_ARGS__)
#define LSX_DBG(pdev, fmt, ...)	dev_dbg(&pdev->dev, fmt, ##__VA_ARGS__)
#define LSX_INFO(pdev, fmt, ...)	dev_info(&pdev->dev, fmt, ##__VA_ARGS__)

#define lsxvdpa_private_to_vf(adapter) \
	(&((struct lsxvdpa_adapter *)adapter)->vf)

#define LSXINIC_MIN_INTR (1)
#define LSXINIC_MAX_INTR (LSXVIO_MAX_QUEUE_PAIRS * 2 + 1)

#define VIRTIO_READ_STATUS_TIMEOUT   100

struct vring_info {
	u64 desc;
	u64 avail;
	u64 used;
	u16 size;
	u16 last_avail_idx;
	bool ready;
	void __iomem *notify_addr;
	u32 irq;
	struct vdpa_callback cb;
	char msix_name[256];
};

struct shadow_vring {
	u16 last_avail_idx;
	u16 res1;
	struct vring_desc desc[LSXVIO_MAX_RING_DESC];
	struct vring_avail avail[LSXVIO_MAX_RING_DESC];
};

struct lsxvdpa_hw {
	u8 __iomem *isr;
	/* Live migration */
	u8 __iomem *ring_base;
	u16 nr_vring;
	/* Notificaiton bar address */
	void __iomem *notify_base;
	u32 notify_off_multiplier;
	u64 req_features;
	struct lsxvio_common_cfg __iomem *common_cfg;
	void __iomem *device_cfg;
	struct vring_info vring[LSXVIO_MAX_QUEUE_PAIRS * 2];
	struct shadow_vring *shadow_vring[LSXVIO_MAX_QUEUE_PAIRS * 2];
	void __iomem * const *bar_addr;
	char config_msix_name[256];
	struct vdpa_callback config_cb;
	unsigned int config_irq;
};

struct lsxvdpa_adapter {
	struct vdpa_device vdpa;
	struct pci_dev *pdev;
	struct lsxvdpa_hw vf;
};

int lsxvdpa_hw_init_hw(struct lsxvdpa_hw *hw, struct pci_dev *dev);
int lsxvdpa_hw_start_hw(struct lsxvdpa_hw *hw);
void lsxvdpa_hw_stop_hw(struct lsxvdpa_hw *hw);
void lsxvdpa_hw_notify_queue(struct lsxvdpa_hw *hw, u16 qid);
void
lsxvdpa_hw_read_net_config(struct lsxvdpa_hw *hw,
	u64 offset, void *dst, int length);
void
lsxvdpa_hw_write_net_config(struct lsxvdpa_hw *hw,
	u64 offset, const void *src, int length);
u8 lsxvdpa_hw_get_status(struct lsxvdpa_hw *hw);
void lsxvdpa_hw_set_status(struct lsxvdpa_hw *hw, u8 status);
void lsxvdpa_hw_reset(struct lsxvdpa_hw *hw);
u64 lsxvdpa_hw_get_features(struct lsxvdpa_hw *hw);
void lsxvdpa_hw_set_features(struct lsxvdpa_hw *hw, u64 features);
u16 lsxvdpa_hw_get_vq_state(struct lsxvdpa_hw *hw, u16 qid);
int lsxvdpa_hw_set_vq_state(struct lsxvdpa_hw *hw, u16 qid, u16 num);
#endif /* _LSXINIC_H_ */
