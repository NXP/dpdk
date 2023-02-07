// SPDX-License-Identifier: BSD-3-Clause
/* Copyright 2020-2023 NXP  */

#ifndef _LSXINIC_VIO_COMMON_H_
#define _LSXINIC_VIO_COMMON_H_

#include "lsxinic_common.h"

/* VirtIO PCI vendor/device ID. */
#define VIRTIO_PCI_VENDORID			0x1AF4
#define VIRTIO_PCI_LEGACY_NET			0x1000
#define VIRTIO_PCI_MODERN_NET			0x1041
#define VIRTIO_PCI_BLK				0x1042
#define VIRTIO_PCI_FSL				0x8d80

#define VIRTIO_ID_DEVICE_ID_BASE 0x1040

#ifndef PCI_CLASS_NETWORK_ETHERNET
#define PCI_CLASS_NETWORK_ETHERNET	0x0200
#endif

#ifndef PCI_CLASS_STORAGE_SCSI
#define PCI_CLASS_STORAGE_SCSI 0x0100
#endif

/* Status byte for guest to report progress. */
#define VIRTIO_CONFIG_STATUS_START	0x10
#define VIRTIO_CONFIG_STATUS_SEND_RESET		0x20
#define VIRTIO_CONFIG_STATUS_NEEDS_RESET	0x40

#define LSXVIO_BAR_NUM				(2)
#define LSXVIO_REG_BAR_IDX 0


#define	VIRTIO_READ_STATUS_DELAY		1
#define LSXVIO_COMMON_OFFSET			0x0
#define LSXVIO_NOTIFY_OFFSET			0x1000
#define LSXVIO_ISR_OFFSET				0x1200
#define LSXVIO_DEVICE_OFFSET			0x1400
#define LSXVIO_NOTIFY_OFF_MULTI			0x4
#define LSXVIO_MAX_QUEUE_PAIRS			LSINIC_RING_MAX_COUNT
#define LSXVIO_MAX_RING_DESC			512

#define LSXVIO_MAX_QUEUES (LSXVIO_MAX_QUEUE_PAIRS * 2)

#define LSX_VIO_RC2EP_DMA_NORSP_POS 0
#define LSX_VIO_RC2EP_DMA_NORSP \
	(1ULL << LSX_VIO_RC2EP_DMA_NORSP_POS)

#define LSX_VIO_RC2EP_IN_ORDER_POS 1
#define LSX_VIO_RC2EP_IN_ORDER \
	(1ULL << LSX_VIO_RC2EP_IN_ORDER_POS)

#define LSX_VIO_EP2RC_PACKED_POS 2
#define LSX_VIO_EP2RC_PACKED \
	(1ULL << LSX_VIO_EP2RC_PACKED_POS)

#define LSX_VIO_EP2RC_DMA_NORSP_POS 3
#define LSX_VIO_EP2RC_DMA_NORSP \
	(1ULL << LSX_VIO_EP2RC_DMA_NORSP_POS)

#define LSX_VIO_RC2EP_DMA_BD_NOTIFY_POS 4
#define LSX_VIO_RC2EP_DMA_BD_NOTIFY \
	(1ULL << LSX_VIO_RC2EP_DMA_BD_NOTIFY_POS)

#define LSX_VIO_EP2RC_DMA_ADDR_NOTIFY_POS 5
#define LSX_VIO_EP2RC_DMA_ADDR_NOTIFY \
	(1ULL << LSX_VIO_EP2RC_DMA_ADDR_NOTIFY_POS)

#define LSX_VIO_EP2RC_DMA_BD_NOTIFY_POS 6
#define LSX_VIO_EP2RC_DMA_BD_NOTIFY \
	(1ULL << LSX_VIO_EP2RC_DMA_BD_NOTIFY_POS)

#define LSX_VIO_EP2RC_DMA_SG_ENABLE_POS 7
#define LSX_VIO_EP2RC_DMA_SG_ENABLE \
	(1ULL << LSX_VIO_EP2RC_DMA_SG_ENABLE_POS)

#define LSX_VIO_RC2EP_DMA_SG_ENABLE_POS 8
#define LSX_VIO_RC2EP_DMA_SG_ENABLE \
	(1ULL << LSX_VIO_RC2EP_DMA_SG_ENABLE_POS)


#define LSX_VIO_HW_START_CONFIG 1
/* This common configuration definition is a little different from
 * the common data stuctures defined in virtio spec because the hw
 * does not support queue_select attribute, so a sereal of queue
 * structure(lsxvio_queue_cfg) are defined after lsxvio_common_cfg.
 */
struct lsxvio_common_cfg {
	/* About the whole device. */
	uint64_t device_feature;	/* read-only */
	uint64_t driver_feature;	/* read-write */
	uint16_t msix_config;		/* read-write */
	uint16_t num_queues;		/* read-only */
	uint8_t device_status;		/* read-write */
	uint8_t config_generation;	/* read-only */
	uint16_t queue_used_num;	/* read-write */
	uint64_t lsx_feature;
} __attribute__((__packed__));

/* Fields in QUEUE_CFG: */
struct lsxvio_queue_cfg {
	uint16_t queue_size;		/* read-write, power of 2. */
	uint16_t queue_msix_vector;	/* read-write */
	uint16_t queue_enable;		/* read-write */
	uint16_t queue_notify_off;	/* read-only */
	uint32_t queue_desc_lo;		/* read-write */
	uint32_t queue_desc_hi;		/* read-write */
	uint32_t queue_avail_lo;	/* read-write */
	uint32_t queue_avail_hi;	/* read-write */
	uint32_t queue_used_lo;		/* read-write */
	uint32_t queue_used_hi;		/* read-write */
	uint64_t queue_rc_shadow_base;
	uint64_t queue_mem_base;
	uint32_t queue_mem_interval;
	uint32_t queue_rsv1;
} __attribute__((__packed__));

struct lsxvio_packed_notify {
	uint16_t last_avail_idx;
	uint16_t dma_idx;
	uint16_t dummy[6];
	/* Align with 16Bytes*/
	union {
		uint32_t addr_offset[0];
		uint64_t addr[0];
	};
} __attribute__((__packed__));

struct lsxvio_short_desc {
	uint32_t addr_offset;
	uint32_t len;
};

#define	BASE_TO_COMMON(base) \
	((void *)((uint8_t *)(base) + LSXVIO_COMMON_OFFSET))
#define	BASE_TO_QUEUE(base, i) \
	((void *)((uint8_t *)(base) + LSXVIO_COMMON_OFFSET + \
	sizeof(struct lsxvio_common_cfg) + \
	(i) * sizeof(struct lsxvio_queue_cfg)))
#define	BASE_TO_NOTIFY(base, q_off) \
	((void *)((uint8_t *)(base) + LSXVIO_NOTIFY_OFFSET + (q_off)))
#define	BASE_TO_ISR(base) \
	((void *)((uint8_t *)(base) + LSXVIO_ISR_OFFSET))
#define	BASE_TO_DEVICE(base) \
	((void *)((uint8_t *)(base) + LSXVIO_DEVICE_OFFSET))

#define LSXVIO_DEVICE_MAX_SIZE 0x1000
#define LSXVIO_CONFIG_BAR_MAX_SIZE \
	(LSXVIO_DEVICE_OFFSET + LSXVIO_DEVICE_MAX_SIZE)

#define LSXVIO_PER_RING_MEM_MAX_SIZE 0x8000

#define LSXVIO_RING_BAR_MAX_SIZE \
	(LSXVIO_PER_RING_MEM_MAX_SIZE * LSXVIO_MAX_QUEUES)

#define RING_BASE_OFF_VIRT(base, q) \
	((void *)((uint8_t *)(base) + \
	(q)->queue_notify_off * LSXVIO_PER_RING_MEM_MAX_SIZE))

#define RING_BASE_OFF_PHY(base, q) \
	((base) + (q)->queue_notify_off * LSXVIO_PER_RING_MEM_MAX_SIZE)

#define LSXVIO_CONFIG_BAR_IDX 0
#define LSXVIO_RING_BAR_IDX 2
#endif /* _LSXINIC_VIO_COMMON_H_ */
