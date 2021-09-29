// SPDX-License-Identifier: BSD-3-Clause
/* Copyright 2020-2021 NXP  */

#ifndef _LSX_VIRTIO_COMMON_H_
#define _LSX_VIRTIO_COMMON_H_

#include "lsxinic_common.h"

/* VirtIO PCI vendor/device ID. */
#define VIRTIO_PCI_VENDORID			0x1AF4
#define VIRTIO_PCI_LEGACY_NET			0x1000
#define VIRTIO_PCI_MODERN_NET			0x1041
#define VIRTIO_PCI_BLK				0x1042
#define VIRTIO_PCI_FSL				0x8d80

#define VIRTIO_ID_DEVICE_ID_BASE 0x1040

#ifndef VIRTIO_ID_NETWORK
#define VIRTIO_ID_NETWORK  0x01
#endif
#ifndef VIRTIO_ID_BLOCK
#define VIRTIO_ID_BLOCK    0x02
#endif

#ifndef VIRTIO_PCI_MODERN_DEVICEID_NET
#define VIRTIO_PCI_MODERN_DEVICEID_NET \
	(VIRTIO_ID_DEVICE_ID_BASE + VIRTIO_ID_NETWORK)
#endif

#ifndef PCI_CLASS_NETWORK_ETHERNET
#define PCI_CLASS_NETWORK_ETHERNET	0x0200
#endif

#ifndef PCI_CLASS_STORAGE_SCSI
#define PCI_CLASS_STORAGE_SCSI 0x0100
#endif

/* Status byte for guest to report progress. */
#define VIRTIO_CONFIG_STATUS_RESET		0x00
#define VIRTIO_CONFIG_STATUS_ACK		0x01
#define VIRTIO_CONFIG_STATUS_DRIVER		0x02
#define VIRTIO_CONFIG_STATUS_DRIVER_OK		0x04
#define VIRTIO_CONFIG_STATUS_FEATURES_OK	0x08
#define VIRTIO_CONFIG_STATUS_SEND_RESET		0x20
#define VIRTIO_CONFIG_STATUS_NEEDS_RESET	0x40
#define VIRTIO_CONFIG_STATUS_FAILED		0x80

#ifndef VIRTIO_MSI_NO_VECTOR
#define	VIRTIO_MSI_NO_VECTOR			0xffff
#endif
#define LSXVIO_BAR_NUM				(2)

#define	VIRTIO_READ_STATUS_DELAY		1
#define LSXVIO_COMMON_OFFSET			0x0
#define LSXVIO_NOTIFY_OFFSET			0x1000
#define LSXVIO_ISR_OFFSET				0x1200
#define LSXVIO_DEVICE_OFFSET			0x1400
#define LSXVIO_NOTIFY_OFF_MULTI			0x4
#define LSXVIO_MAX_QUEUE_PAIRS			1
#define LSXVIO_MAX_RING_DESC			512

/* This common configuration definition is a little different from
 * the common data stuctures defined in virtio spec because the hw
 * does not support queue_select attribute, so a sereal of queue
 * structure(lsxvio_queue_cfg) are defined after lsxvio_common_cfg.
 */
struct lsxvio_common_cfg {
	/* About the whole device. */
	uint32_t device_feature[2];	/* read-only */
	uint32_t driver_feature[2];	/* read-write */
	uint16_t msix_config;		/* read-write */
	uint16_t num_queues;		/* read-only */
	uint8_t device_status;		/* read-write */
	uint8_t config_generation;	/* read-only */
	uint16_t queue_used_num;	/* read-write */
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
} __attribute__((__packed__));

#define	BASE_TO_COMMON(base) ((void *)((base) + LSXVIO_COMMON_OFFSET))
#define	BASE_TO_QUEUE(base, i) \
	((void *)((base) + LSXVIO_COMMON_OFFSET + \
	sizeof(struct lsxvio_common_cfg) + \
	(i) * sizeof(struct lsxvio_queue_cfg)))
#define	BASE_TO_NOTIFY(base) (((base) + LSXVIO_NOTIFY_OFFSET))
#define	BASE_TO_ISR(base) ((void *)((base) + LSXVIO_ISR_OFFSET))
#define	BASE_TO_DEVICE(base) ((void *)((base) + LSXVIO_DEVICE_OFFSET))

#define LSXVIO_DEVICE_MAX_SIZE 0x1000
#define LSXVIO_CONFIG_BAR_MAX_SIZE \
	(LSXVIO_DEVICE_OFFSET + LSXVIO_DEVICE_MAX_SIZE)
#define LSXVIO_RING_BAR_MAX_SIZE 0x4000

#define LSXVIO_CONFIG_BAR_IDX 0
#define LSXVIO_RING_BAR_IDX 2
#endif /* _LSX_VIRTIO_COMMON_H_ */
