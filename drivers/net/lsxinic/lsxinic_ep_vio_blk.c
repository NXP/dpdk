// SPDX-License-Identifier: BSD-3-Clause
/* Copyright 2020-2022 NXP  */

#include <stdio.h>
#include <rte_malloc.h>

#include <rte_interrupts.h>
#include <rte_lsx_pciep_bus.h>

#include <linux/virtio_blk.h>

#include "lsxinic_ep_vio.h"

#define LSX_VIRTIO_BLK_FEATURES (VIRTIO_BLK_F_FLUSH)

uint64_t
lsxvio_virtio_get_blk_feature(void)
{
	return LSX_VIRTIO_BLK_FEATURES;
}

void
lsxvio_virtio_get_blk_id(uint16_t *device_id, uint16_t *class_id)
{
	if (device_id)
		*device_id = VIRTIO_ID_DEVICE_ID_BASE + VIRTIO_ID_BLOCK;
	if (class_id)
		*class_id = PCI_CLASS_STORAGE_SCSI;
}

void
lsxvio_virtio_blk_init(uint64_t virt)
{
	struct lsxvio_common_cfg *common;
	struct virtio_blk_config *blk;

	common = (struct lsxvio_common_cfg *)(virt + LSXVIO_COMMON_OFFSET);
	blk = (struct virtio_blk_config *)(virt + LSXVIO_DEVICE_OFFSET);
	/* TBD */
	blk->capacity = 0x10000000;
	if (common->device_feature & (1ull << VIRTIO_BLK_F_MQ))
		blk->num_queues = LSXVIO_MAX_QUEUE_PAIRS;
}
