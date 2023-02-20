// SPDX-License-Identifier: BSD-3-Clause
/* Copyright 2020-2023 NXP  */

#ifndef _LSXINIC_EP_VIO_H_
#define _LSXINIC_EP_VIO_H_

#include <rte_lsx_pciep_bus.h>

#include "lsxinic_vio_common.h"

/* Features desired/implemented by this driver. */
#define LSX_VIRTIO_NET_FEATURES (1ULL << VIRTIO_F_VERSION_1)

int
lsxvio_virtio_check_driver_feature(struct lsxvio_common_cfg *common);
int
lsxvio_virtio_init(uint64_t virt, uint16_t id, uint64_t lsx_feature);
int
lsxvio_virtio_config_fromrc(struct rte_lsx_pciep_device *dev);
void
lsxvio_virtio_reset_dev(struct rte_eth_dev *dev);
void
lsxvio_virtio_blk_init(uint64_t virt);
void
lsxvio_virtio_get_blk_id(uint16_t *device_id, uint16_t *class_id);
uint64_t
lsxvio_virtio_get_blk_feature(void);

#endif
