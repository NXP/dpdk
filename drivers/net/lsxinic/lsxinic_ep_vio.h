// SPDX-License-Identifier: BSD-3-Clause
/* Copyright 2020-2022 NXP  */

#ifndef _LSXINIC_EP_VIRTIO_H_
#define _LSXINIC_EP_VIRTIO_H_

#include <rte_lsx_pciep_bus.h>

#include "lsxinic_vio_common.h"

/* Features desired/implemented by this driver. */
#define LSX_VIRTIO_NET_FEATURES (1ULL << VIRTIO_F_VERSION_1)

int
lsxvio_vio_check_drv_feature(struct lsxvio_common_cfg *common);
void
lsxvio_vio_init(uint64_t virt, uint16_t id, uint64_t lsx_feature);
int
lsxvio_vio_config_fromrc(struct rte_lsx_pciep_device *dev);
void
lsxvio_vio_reset_dev(struct rte_eth_dev *dev);
void
lsxvio_vio_blk_init(uint64_t virt);
void
lsxvio_vio_get_blk_id(uint16_t *device_id, uint16_t *class_id);
uint64_t
lsxvio_vio_get_blk_feature(void);

#endif /*_LSXINIC_EP_VIRTIO_H_*/
