// SPDX-License-Identifier: BSD-3-Clause
/* Copyright 2020-2021 NXP  */

#ifndef _LSX_VIRTIO_H_
#define _LSX_VIRTIO_H_

#include <linux/virtio_net.h>
#include <linux/virtio_blk.h>

#include <rte_lsx_pciep_bus.h>

#include "lsxinic_vio_common.h"

/* Features desired/implemented by this driver. */
#define LSX_VIRTIO_BLK_FEATURES_TEST		(VIRTIO_BLK_F_FLUSH)

/* Features desired/implemented by this driver. */
#define LSX_VIRTIO_NET_FEATURES (1ULL << VIRTIO_F_VERSION_1)

#define VLAN_ETH_HLEN				18

int lsxvio_virtio_check_driver_feature(struct lsxvio_common_cfg *common);
void lsxvio_virtio_init(uint64_t virt, uint16_t id);
void lsxvio_virtio_config_fromrc(struct rte_lsx_pciep_device *dev);
void lsxvio_virtio_reset_dev(struct rte_eth_dev *dev);
#endif
