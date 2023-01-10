// SPDX-License-Identifier: BSD-3-Clause
/* Copyright 2020-2023 NXP  */

#ifndef _LSXINIC_EP_VIO_NET_H_
#define _LSXINIC_EP_VIO_NET_H_

#include <rte_common.h>
#include <rte_debug.h>
#include <rte_cycles.h>
#include <rte_log.h>
#include <rte_byteorder.h>
#include <rte_io.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mbuf_core.h>
#include <rte_lsx_pciep_bus.h>
#include <rte_dmadev.h>

#include "lsxinic_common_reg.h"
#include "lsxinic_vio_common.h"
#include "lsxinic_ep_vio.h"

#ifndef __packed
#define __packed	__rte_packed
#endif

#ifdef RTE_PCIEP_MULTI_VER_PMD_DRV
#define LSINIC_EP_VIO_DRV_VER_NUM 2111
#define LSINIC_EP_VIO_DRV_VER RTE_STR(LSINIC_EP_DRV_VER_NUM)

#define LSINIC_EP_VIO_DRV_SUFFIX_NAME \
	"_"LSINIC_EP_VIO_DRV_VER"_driver"
#define LSX_PCIE_EP_VIO_PMD \
	net_lsx_vio_##LSINIC_EP_VIO_DRV_VER_NUM
#else
#define LSINIC_EP_VIO_DRV_VER_NUM \
	(RTE_VER_YEAR * 100 | RTE_VER_MONTH)
#define LSINIC_EP_VIO_DRV_SUFFIX_NAME "_driver"
#define LSX_PCIE_EP_VIO_PMD net_lsx_vio
#endif

TAILQ_HEAD(lsxvio_tx_queue_list, lsxvio_queue);

/* Structure to store private data for each driver instance (for each port). */
struct lsxvio_adapter {
	enum lsinic_dev_type dev_type;
	void *cfg_base;
	void *ring_base;
	uint64_t ring_phy_base;
	uint16_t device_id;
	uint16_t vendor_id;
	uint16_t subsystem_device_id;
	uint16_t subsystem_vendor_id;
	uint8_t status;
	uint16_t vtnet_hdr_size;

	uint8_t rawdev_dma;
	int txq_dma_id;
	int rxq_dma_id;
	int txq_dma_silent;
	int rxq_dma_silent;
	uint16_t txq_dma_vchan_used;
	uint16_t rxq_dma_vchan_used;
	int txq_dma_started;
	int rxq_dma_started;
	rte_spinlock_t txq_dma_start_lock;
	rte_spinlock_t rxq_dma_start_lock;
	uint16_t num_queues;
	uint16_t num_descs;
	uint32_t rbp_enable;
	uint32_t msix_mask[32];

	char *ep_ring_virt_base;  /* EP ring base */
	uint64_t ep_ring_phy_base;
	uint64_t ep_ring_win_size;

	uint8_t *rc_ring_virt_base;  /* RC ring shadow base */
	uint64_t rc_ring_phy_base;
	uint64_t rc_ring_win_size;

	uint64_t rx_pcidma_dbg;
	uint64_t tx_pcidma_dbg;

	int pcie_idx;
	int pf_idx;
	int vf_idx;
	int is_vf;
	struct rte_lsx_pciep_device *lsx_dev;
	uint8_t mac_addr[RTE_ETHER_ADDR_LEN];
	uint8_t port_mac_addr[RTE_ETHER_ADDR_LEN];
	uint16_t msix_config;
	uint32_t msix_cfg_cmd;
	void *msix_cfg_addr;

	struct lsxvio_queue *vqs[LSXVIO_MAX_QUEUES];
	struct rte_dpaa2_device *merge_dev;
	struct rte_dpaa2_device *split_dev;
	uint8_t txq_list_initialized[RTE_MAX_LCORE];
	uint8_t txq_num_in_list[RTE_MAX_LCORE];
	struct lsxvio_tx_queue_list txq_list[RTE_MAX_LCORE];

	uint32_t merge_threshold;
};

#define lsxvio_DEV_PRIVATE_TO_ADAPTER(data)\
	((struct lsxvio_adapter *)adapter)
#define lsxvio_DEV_PRIVATE_TO_HW(adapter)\
	(&((struct lsxvio_adapter *)adapter)->hw)

#define lsxvio_DEV_PRIVATE_TO_INTR(adapter) \
	(&((struct lsxvio_adapter *)adapter)->intr)
#endif /* _LSXINIC_EP_VIO_NET_H_ */
