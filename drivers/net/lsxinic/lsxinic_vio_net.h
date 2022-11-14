// SPDX-License-Identifier: BSD-3-Clause
/* Copyright 2020-2022 NXP  */

#ifndef _LSX_NET_H_
#define _LSX_NET_H_

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
#include <compat.h>

#include "lsxinic_common_reg.h"
#include "lsxinic_vio_common.h"
#include "lsxinic_vio.h"

#ifndef __packed
#define __packed	__rte_packed
#endif

#define INIC_VERSION (001)

struct lsxvio_hw {
	void *back;
	uint16_t device_id;
	uint16_t vendor_id;
	uint16_t subsystem_device_id;
	uint16_t subsystem_vendor_id;
	uint8_t revision_id;
	uint8_t adapter_stopped;
	uint8_t force_full_reset;
	uint8_t allow_unsupported_sfp;
} __packed;

TAILQ_HEAD(lsxvio_tx_queue_list, lsxvio_queue);

/* Structure to store private data for each driver instance (for each port). */
struct lsxvio_adapter {
	enum lsinic_dev_type dev_type;
	uint64_t cfg_base;
	uint64_t ring_base;
	uint64_t ring_phy_base;
	uint16_t device_id;
	uint16_t vendor_id;
	uint16_t subsystem_device_id;
	uint16_t subsystem_vendor_id;
	uint8_t revision_id;
	uint8_t adapter_stopped;
	uint8_t force_full_reset;
	uint8_t allow_unsupported_sfp;
	uint8_t status;
	uint16_t vtnet_hdr_size;

	struct rte_pci_device *pci_dev;
	struct lsxvio_hw           hw;
	uint16_t num_queues;
	uint16_t num_descs;
	uint32_t rbp_enable;
	int qdma_dev_id;
	uint32_t msix_mask[32];

	char *ep_ring_virt_base;  /* EP ring base */
	dma_addr_t ep_ring_phy_base;
	uint64_t ep_ring_win_size;

	uint8_t *rc_ring_virt_base;  /* RC ring shadow base */
	dma_addr_t rc_ring_phy_base;
	uint64_t rc_ring_win_size;

	dma_addr_t rx_pcidma_dbg;
	dma_addr_t tx_pcidma_dbg;

	int pcie_idx;
	int pf_idx;
	int vf_idx;
	int is_vf;
	uint64_t ob_base;
	uint8_t *ob_virt_base;
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
} __packed;

#define lsxvio_DEV_PRIVATE_TO_ADAPTER(data)\
	((struct lsxvio_adapter *)adapter)
#define lsxvio_DEV_PRIVATE_TO_HW(adapter)\
	(&((struct lsxvio_adapter *)adapter)->hw)

#define lsxvio_DEV_PRIVATE_TO_INTR(adapter) \
	(&((struct lsxvio_adapter *)adapter)->intr)
#endif /* _LSX_NET_H_ */
