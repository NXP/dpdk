/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2023 NXP
 */

#ifndef _LSXINIC_EP_ETHDEV_H_
#define _LSXINIC_EP_ETHDEV_H_

#include <rte_common.h>
#include <rte_debug.h>
#include <rte_cycles.h>
#include <rte_log.h>
#include <rte_byteorder.h>
#include <rte_io.h>
#include <rte_dmadev.h>

#include <rte_lsx_pciep_bus.h>
#include <compat.h>

#include "lsxinic_common.h"
#include "lsxinic_common_reg.h"

#ifdef RTE_PCIEP_MULTI_VER_PMD_DRV
#define LSINIC_EP_DRV_VER_NUM 2111
#define LSINIC_EP_DRV_VER RTE_STR(LSINIC_EP_DRV_VER_NUM)

#define LSINIC_EP_DRV_SUFFIX_NAME \
	"_"LSINIC_EP_DRV_VER"_driver"
#define LSX_PCIE_EP_PMD \
	net_lsinic_##LSINIC_EP_DRV_VER_NUM
#else
#define LSINIC_EP_DRV_VER_NUM \
	(RTE_VER_YEAR * 100 | RTE_VER_MONTH)
#define LSINIC_EP_DRV_SUFFIX_NAME "_driver"
#define LSX_PCIE_EP_PMD net_lsinic
#endif

static inline uint16_t lsinic_read_reg16(void *addr)
{
	return rte_be_to_cpu_16(rte_read16(addr));
}

static inline uint32_t lsinic_read_reg32(void *addr)
{
	return rte_be_to_cpu_32(rte_read32(addr));
}

static inline uint64_t lsinic_read_reg64(void *addr)
{
	return rte_be_to_cpu_64(rte_read64(addr));
}

static inline void lsinic_write_reg16(void *addr, uint16_t val)
{
	rte_write16((rte_cpu_to_be_16(val)), addr);
}

static inline void lsinic_write_reg32(void *addr, uint32_t val)
{
	rte_write32((rte_cpu_to_be_32(val)), addr);
}

static inline void lsinic_write_reg64(void *addr, uint64_t val)
{
	rte_write64((rte_cpu_to_be_64(val)), addr);
}

/* Structure to store private data for each driver instance (for each port).
 */
#define LSINIC_EP_CAP_TXQ_DMA_NO_RSP 0x00000001
#define LSINIC_EP_CAP_TXQ_SG_DMA 0x00000002
#define LSINIC_EP_CAP_RXQ_SG_DMA 0x00000004
#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
#define LSINIC_EP_CAP_HW_MERGE_PKTS 0x00000008
#define LSINIC_EP_CAP_HW_SPLIT_PKTS 0x00000010
#define LSINIC_EP_CAP_MBUF_CLONE_SPLIT_PKTS 0x00000020
#define LSINIC_EP_CAP_SW_MERGE_PKTS 0x00000040
#define LSINIC_EP_CAP_SW_SPLIT_PKTS 0x00000080
#define LSINIC_EP_CAP_HW_DIRECT_EGRESS 0x00000100
#define LSINIC_EP_CAP_RCV_MERGE_RECYCLE_RX 0x00000200
#define LSINIC_EP_CAP_RCV_SPLIT_RECYCLE_RX 0x00000400
#endif
#define LSINIC_EP_CAP_TXQ_BD_DMA_UPDATE 0x00000800
#define LSINIC_EP_CAP_RXQ_BD_DMA_UPDATE_DBG 0x00001000
#define LSINIC_EP_CAP_TXQ_ADDR_DMA_READ_DBG 0x00002000

struct lsinic_adapter {
	enum lsinic_dev_type dev_type;
	uint8_t *hw_addr;
	uint8_t *bd_desc_base;
	uint16_t device_id;
	uint16_t vendor_id;
	uint16_t subsystem_device_id;
	uint16_t subsystem_vendor_id;

	uint16_t max_qpairs;
	uint8_t rbp_enable;
	uint8_t rawdev_dma;
	int txq_dma_id;
	int rxq_dma_id;
#ifdef RTE_LSINIC_PCIE_RAW_TEST_ENABLE
	int txq_raw_dma_id;
	int rxq_raw_dma_id;
#endif
	int txq_dma_silent;
	int rxq_dma_silent;
	uint16_t txq_dma_vchan_used;
	uint16_t rxq_dma_vchan_used;
	uint32_t tx_ring_bd_count;
	uint32_t rx_ring_bd_count;
	int txq_dma_started;
	int rxq_dma_started;
	rte_spinlock_t txq_dma_start_lock;
	rte_spinlock_t rxq_dma_start_lock;
	uint32_t num_tx_queues;
	uint32_t num_rx_queues;
	uint32_t rc_state;
	uint32_t ep_state;

	uint8_t *ep_ring_virt_base;  /* EP ring base */
	rte_iova_t ep_ring_phy_base;
	uint64_t ep_ring_win_size;

	uint8_t *rc_ring_virt_base;  /* RC ring shadow base */
	rte_iova_t rc_ring_phy_base;
	dma_addr_t rc_ring_bus_base;
	uint64_t rc_ring_size;

	rte_iova_t rx_pcidma_dbg;
	rte_iova_t tx_pcidma_dbg;

	int pcie_idx;
	int pf_idx;
	int vf_idx;
	int is_vf;
	struct rte_lsx_pciep_device *lsinic_dev;
	uint8_t mac_addr[RTE_ETHER_ADDR_LEN];

	struct lsinic_queue *txqs;
	struct lsinic_queue *rxqs;
#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
	struct rte_dpaa2_device *merge_dev;
	struct rte_dpaa2_device *split_dev;
	struct rte_dpaa2_device *split_dst_dev;
	rte_spinlock_t merge_dev_cfg_lock;
	rte_spinlock_t split_dev_cfg_lock;
	int merge_dev_cfg_done;
	int split_dev_cfg_done;
	int rx_mbuf_clone;
	uint32_t merge_threshold;
#endif
	uint32_t cap;
	rte_spinlock_t cap_lock;
	uint32_t ep_cap;
	uint8_t *complete_src;

	uint32_t data_room_size;
	uint64_t rc_dma_base;
	uint32_t rc_dma_elt_size;

	uint64_t cycs_per_us;
};

int
lsinic_reset_config_fromrc(struct lsinic_adapter *adapter);

int
lsinic_remove_config_fromrc(struct lsinic_adapter *adapter);

#ifdef RTE_LSINIC_PKT_MERGE_ACROSS_PCIE
int
lsinic_split_dev_flow_create(struct lsinic_adapter *adapter);
#endif

#endif /* _LSXINIC_EP_ETHDEV_H_ */
