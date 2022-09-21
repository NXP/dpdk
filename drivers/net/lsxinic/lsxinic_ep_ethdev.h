/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2022 NXP
 */

#ifndef _LSXINIC_EP_ETHDEV_H_
#define _LSXINIC_EP_ETHDEV_H_

#include <rte_common.h>
#include <rte_debug.h>
#include <rte_cycles.h>
#include <rte_log.h>
#include <rte_byteorder.h>
#include <rte_io.h>
#include <ethdev_driver.h>
#include <rte_dmadev.h>

#include <rte_lsx_pciep_bus.h>
#include <compat.h>

#include "lsxinic_common.h"
#include "lsxinic_common_reg.h"

#define INIC_VERSION (001)

#define LSINIC_MAX_NUM_TX_QUEUES LSINIC_RING_MAX_COUNT
#define LSINIC_MAX_NUM_RX_QUEUES LSINIC_RING_MAX_COUNT

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

struct lsinic_adapter {
	enum lsinic_dev_type dev_type;
	uint8_t *hw_addr;
	uint8_t *bd_desc_base;
	uint16_t device_id;
	uint16_t vendor_id;
	uint16_t subsystem_device_id;
	uint16_t subsystem_vendor_id;

	uint8_t rbp_enable;
	int txq_dma_id;
	int rxq_dma_id;
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

	void *ep_ring_virt_base;  /* EP ring base */
	rte_iova_t ep_ring_phy_base;
	uint64_t ep_ring_win_size;

	void *rc_ring_virt_base;  /* RC ring shadow base */
	rte_iova_t rc_ring_phy_base;

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
	uint32_t cap;
	rte_spinlock_t cap_lock;
	uint32_t ep_cap;
	uint8_t *complete_src;

	uint32_t data_room_size;
	uint64_t rc_dma_base;
	uint32_t rc_dma_elt_size;

	uint64_t cycs_per_us;
};

/* RX/TX function prototypes
 */
void lsinic_dev_clear_queues(struct rte_eth_dev *dev);
void lsinic_dev_rx_queue_release(struct rte_eth_dev *dev,
	uint16_t qid);
void lsinic_dev_tx_queue_release(struct rte_eth_dev *dev,
	uint16_t qid);
int
lsinic_dev_rx_queue_setup(struct rte_eth_dev *dev,
	uint16_t rx_queue_id,
	uint16_t nb_rx_desc,
	unsigned int socket_id,
	const struct rte_eth_rxconf *rx_conf,
	struct rte_mempool *mb_pool);
int
lsinic_dev_tx_queue_setup(struct rte_eth_dev *dev,
	uint16_t tx_queue_id,
	uint16_t nb_tx_desc,
	unsigned int socket_id,
	const struct rte_eth_txconf *tx_conf);

void lsinic_dev_disable_queue(struct lsinic_ring_reg *ring_reg);
int lsinic_dev_rx_init(struct rte_eth_dev *dev);

void lsinic_dev_tx_init(struct rte_eth_dev *dev);

uint16_t
lsinic_recv_pkts(void *rx_queue, struct rte_mbuf **rx_pkts,
	uint16_t nb_pkts);
uint16_t
lsinic_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts,
	uint16_t nb_pkts);

int lsinic_chk_dev_link_update(struct rte_eth_dev *dev);

int lsinic_dev_chk_eth_status(struct rte_eth_dev *dev);

int lsinic_reset_config_fromrc(struct lsinic_adapter *adapter);

#endif /* _LSXINIC_EP_ETHDEV_H_ */
