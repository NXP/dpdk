/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2026 NXP
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

#define LSINIC_DMA_OPT_TXQ_SG_DMA RTE_BIT32(0)
#define LSINIC_DMA_OPT_RXQ_SG_DMA RTE_BIT32(1)
#define LSINIC_DMA_OPT_TXQ_BD_DMA_UPDATE RTE_BIT32(2)

struct lsinic_adapter {
	enum lsinic_dev_type dev_type;
	uint8_t *hw_addr;
	uint8_t *bd_desc_base;
	uint16_t device_id;
	uint16_t vendor_id;
	uint16_t subsystem_device_id;
	uint16_t subsystem_vendor_id;
	int single_bar;

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
	struct rte_eth_dev_data *eth_data;

	uint8_t *ep_ring_virt_base;  /* EP ring base */
	rte_iova_t ep_ring_phy_base;

	rte_iova_t rc_ring_phy_base;
	dma_addr_t rc_ring_bus_base;
	uint64_t rc_ring_size;

	rte_iova_t rx_pcidma_dbg;
	rte_iova_t tx_pcidma_dbg;

	int pcie_idx;
	int pf_idx;
	int vf_idx;
	int is_vf;
	uint8_t mac_addr[RTE_ETHER_ADDR_LEN];

	struct lsinic_queue *txqs;
	struct lsinic_queue *rxqs;
	uint32_t perf_opt;
	uint8_t ep_mem_dbg;

	uint32_t data_room_size;
	uint32_t max_tx_size;
	uint64_t rc_dma_base;
	uint32_t rc_dma_elt_size;
	const struct rte_memzone *local_mz;

	uint64_t rc_dma_phy;

	uint64_t cycs_per_us;
};

#define LSINIC_DEV_PCIE_DEV(dev) \
	container_of((dev)->device, struct rte_lsx_pciep_device, device)

#define LSINIC_DEV_RC_RING_VIR(ep_dev) ((uint8_t *)(ep_dev)->reserve_data[0])
#define LSINIC_DEV_SET_RC_RING_VIR(ep_dev, ptr) \
	((ep_dev)->reserve_data[0] = (uint64_t)(ptr))

#define LSINIC_DEV_RC_DMA_VIR(ep_dev) ((uint8_t *)(ep_dev)->reserve_data[1])
#define LSINIC_DEV_SET_RC_DMA_VIR(ep_dev, ptr) \
	((ep_dev)->reserve_data[1] = (uint64_t)(ptr))

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

int lsinic_dma_test_mem_config_fromrc(struct rte_eth_dev *dev);

int lsinic_reset_config_fromrc(struct rte_eth_dev *dev);

int lsinic_remove_config_fromrc(struct rte_eth_dev *dev);

static inline void
lsinic_byte_memset(void *s, uint8_t ch, size_t n)
{
	size_t i = 0;
	uint8_t *ps = s;

	for (i = 0; i < n; i++) {
		ps[i] = ch;
		asm volatile ("" : : : "memory");
	}
}
#endif /* _LSXINIC_EP_ETHDEV_H_ */
