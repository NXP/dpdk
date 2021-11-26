/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018-2021 NXP
 */

#include <time.h>
#include <net/if.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <stdarg.h>
#include <rte_byteorder.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/queue.h>
#include <pthread.h>
#include <fcntl.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <signal.h>
#include <stdbool.h>
#include <inttypes.h>
#include <rte_common.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_string_fns.h>
#include <rte_cycles.h>
#include <rte_kvargs.h>
#include <rte_dev.h>

#include <rte_interrupts.h>
#include <rte_log.h>
#include <rte_debug.h>
#include <rte_pci.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_tailq.h>
#include <rte_eal.h>
#include <rte_alarm.h>
#include <rte_ether.h>
#include <rte_ethdev_pci.h>
#include <rte_tcp.h>
#include <rte_memory.h>

#include "lsxinic_common_pmd.h"
#include "lsxinic_common.h"
#include "lsxinic_common_helper.h"
#include "lsxinic_rc_rxtx.h"
#include "lsxinic_rc_ethdev.h"
#include "lsxinic_rc_hw.h"

static const struct rte_eth_desc_lim rx_desc_lim = {
	.nb_max = LSINIC_BD_ENTRY_COUNT,
	.nb_min = LSINIC_BD_ENTRY_COUNT,
	.nb_align = 8,
};

static const struct rte_eth_desc_lim tx_desc_lim = {
	.nb_max = LSINIC_BD_ENTRY_COUNT,
	.nb_min = LSINIC_BD_ENTRY_COUNT,
	.nb_align = 8,
};

static int g_lsxinic_rc_sim;

#define LSXINIC_RC_SELF_XMIT_DFA_LEN 1024

static int g_lsxinic_rc_proc_secondary_standalone;

static struct rte_eth_dev_data *lxsnic_proc_2nd_eth_dev_data;
static rte_spinlock_t lxsnic_proc_2nd_dev_alloc_lock =
	RTE_SPINLOCK_INITIALIZER;

int
lxsnic_set_netdev_state(struct lxsnic_hw *hw,
	enum PCIDEV_COMMAND cmd)
{
	struct lsinic_dev_reg *reg =
		LSINIC_REG_OFFSET(hw->hw_addr, LSINIC_DEV_REG_OFFSET);
	struct lsinic_rcs_reg *rcs_reg =
		LSINIC_REG_OFFSET(hw->hw_addr, LSINIC_RCS_REG_OFFSET);
	int wait_loop = LXSNIC_CMD_LOOP_NUM;
	uint32_t cmd_status;

	switch (cmd) {
	case PCIDEV_COMMAND_START:
		LSINIC_WRITE_REG(&rcs_reg->rc_state, LSINIC_DEV_UP);
		break;
	case PCIDEV_COMMAND_STOP:
		LSINIC_WRITE_REG(&rcs_reg->rc_state, LSINIC_DEV_DOWN);
		break;
	case PCIDEV_COMMAND_REMOVE:
		LSINIC_WRITE_REG(&rcs_reg->rc_state, LSINIC_DEV_REMOVED);
		break;
	case PCIDEV_COMMAND_INIT:
		LSINIC_WRITE_REG(&rcs_reg->rc_state, LSINIC_DEV_INITED);
		break;
	case PCIDEV_COMMAND_SET_MTU:
		LSINIC_WRITE_REG(&rcs_reg->rc_state, LSINIC_DEV_INITED);
		break;
	default:
		break;
	}

	LSINIC_WRITE_REG(&reg->command, cmd);
	do {
		msleep(500);
		cmd_status = LSINIC_READ_REG(&reg->command);
	} while (--wait_loop && (cmd_status != PCIDEV_COMMAND_IDLE));

	if (!wait_loop) {
		printf("Command-%d: failed to get right status!\n", cmd);
		return PCIDEV_RESULT_FAILED;
	}

	return LSINIC_READ_REG(&reg->result);
}

static int
lxsnic_set_netdev(struct lxsnic_adapter *adapter,
				enum PCIDEV_COMMAND cmd)
{
	return lxsnic_set_netdev_state(&adapter->hw, cmd);
}

static int
lxsnic_dev_configure(struct rte_eth_dev *dev __rte_unused)
{
	LSXINIC_PMD_DBG("Configured Physical Function port id: %d",
		dev->data->port_id);

	return 0;
}

static void
lxsnic_up_complete(struct lxsnic_adapter *adapter)
{
	/* Need to clear the DOWN status */
	clear_bit(__LXSNIC_DOWN, &adapter->state);

#ifdef CLEAN_THREAD_ENABLE
	/* xsnic_clean_thread_run_all(adapter); */
#else
	/* lxsnic_napi_enable_all(adapter); */
#endif
	lxsnic_set_netdev(adapter, PCIDEV_COMMAND_START);

	/* bring the link up in the watchdog, this could race with our first
	 * link up interrupt but shouldn't be a problem
	 */
	adapter->flags |= LXSNIC_FLAG_NEED_LINK_UPDATE;
}

static pthread_t debug_pid;

#define DEBUG_STATUS_INTERVAL 10

static void *lxsnic_rc_debug_status(void *arg)
{
	struct rte_eth_dev *eth_dev = arg;

	printf("RC start to print status thread\n");

	while (1) {
		sleep(DEBUG_STATUS_INTERVAL);

		print_port_status(eth_dev, NULL, DEBUG_STATUS_INTERVAL,
			0, 0);
		printf("\r\n\r\n");
	}

	return NULL;
}

static int lxsnic_wait_tx_bd_ready(struct lxsnic_ring *tx_ring)
{
	uint32_t i, bd_status, count;
	struct lsinic_bd_desc *rc_tx_desc;

	for (i = 0; i < tx_ring->count; i++) {
		rc_tx_desc = LSINIC_RC_BD_DESC(tx_ring, i);
		bd_status = rc_tx_desc->bd_status;
		count = 0;
		while ((bd_status & RING_BD_STATUS_MASK) != RING_BD_READY) {
			msleep(1);
			bd_status = rc_tx_desc->bd_status;
			rte_rmb();
			count++;
			if (count > 10000) {
				LSXINIC_PMD_ERR("PORT%d:TXQ%d:BD%d not ready!",
					tx_ring->port, tx_ring->queue_index,
					i);
				return -1;
			}
		}
#ifdef LSINIC_BD_CTX_IDX_USED
		rc_tx_desc->bd_status &= (~LSINIC_BD_CTX_IDX_MASK);
		rc_tx_desc->bd_status |=
			(((uint32_t)LSINIC_BD_CTX_IDX_INVALID) <<
			LSINIC_BD_CTX_IDX_SHIFT);
#else
		rc_tx_desc->sw_ctx = 0;
#endif
	}

	return 0;
}

static int
lxsnic_dev_start(struct rte_eth_dev *dev)
{
	struct lxsnic_adapter *adapter =
		LXSNIC_DEV_PRIVATE(dev->data->dev_private);
	struct lsinic_dev_reg *ep_reg =
		LSINIC_REG_OFFSET(adapter->hw.hw_addr, LSINIC_DEV_REG_OFFSET);
	uint32_t reg_val = 0, i;
	char *penv = getenv("LSINIC_RC_PRINT_STATUS");
	int print_status = 0, ret;
	struct lxsnic_ring *tx_queue;

	if (penv)
		print_status = atoi(penv);

	if (test_bit(__LXSNIC_TESTING, &adapter->state)) {
		LSXINIC_PMD_ERR("adapter->state is not correct %lu",
			adapter->state);
		return -EBUSY;
	}

	reg_val = LSINIC_READ_REG(&ep_reg->ep_state);
	if (reg_val == LSINIC_DEV_INITING) {
		LSXINIC_PMD_ERR("ep has NOT been initialized!");
		return -EBUSY;
	}

	lxsnic_set_netdev(adapter, PCIDEV_COMMAND_INIT);

	lxsnic_up_complete(adapter);

	if (adapter->dmapci_dbg)
		goto skip_wait_tx_bd_ready;

	for (i = 0; i < adapter->eth_dev->data->nb_tx_queues; i++) {
		tx_queue = adapter->eth_dev->data->tx_queues[i];
		ret = lxsnic_wait_tx_bd_ready(tx_queue);
		if (ret)
			return ret;
	}

skip_wait_tx_bd_ready:
	if (print_status) {
		if (pthread_create(&debug_pid, NULL,
			lxsnic_rc_debug_status, dev)) {
			LSXINIC_PMD_ERR("Could not create print_status");
			return -1;
		}
	}

	return 0;
}

static void
lxsnic_configure_rx_ring(struct lxsnic_adapter *adapter,
	struct lxsnic_ring *ring)
{
	int i;
	struct lsinic_bdr_reg *bdr_reg =
		LSINIC_REG_OFFSET(adapter->ep_ring_virt_base,
			LSINIC_RING_REG_OFFSET);
	struct lsinic_bdr_reg *rc_bdr_reg =
		LSINIC_REG_OFFSET(adapter->rc_ring_virt_base,
			LSINIC_RING_REG_OFFSET);
	uint8_t reg_idx = ring->queue_index;
	uint32_t rxdctl = 0;
	struct lsinic_ring_reg *ring_reg = &bdr_reg->rx_ring[reg_idx];
	struct lsinic_ring_reg *rc_ring_reg = &rc_bdr_reg->rx_ring[reg_idx];

	/* disable queue to avoid issues while updating state */
	LSINIC_WRITE_REG(&ring_reg->cr, 0);
	LSINIC_WRITE_REG(&ring_reg->pir, 0); /* RDT */
	LSINIC_WRITE_REG(&ring_reg->cir, 0); /* RDH */

	if (ring->rc_bd_desc) {
		LSINIC_WRITE_REG(&ring_reg->r_descl,
			ring->rc_bd_desc_dma & DMA_BIT_MASK(32));
		LSINIC_WRITE_REG(&ring_reg->r_desch,
			ring->rc_bd_desc_dma >> 32);
	}
	LSINIC_WRITE_REG(&ring_reg->r_ep2rcl,
		ring->ep2rc_ring_dma & DMA_BIT_MASK(32));
	LSINIC_WRITE_REG(&ring_reg->r_ep2rch,
		ring->ep2rc_ring_dma >> 32);
	/* MSIX setting*/
	/* Polling mode, no need to send int from EP.*/
	LSINIC_WRITE_REG(&ring_reg->icr, 0);
	LSINIC_WRITE_REG(&ring_reg->iir, 0);
	ring->ep_reg = ring_reg;
	if (adapter->rc_ring_virt_base)
		ring->rc_reg = rc_ring_reg;
	else
		ring->rc_reg = NULL;

	if (ring->rc_reg) {
		LSINIC_WRITE_REG(&ring->rc_reg->pir, 0);
		LSINIC_WRITE_REG(&ring->rc_reg->cir, 0);
	}

	/* enable receive descriptor ring */
	rxdctl = LSINIC_CR_ENABLE | LSINIC_CR_BUSY;
	LSINIC_WRITE_REG(&ring_reg->cr, rxdctl);
	for (i = 0; i < ring->count; i++)
		lxsnic_rx_bd_init_buffer(ring, i);
	LSXINIC_PMD_DBG("ring_reg->cr %u ring_reg->r_descl %u\n",
		ring->ep_reg->cr, ring->ep_reg->r_descl);
}

/* lxsnic_setup_rx_resources - allocate Rx resources (Descriptors)
 * @rx_ring:    rx descriptor ring (for a specific queue) to setup
 *
 * Returns 0 on success, negative on failure
 */

static int
lxsnic_dev_rx_queue_setup(struct rte_eth_dev *dev,
	uint16_t queue_idx,
	uint16_t nb_desc,
	unsigned int socket_id,
	const struct rte_eth_rxconf *rx_conf __rte_unused,
	struct rte_mempool *mp)
{
	struct lxsnic_adapter *adapter =
		LXSNIC_DEV_PRIVATE(dev->data->dev_private);
	struct lsinic_eth_reg *eth_reg =
		LSINIC_REG_OFFSET(adapter->hw.hw_addr, LSINIC_ETH_REG_OFFSET);
	struct lxsnic_ring *rx_ring;

	LSXINIC_PMD_DBG("config rx_queue");
	rx_ring = rte_zmalloc_socket("lsnic ethdev RX queue",
			sizeof(struct lxsnic_ring),
			RTE_CACHE_LINE_SIZE,
			socket_id);
	if (!rx_ring) {
		LSXINIC_PMD_ERR("get rx_ring  is null");
		return -ENOMEM;
	}
	LSXINIC_PMD_DBG("alloc rx queue mem success");

	if (nb_desc > adapter->rx_ring_bd_count) {
		nb_desc = adapter->rx_ring_bd_count;
		LSXINIC_PMD_DBG("rx_ring_desc is %d "
			"bigger than max %d ",
			nb_desc,
			adapter->rx_ring_bd_count);
		rx_ring->count = nb_desc;
	} else {
		rx_ring->count = nb_desc;
	}

	LSXINIC_PMD_DBG("config rx_queue %d rx desc %d max desc %d",
		queue_idx,
		nb_desc,
		adapter->rx_ring_bd_count);

	if ((uint16_t)adapter->max_data_room >
		((uint16_t)rte_pktmbuf_data_room_size(mp) -
		RTE_PKTMBUF_HEADROOM)) {
		adapter->max_data_room =
			rte_pktmbuf_data_room_size(mp) -
			RTE_PKTMBUF_HEADROOM;
		LSINIC_WRITE_REG(&eth_reg->max_data_room,
			adapter->max_data_room);
		lxsnic_set_netdev(adapter, PCIDEV_COMMAND_SET_MTU);
	}

	rx_ring->queue_index = queue_idx;
	rx_ring->port = dev->data->port_id;

	LSXINIC_PMD_DBG("alloc init sw_ring success");
	rx_ring->type = LSINIC_QUEUE_RX;
	rx_ring->adapter = adapter;
	rx_ring->mb_pool = mp;
	rx_ring->ep_bd_desc =
		(struct lsinic_bd_desc *)
		(adapter->bd_desc_base +
		LSINIC_RX_BD_OFFSET +
		queue_idx * LSINIC_RING_SIZE);

	rx_ring->last_avail_idx = 0;
	rx_ring->last_used_idx = 0;
	rx_ring->mhead = 0;
	rx_ring->mtail = 0;
	rx_ring->mcnt = 0;
	LSXINIC_PMD_DBG("prepare config rx_ring");

#ifdef RC_RING_REG_SHADOW_ENABLE
	rx_ring->rc_bd_desc = (struct lsinic_bd_desc *)((char *)
			adapter->rc_bd_desc_base + LSINIC_RX_BD_OFFSET +
			queue_idx * LSINIC_RING_SIZE);
#ifdef LSINIC_BD_CTX_IDX_USED
	if (LSINIC_CAP_XFER_INGRESS_NOTIFY_GET(adapter->cap) ==
		INGRESS_RING_NOTIFY) {
		rx_ring->ep2rc.rx_notify =
			(void *)((uint8_t *)rx_ring->rc_bd_desc +
				LSINIC_BD_RING_SIZE);
	} else if (LSINIC_CAP_XFER_INGRESS_NOTIFY_GET(adapter->cap) ==
		INGRESS_BD_NOTIFY){
		rx_ring->ep2rc.rx_notify = NULL;
		rx_ring->ep2rc_ring_dma = 0;
	} else {
		LSXINIC_PMD_ERR("Invalid RX notify(%d)",
			LSINIC_CAP_XFER_INGRESS_NOTIFY_GET(adapter->cap));
		return -EINVAL;
	}
#else
	rx_ring->ep2rc_ring_dma = 0;
#endif
	rx_ring->rc_bd_desc_dma = ((uint64_t)adapter->rc_bd_desc_phy) +
		(uint64_t)((uint64_t)rx_ring->rc_bd_desc -
				(uint64_t)adapter->rc_bd_desc_base);
#ifdef LSINIC_BD_CTX_IDX_USED
	if (rx_ring->ep2rc.rx_notify) {
		rx_ring->ep2rc_ring_dma = rx_ring->rc_bd_desc_dma +
			LSINIC_BD_RING_SIZE;
	}
#endif

	LSXINIC_PMD_DBG("RX phy_base: %"
		PRIX64 ", queue[ %" PRId32 " ] "
		" : bd_virt:%p bd_phy: %" PRIX64 " ",
		adapter->ep_ring_phy_base, queue_idx,
		rx_ring->rc_bd_desc,
		rx_ring->rc_bd_desc_dma);

	rx_ring->rc_reg = NULL;
#else
	rx_ring->rc_bd_desc = NULL;
	rx_ring->rc_reg = NULL;
#endif
#ifdef LSINIC_BD_CTX_IDX_USED
	rx_ring->q_mbuf =
		rte_zmalloc(NULL, sizeof(void *) * rx_ring->count, 64);
	RTE_ASSERT(rx_ring->q_mbuf);

	if (rx_ring->ep2rc.rx_notify) {
		memset((uint8_t *)rx_ring->ep2rc.rx_notify,
			0, LSINIC_EP2RC_NOTIFY_RING_SIZE);
	}
#endif

	lxsnic_configure_rx_ring(adapter, rx_ring);
	LSXINIC_PMD_DBG("%s %d:desc:%p %" PRIu64
		" [0x%x]. ep_bd_addr = 0x%p ",
		__func__, __LINE__,
		rx_ring->rc_bd_desc,
		rx_ring->rc_bd_desc_dma,
		rx_ring->size,
		rx_ring->ep_bd_desc);
	dev->data->rx_queues[queue_idx] = rx_ring;
	adapter->config_rx_queues++;
	return 0;
}

static void
lxsnic_dev_rx_queue_release(void *rxq)
{
	struct lxsnic_ring *rx_ring = (struct lxsnic_ring *)rxq;

	rx_ring->rc_bd_desc = NULL;
	rx_ring->rc_reg = NULL;
}

static void
lxsnic_dev_tx_queue_release(void *txq)
{
	struct lxsnic_ring *tx_ring = (struct lxsnic_ring *)txq;

	/*clean_pci_mem */
	if (tx_ring->rc_bd_desc)
		memset(tx_ring->rc_bd_desc, 0, LSINIC_BD_RING_SIZE);

#ifdef LSINIC_BD_CTX_IDX_USED
	if (tx_ring->ep2rc.rx_notify)
		memset((uint8_t *)tx_ring->ep2rc.rx_notify, 0,
			LSINIC_EP2RC_NOTIFY_RING_SIZE);
#endif
	if (tx_ring->rc_reg)
		memset(tx_ring->rc_reg, 0, sizeof(*tx_ring->rc_reg));

	tx_ring->rc_bd_desc = NULL;
	tx_ring->rc_reg = NULL;
}

static void
lxsnic_configure_tx_ring(struct lxsnic_adapter *adapter,
	struct lxsnic_ring *ring)
{
	struct lsinic_bdr_reg *bdr_reg =
		LSINIC_REG_OFFSET(adapter->ep_ring_virt_base,
			LSINIC_RING_REG_OFFSET);
	struct lsinic_bdr_reg *rc_bdr_reg =
		LSINIC_REG_OFFSET(adapter->rc_ring_virt_base,
			LSINIC_RING_REG_OFFSET);
	uint8_t reg_idx = ring->queue_index;
	uint32_t txdctl = LSINIC_CR_ENABLE | LSINIC_CR_BUSY;
	struct lsinic_ring_reg *ring_reg = &bdr_reg->tx_ring[reg_idx];
	struct lsinic_ring_reg *rc_ring_reg = &rc_bdr_reg->tx_ring[reg_idx];

	/* disable queue to avoid issues while updating state */
	LSINIC_WRITE_REG(&ring_reg->cr, LSINIC_CR_DISABLE);
	LSINIC_WRITE_REG(&ring_reg->pir, 0); /* TDT */
	LSINIC_WRITE_REG(&ring_reg->cir, 0); /* TDH */

	if (LSINIC_CAP_XFER_EGRESS_CNF_GET(adapter->cap) ==
		EGRESS_RING_CNF) {
		memset(ring->ep2rc.tx_complete, RING_BD_READY,
			LSINIC_EP2RC_COMPLETE_RING_SIZE);
	}

	if (ring->rc_bd_desc) {
		LSINIC_WRITE_REG(&ring_reg->r_descl,
			ring->rc_bd_desc_dma & DMA_BIT_MASK(32));
		LSINIC_WRITE_REG(&ring_reg->r_desch,
			ring->rc_bd_desc_dma >> 32);
	}
	LSINIC_WRITE_REG(&ring_reg->r_ep2rcl,
		ring->ep2rc_ring_dma & DMA_BIT_MASK(32));
	LSINIC_WRITE_REG(&ring_reg->r_ep2rch,
		ring->ep2rc_ring_dma >> 32);

	LSINIC_WRITE_REG(&ring_reg->iir, 0);

	ring->ep_reg = ring_reg;
	if (adapter->rc_ring_virt_base)
		ring->rc_reg = rc_ring_reg;
	else
		ring->rc_reg = NULL;

	if (ring->rc_reg) {
		LSINIC_WRITE_REG(&ring->rc_reg->pir, 0);
		LSINIC_WRITE_REG(&ring->rc_reg->cir, 0);
	}
	/* enable queue */
	LSINIC_WRITE_REG(&ring_reg->cr, txdctl);
}

static int
lxsnic_dev_tx_queue_setup(struct rte_eth_dev *dev,
		   uint16_t queue_idx,
		   uint16_t nb_desc,
		   unsigned int socket_id,
		   const struct rte_eth_txconf *tx_conf __rte_unused)
{
	struct lxsnic_ring *tx_ring = NULL;
	struct lxsnic_adapter *adapter =
		LXSNIC_DEV_PRIVATE(dev->data->dev_private);

	tx_ring = rte_zmalloc_socket("lsnic ethdev TX queue",
			sizeof(struct lxsnic_ring),
			RTE_CACHE_LINE_SIZE, socket_id);
	if (!tx_ring) {
		LSXINIC_PMD_ERR("get tx_ring  is null");
		return -ENOMEM;
	}
	if (nb_desc > adapter->tx_ring_bd_count) {
		nb_desc = adapter->tx_ring_bd_count;
		LSXINIC_PMD_DBG("tx_ring_desc is %d bigger than max %d",
			nb_desc,
			adapter->tx_ring_bd_count);
		tx_ring->count = nb_desc;
	} else {
		tx_ring->count = nb_desc;
	}

	tx_ring->type = LSINIC_QUEUE_TX;
	tx_ring->queue_index = queue_idx;
	tx_ring->port = dev->data->port_id;
	tx_ring->adapter = adapter;
	tx_ring->ep_bd_desc = (struct lsinic_bd_desc *)
		(adapter->bd_desc_base + (queue_idx * LSINIC_RING_SIZE));

	tx_ring->last_avail_idx = 0;
	tx_ring->last_used_idx = 0;
	tx_ring->mhead = 0;
	tx_ring->mtail = 0;
	tx_ring->mcnt = 0;
#ifdef RC_RING_REG_SHADOW_ENABLE
	tx_ring->rc_bd_desc =
		(struct lsinic_bd_desc *)
		((char *)adapter->rc_bd_desc_base +
		LSINIC_TX_BD_OFFSET +
		queue_idx * LSINIC_RING_SIZE);
	if (LSINIC_CAP_XFER_EGRESS_CNF_GET(adapter->cap) ==
		EGRESS_RING_CNF) {
		tx_ring->ep2rc.tx_complete =
			(uint8_t *)tx_ring->rc_bd_desc +
			LSINIC_BD_RING_SIZE;
	} else if (LSINIC_CAP_XFER_EGRESS_CNF_GET(adapter->cap) ==
		EGRESS_INDEX_CNF) {
		*((uint32_t *)((uint8_t *)tx_ring->rc_bd_desc +
			LSINIC_BD_RING_SIZE)) = 0;
		tx_ring->tx_free_start_idx = 0;
		tx_ring->tx_free_len = 0;
		tx_ring->ep2rc.free_idx =
			(const uint32_t *)((uint8_t *)tx_ring->rc_bd_desc +
			LSINIC_BD_RING_SIZE);
	} else {
		tx_ring->ep2rc.union_ring = NULL;
		tx_ring->ep2rc_ring_dma = 0;
	}
	tx_ring->rc_bd_desc_dma =
		((uint64_t)adapter->rc_bd_desc_phy) +
		(uint64_t)((uint64_t)tx_ring->rc_bd_desc -
		(uint64_t)adapter->rc_bd_desc_base);

	if (tx_ring->ep2rc.union_ring) {
		tx_ring->ep2rc_ring_dma = tx_ring->rc_bd_desc_dma +
			LSINIC_BD_RING_SIZE;
	}

	LSXINIC_PMD_DBG("TX phy_base:%lX, queue:%d "
		"bd_virt:%p bd_phy: %lX\n",
		adapter->ep_ring_phy_base, queue_idx,
		tx_ring->rc_bd_desc, tx_ring->rc_bd_desc_dma);
#else
	tx_ring->rc_bd_desc = NULL;
	tx_ring->rc_reg = NULL;
#endif
#ifdef LSINIC_BD_CTX_IDX_USED
	tx_ring->q_mbuf =
		rte_zmalloc(NULL, sizeof(void *) * tx_ring->count, 64);
	RTE_ASSERT(tx_ring->q_mbuf);
#endif
	lxsnic_configure_tx_ring(adapter, tx_ring);
	dev->data->tx_queues[queue_idx] = tx_ring;
	adapter->config_tx_queues++;
	return 0;
}

static void
lxsnic_disable_rx_queue(struct lxsnic_ring *ring)
{
	uint32_t rxdctl;
	struct lsinic_ring_reg *ring_reg = ring->ep_reg;

	if (ring->rc_reg)
		rxdctl = ring->rc_reg->cr;
	else
		rxdctl = LSINIC_READ_REG(&ring_reg->cr);
	rxdctl &= ~LSINIC_CR_ENABLE;
	/* disable queue to avoid issues while updating state */
	LSINIC_WRITE_REG(&ring_reg->cr, rxdctl);
	if (ring->rc_reg)
		LSINIC_WRITE_REG(&ring->rc_reg->cr, rxdctl);
}

static void
lxsnic_disable_tx_queue(struct lxsnic_ring *ring)
{
	uint32_t txdctl;

	if (ring->rc_reg)
		txdctl = LSINIC_READ_REG(&ring->rc_reg->cr);
	else
		txdctl = LSINIC_READ_REG(&ring->ep_reg->cr);
	txdctl &= ~LSINIC_CR_ENABLE;
	/* disable queue to avoid issues while updating state */
	LSINIC_WRITE_REG(&ring->ep_reg->cr, txdctl);
	if (ring->rc_reg)
		LSINIC_WRITE_REG(&ring->rc_reg->cr, txdctl);
}

static void
lxsnic_down(struct rte_eth_dev *dev)
{
	int i;
	struct lxsnic_adapter *adapter =
		LXSNIC_DEV_PRIVATE(dev->data->dev_private);
	/* signal that we are down to the interrupt handler */

	struct lxsnic_ring *ring = NULL;

	set_bit(__LXSNIC_DOWN, &adapter->state);

	/* disable the netdev receive */
	lxsnic_set_netdev(adapter, PCIDEV_COMMAND_STOP);

	/* disable all enabled rx queues */
	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		/* this call also flushes the previous write */
		ring = dev->data->rx_queues[i];
		lxsnic_disable_rx_queue(ring);
	}

	/* disable all tx queues */
	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		ring = dev->data->rx_queues[i];
		lxsnic_disable_tx_queue(ring);
	}
}

/*
 * Stop device: disable rx and tx functions to allow for reconfiguring.
 */

static void
lxsnic_dev_stop(struct rte_eth_dev *dev)
{
	lxsnic_down(dev);
}

static int
lxsnic_dev_promiscuous_enable(struct rte_eth_dev *dev __rte_unused)
{
	return 0;
}

static int
lxsnic_dev_promiscuous_disable(struct rte_eth_dev *dev __rte_unused)
{
	return 0;
}

static int
lxsnic_dev_allmulticast_enable(struct rte_eth_dev *dev __rte_unused)
{
	return 0;
}

static int
lxsnic_dev_allmulticast_disable(struct rte_eth_dev *dev __rte_unused)
{
	return 0;
}

struct rte_lxsnic_xstats_name_off {
	char name[RTE_ETH_XSTATS_NAME_SIZE];
	uint32_t offset;
};

static const struct rte_lxsnic_xstats_name_off rte_lxsnic_stats_strings[] = {
	{"rx_alloc_mbuf_failed", offsetof(struct lxsnic_hw_stats,
			rx_alloc_mbuf_fail)},
	{"rx clean queue count", offsetof(struct lxsnic_hw_stats,
			rx_clean_count)},
	{"rx once success clean", offsetof(struct lxsnic_hw_stats,
			rx_desc_clean_num)},
	{"rx clean queue failed", offsetof(struct lxsnic_hw_stats,
			rx_desc_clean_fail)},
	{"rx desc is error", offsetof(struct lxsnic_hw_stats,
			rx_desc_err)},
	{"tx free mbuf is null", offsetof(struct lxsnic_hw_stats,
			tx_mbuf_err)},
	{"tx clean queue count", offsetof(struct lxsnic_hw_stats,
			tx_clean_count)},
	{"tx once clean success", offsetof(struct lxsnic_hw_stats,
			tx_desc_clean_num)},
	{"tx clean queue failed", offsetof(struct lxsnic_hw_stats,
			tx_desc_clean_fail)},
	{"tx rc desc is illegal", offsetof(struct lxsnic_hw_stats,
			tx_desc_err)},
};

#define LXSNIC_NB_RXQ_PRIO_STATS (sizeof(rte_lxsnic_stats_strings) / \
			   sizeof(rte_lxsnic_stats_strings[0]))

static int
lxsnic_dev_xstats_get(struct rte_eth_dev *dev,
	struct rte_eth_xstat *xstats, unsigned n __rte_unused)
{
	struct lxsnic_adapter *adapter =
		LXSNIC_DEV_PRIVATE(dev->data->dev_private);
	uint8_t stat = 0;
	struct lxsnic_hw_stats *stats = &adapter->stats;
	uint32_t count = 0;

	for (stat = 0; stat < LXSNIC_NB_RXQ_PRIO_STATS; stat++) {
		xstats[count].value = *(uint64_t *)(((char *)stats) +
					rte_lxsnic_stats_strings[stat].offset);
		xstats[count].id = count;
		count++;
	}

	return count;
}

static unsigned
lxsnic_xstats_calc_num(void)
{
	return LXSNIC_NB_RXQ_PRIO_STATS;
}

static int
lxsnic_dev_xstats_reset(struct rte_eth_dev *dev)
{
	struct lxsnic_adapter *adapter =
		LXSNIC_DEV_PRIVATE(dev->data->dev_private);
	struct lxsnic_hw_stats *stats = &adapter->stats;
	/* HW registers are cleared on read TODO */
	/* Reset software totals */
	memset(stats, 0, sizeof(*stats));

	return 0;
}

static int
lxsnic_dev_xstats_get_names(__rte_unused struct rte_eth_dev *dev,
	struct rte_eth_xstat_name *xstats_names,
	__rte_unused unsigned int size)
{
	const uint32_t cnt_stats = lxsnic_xstats_calc_num();
	uint32_t i = 0, count = 0;

	if (xstats_names) {
		for (i = 0; i < LXSNIC_NB_RXQ_PRIO_STATS; i++) {
			snprintf(xstats_names[count].name,
				sizeof(xstats_names[count].name),
				"%s",
				rte_lxsnic_stats_strings[i].name);
			count++;
		}
	}

	return cnt_stats;
}

static int
lxsnic_dev_stats_get(struct rte_eth_dev *dev,
	struct rte_eth_stats *lxsnic_stats)
{
	struct lxsnic_adapter *adapter =
		LXSNIC_DEV_PRIVATE(dev->data->dev_private);
	struct lxsnic_ring *rx_queue = NULL, *tx_queue = NULL;
	uint8_t i = 0;

	for (i = 0; i < adapter->config_rx_queues; i++) {
		rx_queue = dev->data->rx_queues[i];
		if (!rx_queue)
			continue;
		lxsnic_stats->q_ipackets[i] = rx_queue->packets;
		lxsnic_stats->q_ibytes[i] = rx_queue->bytes;
		lxsnic_stats->q_errors[i] = rx_queue->errors;
		lxsnic_stats->ipackets += rx_queue->packets;
		lxsnic_stats->ibytes += rx_queue->bytes;
		lxsnic_stats->ierrors += rx_queue->errors;
	}
	for (i = 0; i < adapter->config_tx_queues; i++) {
		tx_queue = dev->data->tx_queues[i];
		if (!tx_queue)
			continue;
		lxsnic_stats->q_opackets[i] = tx_queue->packets;
		lxsnic_stats->q_obytes[i] = tx_queue->bytes;
		lxsnic_stats->q_errors[i] = tx_queue->errors;
		lxsnic_stats->opackets += tx_queue->packets;
		lxsnic_stats->obytes += tx_queue->bytes;
		lxsnic_stats->oerrors += tx_queue->errors;
	}
	lxsnic_stats->rx_nombuf = dev->data->rx_mbuf_alloc_failed;
	return 0;
}

static int
lxsnic_dev_stats_reset(struct rte_eth_dev *dev)
{
	struct lxsnic_adapter *adapter =
		LXSNIC_DEV_PRIVATE(dev->data->dev_private);
	struct lxsnic_ring *rx_queue = NULL, *tx_queue = NULL;
	uint8_t i = 0;

	for (i = 0; i < adapter->num_rx_queues; i++) {
		rx_queue = dev->data->rx_queues[i];
		if (!rx_queue)
			continue;
		rx_queue->packets = 0;
		rx_queue->bytes = 0;
		tx_queue->errors = 0;
		rx_queue->packets = 0;
		tx_queue->bytes = 0;
		rx_queue->errors = 0;
	}
	for (i = 0; i < adapter->num_tx_queues; i++) {
		tx_queue = dev->data->tx_queues[i];
		if (!tx_queue)
			continue;
		tx_queue->packets = 0;
		tx_queue->bytes = 0;
		tx_queue->errors = 0;
		tx_queue->packets = 0;
		tx_queue->bytes = 0;
		tx_queue->errors = 0;
	}
	dev->data->rx_mbuf_alloc_failed = 0;

	return 0;
}

static void
lxsnic_dev_rxq_info(struct rte_eth_dev *dev,
	uint16_t rx_queue_id, struct rte_eth_rxq_info *qinfo)
{
	struct lxsnic_ring *rx_queue;

	if (rx_queue_id >= dev->data->nb_rx_queues)
		return;

	rx_queue = dev->data->rx_queues[rx_queue_id];

	memset(qinfo, 0, sizeof(struct rte_eth_rxq_info));
	qinfo->mp = rx_queue->mb_pool;
	qinfo->nb_desc = rx_queue->count;
}

static void
lxsnic_dev_txq_info(struct rte_eth_dev *dev,
	uint16_t tx_queue_id, struct rte_eth_txq_info *qinfo)
{
	struct lxsnic_ring *tx_queue;

	if (tx_queue_id >= dev->data->nb_tx_queues)
		return;

	tx_queue = dev->data->rx_queues[tx_queue_id];

	memset(qinfo, 0, sizeof(struct rte_eth_txq_info));
	qinfo->nb_desc = tx_queue->count;
}

static int
lxsnic_dev_info_get(struct rte_eth_dev *dev, struct rte_eth_dev_info *dev_info)
{
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(dev);
	struct lxsnic_adapter *adapter =
		LXSNIC_DEV_PRIVATE(dev->data->dev_private);

	dev_info->device = &pci_dev->device;
	dev_info->max_rx_queues = adapter->num_rx_queues;
	dev_info->max_tx_queues = adapter->num_tx_queues;
	dev_info->max_rx_pktlen = 4096; /* includes CRC, cf MAXFRS register */
	dev_info->max_mac_addrs = 1;

	dev_info->rx_desc_lim = rx_desc_lim;
	dev_info->tx_desc_lim = tx_desc_lim;
	dev_info->rx_offload_capa = DEV_RX_OFFLOAD_CHECKSUM |
		DEV_RX_OFFLOAD_JUMBO_FRAME;

	return 0;
}

static void
lxsnic_dev_close(struct rte_eth_dev *dev)
{
	struct lxsnic_adapter *adapter =
		LXSNIC_DEV_PRIVATE(dev->data->dev_private);

	lxsnic_dev_stop(dev);
	adapter->adapter_stopped = true;
	lxsnic_set_netdev(adapter, PCIDEV_COMMAND_REMOVE);
}

/* Atomically writes the link status information into global
 * structure rte_eth_dev.
 *
 * @param dev
 *   - Pointer to the structure rte_eth_dev to read from.
 *   - Pointer to the buffer to be saved with the link status.
 *
 * @return
 *   - On success, zero.
 *   - On failure, negative value.
 */

static inline int
rte_lxsnic_dev_atomic_write_link_status(struct rte_eth_dev *dev,
	struct rte_eth_link *link)
{
	struct rte_eth_link *dst = &dev->data->dev_link;
	struct rte_eth_link *src = link;

	if (rte_atomic64_cmpset((uint64_t *)dst,
			*(uint64_t *)dst, *(uint64_t *)src) == 0)
		return -1;

	return 0;
}

static int
lxsnic_dev_link_update(struct rte_eth_dev *dev,
		int wait_to_complete __rte_unused)
{
	struct rte_eth_link link;
	uint32_t rc_state = 0;
	struct lxsnic_adapter *adapter =
		(struct lxsnic_adapter *)dev->data->dev_private;
	struct lsinic_rcs_reg *rcs_reg =
		LSINIC_REG_OFFSET(adapter->hw.hw_addr, LSINIC_RCS_REG_OFFSET);
	struct lsinic_dev_reg *ep_reg =
		LSINIC_REG_OFFSET(adapter->hw.hw_addr, LSINIC_DEV_REG_OFFSET);

	rc_state = LSINIC_READ_REG(&rcs_reg->rc_state);
	if (rc_state != adapter->rc_state) {
		if (rc_state == LSINIC_DEV_UP) {
			LSXINIC_PMD_INFO("rc link up");
		} else {
			LSXINIC_PMD_INFO("rc link down");
		}
	}
	adapter->rc_state = rc_state;
	adapter->ep_state = LSINIC_READ_REG(&ep_reg->ep_state);
	if (rc_state == LSINIC_DEV_UP &&
		adapter->ep_state == LSINIC_DEV_UP) {
		link.link_status = ETH_LINK_UP;
		link.link_duplex = ETH_LINK_FULL_DUPLEX;
		link.link_speed = ETH_SPEED_NUM_10G;
	} else {
		link.link_status = ETH_LINK_DOWN;
		link.link_duplex = ETH_LINK_HALF_DUPLEX;
		link.link_speed = ETH_SPEED_NUM_NONE;
	}

	adapter->link_up = link.link_status;
	adapter->link_speed = link.link_speed;
	rte_lxsnic_dev_atomic_write_link_status(dev, &link);

	return 0;
}

static int
lxsnic_vlan_filter_set(struct rte_eth_dev *dev, uint16_t vlan, int vf)
{
	struct lxsnic_adapter *adapter =
		LXSNIC_DEV_PRIVATE(dev->data->dev_private);
	struct lsinic_rcs_reg *rcs_reg =
		LSINIC_REG_OFFSET(adapter->hw.hw_addr, LSINIC_RCS_REG_OFFSET);
	uint8_t qos = 0;

	if (vf < 0) {
		LSXINIC_PMD_ERR("vlan value is ininvald");
		return -EINVAL;
	}
	if (((uint32_t)vf >= adapter->num_vfs) || vlan > 4095 || qos > 7)
		return -EINVAL;

	if (vlan || qos) {
		adapter->vfinfo[vf].pf_qos = qos;
		adapter->vfinfo[vf].vlan_count++;
		adapter->vfinfo[vf].pf_vlan = vlan;
		LSXINIC_PMD_DBG("Setting VLAN %d, QOS 0x%x on VF %d",
			vlan, qos, vf);
		LSINIC_WRITE_REG(&rcs_reg->cmd.cmd_type, INIC_COMMAND_VF_VLAN);
		LSINIC_WRITE_REG(&rcs_reg->cmd.cmd_vf_vlan, vlan);
		LSINIC_WRITE_REG(&rcs_reg->cmd.cmd_vf_idx, vf);
		lxsnic_set_netdev(adapter, PCIDEV_COMMAND_SET_VF_VLAN);
	} else {
		adapter->vfinfo[vf].pf_qos = 0;
		if (adapter->vfinfo[vf].vlan_count)
			adapter->vfinfo[vf].vlan_count--;

		adapter->vfinfo[vf].pf_vlan = 0;
		LSINIC_WRITE_REG(&rcs_reg->cmd.cmd_type, INIC_COMMAND_VF_VLAN);
		LSINIC_WRITE_REG(&rcs_reg->cmd.cmd_vf_vlan, 0);
		LSINIC_WRITE_REG(&rcs_reg->cmd.cmd_vf_idx, vf);
		lxsnic_set_netdev(adapter, PCIDEV_COMMAND_SET_VF_VLAN);
	}
	return 0;
}

static struct eth_dev_ops eth_lxsnic_eth_dev_ops = {
	.dev_configure        = lxsnic_dev_configure,
	.dev_start            = lxsnic_dev_start,
	.dev_stop             = lxsnic_dev_stop,
	.dev_close            = lxsnic_dev_close,
	.dev_infos_get        = lxsnic_dev_info_get,
	.rx_queue_setup       = lxsnic_dev_rx_queue_setup,
	.rx_queue_release     = lxsnic_dev_rx_queue_release,
	.tx_queue_setup       = lxsnic_dev_tx_queue_setup,
	.tx_queue_release     = lxsnic_dev_tx_queue_release,
	.vlan_filter_set      = lxsnic_vlan_filter_set,
	.link_update          = lxsnic_dev_link_update,
	.promiscuous_enable   = lxsnic_dev_promiscuous_enable,
	.promiscuous_disable  = lxsnic_dev_promiscuous_disable,
	.allmulticast_enable  = lxsnic_dev_allmulticast_enable,
	.allmulticast_disable = lxsnic_dev_allmulticast_disable,
	.stats_get            = lxsnic_dev_stats_get,
	.stats_reset          = lxsnic_dev_stats_reset,
	.xstats_get           = lxsnic_dev_xstats_get,
	.xstats_get_names     = lxsnic_dev_xstats_get_names,
	.xstats_reset         = lxsnic_dev_xstats_reset,
	.rxq_info_get			= lxsnic_dev_rxq_info,
	.txq_info_get			= lxsnic_dev_txq_info,
};

static const struct rte_pci_id pci_id_lxsnic_map[] = {
	{ RTE_PCI_DEVICE(NXP_PCI_VENDOR_ID, NXP_PCI_DEV_ID_LX2160A) },
	{ RTE_PCI_DEVICE(NXP_PCI_VENDOR_ID, NXP_PCI_DEV_ID_LS2088A) },
	{ .vendor_id = 0, /* sentinel */ },
};

static void
lxsnic_reinit_locked(struct lxsnic_adapter *adapter __rte_unused)
{
}

static void
lxsnic_watchdog_update_link(struct lxsnic_adapter *adapter)
{
	uint32_t ep_state = 0;
	uint32_t link_speed = adapter->link_speed;
	bool link_up = adapter->link_up;
	struct lsinic_dev_reg *dev_reg =
		LSINIC_REG_OFFSET(adapter->hw.hw_addr, LSINIC_DEV_REG_OFFSET);
	uint32_t  i;

	if (!(adapter->flags & LXSNIC_FLAG_NEED_LINK_UPDATE))
		return;

	ep_state = LSINIC_READ_REG(&dev_reg->ep_state);
	if (ep_state != LSINIC_DEV_UP) {
		link_up = false;
		link_speed = 0;
	} else {
		link_up = true;
		link_speed = LXSNIC_LINK_SPEED_10GB_FULL;
	}

	if (adapter->link_up != link_up) {
		if (link_up) {
			LSXINIC_PMD_DBG("ep link up");
		} else {
			lxsnic_reinit_locked(adapter);
			LSXINIC_PMD_DBG("ep link down");
		}
	}

	adapter->link_up = link_up;
	adapter->link_speed = link_speed;

	adapter->vf_rate_link_speed = link_speed;

	for (i = 0; i < adapter->num_vfs; i++)
		adapter->vfinfo[i].tx_rate = link_speed;
}

static void
lxsnic_watchdog_link_is_down(struct lxsnic_adapter *adapter)
{
	adapter->link_up = false;
	adapter->link_speed = 0;
}

static void
lxsnic_watchdog_link_is_up(struct lxsnic_adapter *adapter __rte_unused)
{
}

static void
lxsnic_watchdog_subtask(struct lxsnic_adapter *adapter)
{
	/* if interface is down do nothing */
	if (test_bit(__LXSNIC_DOWN, &adapter->state) ||
		test_bit(__LXSNIC_RESETTING, &adapter->state))
		return;

	lxsnic_watchdog_update_link(adapter);

	if (adapter->link_up)
		lxsnic_watchdog_link_is_up(adapter);
	else
		lxsnic_watchdog_link_is_down(adapter);
}

static void
lxsnic_service_event_complete(struct lxsnic_adapter *adapter)
{
	/* BUG_ON(!test_bit(__lxsnic_SERVICE_SCHED, &adapter->state)); */
	clear_bit(__LXSNIC_SERVICE_SCHED, &adapter->state);
}

static void
eth_lxsnic_interrupt_handler(void *param)
{
	struct rte_eth_dev *eth_dev = (struct rte_eth_dev *)param;
	struct lxsnic_adapter *adapter =
		LXSNIC_DEV_PRIVATE(eth_dev->data->dev_private);

	lxsnic_watchdog_subtask(adapter);
	lxsnic_service_event_complete(adapter);
}

/* lxsnic_sw_init - Initialize general software structures
 * @adapter: board private structure to initialize
 *
 * lxsnic_sw_init initializes the Adapter private data structure.
 * Fields are initialized based on PCI device information and
 * OS network device settings (MTU size).
 */

static int
lxsnic_sw_init(struct lxsnic_adapter *adapter)
{
	struct lsinic_eth_reg *eth_reg =
		LSINIC_REG_OFFSET(adapter->hw.hw_addr, LSINIC_ETH_REG_OFFSET);

	/* get ring setting */
	adapter->tx_ring_bd_count = LSINIC_READ_REG(&eth_reg->tx_entry_num);
	adapter->rx_ring_bd_count = LSINIC_READ_REG(&eth_reg->rx_entry_num);
	adapter->num_tx_queues = LSINIC_READ_REG(&eth_reg->tx_ring_num);
	adapter->num_rx_queues = LSINIC_READ_REG(&eth_reg->rx_ring_num);

	adapter->cap = LSINIC_READ_REG(&eth_reg->cap);

	adapter->merge_threshold = LSINIC_READ_REG(&eth_reg->merge_threshold);
	adapter->max_data_room = LSINIC_READ_REG(&eth_reg->max_data_room);

	set_bit(__LXSNIC_DOWN, &adapter->state);

	return 0;
}

static void
lxsnic_get_mac_addr(struct lxsnic_hw *hw)
{
	struct lsinic_eth_reg *eth_reg =
		LSINIC_REG_OFFSET(hw->hw_addr, LSINIC_ETH_REG_OFFSET);;
	int i;
	uint8_t mac_address[RTE_ETHER_ADDR_LEN];
	uint32_t mac_high = LSINIC_READ_REG(&eth_reg->macaddrh);
	uint32_t mac_low = LSINIC_READ_REG(&eth_reg->macaddrl);
	uint8_t low_size = sizeof(uint32_t) / sizeof(uint8_t);

	for (i = 0; i < low_size; i++) {
		mac_address[RTE_ETHER_ADDR_LEN - 1 - i] =
			(uint8_t)(mac_low >> (i * 8));
	}

	for (i = 0; i < RTE_ETHER_ADDR_LEN - low_size; i++)
		mac_address[1 - i] = (uint8_t)(mac_high >> (i * 8));

	memcpy(hw->mac.addr, mac_address,
			RTE_ETHER_ADDR_LEN);
	memcpy(hw->mac.perm_addr, mac_address,
			RTE_ETHER_ADDR_LEN);
}

static int
is_valid_ether_addr(uint8_t *addr)
{
	const char zaddr[6] = { 0,  };

	return !(addr[0] & 1) && memcmp(addr, zaddr, 6);
}

static void
lxsnic_msix_disable_all(struct lxsnic_adapter *adapter)
{
	int i = 0;
	struct lsinic_rcs_reg *rcs_reg =
		LSINIC_REG_OFFSET(adapter->hw.hw_addr, LSINIC_RCS_REG_OFFSET);

	for (i = 0; i < 32; i++)
		LSINIC_WRITE_REG(&rcs_reg->msix_mask[i], 0x01);

	LSINIC_WRITE_REG(&rcs_reg->msi_flag, LSINIC_DONT_INT);
}

static int s_rc_merge_fast_fwd;

int lxsnic_rc_mg_fast_fwd(void)
{
	return s_rc_merge_fast_fwd;
}

static int
eth_lsnic_dev_init(struct rte_eth_dev *eth_dev)
{
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);
	struct lxsnic_adapter *adapter =
		LXSNIC_DEV_PRIVATE(eth_dev->data->dev_private);
	struct rte_intr_handle *intr_handle = &pci_dev->intr_handle;
	struct lxsnic_hw  *hw =
		LXSNIC_DEV_PRIVATE_TO_HW(eth_dev->data->dev_private);
	struct lsinic_dev_reg *ep_reg = NULL;
	struct lsinic_rcs_reg *rcs_reg = NULL;
	int8_t error = 0;
	const struct rte_memzone *rc_ring_mem = NULL;
	char *penv;

	LSXINIC_PMD_INFO("start init lsnic driver");
	adapter->eth_dev = eth_dev;
	eth_dev->dev_ops = &eth_lxsnic_eth_dev_ops;
	eth_dev->rx_pkt_burst = &lxsnic_eth_recv_pkts;
	/* < Pointer to PMD receive function. */
	eth_dev->tx_pkt_burst = &lxsnic_eth_xmit_pkts;
	/* < Pointer to PMD transmit function. */
	if (!g_lsxinic_rc_proc_secondary_standalone) {
		if (rte_eal_process_type() != RTE_PROC_PRIMARY)
			return 0;
	}

	penv = getenv("LSINIC_RC_MERGE_FAST_FWD");
	if (penv)
		s_rc_merge_fast_fwd = atoi(penv);

	hw->device_id = pci_dev->id.device_id;
	hw->vendor_id = pci_dev->id.vendor_id;
	hw->back = adapter;

	LSXINIC_PMD_DBG("device_id %d vendor_id %d",
		hw->device_id,
		hw->vendor_id);

	hw->hw_addr = pci_dev->mem_resource[LSX_PCIEP_REG_BAR_IDX].addr;
	if (!hw->hw_addr) {
		LSXINIC_PMD_ERR("hw_addr map failed");
		error = -ENOMEM;
		goto free_adapter;
	}
	ep_reg = LSINIC_REG_OFFSET(hw->hw_addr, LSINIC_DEV_REG_OFFSET);

	if (LSINIC_READ_REG(&ep_reg->init_flag) != LSINIC_INIT_FLAG) {
		LSXINIC_PMD_ERR("iNIC EP has been NOT initialized!"
				" %d ep_reg->ep_state",
				LSINIC_READ_REG(&ep_reg->ep_state));
		error = -EIO;
		goto free_adapter;
	}

	if (LSINIC_READ_REG(&ep_reg->ep_state) != LSINIC_DEV_UP) {
		LSXINIC_PMD_ERR("EP state(%d) not ready",
			LSINIC_READ_REG(&ep_reg->ep_state));
		error = -EIO;
		goto free_adapter;
	}

	LSXINIC_PMD_DBG("adapter->hw_addr = 0x%p", hw->hw_addr);

	adapter->ep_ring_win_size =
		pci_dev->mem_resource[LSX_PCIEP_RING_BAR_IDX].len;
	/* eb_ring pci phy mem get */
	adapter->ep_ring_phy_base =
		pci_dev->mem_resource[LSX_PCIEP_RING_BAR_IDX].phys_addr;
	/* ep_ring pci bar addr get */
	adapter->ep_ring_virt_base =
		pci_dev->mem_resource[LSX_PCIEP_RING_BAR_IDX].addr;
	if (!adapter->ep_ring_phy_base) {
		LSXINIC_PMD_ERR("eb_ring_phy_base if err");
		return -ENOMEM;
	}
	LSXINIC_PMD_DBG("ep_ring size %ld, vir %p",
		(unsigned long)adapter->ep_ring_win_size,
		adapter->ep_ring_virt_base);

	if (!adapter->ep_ring_virt_base) {
		LSXINIC_PMD_ERR("eb_ring_virt_base reg is null");

		return -ENOMEM;
	}
	/* base eb_ring virt_base addr
	 * this is the net card use to read rx queue tx queue pkt
	 */
	adapter->bd_desc_base =
		adapter->ep_ring_virt_base + LSINIC_RING_BD_OFFSET;

	/* dma resource alloc
	 * requeset a similar card eb_ring space
	 * (pci mem) to rc ring (local mem)
	 */
	adapter->rc_ring_win_size =
		pci_dev->mem_resource[LSX_PCIEP_RING_BAR_IDX].len;
	rc_ring_mem = rte_eth_dma_zone_reserve(eth_dev, "rc_ring", 0,
			adapter->rc_ring_win_size,
			adapter->rc_ring_win_size,
			eth_dev->data->numa_node);
	if (!rc_ring_mem) {
		LSXINIC_PMD_ERR("rc_ring_mem is dma alloc failed");
		error = -ENODEV;
		goto free_adapter;
	}
	adapter->rc_ring_virt_base = rc_ring_mem->addr;
	adapter->rc_ring_phy_base = rc_ring_mem->iova;

	if (!adapter->rc_ring_virt_base) {
		LSXINIC_PMD_ERR("rc_ring_virt_base is NULL, ERROR!");
		error =  -ENOMEM;
		goto free_adapter;
	}

	adapter->rc_bd_desc_base =
		adapter->rc_ring_virt_base + LSINIC_RING_BD_OFFSET;
	adapter->rc_bd_desc_phy =
		adapter->rc_ring_phy_base + LSINIC_RING_BD_OFFSET;
	rcs_reg = LSINIC_REG_OFFSET(hw->hw_addr, LSINIC_RCS_REG_OFFSET);
	LSINIC_WRITE_REG(&rcs_reg->r_regl,
		(adapter->rc_ring_phy_base) & DMA_BIT_MASK(32));

	LSINIC_WRITE_REG(&rcs_reg->r_regh,
		(adapter->rc_ring_phy_base) >> 32);
	eth_dev->data->rx_mbuf_alloc_failed = 0;
	/* RX ring mbuf allocation failures */

	LSXINIC_PMD_DBG("RC RING PHY_BASE ADDR low 0x%" PRIX64 " ",
		adapter->rc_ring_phy_base);
	LSXINIC_PMD_DBG("RC_RING PHY_BASE ADDR high 0x%" PRIX64 " ",
		adapter->rc_ring_phy_base >> 32);

	/* get info from card reg  */
	error = lxsnic_sw_init(adapter);
	if (error) {
		LSXINIC_PMD_ERR("Software init failed");
		error = -ENODEV;
		goto free_adapter;
	}
	/* this is use to control nic mac info */
	eth_dev->data->mac_addrs =
		rte_zmalloc("lsnic_mac", RTE_ETHER_ADDR_LEN, 0);
	if (!eth_dev->data->mac_addrs) {
		LSXINIC_PMD_ERR("alloc mac_addrs failed");
		error = -ENOMEM;
		goto free_adapter;
	}
	/* init hw callback function */
	lxsnic_get_mac_addr(hw);
	if (!is_valid_ether_addr(hw->mac.perm_addr)) {
		LSXINIC_PMD_ERR("invalid MAC address");
		rte_free(eth_dev->data->mac_addrs);
		error = -EIO;
		goto free_adapter;
	}
	rte_ether_addr_copy((struct rte_ether_addr *)hw->mac.perm_addr,
		&eth_dev->data->mac_addrs[0]);
	/* initialize PF if max_vfs not zero */
	lxsnic_pf_host_init(eth_dev);

	lxsnic_msix_disable_all(adapter);

	penv = getenv("LSINIC_PCIE_RX_TEST");
	if (penv) {
		const struct rte_memzone *pcie_rx_mem = NULL;
		uint16_t queue_nb = adapter->num_rx_queues;
		uint32_t size = queue_nb * LSINIC_QDMA_TEST_PKT_MAX_LEN *
						adapter->rx_ring_bd_count;
		char name[64];

		sprintf(name, "PCIE_RX_MEM_%d", eth_dev->data->port_id);
		pcie_rx_mem = rte_memzone_reserve_aligned(name, size,
						eth_dev->data->numa_node,
						RTE_MEMZONE_IOVA_CONTIG, 64);
		if (!pcie_rx_mem) {
			error = -ENOMEM;
			goto free_adapter;
		}

		LSINIC_WRITE_REG(&rcs_reg->txdma_regl,
			(pcie_rx_mem->iova) & DMA_BIT_MASK(32));
		LSINIC_WRITE_REG(&rcs_reg->txdma_regh,
			(pcie_rx_mem->iova) >> 32);

		adapter->dmapci_dbg = 1;
	}

	penv = getenv("LSINIC_PCIE_TX_TEST");
	if (penv) {
		const struct rte_memzone *pcie_tx_mem = NULL;
		uint16_t queue_nb = adapter->num_tx_queues;
		uint32_t size = queue_nb * LSINIC_QDMA_TEST_PKT_MAX_LEN *
						adapter->tx_ring_bd_count;
		char name[64];

		sprintf(name, "PCIE_TX_MEM_%d", eth_dev->data->port_id);
		pcie_tx_mem = rte_memzone_reserve_aligned(name, size,
						eth_dev->data->numa_node,
						RTE_MEMZONE_IOVA_CONTIG, 64);
		if (!pcie_tx_mem) {
			error = -ENOMEM;
			goto free_adapter;
		}

		LSINIC_WRITE_REG(&rcs_reg->rxdma_regl,
			(pcie_tx_mem->iova) & DMA_BIT_MASK(32));
		LSINIC_WRITE_REG(&rcs_reg->rxdma_regh,
			(pcie_tx_mem->iova) >> 32);

		adapter->dmapci_dbg = 1;
	}

	penv = getenv("LSINIC_SELF_XMIT_TEST");
	if (penv) {
		adapter->self_test = true;
		penv = getenv("LSINIC_SELF_XMIT_LEN");
		if (penv) {
			adapter->self_test_len = atoi(penv);
			if (adapter->self_test_len < 60 ||
				adapter->self_test_len > 1500)
				adapter->self_test_len =
					LSXINIC_RC_SELF_XMIT_DFA_LEN;
		} else {
			adapter->self_test_len = LSXINIC_RC_SELF_XMIT_DFA_LEN;
		}
	} else {
		adapter->self_test = false;
	}

	/* register interrupt function for user to
	 * call interrupt by dpdk eal lib
	 */
	rte_intr_callback_register(intr_handle,
		eth_lxsnic_interrupt_handler, (void *)eth_dev);

	return 0;

free_adapter:
	rte_eth_dev_pci_release(eth_dev);
	return error;
}

static int lxsnic_sim_pci_resource_set(struct rte_pci_device *dev)
{
	int i, map_idx = 0;
	void *mapaddr;

	LSXINIC_PMD_INFO("RC Simulator: vendor: 0x%04x",
		dev->id.vendor_id);

	/* Map all BARs */
	for (i = 0; i != PCI_MAX_RESOURCE; i++) {
		/* skip empty BAR */
		if (dev->mem_resource[i].phys_addr == 0)
			continue;

		mapaddr = rte_mem_iova2virt(dev->mem_resource[i].phys_addr);
		dev->mem_resource[i].addr = mapaddr;
		map_idx++;
	}

	return 0;
}

static uint16_t
lxsnic_proc_secondary_find_free_port(void)
{
	unsigned i;

	for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
		if (!rte_eth_devices[i].data)
			return i;
	}
	return RTE_MAX_ETHPORTS;
}

#define LXSINIC_RC_SECDONARY_ETH_NAME_PREFIX "rc_ethdev_data"
static struct rte_eth_dev *
lxsnic_proc_secondary_eth_dev_allocate(const char *name)
{
	const struct rte_memzone *mz;
	struct rte_eth_dev *eth_dev = NULL;
	size_t name_len;
	uint16_t port_id;
	char memzone_name[64];

	name_len = strnlen(name, RTE_ETH_NAME_MAX_LEN);
	if (name_len == 0) {
		LSXINIC_PMD_ERR("Zero length LSINIC RC device name");
		return NULL;
	}

	if (name_len >= RTE_ETH_NAME_MAX_LEN) {
		LSXINIC_PMD_ERR("LSINIC RC device name is too long");
		return NULL;
	}

	rte_spinlock_lock(&lxsnic_proc_2nd_dev_alloc_lock);

	if (!lxsnic_proc_2nd_eth_dev_data) {
		sprintf(memzone_name,
			LXSINIC_RC_SECDONARY_ETH_NAME_PREFIX "_%s",
			rte_pci_get_sysfs_path());
		mz = rte_memzone_reserve(memzone_name,
				sizeof(struct rte_eth_dev_data) *
				RTE_MAX_ETHPORTS,
				rte_socket_id(), 0);
		if (!mz) {
			LSXINIC_PMD_ERR("RC device data mz(%s) alloc failed",
				memzone_name);
			rte_spinlock_unlock(&lxsnic_proc_2nd_dev_alloc_lock);
			return NULL;
		}
		lxsnic_proc_2nd_eth_dev_data = mz->addr;
	}

	port_id = lxsnic_proc_secondary_find_free_port();
	eth_dev = &rte_eth_devices[port_id];
	eth_dev->data =
		&lxsnic_proc_2nd_eth_dev_data[port_id];

	strlcpy(eth_dev->data->name, name, sizeof(eth_dev->data->name));
	eth_dev->data->port_id = port_id;
	eth_dev->data->mtu = RTE_ETHER_MTU;

	rte_spinlock_unlock(&lxsnic_proc_2nd_dev_alloc_lock);

	return eth_dev;
}

static int
eth_lxsnic_proc_secondary_probe(struct rte_pci_device *pci_dev)
{
	struct rte_eth_dev *eth_dev;
	int ret;

	eth_dev = lxsnic_proc_secondary_eth_dev_allocate(pci_dev->name);
	if (!eth_dev)
		return -ENOMEM;
	eth_dev->data->dev_private =
		rte_zmalloc_socket(pci_dev->name,
			sizeof(struct lxsnic_adapter),
			RTE_CACHE_LINE_SIZE,
			pci_dev->device.numa_node);
	if (!eth_dev->data->dev_private) {
		rte_eth_dev_release_port(eth_dev);
		return -ENOMEM;
	}
	eth_dev->device = &pci_dev->device;
	rte_eth_copy_pci_info(eth_dev, pci_dev);
	ret = eth_lsnic_dev_init(eth_dev);
	if (ret)
		rte_eth_dev_pci_release(eth_dev);
	else
		rte_eth_dev_probing_finish(eth_dev);

	return ret;
}

static int
eth_lxsnic_pci_probe(struct rte_pci_driver *pci_drv __rte_unused,
	struct rte_pci_device *pci_dev)
{
	if (g_lsxinic_rc_sim)
		lxsnic_sim_pci_resource_set(pci_dev);

	if (g_lsxinic_rc_proc_secondary_standalone)
		return eth_lxsnic_proc_secondary_probe(pci_dev);

	/* this function will alloc mem for adapter and
	 *  check mem copy pci info to eth ,and call dev_init function
	 */
	return rte_eth_dev_pci_generic_probe(pci_dev,
			sizeof(struct lxsnic_adapter),
			eth_lsnic_dev_init);
}

static void
eth_lxsnic_close(struct rte_eth_dev *dev __rte_unused)
{
	struct lxsnic_adapter *adapter =
		LXSNIC_DEV_PRIVATE(dev->data->dev_private);

	if (!adapter)
		return;
	set_bit(__LXSNIC_DOWN, &adapter->state);

	if (adapter->num_vfs)
		lxsnic_disable_sriov(adapter);

	lxsnic_set_netdev(adapter, PCIDEV_COMMAND_REMOVE);
	if (adapter->rc_ring_virt_base)
		rte_free(adapter->rc_ring_virt_base);

	rte_free(adapter);
}

static int
eth_lxsnic_dev_uninit(struct rte_eth_dev *eth_dev)
{
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);
	struct lxsnic_adapter *adapter =
		LXSNIC_DEV_PRIVATE(eth_dev->data->dev_private);
	struct rte_intr_handle *intr_handle = &pci_dev->intr_handle;

	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return -EPERM;

	if (adapter->adapter_stopped == 0)
		eth_lxsnic_close(eth_dev);

	eth_dev->dev_ops = NULL;
	eth_dev->rx_pkt_burst = NULL;
	eth_dev->tx_pkt_burst = NULL;

	rte_free(eth_dev->data->mac_addrs);
	eth_dev->data->mac_addrs = NULL;

	/* disable uio intr before callback unregister */
	rte_intr_disable(intr_handle);
	rte_intr_callback_unregister(intr_handle,
			eth_lxsnic_interrupt_handler, eth_dev);

	return 0;
}

int
lxsnic_rx_bd_init_buffer(struct lxsnic_ring *rx_queue,
	uint16_t idx)
{
	struct lsinic_bd_desc *ep_rx_desc, *rc_rx_desc;
	struct rte_mbuf *mbuf;
	uint64_t dma_addr = 0;

	rc_rx_desc = LSINIC_RC_BD_DESC(rx_queue, idx);
	ep_rx_desc = LSINIC_EP_BD_DESC(rx_queue, idx);
	mbuf = rte_mbuf_raw_alloc(rx_queue->mb_pool);
	if (unlikely(!mbuf)) {
		struct rte_eth_dev_data *dev_data;

		LSXINIC_PMD_ERR("RX mbuf alloc failed queue_id=%u",
			(unsigned int)rx_queue->queue_index);
		dev_data = rte_eth_devices[rx_queue->port].data;
		dev_data->rx_mbuf_alloc_failed++;
		return -ENOMEM;
	}
	mbuf->data_off = RTE_PKTMBUF_HEADROOM;
	mbuf->port = rx_queue->port;
	dma_addr = rte_cpu_to_le_64(rte_mbuf_data_iova_default(mbuf));

	rc_rx_desc->pkt_addr = dma_addr;
#ifndef LSINIC_BD_CTX_IDX_USED
	rc_rx_desc->sw_ctx = (uint64_t)mbuf;
	rc_rx_desc->bd_status = RING_BD_READY;

	rte_memcpy(ep_rx_desc, rc_rx_desc,
		offsetof(struct lsinic_bd_desc, desc));
	rte_wmb();
	rc_rx_desc->sw_ctx = LSINIC_READ_REG_64B(&ep_rx_desc->sw_ctx);
	ep_rx_desc->desc = rc_rx_desc->desc;
#else
	rx_queue->q_mbuf[idx] = mbuf;
	rc_rx_desc->bd_status =
		(((uint32_t)idx) << LSINIC_BD_CTX_IDX_SHIFT) | RING_BD_READY;
	mem_cp128b_atomic((uint8_t *)ep_rx_desc, (uint8_t *)rc_rx_desc);
#endif

#ifdef INIC_RC_EP_DEBUG_ENABLE
	LSINIC_WRITE_REG(&rx_queue->ep_reg->pir,
		(idx + 1) & (rx_queue->count - 1));
#endif

	return 0;
}

static int
eth_lxsnic_pci_remove(struct rte_pci_device *pci_dev)
{
	return rte_eth_dev_pci_generic_remove(pci_dev, eth_lxsnic_dev_uninit);
}

static struct rte_pci_driver rte_lxsnic_pmd = {
	.id_table = pci_id_lxsnic_map,
	.drv_flags = RTE_PCI_DRV_NEED_MAPPING,
	.probe = eth_lxsnic_pci_probe,
	.remove = eth_lxsnic_pci_remove,
};

static void
lxsnic_dev_construct(void)
{
	char *penv = getenv("LSINIC_RC_SIM");

	if (penv)
		g_lsxinic_rc_sim = atoi(penv);
	if (g_lsxinic_rc_sim)
		rte_lxsnic_pmd.drv_flags &= (~RTE_PCI_DRV_NEED_MAPPING);

	penv = getenv("LSINIC_RC_PROC_SECONDARY_STANDALONE");
	if (penv)
		g_lsxinic_rc_proc_secondary_standalone = atoi(penv);

	rte_lxsnic_pmd.driver.name = RTE_STR(net_lxsnic);
	rte_pci_register(&rte_lxsnic_pmd);
}

RTE_INIT(lxsnic_dev_construct);
RTE_PMD_EXPORT_NAME(net_lxsnic, __COUNTER__);
RTE_PMD_REGISTER_PCI_TABLE(net_lxsnic, pci_id_lxsnic_map);
RTE_PMD_REGISTER_KMOD_DEP(net_lxsnic, "* igb_uio | uio_pci_generic");
