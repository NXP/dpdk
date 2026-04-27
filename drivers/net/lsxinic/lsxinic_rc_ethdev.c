/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018-2026 NXP
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
#include <rte_tcp.h>
#include <rte_memory.h>
#include <ethdev_driver.h>
#include <rte_bus_pci.h>
#include <ethdev_pci.h>

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

static uint64_t
lxsinic_xstats_get_ipackets(struct rte_eth_dev *dev)
{
	return lsxinic_common_get_ipackets(dev, struct lxsnic_ring *);
}

static uint64_t
lxsinic_xstats_get_ibytes(struct rte_eth_dev *dev)
{
	return lsxinic_common_get_ibytes(dev, struct lxsnic_ring *);
}

static uint64_t
lxsinic_xstats_get_epackets(struct rte_eth_dev *dev)
{
	return lsxinic_common_get_epackets(dev, struct lxsnic_ring *);
}

static uint64_t
lxsinic_xstats_get_ebytes(struct rte_eth_dev *dev)
{
	return lsxinic_common_get_ebytes(dev, struct lxsnic_ring *);
}

static uint64_t
lxsinic_xstats_get_ierrs(struct rte_eth_dev *dev)
{
	return lsxinic_common_get_ierrs(dev, struct lxsnic_ring *);
}

static uint64_t
lxsinic_xstats_get_eerrs(struct rte_eth_dev *dev)
{
	return lsxinic_common_get_eerrs(dev, struct lxsnic_ring *);
}

static uint64_t
lxsinic_xstats_get_ibd_errs(struct rte_eth_dev *dev)
{
	return lsxinic_common_get_ibd_errs(dev, struct lxsnic_ring *);
}

static uint64_t
lxsinic_xstats_get_efulls(struct rte_eth_dev *dev)
{
	return lsxinic_common_get_efulls(dev, struct lxsnic_ring *);
}

static uint64_t
lxsinic_xstats_get_edrops(struct rte_eth_dev *dev)
{
	return lsxinic_common_get_edrops(dev, struct lxsnic_ring *);
}

static const lsxinic_common_xstats_count s_lxsnic_xstat_cbs[] = {
	lxsinic_xstats_get_ipackets,
	lxsinic_xstats_get_ibytes,
	lxsinic_xstats_get_epackets,
	lxsinic_xstats_get_ebytes,
	lxsinic_xstats_get_ierrs,
	lxsinic_xstats_get_eerrs,
	lxsinic_xstats_get_ibd_errs,
	lxsinic_xstats_get_efulls,
	lxsinic_xstats_get_edrops
};

int
lxsnic_set_netdev_state(struct lxsnic_adapter *adapter,
	enum PCIDEV_COMMAND cmd)
{
	struct lxsnic_hw *hw = &adapter->hw;
	struct lsinic_dev_reg *reg =
		LSINIC_REG_OFFSET(hw->hw_addr, LSINIC_DEV_REG_OFFSET);
	struct lsinic_rcs_reg *rcs_reg =
		LSINIC_REG_OFFSET(hw->hw_addr, LSINIC_RCS_REG_OFFSET);
	int wait_ms = LXSNIC_CMD_WAIT_DEFAULT_SEC * 1000;
	uint32_t cmd_status, res;

	if (getenv("LXSNIC_CMD_WAIT_SEC")) {
		wait_ms = atoi("LXSNIC_CMD_WAIT_SEC") * 1000;
		if (wait_ms < 0)
			wait_ms = LXSNIC_CMD_WAIT_DEFAULT_SEC * 1000;
	}

	if (cmd == PCIDEV_COMMAND_DMA_TEST) {
		LSINIC_WRITE_REG_64B(&rcs_reg->r_dma_base,
			adapter->rc_memzone_iova);
		LSINIC_WRITE_REG(&rcs_reg->r_dma_elt_size,
			adapter->rc_memzone_size);
		LSXINIC_PMD_INFO("Reserve 0x%08xB from 0x%lx for DMA test",
			adapter->rc_memzone_size,
			adapter->rc_memzone_iova);
	}

	LSINIC_WRITE_REG(&reg->command, cmd);
	cmd_status = cmd;
	do {
		rte_delay_us_sleep(1000);
		cmd_status = LSINIC_READ_REG(&reg->command);
		wait_ms--;
		if (wait_ms < 0)
			break;
	} while (cmd_status != PCIDEV_COMMAND_IDLE);

	if (cmd_status != PCIDEV_COMMAND_IDLE) {
		LSXINIC_PMD_ERR("CMD-%d executed failed, wait longer?",
			cmd);
		return PCIDEV_RESULT_FAILED;
	}

	rte_rmb();
	res = LSINIC_READ_REG(&reg->result);
	if (res != PCIDEV_RESULT_SUCCEED) {
		LSXINIC_PMD_ERR("CMD-%d executed result error(%d)",
			cmd, res);
		return res;
	}

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
	case PCIDEV_COMMAND_DMA_TEST:
		LSINIC_WRITE_REG(&rcs_reg->rc_state, LSINIC_DEV_DMA_TEST);
		break;
	default:
		break;
	}

	return res;
}

static int
lxsnic_set_netdev(struct lxsnic_adapter *adapter,
				enum PCIDEV_COMMAND cmd)
{
	return lxsnic_set_netdev_state(adapter, cmd);
}

static int
lxsnic_dev_configure(struct rte_eth_dev *dev)
{
	struct rte_eth_conf *cfg = &dev->data->dev_conf;
	struct lxsnic_adapter *adapter = LSINIC_DEV_PRIVATE(dev);

	LSXINIC_PMD_DBG("Configured Physical Function port id: %d",
		dev->data->port_id);
	if (cfg->txmode.offloads & RTE_ETH_TX_OFFLOAD_MULTI_SEGS)
		adapter->tx_segment = true;
	if (cfg->rxmode.offloads & RTE_ETH_RX_OFFLOAD_BUFFER_SPLIT)
		adapter->rx_split = true;

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
	if (lxsnic_set_netdev(adapter, PCIDEV_COMMAND_START)) {
		LSXINIC_PMD_ERR("Start %s failed!",
			adapter->eth_dev->data->name);
	}
}

static pthread_t debug_pid;

#define DEBUG_STATUS_INTERVAL 10

static void *lxsnic_rc_debug_status(void *arg)
{
	struct rte_eth_dev *eth_dev = arg;
	int ret;
	uint64_t cycles;
	cpu_set_t cpuset;

	CPU_SET(0, &cpuset);

	ret = pthread_setaffinity_np(pthread_self(),
			sizeof(cpu_set_t), &cpuset);
	LSXINIC_PMD_INFO("affinity status thread to cpu 0 %s",
		ret ? "failed" : "success");

	LSXINIC_PMD_INFO("RC start to print status thread");

	cycles = rte_get_timer_cycles();
	while (1) {
		sleep(DEBUG_STATUS_INTERVAL);

		print_port_status_cycle(eth_dev, &cycles, LSINIC_RC_PORT);
	}

	return NULL;
}

static void
lxsnic_dev_rx_tx_bind(struct rte_eth_dev *dev)
{
	struct lxsnic_ring *txq;
	struct lxsnic_ring *rxq;
	uint16_t i, num;

	num = RTE_MIN(dev->data->nb_tx_queues, dev->data->nb_rx_queues);

	/* Link RX and Tx Descriptor Rings */
	for (i = 0; i < num; i++) {
		txq = dev->data->tx_queues[i];
		rxq = dev->data->rx_queues[i];
		if (!txq || !rxq)
			continue;

		rxq->pair = txq;
		txq->pair = rxq;
	}
}

static int
lxsnic_dev_queues_ready(struct rte_eth_dev *dev,
	struct lsinic_bdr_reg *bdr_reg, enum lsinic_queue_type type)
{
	uint32_t i, nb, count, reg_val;
	struct lsinic_ring_reg *ring_reg;

	if (type == LSINIC_QUEUE_RX) {
		nb = dev->data->nb_rx_queues;
		ring_reg = bdr_reg->rx_ring;
	} else {
		nb = dev->data->nb_tx_queues;
		ring_reg = bdr_reg->tx_ring;
	}

	for (i = 0; i < nb; i++) {
		count = 0;
read_again:
		reg_val = LSINIC_READ_REG(&ring_reg[i].sr);
		count++;
		if (reg_val != LSINIC_QUEUE_RUNNING) {
			if (count > 1000) {
				LSXINIC_PMD_ERR("%s%d not ready!",
					type == LSINIC_QUEUE_RX ? "RXQ" : "TXQ", i);
				return -EIO;
			}
			rte_delay_us(1000);
			goto read_again;
		}
	}

	return 0;
}

static int
lxsinic_dev_mtu_set(struct rte_eth_dev *dev, uint16_t mtu)
{
	/* TODO: Add proper implementation */

	RTE_SET_USED(dev);
	RTE_SET_USED(mtu);

	return 0;
}

static int
lxsnic_dev_start(struct rte_eth_dev *dev)
{
	struct lxsnic_adapter *adapter = LSINIC_DEV_PRIVATE(dev);
	uint8_t __iomem *hw_addr = adapter->hw.hw_addr;
	struct lsinic_dev_reg *ep_reg;
	struct lsinic_rcs_reg *rcs_reg;
	struct lsinic_bdr_reg *bdr_reg;
	struct lsinic_ring_reg *tx_ring_reg;
	uint32_t reg_val = 0, i;
	char *penv = getenv("LSINIC_RC_PRINT_STATUS");
	int print_status = 0, ret, q_pair = 1, xmit_bd_64 = 1;
	struct lxsnic_ring *tx_queue;
	enum RC_MEM_BD_TYPE tx_cnf = RC_MEM_IDX_CNF;
	void *_start;

	if (penv)
		print_status = atoi(penv);

	if (test_bit(__LXSNIC_TESTING, &adapter->state)) {
		LSXINIC_PMD_ERR("adapter->state is not correct %lu",
			adapter->state);
		return -EBUSY;
	}

	ep_reg = LSINIC_REG_OFFSET(hw_addr, LSINIC_DEV_REG_OFFSET);
	rcs_reg = LSINIC_REG_OFFSET(hw_addr, LSINIC_RCS_REG_OFFSET);
	bdr_reg = LSINIC_REG_OFFSET(adapter->ep_ring_virt_base, LSINIC_RING_REG_OFFSET);

	reg_val = LSINIC_READ_REG(&ep_reg->ep_state);
	if (reg_val == LSINIC_DEV_INITING) {
		LSXINIC_PMD_ERR("ep has NOT been initialized!");
		return -EBUSY;
	}

	penv = getenv("LSINIC_RC_QUEUE_PAIR");
	if (penv)
		q_pair = atoi(penv);
	if (q_pair)
		lxsnic_dev_rx_tx_bind(dev);

	penv = getenv("LSINIC_RC_XMIT_BD_64");
	if (penv)
		xmit_bd_64 = atoi(penv);

	penv = getenv("LSINIC_RC_XMIT_CNF");
	if (penv)
		tx_cnf = atoi(penv);

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		tx_queue = dev->data->tx_queues[i];
		tx_queue->ep_mem_bd_type = EP_MEM_BD_128;
		tx_queue->rc_mem_bd_type = tx_cnf;

		if (adapter->tx_segment)
			tx_queue->ep_mem_bd_type = EP_MEM_SRC_SEG_BD;

		if (xmit_bd_64 && tx_queue->ep_mem_bd_type != EP_MEM_SRC_SEG_BD)
			tx_queue->ep_mem_bd_type = EP_MEM_SRC_BD_64;
		tx_ring_reg = &bdr_reg->tx_ring[i];
		if (tx_queue->ep_mem_bd_type == EP_MEM_BD_128) {
			tx_queue->ep_bd_desc = tx_queue->ep_bd_mapped_addr;
		} else if (tx_queue->ep_mem_bd_type == EP_MEM_SRC_BD_64) {
			tx_queue->ep_bd_desc_64 = tx_queue->ep_bd_mapped_addr;
		} else if (tx_queue->ep_mem_bd_type == EP_MEM_SRC_SEG_BD) {
			tx_queue->ep_tx_sg = tx_queue->ep_bd_mapped_addr;
		} else {
			rte_panic("TXQ%d invalid ep mem type(%d)",
				tx_queue->queue_index, tx_queue->ep_mem_bd_type);
		}

		if (tx_queue->rc_mem_bd_type == RC_MEM_BD_128) {
			tx_queue->rc_bd_desc = tx_queue->rc_bd_shared_addr;
			_start = &tx_queue->rc_bd_desc[tx_queue->count];
			if (tx_queue->ep_mem_bd_type == EP_MEM_SRC_BD_64)
				tx_queue->rc_bd_desc_64 = _start;
		} else if (tx_queue->rc_mem_bd_type == RC_MEM_BD_CNF) {
			tx_queue->tx_complete = tx_queue->rc_bd_shared_addr;
			_start = &tx_queue->tx_complete[tx_queue->count];
			if (tx_queue->ep_mem_bd_type == EP_MEM_BD_128)
				tx_queue->rc_bd_desc = _start;
			else if (tx_queue->ep_mem_bd_type == EP_MEM_SRC_BD_64)
				tx_queue->rc_bd_desc_64 = _start;
			else if (tx_queue->ep_mem_bd_type == EP_MEM_SRC_SEG_BD)
				tx_queue->rc_sg_desc = _start;
		} else if (tx_queue->rc_mem_bd_type == RC_MEM_IDX_CNF) {
			if (tx_queue->ep_mem_bd_type == EP_MEM_BD_128)
				tx_queue->rc_bd_desc = tx_queue->rc_bd_shared_addr;
			else if (tx_queue->ep_mem_bd_type == EP_MEM_SRC_BD_64)
				tx_queue->rc_bd_desc_64 = tx_queue->rc_bd_shared_addr;
			else if (tx_queue->ep_mem_bd_type == EP_MEM_SRC_SEG_BD)
				tx_queue->rc_sg_desc = tx_queue->rc_bd_shared_addr;
		} else {
			LSXINIC_PMD_ERR("TXQ%d invalid rc mem type(%d)",
				tx_queue->queue_index,
				tx_queue->rc_mem_bd_type);
			return -EINVAL;
		}
		LSINIC_WRITE_REG(&tx_ring_reg->r_ep_mem_bd_type,
			tx_queue->ep_mem_bd_type);
		LSINIC_WRITE_REG(&tx_ring_reg->r_rc_mem_bd_type,
			tx_queue->rc_mem_bd_type);
		if (tx_queue->ep_mem_bd_type == EP_MEM_BD_128)
			LSXINIC_PMD_INFO("RC txq%d set 128b BD.", i);
		else if (tx_queue->ep_mem_bd_type == EP_MEM_SRC_BD_64)
			LSXINIC_PMD_INFO("RC txq%d set 64b BD.", i);
		else if (tx_queue->ep_mem_bd_type == EP_MEM_SRC_SEG_BD)
			LSXINIC_PMD_INFO("RC txq%d set segment BD.", i);

		if (tx_queue->rc_mem_bd_type == RC_MEM_BD_128)
			LSXINIC_PMD_INFO("RC txq%d conf with 128b BD.", i);
		else if (tx_queue->rc_mem_bd_type == RC_MEM_BD_CNF)
			LSXINIC_PMD_INFO("RC txq%d conf with flag.", i);
		else if (tx_queue->rc_mem_bd_type == RC_MEM_IDX_CNF)
			LSXINIC_PMD_INFO("RC txq%d conf with index.", i);
	}

	ret = lxsnic_set_netdev(adapter, PCIDEV_COMMAND_INIT);
	if (ret != PCIDEV_RESULT_SUCCEED)
		return -EIO;

	adapter->dma_mem_complete = LSINIC_READ_REG(&rcs_reg->dma_mem_complete);
	if (adapter->dma_mem_complete)
		LSXINIC_PMD_INFO("Help EP to set memory complete flag.");

	lxsnic_up_complete(adapter);

	ret = lxsnic_dev_queues_ready(dev, bdr_reg, LSINIC_QUEUE_RX);
	if (ret)
		return ret;
	ret = lxsnic_dev_queues_ready(dev, bdr_reg, LSINIC_QUEUE_TX);
	if (ret)
		return ret;

	if (print_status) {
		ret = pthread_create(&debug_pid, NULL,
			lxsnic_rc_debug_status, dev);
		if (ret) {
			LSXINIC_PMD_ERR("Could not create print_status");
			return ret;
		}
	}

	return 0;
}

static int
lxsnic_configure_rxq_bd(struct lxsnic_ring *rxq)
{
	uint64_t rdma_addr = 0, offset = 0, len = 0;
	void *v_rdma_addr = NULL;

	if (rxq->rc_mem_bd_type == RC_MEM_BD_128) {
		offset = 0;
	} else if (rxq->rc_mem_bd_type == RC_MEM_LEN_CMD) {
		offset = sizeof(struct lsinic_rc_rx_len) * rxq->count;
	} else if (rxq->rc_mem_bd_type == RC_MEM_SEG_LEN) {
		offset = sizeof(struct lsinic_rc_rx_seg) * rxq->count;
	} else {
		LSXINIC_PMD_ERR("%s: type(%d) of BD in RC mem not support",
			__func__, rxq->rc_mem_bd_type);

		return -ENOTSUP;
	}

	rdma_addr = rxq->rc_bd_desc_dma + offset;
	rdma_addr = RTE_CACHE_LINE_ROUNDUP(rdma_addr);
	offset = rdma_addr - rxq->rc_bd_desc_dma;
	v_rdma_addr = (uint8_t *)rxq->rc_bd_shared_addr + offset;

	if (rxq->ep_mem_bd_type == EP_MEM_BD_128) {
		rxq->rc_bd_desc = v_rdma_addr;
		len = sizeof(struct lsinic_bd_desc_128) * rxq->count;
	} else if (rxq->ep_mem_bd_type == EP_MEM_DST_ADDR_BD) {
		rxq->rc_rx_addr = v_rdma_addr;
		len = sizeof(struct lsinic_ep_tx_dst_addr) * rxq->count;
	} else if (rxq->ep_mem_bd_type == EP_MEM_DST_ADDR_SEG) {
		rxq->rc_sg_desc = v_rdma_addr;
		len = sizeof(struct lsinic_ep_tx_seg_entry) * rxq->count;
	} else {
		LSXINIC_PMD_ERR("%s: type(%d) of BD in EP mem not support",
			__func__, rxq->ep_mem_bd_type);

		return -ENOTSUP;
	}

	if ((offset + len) > LSINIC_BD_RING_SIZE) {
		LSXINIC_PMD_ERR("%s: offset(%ld) + (len)%ld > %ld",
			__func__, offset, len,
			LSINIC_BD_RING_SIZE);
		rxq->rc_bd_desc = NULL;
		rxq->rc_rx_addr = NULL;

		return -EOVERFLOW;
	}

	return 0;
}

static int
lxsnic_configure_rx_ring(struct lxsnic_adapter *adapter,
	struct lxsnic_ring *ring)
{
	int ret;
	struct lsinic_bdr_reg *bdr_reg =
		LSINIC_REG_OFFSET(adapter->ep_ring_virt_base,
			LSINIC_RING_REG_OFFSET);
	struct lsinic_bdr_reg *rc_bdr_reg =
		LSINIC_REG_OFFSET(adapter->rc_ring_virt_base,
			LSINIC_RING_REG_OFFSET);
	uint8_t reg_idx = ring->queue_index;
	uint32_t rxdctl = 0, i, ready;
	struct lsinic_ring_reg *ring_reg = &bdr_reg->rx_ring[reg_idx];
	struct lsinic_ring_reg *rc_ring_reg = &rc_bdr_reg->rx_ring[reg_idx];

	ready = LSINIC_READ_REG(&ring_reg->ready);
	if (ready != LSINIC_INIT_FLAG) {
		LSXINIC_PMD_ERR("RX Ring%d is not ready(0x%08x)!", reg_idx, ready);
		return -EIO;
	}

	/* disable queue to avoid issues while updating state */
	LSINIC_WRITE_REG(&ring_reg->cr, 0);
	LSINIC_WRITE_REG(&ring_reg->pir, 0); /* RDT */
	LSINIC_WRITE_REG(&ring_reg->cir, 0); /* RDH */

	if (ring->rc_bd_shared_addr) {
		LSINIC_WRITE_REG(&ring_reg->r_descl,
			ring->rc_bd_desc_dma & DMA_BIT_MASK(32));
		LSINIC_WRITE_REG(&ring_reg->r_desch,
			ring->rc_bd_desc_dma >> 32);
	}
	LSINIC_WRITE_REG(&ring_reg->isr, 0);
	LSINIC_WRITE_REG(&ring_reg->r_ep_mem_bd_type,
		ring->ep_mem_bd_type);
	LSINIC_WRITE_REG(&ring_reg->r_rc_mem_bd_type,
		ring->rc_mem_bd_type);
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
	for (i = 0; i < ring->count; i++) {
		ret = lxsnic_rx_bd_init_buffer(ring, i);
		if (ret)
			return ret;
	}
	ring->rx_fill_start_idx = 0;
	ring->rx_fill_len = 0;

	ret = lxsnic_configure_rxq_bd(ring);
	if (ret)
		return ret;

	LSXINIC_PMD_DBG("ring_reg->cr %u ring_reg->r_descl %u",
		ring->ep_reg->cr, ring->ep_reg->r_descl);

	return 0;
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
	struct lxsnic_adapter *adapter = LSINIC_DEV_PRIVATE(dev);
	struct lsinic_eth_reg *eth_reg =
		LSINIC_REG_OFFSET(adapter->hw.hw_addr, LSINIC_ETH_REG_OFFSET);
	uint16_t max_qpairs = LSINIC_READ_REG(&eth_reg->max_qpairs);
	struct lxsnic_ring *rx_ring;
	int ret;
	uint64_t base_offset = LSINIC_EP2RC_RING_OFFSET(max_qpairs);
	uint8_t *ep_ring_base, *rc_ring_base;
	uint64_t q_offset = queue_idx * LSINIC_RING_SIZE;
	uint64_t total_offset = base_offset + q_offset;
	enum EP_MEM_BD_TYPE ep_bd = EP_MEM_DST_ADDR_BD;
	enum RC_MEM_BD_TYPE rc_bd = RC_MEM_LEN_CMD;
	char *penv;
	uint16_t mp_data_room;

	LSXINIC_PMD_DBG("config rx_queue");
	ep_ring_base = adapter->bd_desc_base + base_offset;
	rc_ring_base = adapter->rc_bd_desc_base + base_offset;

	if (queue_idx >= max_qpairs) {
		LSXINIC_PMD_ERR("config rxq index(%d) >= max qpair(%d)",
			queue_idx, max_qpairs);
		return -EINVAL;
	}
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
		LSXINIC_PMD_WARN("nb_desc(%d) > max(%d)",
			nb_desc,
			adapter->rx_ring_bd_count);
		nb_desc = adapter->rx_ring_bd_count;
		rx_ring->count = nb_desc;
	} else {
		rx_ring->count = nb_desc;
	}

	LSXINIC_PMD_DBG("config rx_queue %d rx desc %d max desc %d",
		queue_idx, nb_desc, adapter->rx_ring_bd_count);

	mp_data_room = rte_pktmbuf_data_room_size(mp) - RTE_PKTMBUF_HEADROOM;
	if (adapter->max_data_room > mp_data_room) {
		adapter->max_data_room = mp_data_room;
		LSINIC_WRITE_REG(&eth_reg->max_data_room, mp_data_room);
		if (lxsnic_set_netdev(adapter, PCIDEV_COMMAND_SET_MTU)) {
			LSXINIC_PMD_ERR("Set %s's MTU failed!",
				adapter->eth_dev->data->name);
		}
	}

	rx_ring->queue_index = queue_idx;
	rx_ring->port = dev->data->port_id;

	LSXINIC_PMD_DBG("alloc init sw_ring success");
	rx_ring->type = LSINIC_QUEUE_RX;
	rx_ring->adapter = adapter;
	rx_ring->mb_pool = mp;
	rx_ring->ep_bd_mapped_addr = ep_ring_base + q_offset;

	rx_ring->last_avail_idx = 0;
	rx_ring->last_used_idx = 0;
	rx_ring->mhead = 0;
	rx_ring->mtail = 0;
	rx_ring->mcnt = 0;
	LSXINIC_PMD_DBG("prepare config rx_ring");

	rx_ring->rc_bd_shared_addr = rc_ring_base + q_offset;
	rx_ring->rc_bd_desc_dma = adapter->rc_bd_desc_phy + total_offset;
	rx_ring->rc_reg = NULL;
	rx_ring->q_mbuf = rte_zmalloc(NULL,
		sizeof(void *) * rx_ring->count, 64);
	if (!rx_ring->q_mbuf) {
		LSXINIC_PMD_ERR("rxq%d: q_mbuf alloc failed", queue_idx);
		return -ENOMEM;
	}
	rx_ring->seg_mbufs = rte_zmalloc(NULL,
		sizeof(struct lxsnic_seg_mbuf) * rx_ring->count, 64);
	if (!rx_ring->seg_mbufs) {
		LSXINIC_PMD_ERR("rxq%d: seg_mbufs alloc failed", queue_idx);
		return -ENOMEM;
	}

	rx_ring->ep_mem_bd_type = EP_MEM_DST_ADDR_BD;
	rx_ring->rc_mem_bd_type = RC_MEM_LEN_CMD;
	if (adapter->rx_split) {
		rx_ring->ep_mem_bd_type = EP_MEM_DST_ADDR_SEG;
		rx_ring->rc_mem_bd_type = RC_MEM_SEG_LEN;
	} else {
		penv = getenv("LSINIC_RC_RECV_SET_BD");
		if (penv)
			ep_bd = atoi(penv);
		if (ep_bd == EP_MEM_BD_128) {
			LSXINIC_PMD_INFO("RC rxq%d set 128b BD.", queue_idx);
		} else if (ep_bd == EP_MEM_DST_ADDR_BD) {
			LSXINIC_PMD_INFO("RC rxq%d set address BD.", queue_idx);
		} else {
			LSXINIC_PMD_ERR("RC rxq%d set invalid BD(%d).", queue_idx, ep_bd);
			return -EINVAL;
		}
		penv = getenv("LSINIC_RC_RECV_RSP_BD");
		if (penv)
			rc_bd = atoi(penv);
		if (rc_bd == RC_MEM_BD_128) {
			LSXINIC_PMD_INFO("RC recv with 128b BD.");
		} else if (rc_bd == RC_MEM_LEN_CMD) {
			LSXINIC_PMD_INFO("RC recv with len.");
		} else {
			LSXINIC_PMD_ERR("RC recv with invalid BD(%d).", rc_bd);
			return -EINVAL;
		}
		rx_ring->ep_mem_bd_type = ep_bd;
		rx_ring->rc_mem_bd_type = rc_bd;
	}

	if (rx_ring->ep_mem_bd_type == EP_MEM_BD_128) {
		rx_ring->ep_bd_desc = rx_ring->ep_bd_mapped_addr;
	} else if (rx_ring->ep_mem_bd_type == EP_MEM_DST_ADDR_BD) {
		rx_ring->ep_rx_addr = rx_ring->ep_bd_mapped_addr;
	} else if (rx_ring->ep_mem_bd_type == EP_MEM_DST_ADDR_SEG) {
		rx_ring->ep_rx_addr_seg = rx_ring->ep_bd_mapped_addr;
		rx_ring->local_rx_addr_seg = rte_zmalloc(NULL,
			sizeof(struct lsinic_ep_tx_seg_dst_addr),
			RTE_CACHE_LINE_SIZE);
		if (!rx_ring->local_rx_addr_seg) {
			LSXINIC_PMD_ERR("rxq%d: local seg alloc failed",
				queue_idx);
			return -ENOMEM;
		}
	} else {
		rte_panic("Invalid RXQ ep mem bd type(%d)",
			rx_ring->ep_mem_bd_type);
	}

	if (rx_ring->rc_mem_bd_type == RC_MEM_BD_128) {
		rx_ring->rc_bd_desc = rx_ring->rc_bd_shared_addr;
	} else if (rx_ring->rc_mem_bd_type == RC_MEM_LEN_CMD) {
		rx_ring->rx_len = rx_ring->rc_bd_shared_addr;
		memset(rx_ring->rx_len, 0, LSINIC_LEN_RING_SIZE);
	} else if (rx_ring->rc_mem_bd_type == RC_MEM_SEG_LEN) {
		rx_ring->rx_seg = rx_ring->rc_bd_shared_addr;
		memset(rx_ring->rx_seg, 0, LSINIC_SEG_LEN_RING_SIZE);
	} else {
		rte_panic("Invalid RXQ rc mem bd type(%d)",
			rx_ring->rc_mem_bd_type);
	}

	ret = lxsnic_configure_rx_ring(adapter, rx_ring);
	if (ret)
		return ret;
	dev->data->rx_queues[queue_idx] = rx_ring;
	adapter->config_rx_queues++;

	return 0;
}

static void
lxsnic_dev_rx_queue_release(struct rte_eth_dev *dev,
	uint16_t qid)
{
	struct lxsnic_ring *rx_ring = dev->data->rx_queues[qid];

	rx_ring->rc_bd_shared_addr = NULL;
	rx_ring->rc_reg = NULL;
	if (rx_ring->q_mbuf) {
		rte_free(rx_ring->q_mbuf);
		rx_ring->q_mbuf = NULL;
	}
	if (rx_ring->seg_mbufs) {
		rte_free(rx_ring->seg_mbufs);
		rx_ring->seg_mbufs = NULL;
	}
}

static void
lxsnic_dev_tx_queue_release(struct rte_eth_dev *dev,
	uint16_t qid)
{
	struct lxsnic_ring *tx_ring = dev->data->tx_queues[qid];

	/*clean_pci_mem */
	if (tx_ring->rc_bd_shared_addr)
		memset(tx_ring->rc_bd_shared_addr, 0, LSINIC_BD_RING_SIZE);

	if (tx_ring->rc_reg)
		memset(tx_ring->rc_reg, 0, sizeof(*tx_ring->rc_reg));

	tx_ring->rc_bd_shared_addr = NULL;
	tx_ring->rc_reg = NULL;
	if (tx_ring->q_mbuf) {
		rte_free(tx_ring->q_mbuf);
		tx_ring->q_mbuf = NULL;
	}
	if (tx_ring->seg_mbufs) {
		rte_free(tx_ring->seg_mbufs);
		tx_ring->seg_mbufs = NULL;
	}
}

static int
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
	uint32_t txdctl = LSINIC_CR_ENABLE | LSINIC_CR_BUSY, ready;
	struct lsinic_ring_reg *ring_reg = &bdr_reg->tx_ring[reg_idx];
	struct lsinic_ring_reg *rc_ring_reg = &rc_bdr_reg->tx_ring[reg_idx];

	ready = LSINIC_READ_REG(&ring_reg->ready);
	if (ready != LSINIC_INIT_FLAG) {
		LSXINIC_PMD_ERR("TX Ring%d is not ready(0x%08x)!", reg_idx, ready);
		return -EIO;
	}

	/* disable queue to avoid issues while updating state */
	LSINIC_WRITE_REG(&ring_reg->cr, LSINIC_CR_DISABLE);
	LSINIC_WRITE_REG(&ring_reg->pir, 0); /* TDT */
	LSINIC_WRITE_REG(&ring_reg->cir, 0); /* TDH */

	if (ring->rc_bd_shared_addr) {
		LSINIC_WRITE_REG(&ring_reg->r_descl,
			ring->rc_bd_desc_dma & DMA_BIT_MASK(32));
		LSINIC_WRITE_REG(&ring_reg->r_desch,
			ring->rc_bd_desc_dma >> 32);
	}

	LSINIC_WRITE_REG(&ring_reg->isr, 0);
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

	return 0;
}

static int
lxsnic_dev_tx_queue_setup(struct rte_eth_dev *dev,
	uint16_t queue_idx,
	uint16_t nb_desc,
	unsigned int socket_id,
	const struct rte_eth_txconf *tx_conf __rte_unused)
{
	struct lxsnic_ring *tx_ring = NULL;
	struct lxsnic_adapter *adapter = LSINIC_DEV_PRIVATE(dev);
	struct lsinic_eth_reg *eth_reg =
		LSINIC_REG_OFFSET(adapter->hw.hw_addr, LSINIC_ETH_REG_OFFSET);
	uint64_t base_offset, total_offset;
	uint64_t q_offset = queue_idx * LSINIC_RING_SIZE;
	uint16_t max_qpairs = LSINIC_READ_REG(&eth_reg->max_qpairs);
	int ret;

	base_offset = LSINIC_RC2EP_RING_OFFSET(max_qpairs);
	total_offset = base_offset + q_offset;

	if (queue_idx >= max_qpairs) {
		LSXINIC_PMD_ERR("config txq index(%d) >= max qpair(%d)",
			queue_idx, max_qpairs);
		return -EINVAL;
	}
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
	tx_ring->core_id = RTE_MAX_LCORE;
	tx_ring->pid = 0;
	rte_spinlock_init(&tx_ring->multi_core_lock);
	tx_ring->queue_index = queue_idx;
	tx_ring->port = dev->data->port_id;
	tx_ring->adapter = adapter;
	tx_ring->ep_bd_mapped_addr = adapter->bd_desc_base + total_offset;

	tx_ring->last_avail_idx = 0;
	tx_ring->last_used_idx = 0;
	tx_ring->mhead = 0;
	tx_ring->mtail = 0;
	tx_ring->mcnt = 0;
	tx_ring->rc_bd_shared_addr = adapter->rc_bd_desc_base + total_offset;
	tx_ring->rc_bd_desc_dma = adapter->rc_bd_desc_phy + total_offset;

	ret = lxsnic_configure_tx_ring(adapter, tx_ring);
	if (ret)
		return ret;

	tx_ring->q_mbuf = rte_zmalloc(NULL,
		sizeof(void *) * tx_ring->count,
		RTE_CACHE_LINE_SIZE);
	RTE_ASSERT(tx_ring->q_mbuf);
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
	struct lxsnic_adapter *adapter = LSINIC_DEV_PRIVATE(dev);
	/* signal that we are down to the interrupt handler */

	struct lxsnic_ring *ring = NULL;

	set_bit(__LXSNIC_DOWN, &adapter->state);

	/* disable the netdev receive */
	if (lxsnic_set_netdev(adapter, PCIDEV_COMMAND_STOP)) {
		LSXINIC_PMD_ERR("Stop %s failed!",
			adapter->eth_dev->data->name);
	}

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

/**
 * Stop device: disable rx and tx functions to allow for reconfiguring.
 */
static int
lxsnic_dev_stop(struct rte_eth_dev *dev)
{
	lxsnic_down(dev);

	return 0;
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

static int
lxsnic_dev_stats_get(struct rte_eth_dev *dev, struct rte_eth_stats *stats,
	struct eth_queue_stats *qstats __rte_unused)
{
	stats->ipackets = lsxinic_common_get_ipackets(dev, struct lxsnic_ring *);
	stats->opackets = lsxinic_common_get_epackets(dev, struct lxsnic_ring *);
	stats->ibytes = lsxinic_common_get_ibytes(dev, struct lxsnic_ring *);
	stats->obytes = lsxinic_common_get_ebytes(dev, struct lxsnic_ring *);
	stats->ierrors = lsxinic_common_get_ierrs(dev, struct lxsnic_ring *);
	stats->oerrors = lsxinic_common_get_eerrs(dev, struct lxsnic_ring *);
	stats->rx_nombuf = dev->data->rx_mbuf_alloc_failed;

	return 0;
}

static int
lxsnic_dev_stats_reset(struct rte_eth_dev *dev)
{
	lsxinic_common_q_reset(dev, struct lxsnic_ring *);
	dev->data->rx_mbuf_alloc_failed = 0;

	return 0;
}

static int
lxsnic_dev_xstats_reset(struct rte_eth_dev *dev)
{
	return lxsnic_dev_stats_reset(dev);
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
	struct lxsnic_adapter *adapter = LSINIC_DEV_PRIVATE(dev);

	dev_info->device = &pci_dev->device;
	dev_info->max_rx_queues = adapter->num_rx_queues;
	dev_info->max_tx_queues = adapter->num_tx_queues;
	dev_info->max_rx_pktlen = 15872; /* includes CRC, cf MAXFRS register */
	dev_info->max_mac_addrs = 1;

	dev_info->rx_desc_lim = rx_desc_lim;
	dev_info->tx_desc_lim = tx_desc_lim;
	dev_info->rx_offload_capa = RTE_ETH_RX_OFFLOAD_CHECKSUM |
		RTE_ETH_RX_OFFLOAD_BUFFER_SPLIT;
	dev_info->tx_offload_capa = RTE_ETH_TX_OFFLOAD_MULTI_SEGS;

	return 0;
}

static int
lxsnic_dev_close(struct rte_eth_dev *dev)
{
	struct lxsnic_adapter *adapter = LSINIC_DEV_PRIVATE(dev);
	int ret;

	ret = lxsnic_dev_stop(dev);
	if (ret)
		return ret;
	adapter->adapter_stopped = true;
	ret = lxsnic_set_netdev(adapter, PCIDEV_COMMAND_REMOVE);

	return ret;
}

static int
lxsnic_dev_link_update(struct rte_eth_dev *dev,
	int wait_to_complete __rte_unused)
{
	uint32_t rc_state = 0;
	int up = 0, ret;
	struct lxsnic_adapter *adapter = LSINIC_DEV_PRIVATE(dev);
	struct lsinic_rcs_reg *rcs_reg =
		LSINIC_REG_OFFSET(adapter->hw.hw_addr, LSINIC_RCS_REG_OFFSET);
	struct lsinic_dev_reg *ep_reg =
		LSINIC_REG_OFFSET(adapter->hw.hw_addr, LSINIC_DEV_REG_OFFSET);

	rc_state = LSINIC_READ_REG(&rcs_reg->rc_state);
	if (rc_state != adapter->rc_state) {
		if (rc_state == LSINIC_DEV_UP)
			LSXINIC_PMD_INFO("rc link up");
		else
			LSXINIC_PMD_INFO("rc link down");
	}
	adapter->rc_state = rc_state;
	adapter->ep_state = LSINIC_READ_REG(&ep_reg->ep_state);

	if (rc_state == LSINIC_DEV_UP && adapter->ep_state == LSINIC_DEV_UP)
		up = 1;
	ret = lsxinic_common_link_update(dev, up);
	if (ret)
		return ret;

	adapter->link_up = dev->data->dev_link.link_status;
	adapter->link_speed = dev->data->dev_link.link_speed;

	return 0;
}

static struct eth_dev_ops eth_lxsnic_eth_dev_ops = {
	.dev_configure        = lxsnic_dev_configure,
	.dev_start            = lxsnic_dev_start,
	.dev_stop             = lxsnic_dev_stop,
	.dev_close            = lxsnic_dev_close,
	.dev_infos_get        = lxsnic_dev_info_get,
	.mtu_set	      = lxsinic_dev_mtu_set,
	.rx_queue_setup       = lxsnic_dev_rx_queue_setup,
	.rx_queue_release     = lxsnic_dev_rx_queue_release,
	.tx_queue_setup       = lxsnic_dev_tx_queue_setup,
	.tx_queue_release     = lxsnic_dev_tx_queue_release,
	.link_update          = lxsnic_dev_link_update,
	.promiscuous_enable   = lxsnic_dev_promiscuous_enable,
	.promiscuous_disable  = lxsnic_dev_promiscuous_disable,
	.allmulticast_enable  = lxsnic_dev_allmulticast_enable,
	.allmulticast_disable = lxsnic_dev_allmulticast_disable,
	.stats_get            = lxsnic_dev_stats_get,
	.stats_reset          = lxsnic_dev_stats_reset,
	.xstats_get	       = lsxinic_common_xstats_get,
	.xstats_get_by_id     = lsinic_common_xstats_get_by_id,
	.xstats_get_names_by_id = lsinic_common_xstats_get_names_by_id,
	.xstats_get_names      = lsxinic_common_xstats_get_names,
	.xstats_reset          = lxsnic_dev_xstats_reset,
	.rxq_info_get			= lxsnic_dev_rxq_info,
	.txq_info_get			= lxsnic_dev_txq_info,
};

static struct rte_pci_id pci_id_lxsnic_map[32];

static void lxsnic_pre_init_pci_id(void)
{
	int i, num = RTE_DIM(s_lsinic_rev2_id_map);
	char *penv = getenv("LSINIC_PCI_DEVICE_ID");

	memset(pci_id_lxsnic_map, 0, sizeof(pci_id_lxsnic_map));
	for (i = 0; i < (num + 1); i++) {
		pci_id_lxsnic_map[i].class_id = RTE_CLASS_ANY_ID;
		pci_id_lxsnic_map[i].vendor_id = NXP_PCI_VENDOR_ID;
		pci_id_lxsnic_map[i].subsystem_vendor_id = RTE_PCI_ANY_ID;
		pci_id_lxsnic_map[i].subsystem_device_id = RTE_PCI_ANY_ID;
		if (penv) {
			pci_id_lxsnic_map[i].device_id = strtol(penv, 0, 16);
			break;
		}
		if (i < num)
			pci_id_lxsnic_map[i].device_id = s_lsinic_rev2_id_map[i].pci_dev_id;
		else
			pci_id_lxsnic_map[i].device_id = NXP_PCI_DEV_ID_LS2088A;
	}
}

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
	uint32_t i;

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
	struct lxsnic_adapter *adapter = LSINIC_DEV_PRIVATE(param);

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

	adapter->max_data_room = LSINIC_READ_REG(&eth_reg->max_data_room);

	set_bit(__LXSNIC_DOWN, &adapter->state);

	return 0;
}

static void
lxsnic_get_mac_addr(struct lxsnic_hw *hw)
{
	struct lsinic_eth_reg *eth_reg =
		LSINIC_REG_OFFSET(hw->hw_addr, LSINIC_ETH_REG_OFFSET);
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

static void
lxsnic_msix_disable_all(struct lxsnic_adapter *adapter)
{
	int i = 0;
	struct lsinic_rcs_reg *rcs_reg =
		LSINIC_REG_OFFSET(adapter->hw.hw_addr, LSINIC_RCS_REG_OFFSET);

	for (i = 0; i < LSINIC_DEV_MSIX_MAX_NB; i++)
		LSINIC_WRITE_REG(&rcs_reg->msix_mask[i], 0x01);

	LSINIC_WRITE_REG(&rcs_reg->msi_flag, LSINIC_DONT_INT);
}

static int
eth_lsnic_dev_init(struct rte_eth_dev *eth_dev)
{
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);
	struct lxsnic_adapter *adapter = LSINIC_DEV_PRIVATE(eth_dev);
	struct rte_intr_handle *intr_handle = pci_dev->intr_handle;
	struct lxsnic_hw *hw = &adapter->hw;
	struct lsinic_dev_reg *ep_reg = NULL;
	struct lsinic_rcs_reg *rcs_reg = NULL;
	int error = 0, snoop, single_bar;
	const struct rte_memzone *rc_ring_mem = NULL;
	char *penv;
	struct rte_mem_resource *reg_mem_res;
	struct rte_mem_resource *ring_mem_res;
	struct rte_mem_resource *xfer_mem_res;

	LSXINIC_PMD_INFO("start init lsnic driver");
	adapter->eth_dev = eth_dev;
	eth_dev->dev_ops = &eth_lxsnic_eth_dev_ops;
	eth_dev->rx_pkt_burst = lxsnic_eth_recv_pkts;
	/* < Pointer to PMD receive function. */
	eth_dev->tx_pkt_burst = lxsnic_eth_xmit_pkts;
	/* < Pointer to PMD transmit function. */
	if (!g_lsxinic_rc_proc_secondary_standalone) {
		if (rte_eal_process_type() != RTE_PROC_PRIMARY)
			return 0;
	}

	hw->device_id = pci_dev->id.device_id;
	hw->vendor_id = pci_dev->id.vendor_id;

	LSXINIC_PMD_DBG("device_id %d vendor_id %d",
		hw->device_id, hw->vendor_id);

	reg_mem_res = &pci_dev->mem_resource[LSX_PCIEP_REG_BAR_IDX];
	ring_mem_res = &pci_dev->mem_resource[LSX_PCIEP_RING_BAR_IDX];
	xfer_mem_res = &pci_dev->mem_resource[LSX_PCIEP_EP_MEM_POOL_BAR_IDX];

	hw->hw_addr = reg_mem_res->addr;
	if (!hw->hw_addr) {
		LSXINIC_PMD_ERR("hw_addr map failed");
		error = -ENOMEM;
		goto free_adapter;
	}
	ep_reg = LSINIC_REG_OFFSET(hw->hw_addr, LSINIC_DEV_REG_OFFSET);

	if (LSINIC_READ_REG(&ep_reg->init_flag) != LSINIC_INIT_FLAG) {
		LSXINIC_PMD_ERR("EP(state %d) NOT initialized!(0x%08x)",
				LSINIC_READ_REG(&ep_reg->ep_state),
				LSINIC_READ_REG(&ep_reg->init_flag));
		error = -EIO;
		goto free_adapter;
	}

	if (LSINIC_READ_REG(&ep_reg->ep_state) != LSINIC_DEV_UP) {
		LSXINIC_PMD_ERR("EP state(%d) NOT ready",
			LSINIC_READ_REG(&ep_reg->ep_state));
		error = -EIO;
		goto free_adapter;
	}

	snoop = lxsnic_br_of_dev_snoop(pci_dev);
	if (snoop < 0) {
		LSXINIC_PMD_ERR("Read snoop attr of bridge failed(%d)",
			snoop);
		error = snoop;
		goto free_adapter;
	}

	LSINIC_WRITE_REG(&ep_reg->snoop, snoop);

	LSXINIC_PMD_DBG("adapter->hw_addr = 0x%p", hw->hw_addr);

	single_bar = LSINIC_READ_REG(&ep_reg->single_bar);
	if (single_bar) {
		adapter->ep_ring_phy_base = reg_mem_res->phys_addr +
			lsinic_reg_ring_bar_offset(0);
		adapter->ep_ring_virt_base = (uint8_t *)reg_mem_res->addr +
			lsinic_reg_ring_bar_offset(0);
		adapter->rc_ring_align_size = reg_mem_res->len - lsinic_reg_bar_size();
		adapter->rc_ring_align_size = rte_align64pow2(adapter->rc_ring_align_size);
	} else {
		/* eb_ring pci phy mem get */
		adapter->ep_ring_phy_base = ring_mem_res->phys_addr;
		/* ep_ring pci bar addr get */
		adapter->ep_ring_virt_base = ring_mem_res->addr;
		adapter->rc_ring_align_size = ring_mem_res->len;
	}
	if (!adapter->ep_ring_phy_base) {
		LSXINIC_PMD_ERR("eb_ring_phy_base if err");
		return -ENOMEM;
	}
	LSXINIC_PMD_DBG("ep_ring vir %p", adapter->ep_ring_virt_base);

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
	rc_ring_mem = rte_eth_dma_zone_reserve(eth_dev, "rc_ring", 0,
		adapter->rc_ring_align_size, adapter->rc_ring_align_size,
		eth_dev->data->numa_node);
	if (!rc_ring_mem) {
		LSXINIC_PMD_ERR("rc_ring_mem is dma alloc failed");
		error = -ENODEV;
		goto free_adapter;
	}
	adapter->rc_ring_virt_base = rc_ring_mem->addr;
	adapter->rc_ring_phy_base = rc_ring_mem->iova;
	adapter->rc_ring_mz = rc_ring_mem;

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

	if (xfer_mem_res->len) {
		adapter->ep_memzone_phy = xfer_mem_res->phys_addr;
		adapter->ep_memzone_vir = xfer_mem_res->addr;
		adapter->ep_memzone_size = xfer_mem_res->len;
	}
	rc_ring_mem = rte_eth_dma_zone_reserve(eth_dev,
			"rc_memzone", 0, 32 * 1024 * 1024,
			32 * 1024 * 1024, eth_dev->data->numa_node);
	if (!rc_ring_mem) {
		LSXINIC_PMD_WARN("rc_memzone_vir reserve failed");
		adapter->rc_mz = NULL;
	} else {
		adapter->rc_memzone_vir = rc_ring_mem->addr;
		adapter->rc_memzone_iova = rc_ring_mem->iova;
		adapter->rc_memzone_size = 32 * 1024 * 1024;
		adapter->rc_mz = rc_ring_mem;
	}

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

	penv = getenv("LSINIC_SELF_XMIT_TEST");
	if (penv) {
		adapter->self_test = atoi(penv);
		if (adapter->self_test > LXSNIC_RC_SELF_LOCAL_MEM_TEST) {
			LSXINIC_PMD_WARN("Invalid self test mode(%d)",
				adapter->self_test);
			adapter->self_test = LXSNIC_RC_SELF_NONE_TEST;
		}
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
		adapter->self_test = LXSNIC_RC_SELF_NONE_TEST;
	}

	penv = getenv("LSINIC_RC_START_EP_PCI_DMA_DEMO");
	if (penv) {
		if (lxsnic_set_netdev(adapter, PCIDEV_COMMAND_DMA_TEST)) {
			LSXINIC_PMD_ERR("Start %s's DMA demo failed!",
				adapter->eth_dev->data->name);
		}
	}

	/* register interrupt function for user to
	 * call interrupt by dpdk eal lib
	 */
	rte_intr_callback_register(intr_handle,
		eth_lxsnic_interrupt_handler, (void *)eth_dev);

	return 0;

free_adapter:

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
		if (!mapaddr) {
			mapaddr = mmap(NULL, dev->mem_resource[i].len,
					PROT_READ | PROT_WRITE, MAP_SHARED, -1,
					dev->mem_resource[i].phys_addr);
			LSXINIC_PMD_INFO("%s: bar[%d] map phy(%lx)",
				"RC Simulator",
				i, dev->mem_resource[i].phys_addr);
			if (mapaddr == MAP_FAILED) {
				LSXINIC_PMD_ERR("%s: map bar[%d](%lx) failed",
					"RC Simulator",
					i, dev->mem_resource[i].phys_addr);
				return -ENOMEM;
			}
		}
		dev->mem_resource[i].addr = mapaddr;
		map_idx++;
	}

	return 0;
}

static uint16_t
lxsnic_proc_secondary_find_free_port(void)
{
	uint32_t i;

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

	name_len = strlen(name);
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

	strcpy(eth_dev->data->name, name);
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
	eth_dev->data->dev_private = rte_zmalloc_socket(pci_dev->name,
		sizeof(struct lxsnic_adapter), RTE_CACHE_LINE_SIZE,
		pci_dev->device.numa_node);
	if (!eth_dev->data->dev_private) {
		rte_eth_dev_release_port(eth_dev);
		return -ENOMEM;
	}
	eth_dev->device = &pci_dev->device;
	rte_eth_copy_pci_info(eth_dev, pci_dev);
	ret = eth_lsnic_dev_init(eth_dev);
	if (!ret)
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
eth_lxsnic_close(struct rte_eth_dev *dev)
{
	struct lxsnic_adapter *adapter = LSINIC_DEV_PRIVATE(dev);

	if (!adapter)
		return;
	set_bit(__LXSNIC_DOWN, &adapter->state);

	if (adapter->num_vfs)
		lxsnic_disable_sriov(adapter);

	if (lxsnic_set_netdev(adapter, PCIDEV_COMMAND_REMOVE)) {
		LSXINIC_PMD_ERR("Remove %s failed!",
			adapter->eth_dev->data->name);
	}
	if (adapter->rc_ring_mz) {
		rte_eth_dma_zone_free(dev,
			adapter->rc_ring_mz->name, 0);
	}
	if (adapter->rc_mz) {
		rte_eth_dma_zone_free(dev,
			adapter->rc_mz->name, 0);
	}

	rte_free(adapter);
}

static int
eth_lxsnic_dev_uninit(struct rte_eth_dev *eth_dev)
{
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);
	struct lxsnic_adapter *adapter = LSINIC_DEV_PRIVATE(eth_dev);
	struct rte_intr_handle *intr_handle = pci_dev->intr_handle;

	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return -EPERM;

	if (!adapter->adapter_stopped)
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

static int
lxsnic_rc_seg_bd_init_buffer(struct lxsnic_ring *rx_queue,
	uint16_t idx)
{
	uint64_t dma_addr = 0;
	struct lsinic_ep_tx_seg_dst_addr *ep_rx_seg = NULL;
	struct lsinic_ep_tx_seg_dst_addr local_rx_seg;
	struct lxsnic_seg_mbuf *seg_mbuf;
	int ret, i;
	struct rte_mbuf *mbuf;

	ep_rx_seg = &rx_queue->ep_rx_addr_seg[idx];
	seg_mbuf = &rx_queue->seg_mbufs[idx];
	ret = rte_pktmbuf_alloc_bulk(rx_queue->mb_pool,
		seg_mbuf->mbufs, LSINIC_EP_TX_SEG_MAX_ENTRY);
	if (ret) {
		struct rte_eth_dev_data *dev_data;

		LSXINIC_PMD_ERR("RX mbuf alloc failed queue_id=%u",
			(unsigned int)rx_queue->queue_index);
		dev_data = rte_eth_devices[rx_queue->port].data;
		dev_data->rx_mbuf_alloc_failed++;
		return -ENOMEM;
	}

	seg_mbuf->count = LSINIC_EP_TX_SEG_MAX_ENTRY;

	mbuf = seg_mbuf->mbufs[0];
	mbuf->data_off = RTE_PKTMBUF_HEADROOM;
	mbuf->port = rx_queue->port;
	dma_addr = rte_mbuf_data_iova_default(mbuf);
	dma_addr = rte_cpu_to_le_64(dma_addr);
	memset(&local_rx_seg, 0,
		sizeof(struct lsinic_ep_tx_seg_dst_addr));
	local_rx_seg.addr_base = dma_addr;
	local_rx_seg.entry[0].positive = 0;
	local_rx_seg.entry[0].offset = 0;
	local_rx_seg.ready = 1;
	rte_memcpy(ep_rx_seg, &local_rx_seg,
		sizeof(struct lsinic_ep_tx_seg_dst_addr));

	for (i = 1; i < LSINIC_EP_TX_SEG_MAX_ENTRY; i++) {
		mbuf = seg_mbuf->mbufs[i];
		mbuf->data_off = RTE_PKTMBUF_HEADROOM;
		mbuf->port = rx_queue->port;
		dma_addr = rte_mbuf_data_iova_default(mbuf);
		dma_addr = rte_cpu_to_le_64(dma_addr);
		if (dma_addr > local_rx_seg.addr_base) {
			if ((dma_addr - local_rx_seg.addr_base) >
				LSINIC_SEG_OFFSET_MAX) {
				LSXINIC_PMD_ERR("%s: 0x%lx - 0x%lx > 0x%lx",
					__func__, (unsigned long)dma_addr,
					(unsigned long)local_rx_seg.addr_base,
					(unsigned long)LSINIC_SEG_OFFSET_MAX);
				return -EFAULT;
			}
			local_rx_seg.entry[i].positive = 1;
			local_rx_seg.entry[i].offset =
				dma_addr - local_rx_seg.addr_base;
		} else {
			if ((local_rx_seg.addr_base - dma_addr) >
				LSINIC_SEG_OFFSET_MAX) {
				LSXINIC_PMD_ERR("%s: 0x%lx - 0x%lx > 0x%lx",
					__func__,
					(unsigned long)local_rx_seg.addr_base,
					(unsigned long)dma_addr,
					(unsigned long)LSINIC_SEG_OFFSET_MAX);
				return -EFAULT;
			}
			local_rx_seg.entry[i].positive = 0;
			local_rx_seg.entry[i].offset =
				local_rx_seg.addr_base - dma_addr;
		}
		ep_rx_seg->entry[i].seg_entry =
			local_rx_seg.entry[i].seg_entry;
	}
	LSINIC_WRITE_REG(&rx_queue->ep_reg->pir, 0);

	return 0;
}

int
lxsnic_rx_bd_init_buffer(struct lxsnic_ring *rx_queue,
	uint16_t idx)
{
	struct lsinic_bd_desc_128 *ep_rx_desc = NULL, rc_rx_desc;
	struct rte_mbuf *mbuf;
	uint64_t dma_addr = 0;
	struct lsinic_ep_tx_dst_addr *ep_rx_addr = NULL;

	if (rx_queue->ep_mem_bd_type == EP_MEM_DST_ADDR_SEG)
		return lxsnic_rc_seg_bd_init_buffer(rx_queue, idx);

	if (rx_queue->ep_mem_bd_type == EP_MEM_BD_128) {
		ep_rx_desc = &rx_queue->ep_bd_desc[idx];
	} else if (rx_queue->ep_mem_bd_type == EP_MEM_DST_ADDR_BD) {
		ep_rx_addr = &rx_queue->ep_rx_addr[idx];
	} else {
		rte_panic("RXQ%d ep mem type(%d) not support",
			rx_queue->queue_index, rx_queue->ep_mem_bd_type);
	}

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

	memset(&rc_rx_desc, 0, sizeof(struct lsinic_bd_desc_128));
	rc_rx_desc.pkt_addr = dma_addr;

	rx_queue->q_mbuf[idx] = mbuf;
	rc_rx_desc.bd_status = RING_BD_READY;
	if (ep_rx_desc)
		rte_memcpy(ep_rx_desc, &rc_rx_desc, sizeof(struct lsinic_bd_desc_128));
	else
		ep_rx_addr->pkt_addr = dma_addr;
	LSINIC_WRITE_REG(&rx_queue->ep_reg->pir, 0);

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

	lxsnic_pre_init_pci_id();

	lsxinic_common_xstats_add_cb(s_lxsnic_xstat_cbs);

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
RTE_PMD_EXPORT_NAME(net_lxsnic);
RTE_PMD_REGISTER_PCI_TABLE(net_lxsnic, pci_id_lxsnic_map);
RTE_PMD_REGISTER_KMOD_DEP(net_lxsnic, "* igb_uio | uio_pci_generic");
