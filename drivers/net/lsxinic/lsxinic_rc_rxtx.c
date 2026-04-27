/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018-2026 NXP
 */

#include <stdio.h>
#include <sys/queue.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>

#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_log.h>
#include <rte_debug.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_launch.h>
#include <rte_tailq.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_prefetch.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_sctp.h>

#include "lsxinic_common.h"
#include "lsxinic_common_helper.h"
#include "lsxinic_rc_rxtx.h"
#include "lsxinic_rc_hw.h"

#include "lsxinic_self_test_data.h"

/* Default RS bit threshold values */
#ifndef DEFAULT_TX_RS_THRESH
#define DEFAULT_TX_RS_THRESH   32
#endif

/* TX queues list */
TAILQ_HEAD(lxsnic_tx_queue_list, lxsnic_ring);

/* per thread TX queue list */
RTE_DEFINE_PER_LCORE(uint8_t, lxsnic_txq_list_initialized);
RTE_DEFINE_PER_LCORE(uint8_t, lxsnic_txq_num_in_list);
RTE_DEFINE_PER_LCORE(struct lxsnic_tx_queue_list, lxsnic_txq_list);

static RTE_DEFINE_PER_LCORE(pthread_t, pthrd_id);
static RTE_DEFINE_PER_LCORE(int, txq_added[LSINIC_RING_MAX_COUNT]);

static int lxsnic_add_txq_to_list(struct lxsnic_ring *txq)
{
	struct lxsnic_ring *queue = NULL;

	if (txq->core_id != RTE_MAX_LCORE)
		return 0;

	if (!RTE_PER_LCORE(lxsnic_txq_list_initialized)) {
		TAILQ_INIT(&RTE_PER_LCORE(lxsnic_txq_list));
		RTE_PER_LCORE(lxsnic_txq_list_initialized) = 1;
		RTE_PER_LCORE(lxsnic_txq_num_in_list) = 0;
	}

	/* Check if txq already added to list */
	TAILQ_FOREACH(queue, &RTE_PER_LCORE(lxsnic_txq_list), next) {
		if (queue == txq)
			return 0;
	}

	TAILQ_INSERT_TAIL(&RTE_PER_LCORE(lxsnic_txq_list), txq, next);
	txq->core_id = rte_lcore_id();
	txq->pid = pthread_self();
	RTE_PER_LCORE(lxsnic_txq_num_in_list)++;

	LSXINIC_PMD_DBG("Add port%d txq%d to list NUM%d",
		txq->port, txq->queue_index,
		RTE_PER_LCORE(lxsnic_txq_num_in_list));

	return 0;
}

static void lxsnic_tx_complete_ring_clean(struct lxsnic_ring *tx_ring)
{
	uint16_t bd_idx;
	struct rte_mbuf *last_mbuf;
	uint8_t *tx_complete = &tx_ring->tx_complete->bd_complete;

	bd_idx = tx_ring->last_used_idx & (tx_ring->count - 1);

	rte_rmb();

	do {
		if (tx_complete[bd_idx] != RING_BD_HW_COMPLETE)
			break;

		last_mbuf = tx_ring->q_mbuf[bd_idx];
		RTE_ASSERT(last_mbuf);
		rte_pktmbuf_free(last_mbuf);

		tx_complete[bd_idx] = RING_BD_READY;

		tx_ring->last_used_idx++;

		bd_idx = tx_ring->last_used_idx & (tx_ring->count - 1);

		rte_rmb();
	} while (1);
}

static void lxsnic_tx_ring_clean(struct lxsnic_ring *tx_ring)
{
	uint16_t bd_idx;
	uint32_t status;
	struct lsinic_bd_desc_128 *rc_tx_desc;
	struct rte_mbuf *last_mbuf;

	bd_idx = tx_ring->last_used_idx & (tx_ring->count - 1);
	rc_tx_desc = &tx_ring->rc_bd_desc[bd_idx];

	status = rc_tx_desc->bd_status;

	rte_rmb();

	do {
		if (status != RING_BD_HW_COMPLETE)
			break;

		last_mbuf = tx_ring->q_mbuf[bd_idx];
		RTE_ASSERT(last_mbuf);
		rte_pktmbuf_free(last_mbuf);

		rc_tx_desc->bd_status = RING_BD_READY;

		tx_ring->last_used_idx++;

		bd_idx = tx_ring->last_used_idx & (tx_ring->count - 1);
		rc_tx_desc = &tx_ring->rc_bd_desc[bd_idx];
		status = rc_tx_desc->bd_status;

		rte_rmb();
	} while (1);
}

static void lxsnic_tx_ring_idx_clean(struct lxsnic_ring *tx_ring)
{
	uint32_t start_free_idx = tx_ring->last_used_idx, i = 0;
	const uint32_t last_free_idx = tx_ring->rc_reg->cir;
	struct rte_mbuf *mbufs[LSINIC_MAX_BURST_NUM];
	struct lsinic_bd_desc_128 *rc_bd_desc = tx_ring->rc_bd_desc;
	union lsinic_bd_desc_64 *rc_bd_desc_64 = tx_ring->rc_bd_desc_64;
	struct lsinic_seg_desc *rc_sg_desc = tx_ring->rc_sg_desc;

	start_free_idx = start_free_idx & (tx_ring->count - 1);

	while (start_free_idx != last_free_idx) {
		mbufs[i] = tx_ring->q_mbuf[start_free_idx];
		i++;

		if (rc_bd_desc)
			rc_bd_desc[start_free_idx].bd_status = RING_BD_READY;
		else if (rc_bd_desc_64)
			rc_bd_desc_64[start_free_idx].desc = 0;
		else if (rc_sg_desc)
			rc_sg_desc[start_free_idx].nb = 0;

		tx_ring->last_used_idx++;
		start_free_idx = (start_free_idx + 1) & (tx_ring->count - 1);
		if (i >= LSINIC_MAX_BURST_NUM)
			break;
	}

	if (i > 0)
		rte_pktmbuf_free_bulk(mbufs, i);
}

static int
lxsnic_xmit_one_pkt(struct lxsnic_ring *tx_ring,
	struct rte_mbuf *tx_pkt)
{
	dma_addr_t dma;
	uint16_t bd_idx = 0;
	uint32_t cmd_type, pkt_len = 0;
	struct lsinic_bd_desc_128 *rc_tx_desc;
	union lsinic_bd_desc_64 *rc_tx_desc_64;
	uint8_t *tx_complete;
	char *pdata = NULL;

	if (tx_pkt->nb_segs > 1)
		return -EINVAL;

	dma = rte_mbuf_data_iova(tx_pkt);
	if (tx_ring->ep_mem_bd_type == EP_MEM_SRC_BD_64) {
		if (dma & (~LSINIC_BD_DESC_64_ADDR_MASK)) {
			LSXINIC_PMD_DBG("Fatal TX addr(0x%lx) > 0x%lx",
				dma, LSINIC_BD_DESC_64_ADDR_MASK);
			return -EINVAL;
		}
	}

	bd_idx = tx_ring->last_avail_idx & (tx_ring->count - 1);

	if (tx_ring->rc_mem_bd_type == RC_MEM_IDX_CNF) {
		if (unlikely(((bd_idx + 1) & (tx_ring->count - 1)) ==
			(tx_ring->last_used_idx & (tx_ring->count - 1)))) {
			/** Make special room, otherwise no way to
			 * identify ring is empty or full.
			 */
			tx_ring->ring_full++;
			tx_ring->errors++;
			LSXINIC_PMD_DBG("TX ring is full, BD=%d", bd_idx);
			return -EAGAIN;
		}
		tx_ring->q_mbuf[bd_idx] = tx_pkt;
	} else if (tx_ring->rc_mem_bd_type == RC_MEM_BD_CNF) {
		tx_complete = &tx_ring->tx_complete[bd_idx].bd_complete;
		if (*tx_complete != RING_BD_READY) {
			if (tx_ring->ep_bd_desc &&
				tx_ring->ep_bd_desc[bd_idx].bd_status == RING_BD_HW_COMPLETE) {
				/** Workaround to sync with EP BD status.*/
				*tx_complete = RING_BD_HW_COMPLETE;
				tx_ring->sync_err++;
			}
			tx_ring->ring_full++;
			tx_ring->errors++;
			return -EAGAIN;
		}
		*tx_complete = RING_BD_AVAILABLE;
		tx_ring->q_mbuf[bd_idx] = tx_pkt;
	} else if (tx_ring->rc_mem_bd_type == RC_MEM_BD_128) {
		rc_tx_desc = &tx_ring->rc_bd_desc[bd_idx];
		if (rc_tx_desc->bd_status != RING_BD_READY) {
			tx_ring->ring_full++;
			tx_ring->errors++;
			return -EAGAIN;
		}

		tx_ring->q_mbuf[bd_idx] = tx_pkt;
		rc_tx_desc->bd_status = RING_BD_AVAILABLE;
	}

	pkt_len = tx_pkt->pkt_len;  /* total packet length */
	cmd_type = LSINIC_BD_CMD_EOP;
	if (tx_ring->adapter->dma_mem_complete) {
		pdata = (char *)rte_pktmbuf_mtod(tx_pkt, char *);
		*((uint8_t *)pdata + pkt_len) = LSINIC_XFER_COMPLETE_DONE_FLAG;
	}

	/* write last descriptor with RS and EOP bits */

	if (tx_ring->ep_mem_bd_type == EP_MEM_BD_128) {
		RTE_ASSERT(tx_ring->rc_bd_desc);
		rc_tx_desc = &tx_ring->rc_bd_desc[bd_idx];
		cmd_type |= pkt_len;
		rc_tx_desc->pkt_addr = dma;
		rc_tx_desc->len_cmd = cmd_type;
		rc_tx_desc->bd_status = RING_BD_AVAILABLE;
	} else {
		RTE_ASSERT(tx_ring->rc_bd_desc_64);
		rc_tx_desc_64 = &tx_ring->rc_bd_desc_64[bd_idx];
		rc_tx_desc_64->pkt_addr = dma;
		rc_tx_desc_64->len_cmd = pkt_len;
	}

	tx_ring->packets++;
	tx_ring->bytes += tx_pkt->pkt_len;
	tx_ring->bytes_fcs += tx_pkt->pkt_len + LSINIC_ETH_FCS_SIZE;
	tx_ring->bytes_overhead += tx_pkt->pkt_len + LSINIC_ETH_OVERHEAD_SIZE;
	tx_ring->last_avail_idx++;

	return 0;
}

static int
lxsnic_xmit_one_seg_pkt(struct lxsnic_ring *tx_ring,
	struct rte_mbuf *tx_pkt)
{
	dma_addr_t dma;
	struct rte_mbuf *pkt_curr = NULL;
	uint16_t bd_idx = 0, idx, copy_len;
	struct lsinic_seg_desc *ep_sg_desc = 0;
	struct lsinic_seg_desc *local_sg_desc;
	char *pdata = NULL;

	bd_idx = tx_ring->last_avail_idx & (tx_ring->count - 1);

	ep_sg_desc = &tx_ring->ep_tx_sg[bd_idx];
	local_sg_desc = &tx_ring->rc_sg_desc[bd_idx];

	if (tx_ring->rc_mem_bd_type == RC_MEM_IDX_CNF) {
		if (unlikely(((bd_idx + 1) & (tx_ring->count - 1)) ==
			(tx_ring->last_used_idx & (tx_ring->count - 1)))) {
			/** Make special room, otherwise no way to
			 * identify ring is empty or full.
			 */
			tx_ring->ring_full++;
			tx_ring->errors++;
			return -EAGAIN;
		}
		tx_ring->q_mbuf[bd_idx] = tx_pkt;
	} else {
		return -EINVAL;
	}

	local_sg_desc->base_addr = tx_pkt->buf_iova + tx_pkt->data_off;
	local_sg_desc->entry[0].positive = 0;
	local_sg_desc->entry[0].offset = 0;
	if (tx_pkt->data_len == tx_pkt->pkt_len ||
		tx_pkt->nb_segs <= 1) {
		local_sg_desc->entry[0].len = tx_pkt->pkt_len;
		local_sg_desc->nb = 1;
	} else {
		pkt_curr = tx_pkt;
		local_sg_desc->entry[0].len = pkt_curr->data_len;
		for (idx = 1; idx < tx_pkt->nb_segs; idx++) {
			pkt_curr = pkt_curr->next;
			dma = pkt_curr->buf_iova + pkt_curr->data_off;
			if (dma > local_sg_desc->base_addr) {
				local_sg_desc->entry[idx].positive = 1;
				local_sg_desc->entry[idx].offset =
					dma - local_sg_desc->base_addr;
			} else {
				local_sg_desc->entry[idx].positive = 0;
				local_sg_desc->entry[idx].offset =
					local_sg_desc->base_addr - dma;
			}
			local_sg_desc->entry[idx].len = pkt_curr->data_len;
		}
		local_sg_desc->nb = tx_pkt->nb_segs;
	}

	if (tx_ring->adapter->dma_mem_complete) {
		if (pkt_curr) {
			pdata = (char *)rte_pktmbuf_mtod(pkt_curr, char *);
			*((uint8_t *)pdata + pkt_curr->data_len) =
				LSINIC_XFER_COMPLETE_DONE_FLAG;
		} else {
			pdata = (char *)rte_pktmbuf_mtod(tx_pkt, char *);
			*((uint8_t *)pdata + tx_pkt->pkt_len) =
				LSINIC_XFER_COMPLETE_DONE_FLAG;
		}
	}

	copy_len = sizeof(uint64_t) +
		sizeof(struct lsinic_seg_desc_entry) * local_sg_desc->nb;

	lsinic_pcie_memcp_align(ep_sg_desc,
		local_sg_desc, copy_len);
	rte_wmb();
	ep_sg_desc->nb = local_sg_desc->nb;

	tx_ring->packets += local_sg_desc->nb;
	tx_ring->bytes += tx_pkt->pkt_len;
	tx_ring->bytes_fcs += tx_pkt->pkt_len + LSINIC_ETH_FCS_SIZE;
	tx_ring->bytes_overhead += tx_pkt->pkt_len +
			LSINIC_ETH_OVERHEAD_SIZE;

	tx_ring->last_avail_idx++;

	return 0;
}

static inline void
lxsnic_eth_xmit_notify(struct lxsnic_ring *txq,
	uint16_t start, uint16_t num)
{
	void *src, *dst;
	uint16_t i, idx;

	if (txq->ep_mem_bd_type == EP_MEM_BD_128) {
		for (i = 0; i < num; i++) {
			idx = (start + i) & (txq->count - 1);
			src = &txq->rc_bd_desc[idx];
			dst = &txq->ep_bd_desc[idx];
			mem_cp128b_atomic(dst, src);
		}
	} else if (txq->ep_mem_bd_type == EP_MEM_SRC_BD_64) {
		src = &txq->rc_bd_desc_64[start];
		dst = &txq->ep_bd_desc_64[start];
		if ((start + num) <= txq->count) {
			rte_memcpy(dst, src,
				num * sizeof(union lsinic_bd_desc_64));
		} else {
			rte_memcpy(dst, src,
				(txq->count - start) * sizeof(union lsinic_bd_desc_64));
			dst = &txq->ep_bd_desc_64[0];
			src = &txq->rc_bd_desc_64[0];
			rte_memcpy(dst, src,
				(num - (txq->count - start)) * sizeof(union lsinic_bd_desc_64));
		}
	} else {
		LSXINIC_PMD_ERR("%s: type(%d) of bd in ep mem un-support",
			__func__, txq->ep_mem_bd_type);

		return;
	}
}

static uint16_t
_lxsnic_eth_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts,
		uint16_t nb_pkts)
{
	int ret = 0;
	uint8_t ret_val = 0;
	uint16_t total_nb_pkts = nb_pkts;
	struct lxsnic_ring *tx_ring = tx_queue;
	struct rte_mbuf *free_pkts[LSINIC_MAX_BURST_NUM];
	uint16_t free_nb = 0, tx_num = 0;
	uint16_t start = tx_ring->last_avail_idx & (tx_ring->count - 1);

	tx_ring->loop_total++;

	if (tx_ring->rc_reg)
		ret_val = LSINIC_READ_REG(&tx_ring->rc_reg->sr);
	else
		ret_val = LSINIC_READ_REG(&tx_ring->ep_reg->sr);

	tx_ring->status = ret_val;

	if (unlikely(!RTE_PER_LCORE(txq_added[tx_ring->queue_index]))) {
		rte_spinlock_lock(&tx_ring->multi_core_lock);
		lxsnic_add_txq_to_list(tx_ring);
		rte_spinlock_unlock(&tx_ring->multi_core_lock);
		RTE_PER_LCORE(txq_added[tx_ring->queue_index]) = 1;
	} else {
		lxsnic_add_txq_to_list(tx_ring);
	}

	if (unlikely(!RTE_PER_LCORE(pthrd_id)))
		RTE_PER_LCORE(pthrd_id) = pthread_self();

	if (tx_ring->pair && unlikely(tx_ring->core_id !=
		rte_lcore_id() || !pthread_equal(tx_ring->pid,
		RTE_PER_LCORE(pthrd_id)))) {
		if (!tx_ring->multi_core_ring) {
			char ring_name[RTE_MEMZONE_NAMESIZE];

			sprintf(ring_name, "tx_ring_mpsc_ring_%d_%d",
				tx_ring->port, tx_ring->queue_index);
			rte_spinlock_lock(&tx_ring->multi_core_lock);
			if (tx_ring->multi_core_ring) {
				rte_spinlock_unlock(&tx_ring->multi_core_lock);
				goto eq_start;
			}
			tx_ring->multi_core_ring = rte_ring_create(ring_name,
				tx_ring->count, rte_socket_id(),
				RING_F_SC_DEQ);
			rte_spinlock_unlock(&tx_ring->multi_core_lock);
			if (tx_ring->multi_core_ring) {
				LSXINIC_PMD_INFO("%s created on core%d",
					ring_name, rte_lcore_id());
			} else {
				LSXINIC_PMD_ERR("%s created on core%d failed",
					ring_name, rte_lcore_id());
				return 0;
			}
		}

eq_start:
		ret = rte_ring_mp_enqueue_burst(tx_ring->multi_core_ring,
			(void * const *)tx_pkts, nb_pkts, NULL);
		return ret;
	}

	if (ret_val == LSINIC_QUEUE_STOP) {
		if (ret_val != tx_ring->ep_sr)
			LSXINIC_PMD_DBG("ep-rx queue down");

		tx_ring->ep_sr = ret_val;
		tx_ring->errors++;
		tx_num = 0;
		goto end_of_tx;
	}

	if (tx_ring->rc_mem_bd_type == RC_MEM_BD_CNF)
		lxsnic_tx_complete_ring_clean(tx_ring);
	else if (tx_ring->rc_mem_bd_type == RC_MEM_IDX_CNF)
		lxsnic_tx_ring_idx_clean(tx_ring);
	else
		lxsnic_tx_ring_clean(tx_ring);

	nb_pkts = (uint16_t)RTE_MIN(tx_ring->count, total_nb_pkts);
	if (unlikely(!nb_pkts)) {
		tx_num = 0;
		goto end_of_tx;
	}

	if (tx_ring->ep_mem_bd_type == EP_MEM_SRC_SEG_BD) {
		while (nb_pkts) {
			ret = lxsnic_xmit_one_seg_pkt(tx_ring, tx_pkts[tx_num]);
			if (likely(!ret)) {
				tx_num++;
				nb_pkts--;
			} else {
				break;
			}
		}
		return tx_num;
	}

	while (nb_pkts) {
		ret = lxsnic_xmit_one_pkt(tx_ring, tx_pkts[tx_num]);
		if (ret)
			goto end_of_tx;

		tx_num++;
		nb_pkts--;
	}

end_of_tx:
	if (tx_num > 0)
		lxsnic_eth_xmit_notify(tx_ring, start, tx_num);

	if (free_nb > 0)
		rte_pktmbuf_free_bulk(free_pkts, free_nb);

	tx_ring->loop_avail++;

	tx_ring->drop_packet_num += (total_nb_pkts - tx_num);

	return tx_num;
}

uint16_t
lxsnic_eth_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts,
	uint16_t nb_pkts)
{
	struct lxsnic_ring *tx_ring = (struct lxsnic_ring *)tx_queue;

	if (unlikely(tx_ring->adapter->self_test !=
		LXSNIC_RC_SELF_NONE_TEST))
		return 0;

	return _lxsnic_eth_xmit_pkts(tx_queue, tx_pkts, nb_pkts);
}

static struct rte_mbuf *
lxsnic_fetch_rx_buffer(struct lxsnic_ring *rx_queue,
	void *rx_desc)
{
	struct rte_mbuf *mbuf;
	uint16_t rx_packet_len, mbuf_idx;
	struct lsinic_bd_desc_128 *bd_desc;
	struct lsinic_rc_rx_len *rx_len;

	mbuf_idx = rx_queue->last_used_idx & (rx_queue->count - 1);
	mbuf = rx_queue->q_mbuf[mbuf_idx];
	if (rx_queue->rc_mem_bd_type == RC_MEM_LEN_CMD) {
		rx_len = rx_desc;
		rx_packet_len = rx_len->total_len;
	} else {
		bd_desc = rx_desc;
		rx_packet_len = LSINIC_READ_REG(&bd_desc->len_cmd) &
			LSINIC_BD_LEN_MASK;
	}

	RTE_ASSERT(mbuf);

	rte_lxsnic_prefetch(mbuf);

	if (rx_packet_len  > rx_queue->adapter->max_data_room) {
		LSXINIC_PMD_ERR("recv pkt len %d, too big!",
			rx_packet_len);

		return NULL;
	}

	mbuf->data_off = RTE_PKTMBUF_HEADROOM;
	rte_lxsnic_packet_prefetch((char *)mbuf->buf_addr);
	mbuf->nb_segs = 1;
	mbuf->next = NULL;
	mbuf->pkt_len = rx_packet_len;
	mbuf->data_len = rx_packet_len;
	mbuf->port = rx_queue->port;
	mbuf->packet_type = RTE_PTYPE_L3_IPV4;
	/* TODO populate checksum, timestamp, VLAN, and protocol */

	return mbuf;
}

static inline void
lxsnic_rx_bd_128b_fill(struct lxsnic_ring *rx_queue, uint16_t start_idx,
	struct rte_mbuf *mbufs[], int count)
{
	int cnt = 0;
	uint64_t dma_addr = 0;
	uint16_t idx = start_idx;
	struct lsinic_bd_desc_128 *ep_rx_desc = NULL, *rc_rx_desc = NULL;
	struct lsinic_bd_desc_128 local_rx_desc;

	ep_rx_desc = rx_queue->ep_bd_desc;
	while (cnt < count) {
		mbufs[cnt]->data_off = RTE_PKTMBUF_HEADROOM;
		mbufs[cnt]->port = rx_queue->port;
		dma_addr = rte_mbuf_data_iova_default(mbufs[cnt]);

		if (rx_queue->rc_mem_bd_type == RC_MEM_BD_128) {
			rc_rx_desc = &rx_queue->rc_bd_desc[idx];
		} else {
			rx_queue->rx_len[idx].total_len = 0;
			rc_rx_desc = &local_rx_desc;
			memset(rc_rx_desc, 0, sizeof(struct lsinic_bd_desc_128));
		}
		rc_rx_desc->pkt_addr = dma_addr;
		rc_rx_desc->bd_status = RING_BD_READY;
		rte_memcpy(&ep_rx_desc[idx], rc_rx_desc,
			sizeof(struct lsinic_bd_desc_128));
		rx_queue->q_mbuf[idx] = mbufs[cnt];
		cnt++;
		idx = (idx + 1) & (rx_queue->count - 1);
	}
}

static inline void
lxsnic_rx_bd_addr_fill(struct lxsnic_ring *rx_queue, uint16_t start_idx,
	struct rte_mbuf *mbufs[], int count)
{
	int cnt = 0;
	uint64_t dma_addr = 0;
	uint16_t idx = start_idx;
	struct lsinic_ep_tx_dst_addr *local_recv_addr;

	local_recv_addr = rx_queue->rc_rx_addr;

	while (cnt < count) {
		mbufs[cnt]->data_off = RTE_PKTMBUF_HEADROOM;
		mbufs[cnt]->port = rx_queue->port;
		dma_addr = rte_mbuf_data_iova_default(mbufs[cnt]);

		local_recv_addr[idx].pkt_addr = dma_addr;
		if (rx_queue->rc_mem_bd_type == RC_MEM_LEN_CMD)
			rx_queue->rx_len[idx].total_len = 0;
		rx_queue->q_mbuf[idx] = mbufs[cnt];
		cnt++;
		idx = (idx + 1) & (rx_queue->count - 1);
	}

	if ((start_idx + cnt) <= rx_queue->count) {
		memcpy(&rx_queue->ep_rx_addr[start_idx],
			&local_recv_addr[start_idx],
			sizeof(uint64_t) * cnt);
	} else {
		memcpy(&rx_queue->ep_rx_addr[start_idx],
			&local_recv_addr[start_idx],
			sizeof(uint64_t) *
			(rx_queue->count - start_idx));
		memcpy(&rx_queue->ep_rx_addr[0],
			&local_recv_addr[0],
			sizeof(uint64_t) *
			(start_idx + cnt - rx_queue->count));
	}
}

static void
lxsnic_rx_bd_fill(struct lxsnic_ring *rx_queue, uint16_t start_idx,
	struct rte_mbuf *mbufs[], int count)
{
	if (unlikely(!count))
		return;

	if (rx_queue->ep_mem_bd_type == EP_MEM_DST_ADDR_BD)
		lxsnic_rx_bd_addr_fill(rx_queue, start_idx, mbufs, count);
	else
		lxsnic_rx_bd_128b_fill(rx_queue, start_idx, mbufs, count);
}

static inline void
lxsnic_rx_seg_bd_fill(struct lxsnic_ring *rx_queue, uint16_t start_idx,
	struct rte_mbuf *mbufs[], uint8_t count)
{
	int cnt = 0;
	uint64_t dma_addr = 0;
	struct lsinic_ep_tx_seg_dst_addr *local_seg =
		rx_queue->local_rx_addr_seg;
	struct lsinic_ep_tx_seg_dst_addr *ep_rx_addr_seg;

	local_seg->addr_base = rte_mbuf_data_iova_default(mbufs[0]);
	ep_rx_addr_seg = &rx_queue->ep_rx_addr_seg[start_idx];
	while (cnt < count) {
		mbufs[cnt]->data_off = RTE_PKTMBUF_HEADROOM;
		mbufs[cnt]->port = rx_queue->port;
		dma_addr = rte_mbuf_data_iova_default(mbufs[cnt]);

		if (dma_addr > local_seg->addr_base) {
			local_seg->entry[cnt].positive = 1;
			local_seg->entry[cnt].offset =
				dma_addr - local_seg->addr_base;
		} else {
			local_seg->entry[cnt].positive = 0;
			local_seg->entry[cnt].offset =
				local_seg->addr_base - dma_addr;
		}

		rx_queue->seg_mbufs[start_idx].mbufs[cnt] = mbufs[cnt];
		cnt++;
	}

	lsinic_pcie_memcp_align(ep_rx_addr_seg,
		local_seg, sizeof(uint64_t) +
		sizeof(struct lsinic_ep_tx_seg_entry) * count);
	rte_wmb();
	ep_rx_addr_seg->ready = count;
}

static uint16_t
lxsnic_eth_recv_seg_pkts_to_cache(struct lxsnic_ring *rxq)
{
	int ret, total_nb, i;
	uint32_t ret_val = 0, total_len = 0;
	uint16_t nb_rx = 0;
	struct lsinic_rc_rx_seg *rx_seg;
	struct rte_mbuf *mbuf, *next_mbuf = NULL;
	uint16_t idx = 0, seg_nb = 0, next_idx;

	rxq->loop_total++;

	if (rxq->rc_reg)
		ret_val = LSINIC_READ_REG(&rxq->rc_reg->sr);
	else
		ret_val = LSINIC_READ_REG(&rxq->ep_reg->sr);

	rxq->status = ret_val;
	rxq->core_id = rte_lcore_id();

	if (ret_val == LSINIC_QUEUE_STOP) {
		if (ret_val != rxq->ep_sr)
			LSXINIC_PMD_DBG("ep-tx queue down");
		rxq->ep_sr = ret_val;
		return 0;
	}
	rxq->ep_sr = ret_val;

	rx_seg = rxq->rx_seg;

	while (nb_rx < rxq->count) {
		if (rxq->mcnt > LSINIC_MAX_BURST_NUM)
			break;
		idx = rxq->last_used_idx & (rxq->count - 1);

		next_idx = (idx + 1) & (rxq->count - 1);
		rte_prefetch0(&rx_seg[next_idx]);

		if (!rx_seg[idx].nb)
			break;

		rxq->rx_fill_len++;
		total_nb = rx_seg[idx].nb;
		total_len = 0;
		seg_nb = 0;
		next_mbuf = NULL;
		for (i = total_nb - 1; i >= 0; i--) {
			mbuf = rxq->seg_mbufs[idx].mbufs[i];
			mbuf->data_len = rx_seg[idx].len[i];
			total_len += mbuf->data_len;
			mbuf->pkt_len = total_len;
			seg_nb++;
			mbuf->nb_segs = seg_nb;
			mbuf->next = next_mbuf;
			next_mbuf = mbuf;
		}
		rx_seg[idx].nb = 0;
		rxq->mcache[rxq->mtail] = rxq->seg_mbufs[idx].mbufs[0];
		rxq->mtail = (rxq->mtail + 1) & MCACHE_MASK;
		rxq->mcnt++;

		nb_rx++;

		rxq->last_used_idx++;  /* step to next */
		ret = rte_pktmbuf_alloc_bulk(rxq->mb_pool,
			rxq->seg_mbufs[idx].mbufs, total_nb);
		if (ret)
			break;

		lxsnic_rx_seg_bd_fill(rxq, rxq->rx_fill_start_idx,
			rxq->seg_mbufs[idx].mbufs, LSINIC_EP_TX_SEG_MAX_ENTRY);
		rxq->rx_fill_start_idx++;
		rxq->rx_fill_start_idx =
			rxq->rx_fill_start_idx & (rxq->count - 1);
		rxq->rx_fill_len--;
	}

	rxq->loop_avail++;

	return nb_rx;
}

static uint16_t
lxsnic_eth_recv_pkts_to_cache(struct lxsnic_ring *rx_queue)
{
	int count = 0;
	uint32_t ret_val = 0;
	uint16_t nb_rx = 0;
	struct lsinic_bd_desc_128 *rx_desc, local_desc;
	struct lsinic_rc_rx_len *rx_len = NULL;
	struct rte_mbuf *mbuf = NULL;
	uint16_t idx = 0;

	if (rx_queue->rc_mem_bd_type == RC_MEM_SEG_LEN)
		return lxsnic_eth_recv_seg_pkts_to_cache(rx_queue);

	rx_queue->loop_total++;

	if (rx_queue->rc_reg)
		ret_val = LSINIC_READ_REG(&rx_queue->rc_reg->sr);
	else
		ret_val = LSINIC_READ_REG(&rx_queue->ep_reg->sr);

	rx_queue->status = ret_val;
	rx_queue->core_id = rte_lcore_id();

	if (ret_val == LSINIC_QUEUE_STOP) {
		if (ret_val != rx_queue->ep_sr)
			LSXINIC_PMD_DBG("ep-tx queue down");
		rx_queue->ep_sr = ret_val;
		return 0;
	}
	rx_queue->ep_sr = ret_val;

	if (rx_queue->rc_mem_bd_type == RC_MEM_LEN_CMD)
		rx_len = rx_queue->rx_len;

	while (nb_rx < rx_queue->count) {
		idx = rx_queue->last_used_idx & (rx_queue->count - 1);

		if (rx_len) {
			if (!rx_len[idx].total_len)
				break;
			goto skip_parse_bd;
		}
		rx_desc = &rx_queue->rc_bd_desc[idx];
		mem_cp128b_atomic(&local_desc, rx_desc);
		if (local_desc.bd_status != RING_BD_HW_COMPLETE)
			break;
		rx_desc = &local_desc;

skip_parse_bd:
		rx_queue->rx_fill_len++;

		/* This memory barrier is needed to keep us from reading
		 * any other fields out of the rx_desc until we know the
		 * descriptor has been written back
		 */
		count = 0;
		if (rx_len) {
			mbuf = lxsnic_fetch_rx_buffer(rx_queue, &rx_len[idx]);
			if (mbuf) {
				rx_queue->mcache[rx_queue->mtail] = mbuf;
				rx_queue->mtail = (rx_queue->mtail + 1) & MCACHE_MASK;
				rx_queue->mcnt++;
				count = 1;
			}
		} else {
			mbuf = lxsnic_fetch_rx_buffer(rx_queue, rx_desc);
			if (mbuf) {
				rx_queue->mcache[rx_queue->mtail] = mbuf;
				rx_queue->mtail = (rx_queue->mtail + 1)
					& MCACHE_MASK;
				rx_queue->mcnt++;
				count = 1;
			}
		}

		nb_rx++;

		rx_queue->last_used_idx++;  /* step to next */
		if (!count) {
			rx_queue->drop_packet_num++;
			break;
		}
		if (rx_queue->mcnt > LSINIC_MAX_BURST_NUM)
			break;
	}

	if (rx_queue->rx_fill_len > 1) {
		int ret = -ENOMEM, nb;
		struct rte_mbuf *mbufs[2 * LSINIC_MAX_BURST_NUM];

		if (unlikely(rx_queue->rx_fill_len >
			(2 * LSINIC_MAX_BURST_NUM)))
			nb = (2 * LSINIC_MAX_BURST_NUM);
		else
			nb = rx_queue->rx_fill_len / 2 * 2;
		while (ret) {
			ret = rte_pktmbuf_alloc_bulk(rx_queue->mb_pool,
				mbufs, nb);
			if (ret)
				nb = nb / 2;
			if (!nb)
				break;
		}
		lxsnic_rx_bd_fill(rx_queue, rx_queue->rx_fill_start_idx,
			mbufs, nb);
		rx_queue->rx_fill_start_idx =
			(rx_queue->rx_fill_start_idx + nb) &
			(rx_queue->count - 1);
		rx_queue->rx_fill_len -= nb;
	}

	rx_queue->loop_avail++;

	return nb_rx;
}

static void lxsnic_eth_self_xmit_gen_pkt(uint8_t *payload,
	uint16_t len)
{
	struct rte_ether_hdr *eth_header;
	struct rte_ipv4_hdr *ipv4_header;
	uint64_t rand = rte_rand();

	len -= sizeof(struct rte_ether_hdr);
	memcpy(payload, s_self_test_xmit_data_base,
		sizeof(s_self_test_xmit_data_base));
	eth_header = (struct rte_ether_hdr *)payload;
	ipv4_header = (struct rte_ipv4_hdr *)(eth_header + 1);
	ipv4_header->total_length = rte_cpu_to_be_16(len);
	ipv4_header->src_addr = (rte_be32_t)(rand & 0xffffffff);
	ipv4_header->dst_addr = (rte_be32_t)((rand >> 32) & 0xffffffff);
	ipv4_header->hdr_checksum = 0;
	ipv4_header->hdr_checksum = rte_ipv4_cksum(ipv4_header);
}

static uint8_t s_perf_mode_set[RTE_MAX_LCORE];

static uint16_t
lxsnic_eth_xmit_by_rc_cpu(struct lxsnic_ring *tx_queue,
	struct rte_mbuf **tx_pkts, uint16_t nb_pkts,
	uint8_t *vir_base)
{
	int i, max_size = RTE_MBUF_DEFAULT_DATAROOM;
	uint16_t bd_idx;
	uint8_t *src;

	vir_base += 2 * max_size * tx_queue->count * tx_queue->reg_idx;
	for (i = 0; i < nb_pkts; i++) {
		bd_idx = tx_queue->last_avail_idx & (tx_queue->count - 1);
		src = (uint8_t *)tx_pkts[i]->buf_addr + tx_pkts[i]->data_off;
		memcpy(vir_base + max_size * bd_idx, src,
			tx_pkts[i]->pkt_len);
		tx_queue->packets++;
		tx_queue->bytes += tx_pkts[i]->pkt_len;
		tx_queue->bytes_fcs += tx_pkts[i]->pkt_len +
			LSINIC_ETH_FCS_SIZE;
		tx_queue->bytes_overhead += tx_pkts[i]->pkt_len +
			LSINIC_ETH_OVERHEAD_SIZE;
		tx_queue->last_avail_idx++;
	}

	return nb_pkts;
}

static uint16_t
lxsnic_eth_recv_by_rc_cpu(struct lxsnic_ring *rx_queue,
	struct rte_mbuf **rx_pkts, uint16_t nb_pkts,
	uint8_t *vir_base, uint16_t test_len)
{
	int i, max_size = RTE_MBUF_DEFAULT_DATAROOM;
	uint16_t bd_idx;
	uint8_t *dst;

	vir_base += 2 * max_size * rx_queue->count * rx_queue->reg_idx;
	vir_base += max_size * rx_queue->count;
	for (i = 0; i < nb_pkts; i++) {
		bd_idx = rx_queue->last_avail_idx & (rx_queue->count - 1);
		dst = (uint8_t *)rx_pkts[i]->buf_addr + rx_pkts[i]->data_off;
		memcpy(dst, vir_base + max_size * bd_idx, test_len);
		rx_queue->packets++;
		rx_queue->bytes += test_len;
		rx_queue->bytes_fcs += test_len +
			LSINIC_ETH_FCS_SIZE;
		rx_queue->bytes_overhead += test_len +
			LSINIC_ETH_OVERHEAD_SIZE;
		rx_queue->last_avail_idx++;
		rx_pkts[i]->pkt_len = test_len;
		rx_pkts[i]->data_len = test_len;
	}

	return nb_pkts;
}

static void lxsnic_txq_loop(void)
{
	struct lxsnic_ring *q, *tq;
	struct rte_mbuf *tx_pkts[DEFAULT_TX_RS_THRESH];
	uint16_t ret, i, xmit_ret, sent, wait = 0;

	if (RTE_PER_LCORE(lxsnic_txq_num_in_list) == 0)
		return;

	/* Check if txq already added to list */
	RTE_TAILQ_FOREACH_SAFE(q, &RTE_PER_LCORE(lxsnic_txq_list), next, tq) {
		if (unlikely(q->multi_core_ring &&
			q->core_id == rte_lcore_id())) {
			ret = rte_ring_sc_dequeue_burst(q->multi_core_ring,
				(void **)tx_pkts, DEFAULT_TX_RS_THRESH, NULL);
			if (ret) {
				xmit_ret = 0;
xmit_again:
				sent = lxsnic_eth_xmit_pkts(q,
					&tx_pkts[xmit_ret], ret - xmit_ret);
				xmit_ret += sent;
				wait++;
				if (xmit_ret < ret && wait < 10000)
					goto xmit_again;
				for (i = xmit_ret; i < ret; i++)
					rte_pktmbuf_free(tx_pkts[i]);
			}
		}

		if (unlikely(q->core_id != rte_lcore_id())) {
			TAILQ_REMOVE(&RTE_PER_LCORE(lxsnic_txq_list),
				q, next);
			continue;
		}

		q->loop_total++;
	}
}

static uint16_t
_lxsnic_eth_recv_pkts(struct lxsnic_ring *rxq,
	struct rte_mbuf **rx_pkts, uint16_t nb_pkts)
{
	uint16_t nb_rx = 0;
	uint16_t count = 0;
	struct rte_mbuf *mbuf = NULL;

	lxsnic_eth_recv_pkts_to_cache(rxq);

	lxsnic_txq_loop();

	count = RTE_MIN(nb_pkts, rxq->mcnt);
	for (nb_rx = 0; nb_rx < count; nb_rx++) {
		mbuf = rxq->mcache[rxq->mhead];
		rxq->mhead = (rxq->mhead + 1) & MCACHE_MASK;
		rxq->mcnt--;

		rx_pkts[nb_rx] = mbuf;
		rxq->packets++;
		rxq->bytes += mbuf->pkt_len;
		rxq->bytes_fcs += mbuf->pkt_len +
			LSINIC_ETH_FCS_SIZE;
		rxq->bytes_overhead += mbuf->pkt_len +
			LSINIC_ETH_OVERHEAD_SIZE;

#ifdef DEBUG_MBUF
		print_mbuf(mbuf);
#endif
	}

	return nb_rx;
}

static uint16_t
lxsnic_eth_self_test(struct lxsnic_ring *rxq,
	struct rte_mbuf **rx_pkts, uint16_t nb_pkts)
{
	int tx_nb, ret;
	struct rte_mbuf *pkt;
	struct rte_mbuf *tx_pkts[LSINIC_MAX_BURST_NUM];
	struct lxsnic_adapter *adapter = rxq->adapter;
	struct rte_eth_dev *eth_dev = adapter->eth_dev;
	struct lxsnic_ring *txq =
		eth_dev->data->tx_queues[rxq->queue_index];
	uint8_t *pay_load;

	if (!txq)
		return 0;

	ret = rte_pktmbuf_alloc_bulk(rxq->mb_pool, tx_pkts,
		LSINIC_MAX_BURST_NUM);
	if (ret)
		return 0;

	for (tx_nb = 0; tx_nb < LSINIC_MAX_BURST_NUM; tx_nb++) {
		pkt = tx_pkts[tx_nb];
		pkt->data_off = RTE_PKTMBUF_HEADROOM;
		pay_load = (uint8_t *)pkt->buf_addr + pkt->data_off;
		if (0) {
			/**In case pkts go to EP MAC.*/
			lxsnic_eth_self_xmit_gen_pkt(pay_load,
				adapter->self_test_len);
		}
		pkt->pkt_len = adapter->self_test_len;
		pkt->data_len = adapter->self_test_len;
	}

	if (adapter->self_test == LXSNIC_RC_SELF_REMOTE_MEM_TEST) {
		if (!adapter->ep_memzone_vir) {
			LSXINIC_PMD_ERR("NO EP memory mapped");
			LSXINIC_PMD_ERR("please export %s = 1 in EP",
				LSINIC_EP_MAP_MEM_ENV);
			LSXINIC_PMD_ERR("please quit");
			rte_delay_ms(2000);

			return 0;
		}
		tx_nb = lxsnic_eth_xmit_by_rc_cpu(txq, tx_pkts,
			LSINIC_MAX_BURST_NUM, adapter->ep_memzone_vir);
		rte_pktmbuf_free_bulk(tx_pkts, LSINIC_MAX_BURST_NUM);
	} else if (adapter->self_test == LXSNIC_RC_SELF_LOCAL_MEM_TEST) {
		if (!adapter->rc_memzone_vir) {
			LSXINIC_PMD_ERR("NO RC memory reserved");
			LSXINIC_PMD_ERR("please quit");
			rte_delay_ms(2000);

			return 0;
		}
		tx_nb = lxsnic_eth_xmit_by_rc_cpu(txq, tx_pkts,
			LSINIC_MAX_BURST_NUM, adapter->rc_memzone_vir);
		rte_pktmbuf_free_bulk(tx_pkts, LSINIC_MAX_BURST_NUM);
	} else {
		tx_nb = _lxsnic_eth_xmit_pkts(txq, tx_pkts,
			LSINIC_MAX_BURST_NUM);
		if (tx_nb < LSINIC_MAX_BURST_NUM) {
			rte_pktmbuf_free_bulk(&tx_pkts[tx_nb],
				LSINIC_MAX_BURST_NUM - tx_nb);
		}
	}

	if (adapter->self_test == LXSNIC_RC_SELF_PMD_TEST)
		return _lxsnic_eth_recv_pkts(rxq, rx_pkts, nb_pkts);

	ret = rte_pktmbuf_alloc_bulk(rxq->mb_pool, rx_pkts, nb_pkts);
	if (ret)
		return 0;

	if (adapter->self_test == LXSNIC_RC_SELF_LOCAL_MEM_TEST) {
		return lxsnic_eth_recv_by_rc_cpu(rxq, rx_pkts, nb_pkts,
				adapter->rc_memzone_vir,
				adapter->self_test_len);
	} else {
		return lxsnic_eth_recv_by_rc_cpu(rxq, rx_pkts, nb_pkts,
				adapter->ep_memzone_vir,
				adapter->self_test_len);
	}
}

uint16_t
lxsnic_eth_recv_pkts(void *queue, struct rte_mbuf **rx_pkts,
	uint16_t nb_pkts)
{
	struct lxsnic_ring *rx_queue = (struct lxsnic_ring *)queue;
	struct lxsnic_adapter *adapter = rx_queue->adapter;
	struct lxsnic_ring *pair_txq = rx_queue->pair;

	if (pair_txq) {
		uint8_t idx = pair_txq->queue_index;

		if (unlikely(!RTE_PER_LCORE(txq_added[idx]))) {
			rte_spinlock_lock(&pair_txq->multi_core_lock);
			lxsnic_add_txq_to_list(pair_txq);
			rte_spinlock_unlock(&pair_txq->multi_core_lock);
			RTE_PER_LCORE(txq_added[idx]) = 1;
		} else {
			lxsnic_add_txq_to_list(pair_txq);
		}
	}

	if (unlikely(!s_perf_mode_set[rte_lcore_id()])) {
		if (getenv("NXP_CHRT_PERF_MODE")) {
			pid_t tid = rte_gettid();
			char command[256];
			int ret;

			snprintf(command, 256, "chrt -p 90 %d", tid);
			ret = system(command);
			if (ret < 0)
				LSXINIC_PMD_ERR("%s excuted failed", command);
			else
				LSXINIC_PMD_INFO("%s excuted success", command);
		}
		s_perf_mode_set[rte_lcore_id()] = 1;
	}

	if (unlikely(adapter->self_test != LXSNIC_RC_SELF_NONE_TEST))
		return lxsnic_eth_self_test(rx_queue, rx_pkts, nb_pkts);

	return _lxsnic_eth_recv_pkts(rx_queue, rx_pkts, nb_pkts);
}
