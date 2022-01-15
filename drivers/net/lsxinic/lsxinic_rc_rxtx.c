/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018-2022 NXP
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

static void lxsnic_tx_complete_ring_clean(struct lxsnic_ring *tx_ring)
{
	uint16_t bd_idx;
	uint32_t mbuf_idx;
	struct rte_mbuf *last_mbuf;
	uint8_t *tx_complete = &tx_ring->tx_complete->bd_complete;

	bd_idx = tx_ring->last_used_idx & (tx_ring->count - 1);

	rte_rmb();

	do {
		if (tx_complete[bd_idx] != RING_BD_HW_COMPLETE)
			break;

		mbuf_idx = bd_idx;
		if (mbuf_idx == LSINIC_BD_CTX_IDX_INVALID)
			break;
		last_mbuf = (struct rte_mbuf *)tx_ring->q_mbuf[mbuf_idx];
		RTE_ASSERT(last_mbuf);
		if (tx_ring->adapter->self_test &&
			tx_ring->self_xmit_ring)
			rte_ring_enqueue(tx_ring->self_xmit_ring, last_mbuf);
		else
			rte_pktmbuf_free_seg(last_mbuf);

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
	uint32_t mbuf_idx;
	struct lsinic_bd_desc *rc_tx_desc;
	struct rte_mbuf *last_mbuf;

	bd_idx = tx_ring->last_used_idx & (tx_ring->count - 1);
	rc_tx_desc = &tx_ring->rc_bd_desc[bd_idx];

	status = rc_tx_desc->bd_status & RING_BD_STATUS_MASK;

	rte_rmb();

	do {
		if (status != RING_BD_HW_COMPLETE)
			break;

		mbuf_idx = lsinic_bd_ctx_idx(rc_tx_desc->bd_status);
		last_mbuf = (struct rte_mbuf *)tx_ring->q_mbuf[mbuf_idx];
		RTE_ASSERT(last_mbuf);
#ifdef RTE_ENABLE_ASSERT
		if (rc_tx_desc->bd_status & RING_BD_ADDR_CHECK) {
			if (rc_tx_desc->len_cmd & LSINIC_BD_CMD_MG)
				RTE_ASSERT((rte_mbuf_data_iova(last_mbuf) -
					sizeof(struct lsinic_mg_header)) ==
					rc_tx_desc->pkt_addr);
			else
				RTE_ASSERT(rte_mbuf_data_iova(last_mbuf) ==
					rc_tx_desc->pkt_addr);
		}
#endif
		if (tx_ring->adapter->self_test &&
			tx_ring->self_xmit_ring)
			rte_ring_enqueue(tx_ring->self_xmit_ring, last_mbuf);
		else
			rte_pktmbuf_free_seg(last_mbuf);

		rc_tx_desc->bd_status &= (~((uint32_t)RING_BD_STATUS_MASK));
		rc_tx_desc->bd_status |= RING_BD_READY;

		tx_ring->last_used_idx++;

		bd_idx = tx_ring->last_used_idx & (tx_ring->count - 1);
		rc_tx_desc = &tx_ring->rc_bd_desc[bd_idx];
		status = rc_tx_desc->bd_status & RING_BD_STATUS_MASK;

		rte_rmb();
	} while (1);
}

static void lxsnic_tx_ring_idx_clean(struct lxsnic_ring *tx_ring)
{
	uint32_t start_free_idx = tx_ring->tx_free_start_idx;
	const uint32_t last_free_idx = tx_ring->free_idx->idx_complete;
	uint32_t mbuf_idx;
	struct rte_mbuf *last_mbuf;

	if (!tx_ring->tx_free_len)
		return;

	while (start_free_idx != last_free_idx) {
		mbuf_idx = start_free_idx;
		last_mbuf = (struct rte_mbuf *)tx_ring->q_mbuf[mbuf_idx];
		if (tx_ring->adapter->self_test &&
			tx_ring->self_xmit_ring)
			rte_ring_enqueue(tx_ring->self_xmit_ring, last_mbuf);
		else
			rte_pktmbuf_free_seg(last_mbuf);

		tx_ring->last_used_idx++;
		start_free_idx = (start_free_idx + 1) & (tx_ring->count - 1);
		tx_ring->tx_free_len--;
		RTE_ASSERT(tx_ring->tx_free_len >= 0);
	}

	tx_ring->tx_free_start_idx = start_free_idx;
}

static int
lxsnic_xmit_one_pkt_idx(struct lxsnic_ring *tx_ring,
	struct rte_mbuf *tx_pkt, uint16_t mg_num,
	struct lsinic_ep_rx_src_addrx *notify)
{
	dma_addr_t dma;
	uint16_t bd_idx = 0;
	uint32_t pkt_len = 0;
	struct lsinic_ep_rx_src_addrx *ep_tx_desc = 0;
	struct lsinic_ep_rx_src_addrx local_desc;
	struct lxsnic_adapter *adapter = tx_ring->adapter;
	uint32_t mbuf_idx = 0, pending_cnt = 0;
	char *pdata = NULL;
	uint8_t *tx_complete;
	const uint32_t pkt_addr_interval = adapter->pkt_addr_interval;
	const uint64_t pkt_addr_base = adapter->pkt_addr_base;

	if (unlikely(tx_pkt->data_off != RTE_PKTMBUF_HEADROOM)) {
		LSXINIC_PMD_ERR("IDX xmit invalid offset(%d != %d)",
			tx_pkt->data_off, RTE_PKTMBUF_HEADROOM);

		return -1;
	}

	if (tx_pkt->nb_segs > 1)
		return -1;

	bd_idx = tx_ring->last_avail_idx & (tx_ring->count - 1);
	ep_tx_desc = &tx_ring->ep_tx_addrx[bd_idx];
	if (tx_ring->rc_mem_bd_type == RC_MEM_IDX_CNF) {
		while (unlikely(((bd_idx + 1 + XMIT_IDX_EXTRA_SPACE) &
			(tx_ring->count - 1)) ==
			tx_ring->tx_free_start_idx)) {
			/** Make special room, otherwise no way to
			 * identify ring is empty or full.
			 */
			if (pending_cnt > 1000) {
				tx_ring->ring_full++;
				return -1;
			}
			pending_cnt++;
			lxsnic_tx_ring_idx_clean(tx_ring);
			rte_wmb();
			rte_rmb();
		}
		mbuf_idx = bd_idx;
	} else if (tx_ring->rc_mem_bd_type == RC_MEM_BD_CNF) {
		tx_complete = &tx_ring->tx_complete[bd_idx].bd_complete;
		if (*tx_complete != RING_BD_READY) {
#ifdef LXSNIC_DEBUG_RX_TX
			adapter->stats.tx_desc_err++;
#endif
			tx_ring->ring_full++;
			return -1;
		}
		mbuf_idx = bd_idx;
		*tx_complete = RING_BD_AVAILABLE;
	} else {
		rte_panic("Invalid confirm(%d) for xmit pkt idx",
			tx_ring->rc_mem_bd_type);
	}

	pkt_len = tx_pkt->pkt_len;  /* total packet length */
	dma = rte_mbuf_data_iova(tx_pkt);
	pdata = (char *)rte_pktmbuf_mtod(tx_pkt, char *);
	*((uint8_t *)pdata + pkt_len) =
		LSINIC_XFER_COMPLETE_DONE_FLAG;

	tx_ring->q_mbuf[mbuf_idx] = tx_pkt;

	local_desc.pkt_idx = (dma - pkt_addr_base) / pkt_addr_interval;
	if (unlikely((local_desc.pkt_idx * pkt_addr_interval +
		pkt_addr_base) != dma)) {
		rte_panic("RC xmit buf idx fatal!");
	}
	RTE_ASSERT((local_desc.pkt_idx * pkt_addr_interval +
		pkt_addr_base) == dma);
	RTE_ASSERT(pkt_len < (MAX_U16 / 2));
	local_desc.len_cmd = pkt_len;
	if (mg_num)
		local_desc.len_cmd |= LSINIC_EP_RX_SRC_ADDRX_MERGE;

	if (!notify)
		ep_tx_desc->idx_cmd_len = local_desc.idx_cmd_len;
	else
		notify->idx_cmd_len = local_desc.idx_cmd_len;

	if (mg_num == 0) {
		tx_ring->packets++;
		tx_ring->bytes += tx_pkt->pkt_len;
		tx_ring->bytes_fcs += tx_pkt->pkt_len + LSINIC_ETH_FCS_SIZE;
		tx_ring->bytes_overhead += tx_pkt->pkt_len +
			LSINIC_ETH_OVERHEAD_SIZE;
	}

	tx_ring->tx_free_len++;
	tx_ring->last_avail_idx++;

	return 0;
}

static int
lxsnic_xmit_one_pkt_addrl(struct lxsnic_ring *tx_ring,
	struct rte_mbuf *tx_pkt, uint16_t mg_num,
	struct lsinic_ep_rx_src_addrl *notify)
{
	dma_addr_t dma;
	uint32_t cmd_type;
	uint16_t bd_idx = 0;
	uint32_t pkt_len = 0;
	struct lsinic_ep_rx_src_addrl *ep_tx_desc = 0;
	struct lsinic_ep_rx_src_addrl local_desc;
	uint32_t mbuf_idx = 0;
	char *pdata = NULL;
	uint8_t *tx_complete;

	if (tx_pkt->nb_segs > 1)
		return -1;

	bd_idx = tx_ring->last_avail_idx & (tx_ring->count - 1);
	ep_tx_desc = &tx_ring->ep_tx_addrl[bd_idx];
	if (tx_ring->rc_mem_bd_type == RC_MEM_IDX_CNF) {
		if (unlikely(((bd_idx + 1) &
			(tx_ring->count - 1)) ==
			tx_ring->tx_free_start_idx)) {
			/** Make special room, otherwise no way to
			 * identify ring is empty or full.
			 */
			tx_ring->ring_full++;
			return -1;
		}
		mbuf_idx = bd_idx;
	} else if (tx_ring->rc_mem_bd_type == RC_MEM_BD_CNF) {
		tx_complete = &tx_ring->tx_complete[bd_idx].bd_complete;
		if (*tx_complete != RING_BD_READY) {
#ifdef LXSNIC_DEBUG_RX_TX
			tx_ring->adapter->stats.tx_desc_err++;
#endif
			tx_ring->ring_full++;
			return -1;
		}
		*tx_complete = RING_BD_AVAILABLE;
		mbuf_idx = bd_idx;
	} else {
		rte_panic("Invalid confirm(%d) for xmit pkt addl",
			tx_ring->rc_mem_bd_type);
	}

	pkt_len = tx_pkt->pkt_len;  /* total packet length */
	cmd_type = LSINIC_BD_CMD_EOP;
	dma = rte_mbuf_data_iova(tx_pkt);
	if (tx_ring->adapter->cap & LSINIC_CAP_XFER_COMPLETE) {
		pdata = (char *)rte_pktmbuf_mtod(tx_pkt, char *);
		*((uint8_t *)pdata + pkt_len) =
			LSINIC_XFER_COMPLETE_DONE_FLAG;
	}
	tx_ring->q_mbuf[mbuf_idx] = tx_pkt;

	/* write last descriptor with RS and EOP bits */
	if (mg_num) {
		cmd_type |= LSINIC_BD_CMD_MG | pkt_len;
		cmd_type |=
			((uint32_t)mg_num) << LSINIC_BD_MG_NUM_SHIFT;
	} else {
		cmd_type |= pkt_len;
	}

	local_desc.pkt_addr_low = dma - tx_ring->adapter->pkt_addr_base;
	local_desc.len_cmd = cmd_type;

	if (!notify)
		ep_tx_desc->addr_cmd_len = local_desc.addr_cmd_len;
	else
		notify->addr_cmd_len = local_desc.addr_cmd_len;

	if (mg_num == 0) {
		tx_ring->packets++;
		tx_ring->bytes += tx_pkt->pkt_len;
		tx_ring->bytes_fcs += tx_pkt->pkt_len + LSINIC_ETH_FCS_SIZE;
		tx_ring->bytes_overhead += tx_pkt->pkt_len +
			LSINIC_ETH_OVERHEAD_SIZE;
	}
	tx_ring->tx_free_len++;
	tx_ring->last_avail_idx++;

	return 0;
}

static int
lxsnic_xmit_one_pkt(struct lxsnic_ring *tx_ring, struct rte_mbuf *tx_pkt,
	uint16_t mg_num, struct lsinic_bd_desc *local_desc)
{
	dma_addr_t dma;
	uint32_t cmd_type;
	uint16_t bd_idx = 0;
	uint32_t pkt_len = 0, bd_status;
	struct lsinic_bd_desc *ep_tx_desc = 0;
	struct lsinic_bd_desc local_tx_desc;
	struct lsinic_bd_desc *tx_complete_desc;
	uint32_t mbuf_idx = 0;
	char *pdata = NULL;
	uint8_t *tx_complete;
	uint32_t cap = tx_ring->adapter->cap;

	if (tx_pkt->nb_segs > 1)
		return -1;

	bd_idx = tx_ring->last_avail_idx & (tx_ring->count - 1);

	ep_tx_desc = &tx_ring->ep_bd_desc[bd_idx];

	if (tx_ring->rc_mem_bd_type == RC_MEM_IDX_CNF) {
		if (unlikely(((bd_idx + 1) &
			(tx_ring->count - 1)) ==
			tx_ring->tx_free_start_idx)) {
			/** Make special room, otherwise no way to
			 * identify ring is empty or full.
			 */
			tx_ring->ring_full++;
			return -1;
		}
		mbuf_idx = bd_idx;
		tx_ring->q_mbuf[mbuf_idx] = tx_pkt;
	} else if (tx_ring->rc_mem_bd_type == RC_MEM_BD_CNF) {
		tx_complete = &tx_ring->tx_complete[bd_idx].bd_complete;
		if (*tx_complete != RING_BD_READY) {
			uint8_t current_ep_status;

			ep_tx_desc = &tx_ring->ep_bd_desc[bd_idx];
			current_ep_status =
				ep_tx_desc->bd_status & RING_BD_STATUS_MASK;
			if (current_ep_status == RING_BD_HW_COMPLETE) {
				/** Workaround to sync with EP BD status.*/
				*tx_complete = RING_BD_HW_COMPLETE;
				tx_ring->sync_err++;
			}
#ifdef LXSNIC_DEBUG_RX_TX
			tx_ring->adapter->stats.tx_desc_err++;
#endif
			tx_ring->ring_full++;
			return -1;
		}
		*tx_complete = RING_BD_AVAILABLE;
		mbuf_idx = bd_idx;
		tx_ring->q_mbuf[mbuf_idx] = tx_pkt;
	} else if (tx_ring->rc_mem_bd_type == RC_MEM_LONG_BD) {
		tx_complete_desc = &tx_ring->rc_bd_desc[bd_idx];
		bd_status = tx_complete_desc->bd_status;
		if ((bd_status & RING_BD_STATUS_MASK) != RING_BD_READY) {
#ifdef LXSNIC_DEBUG_RX_TX
			tx_ring->adapter->stats.tx_desc_err++;
#endif
			tx_ring->ring_full++;
			return -1;
		}
		mbuf_idx = lsinic_bd_ctx_idx(bd_status);
		if (unlikely(mbuf_idx == LSINIC_BD_CTX_IDX_INVALID))
			mbuf_idx = bd_idx;

		tx_ring->q_mbuf[mbuf_idx] = tx_pkt;
	}

	pkt_len = tx_pkt->pkt_len;  /* total packet length */
	cmd_type = LSINIC_BD_CMD_EOP;
	dma = rte_mbuf_data_iova(tx_pkt);
	if (cap & LSINIC_CAP_XFER_COMPLETE) {
		pdata = (char *)rte_pktmbuf_mtod(tx_pkt, char *);
		*((uint8_t *)pdata + pkt_len) =
			LSINIC_XFER_COMPLETE_DONE_FLAG;
	}

	/* write last descriptor with RS and EOP bits */
	if (mg_num) {
		cmd_type |= LSINIC_BD_CMD_MG | pkt_len;
		cmd_type |=
			(((uint32_t)mg_num) << LSINIC_BD_MG_NUM_SHIFT);
	} else {
		cmd_type |= pkt_len;
	}

	local_tx_desc.pkt_addr = dma;
	local_tx_desc.len_cmd = cmd_type;
	local_tx_desc.bd_status = (mbuf_idx << LSINIC_BD_CTX_IDX_SHIFT);
	local_tx_desc.bd_status |= RING_BD_AVAILABLE;
	if (local_desc) {
		memcpy(local_desc, &local_tx_desc,
			sizeof(struct lsinic_bd_desc));
	} else {
		memcpy(ep_tx_desc, &local_tx_desc,
			sizeof(struct lsinic_bd_desc));
	}

	if (mg_num == 0) {
		tx_ring->packets++;
		tx_ring->bytes += tx_pkt->pkt_len;
		tx_ring->bytes_fcs += tx_pkt->pkt_len + LSINIC_ETH_FCS_SIZE;
		tx_ring->bytes_overhead += tx_pkt->pkt_len +
			LSINIC_ETH_OVERHEAD_SIZE;
	}
	tx_ring->tx_free_len++;
	tx_ring->last_avail_idx++;

	return 0;
}

static int
lxsnic_try_to_merge(struct lxsnic_ring *txq,
	struct rte_mbuf **tx_pkts, uint16_t nb_pkts,
	struct rte_mbuf **free_pkts, uint16_t *nb_free,
	void *local_notify)
{
	uint16_t i, free_idx = 0;
	int ret = 0;
	uint16_t mg_num;
	uint16_t mg_len = 0, align_len, align_off;
	uint32_t bytes, overhead, fcs;
	struct rte_mbuf *tx_pkt;
	char *dst_buf, *data = NULL;
	struct lsinic_mg_header *mg_header;
	uint32_t max_data_room;
	const uint32_t cap = txq->adapter->cap;

	if (!(cap & LSINIC_CAP_XFER_PKT_MERGE))
		return 0;

	bytes = 0;
	overhead = 0;
	fcs = 0;

	max_data_room = txq->adapter->max_data_room;
	max_data_room -= LSINIC_RC_TX_DATA_ROOM_OVERHEAD;
	if (cap & LSINIC_CAP_XFER_COMPLETE)
		max_data_room--;

	for (mg_num = 0; mg_num < nb_pkts; mg_num++) {
		if (mg_num == LSINIC_MERGE_MAX_NUM)
			break;

		tx_pkt = tx_pkts[mg_num];
#ifdef LSXINIC_ASSERT_PKT_SIZE
		RTE_ASSERT(tx_pkt->pkt_len ==
			(LSXINIC_ASSERT_PKT_SIZE - LSINIC_ETH_FCS_SIZE));
#endif
		if (tx_pkt->nb_segs > 1)
			return 0;

		if (tx_pkt->pkt_len > txq->adapter->merge_threshold)
			break;

		if ((mg_len + ALIGN(tx_pkt->pkt_len, LSINIC_MG_ALIGN_SIZE)) >=
			max_data_room)
			break;

		mg_len += ALIGN(tx_pkt->pkt_len, LSINIC_MG_ALIGN_SIZE);
		/* todo calculate sg mbuf */
	}

	/* No need to merge */
	if (mg_num <= 1)
		return 0;

	/* The first packet */
	tx_pkt = tx_pkts[0];

	data = (char *)rte_pktmbuf_mtod(tx_pkt, char *);
	mg_header = (struct lsinic_mg_header *)
		(data - sizeof(struct lsinic_mg_header));
	align_len = ALIGN(tx_pkt->pkt_len, LSINIC_MG_ALIGN_SIZE);
	align_off = align_len - tx_pkt->pkt_len;
	mg_header->len_cmd[0] =
		lsinic_mg_entry_set(tx_pkt->pkt_len, align_off);

	dst_buf = data + align_len;
	bytes += tx_pkt->pkt_len;
	fcs += tx_pkt->pkt_len + LSINIC_ETH_FCS_SIZE;
	overhead += tx_pkt->pkt_len + LSINIC_ETH_OVERHEAD_SIZE;

	for (i = 1; i < mg_num; i++) {
		tx_pkt = tx_pkts[i];
		align_len = ALIGN(tx_pkt->pkt_len, LSINIC_MG_ALIGN_SIZE);
		align_off = align_len - tx_pkt->pkt_len;
		mg_header->len_cmd[i] =
			lsinic_mg_entry_set(tx_pkt->pkt_len, align_off);
		rte_memcpy(dst_buf, rte_pktmbuf_mtod(tx_pkt, char *),
			tx_pkt->pkt_len);
		dst_buf += align_len;

		bytes += tx_pkt->pkt_len;
		fcs += tx_pkt->pkt_len + LSINIC_ETH_FCS_SIZE;
		overhead += tx_pkt->pkt_len + LSINIC_ETH_OVERHEAD_SIZE;

		free_pkts[free_idx] = tx_pkt;
		free_idx++;
	}
	if (mg_num < LSINIC_MERGE_MAX_NUM)
		mg_header->len_cmd[mg_num] = 0;

	tx_pkt = tx_pkts[0];
	tx_pkt->pkt_len = mg_len;
	tx_pkt->data_len = mg_len;
	RTE_ASSERT(tx_pkt->data_off > sizeof(struct lsinic_mg_header));
	tx_pkt->nb_segs = 1;
	tx_pkt->next = NULL;
	if (txq->ep_mem_bd_type == EP_MEM_SRC_ADDRX_BD) {
		ret = lxsnic_xmit_one_pkt_idx(txq,
			tx_pkt, mg_num, local_notify);
	} else if (txq->ep_mem_bd_type == EP_MEM_SRC_ADDRL_BD) {
		ret = lxsnic_xmit_one_pkt_addrl(txq,
			tx_pkt, mg_num, local_notify);
	} else {
		ret = lxsnic_xmit_one_pkt(txq, tx_pkt, mg_num, local_notify);
	}
	if (unlikely(ret))
		return -1;

	txq->bytes += bytes;
	txq->bytes_fcs += fcs;
	txq->bytes_overhead += overhead;
	txq->packets += mg_num;
	(*nb_free) += free_idx;

	return mg_num;
}

static uint16_t
_lxsnic_eth_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts,
		uint16_t nb_pkts)
{
	int ret = 0;
	uint8_t ret_val = 0;
	uint16_t tx_num = 0, idx_tx_num;
	uint16_t total_nb_pkts = nb_pkts;
	struct lxsnic_ring *tx_ring = (struct lxsnic_ring *)tx_queue;
	struct rte_mbuf *free_pkts[LSINIC_MERGE_MAX_NUM];
	uint16_t free_nb = 0, notify_idx = 0;
	uint16_t first_idx =
		tx_ring->last_avail_idx & (tx_ring->count - 1);
	union lsinic_ep2rc_notify notify;
	uint8_t *src, *dst;

	tx_ring->loop_total++;

	if (tx_ring->rc_reg)
		ret_val = LSINIC_READ_REG(&tx_ring->rc_reg->sr);
	else
		ret_val = LSINIC_READ_REG(&tx_ring->ep_reg->sr);

	tx_ring->status = ret_val;
	tx_ring->core_id = rte_lcore_id();

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

	if (tx_ring->ep_mem_bd_type == EP_MEM_SRC_ADDRL_BD) {
		while (nb_pkts) {
			ret = lxsnic_try_to_merge(tx_ring, &tx_pkts[tx_num],
				nb_pkts, &free_pkts[free_nb], &free_nb,
				&notify.ep_tx_addrl[notify_idx]);
			if (ret < 0)
				goto end_of_tx;
			if (ret) {
				notify_idx++;
				tx_num += ret;
				nb_pkts -= ret;
			} else {
				ret = lxsnic_xmit_one_pkt_addrl(tx_ring,
					tx_pkts[tx_num], 0,
					&notify.ep_tx_addrl[notify_idx]);
				if (ret)
					goto end_of_tx;
				notify_idx++;
				tx_num++;
				nb_pkts--;
			}
		}
		goto end_of_tx;
	} else if (tx_ring->ep_mem_bd_type == EP_MEM_SRC_ADDRX_BD) {
		while (nb_pkts) {
			ret = lxsnic_try_to_merge(tx_ring, &tx_pkts[tx_num],
				nb_pkts, &free_pkts[free_nb], &free_nb,
				&notify.ep_tx_addrx[notify_idx]);
			if (ret < 0)
				goto end_of_tx;
			if (ret) {
				notify_idx++;
				tx_num += ret;
				nb_pkts -= ret;
			} else {
				ret = lxsnic_xmit_one_pkt_idx(tx_ring,
					tx_pkts[tx_num], 0,
					&notify.ep_tx_addrx[notify_idx]);
				if (ret)
					goto end_of_tx;
				notify_idx++;
				tx_num++;
				nb_pkts--;
			}
		}
		goto end_of_tx;
	}

	while (nb_pkts) {
		ret = lxsnic_try_to_merge(tx_ring, &tx_pkts[tx_num],
			nb_pkts, &free_pkts[free_nb], &free_nb,
			&notify.ep_tx_addr[notify_idx]);
		if (ret < 0)
			goto end_of_tx;

		if (ret) {
			notify_idx++;
			tx_num += ret;
			nb_pkts -= ret;
		} else {
			ret = lxsnic_xmit_one_pkt(tx_ring,
				tx_pkts[tx_num], 0,
				&notify.ep_tx_addr[notify_idx]);
			if (ret)
				goto end_of_tx;

			notify_idx++;
			tx_num++;
			nb_pkts--;
		}
	}

end_of_tx:
	if (tx_ring->ep_mem_bd_type == EP_MEM_SRC_ADDRL_BD) {
		if ((first_idx + notify_idx) <= tx_ring->count) {
			src = (uint8_t *)&notify.ep_tx_addrl[0];
			dst = (uint8_t *)&tx_ring->ep_tx_addrl[first_idx];
			memcpy(dst, src, notify_idx *
				sizeof(struct lsinic_ep_rx_src_addrl));
		} else {
			src = (uint8_t *)&notify.ep_tx_addrl[0];
			dst = (uint8_t *)&tx_ring->ep_tx_addrl[first_idx];
			memcpy(dst, src, (tx_ring->count - first_idx) *
				sizeof(struct lsinic_ep_rx_src_addrl));

			src = (uint8_t *)
				&notify.ep_tx_addrl[tx_ring->count - first_idx];
			dst = (uint8_t *)
				&tx_ring->ep_tx_addrl[0];
			memcpy(dst, src,
				(notify_idx + first_idx - tx_ring->count) *
				sizeof(struct lsinic_ep_rx_src_addrl));
		}
	} else if (tx_ring->ep_mem_bd_type == EP_MEM_SRC_ADDRX_BD) {
		int i;
		struct lsinic_ep_rx_src_addrx *addrx;

		if ((first_idx + notify_idx) <= tx_ring->count) {
			addrx = &notify.ep_tx_addrx[notify_idx];
			for (i = 0; i < XMIT_IDX_EXTRA_SPACE; i++)
				addrx[i].idx_cmd_len = 0;

			idx_tx_num = notify_idx + XMIT_IDX_EXTRA_SPACE;
			src = (uint8_t *)&notify.ep_tx_addrx[0];
			dst = (uint8_t *)&tx_ring->ep_tx_addrx[first_idx];
			memcpy(dst, src, idx_tx_num *
				sizeof(struct lsinic_ep_rx_src_addrx));
		} else {
			idx_tx_num = tx_ring->count - first_idx +
				XMIT_IDX_EXTRA_SPACE;
			src = (uint8_t *)&notify.ep_tx_addrx[0];
			dst = (uint8_t *)&tx_ring->ep_tx_addrx[first_idx];
			memcpy(dst, src, idx_tx_num *
				sizeof(struct lsinic_ep_rx_src_addrx));

			addrx = &notify.ep_tx_addrx[notify_idx];
			for (i = 0; i < XMIT_IDX_EXTRA_SPACE; i++)
				addrx[i].idx_cmd_len = 0;
			idx_tx_num = first_idx + notify_idx - tx_ring->count +
				XMIT_IDX_EXTRA_SPACE;
			src = (uint8_t *)
				&notify.ep_tx_addrx[tx_ring->count - first_idx];
			dst = (uint8_t *)
				&tx_ring->ep_tx_addrx[0];
			memcpy(dst, src, idx_tx_num *
				sizeof(struct lsinic_ep_rx_src_addrx));
		}
	} else {
		if ((first_idx + notify_idx) <= tx_ring->count) {
			src = (uint8_t *)&notify.ep_tx_addr[0];
			dst = (uint8_t *)&tx_ring->ep_bd_desc[first_idx];
			memcpy(dst, src, notify_idx *
				sizeof(struct lsinic_bd_desc));
		} else {
			src = (uint8_t *)&notify.ep_tx_addr[0];
			dst = (uint8_t *)&tx_ring->ep_bd_desc[first_idx];
			memcpy(dst, src, (tx_ring->count - first_idx) *
				sizeof(struct lsinic_bd_desc));

			src = (uint8_t *)
				&notify.ep_tx_addr[tx_ring->count - first_idx];
			dst = (uint8_t *)
				&tx_ring->ep_bd_desc[0];
			memcpy(dst, src,
				(notify_idx + first_idx - tx_ring->count) *
				sizeof(struct lsinic_bd_desc));
		}
	}

	tx_ring->loop_avail++;

	tx_ring->drop_packet_num += (total_nb_pkts - tx_num);

	if (tx_ring->adapter->self_test &&
		tx_ring->self_xmit_ring) {
		rte_ring_enqueue_bulk(tx_ring->self_xmit_ring,
			(void * const *)free_pkts, free_nb, NULL);
	} else {
		rte_pktmbuf_free_bulk(free_pkts, free_nb);
	}

	return tx_num;
}

uint16_t
lxsnic_eth_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts,
	uint16_t nb_pkts)
{
	struct lxsnic_ring *tx_ring = (struct lxsnic_ring *)tx_queue;

	if (tx_ring->adapter->self_test)
		return 0;

	return _lxsnic_eth_xmit_pkts(tx_queue, tx_pkts, nb_pkts);
}

static int
lxsnic_fetch_merge_rx_buffer(struct lxsnic_ring *rx_queue,
	void *rx_desc, uint16_t mg_num)
{
	char *data = NULL;
	char *data_base;
	uint16_t pkt_len = 0, align_off;
	int idx = 0, offset = 0;
	struct rte_mbuf *mbuf;
	struct lsinic_mg_header *mg_header;
	uint32_t total_size;
	struct lsinic_bd_desc *bd_desc = NULL;
	uint32_t mbuf_idx;
	struct lsinic_rc_rx_len_cmd *rx_len_cmd;
	const uint32_t cap = rx_queue->adapter->cap;

	if (rx_queue->rc_mem_bd_type == RC_MEM_LEN_CMD) {
		rx_len_cmd = rx_desc;
		if (cap & LSINIC_CAP_XFER_ORDER_PRSV) {
			mbuf_idx = rx_queue->last_used_idx &
				(rx_queue->count - 1);
		} else {
			mbuf_idx = EP2RC_TX_CTX_IDX(rx_len_cmd->cnt_idx);
		}
		mbuf = (struct rte_mbuf *)rx_queue->q_mbuf[mbuf_idx];
		total_size = rx_len_cmd->total_len;
	} else {
		bd_desc = rx_desc;
		if (cap & LSINIC_CAP_XFER_ORDER_PRSV) {
			mbuf_idx = rx_queue->last_used_idx &
				(rx_queue->count - 1);
		} else {
			mbuf_idx = lsinic_bd_ctx_idx(bd_desc->bd_status);
		}
		mbuf = (struct rte_mbuf *)rx_queue->q_mbuf[mbuf_idx];
		total_size = LSINIC_READ_REG(&bd_desc->len_cmd) &
			LSINIC_BD_LEN_MASK;
	}

	RTE_ASSERT(mbuf);

#ifdef RTE_ENABLE_ASSERT
	if (bd_desc && bd_desc->bd_status & RING_BD_ADDR_CHECK) {
		rte_iova_t iova = rte_mbuf_data_iova_default(mbuf);

		if (iova != rx_desc->pkt_addr) {
			LSXINIC_PMD_ERR("pkt_addr:0x%lx, 0x%lx, data_len:%d,"
				" bd_status:0x%08x\r\n",
				rx_desc->pkt_addr, iova,
				mbuf->data_len, bd_desc->bd_status);
		}
		RTE_ASSERT(rte_cpu_to_le_64(iova) == bd_desc->pkt_addr);
	}
#endif
	rte_lxsnic_prefetch(mbuf);

	if (total_size  > rx_queue->adapter->max_data_room) {
		LSXINIC_PMD_ERR("packet(%d) is too bigger!\n",
			total_size);
		return 0;
	}

	mbuf->data_off = RTE_PKTMBUF_HEADROOM;
	data_base = rte_pktmbuf_mtod(mbuf, char *);
	rte_lxsnic_packet_prefetch(data_base);
	mg_header = (struct lsinic_mg_header *)
		(data_base - sizeof(struct lsinic_mg_header));

	pkt_len = lsinic_mg_entry_len(mg_header->len_cmd[0]);

#ifdef LSXINIC_ASSERT_PKT_SIZE
	RTE_ASSERT(pkt_len == (LSXINIC_ASSERT_PKT_SIZE - LSINIC_ETH_FCS_SIZE));
#endif
	mbuf->nb_segs = 1;
	mbuf->next = NULL;
	mbuf->pkt_len = pkt_len;
	mbuf->data_len = pkt_len;
	mbuf->port = rx_queue->port;
	mbuf->packet_type = RTE_PTYPE_L3_IPV4;
	rx_queue->mcache[rx_queue->mtail] = mbuf;
	rx_queue->mtail = (rx_queue->mtail + 1) & MCACHE_MASK;
	rx_queue->mcnt++;

#ifdef LSXINIC_ASSERT_PKT_SIZE
	RTE_ASSERT(mbuf->pkt_len ==
			(LSXINIC_ASSERT_PKT_SIZE - LSINIC_ETH_FCS_SIZE));
#endif

	align_off = lsinic_mg_entry_align_offset(mg_header->len_cmd[0]);
	offset = pkt_len + align_off;

	LSXINIC_PMD_DBG("RC MGD0: len=%d next mgd offset=%d\n",
		pkt_len, offset);

	for (idx = 1; idx < mg_num; idx++) {
		pkt_len = lsinic_mg_entry_len(mg_header->len_cmd[idx]);
#ifdef LSXINIC_ASSERT_PKT_SIZE
		RTE_ASSERT(pkt_len ==
			(LSXINIC_ASSERT_PKT_SIZE - LSINIC_ETH_FCS_SIZE));
#endif
		align_off =
			lsinic_mg_entry_align_offset(mg_header->len_cmd[idx]);

		mbuf = rte_mbuf_raw_alloc(rx_queue->mb_pool);
		if (!mbuf) {
			LSXINIC_PMD_DBG("MG RX mbuf alloc failed p:%u q:%u",
				rx_queue->port, rx_queue->queue_index);
			break;
		}

		mbuf->data_off = RTE_PKTMBUF_HEADROOM;
		data = rte_pktmbuf_mtod(mbuf, char *);
		rte_memcpy(data, (void *)(data_base + offset), pkt_len);
		mbuf->nb_segs = 1;
		mbuf->next = NULL;
		mbuf->pkt_len = pkt_len;
		mbuf->data_len = pkt_len;
		mbuf->port = rx_queue->port;
		mbuf->packet_type = RTE_PTYPE_L3_IPV4;

#ifdef LSXINIC_ASSERT_PKT_SIZE
		RTE_ASSERT(mbuf->pkt_len ==
			(LSXINIC_ASSERT_PKT_SIZE - LSINIC_ETH_FCS_SIZE));
#endif
		rx_queue->mcache[rx_queue->mtail] = mbuf;
		rx_queue->mtail = (rx_queue->mtail + 1) & MCACHE_MASK;
		rx_queue->mcnt++;

		offset += pkt_len + align_off;
		LSXINIC_PMD_DBG("RC CBD%d: len=%d next mg offset=%d",
			idx, pkt_len, offset);
	}

	return idx;
}

static struct rte_mbuf *
lxsnic_fetch_rx_buffer(struct lxsnic_ring *rx_queue,
	void *rx_desc)
{
	struct rte_mbuf *mbuf;
	uint16_t rx_packet_len;
	struct lsinic_bd_desc *bd_desc;
	uint32_t mbuf_idx;
	struct lsinic_rc_rx_len_cmd *rx_len_cmd;
	const uint32_t cap = rx_queue->adapter->cap;

	if (rx_queue->rc_mem_bd_type == RC_MEM_LEN_CMD) {
		rx_len_cmd = rx_desc;
		if (cap & LSINIC_CAP_XFER_ORDER_PRSV) {
			mbuf_idx = rx_queue->last_used_idx &
				(rx_queue->count - 1);
		} else {
			mbuf_idx = EP2RC_TX_CTX_IDX(rx_len_cmd->cnt_idx);
		}
		mbuf = (struct rte_mbuf *)rx_queue->q_mbuf[mbuf_idx];
		rx_packet_len = rx_len_cmd->total_len;
	} else {
		bd_desc = rx_desc;
		if (cap & LSINIC_CAP_XFER_ORDER_PRSV) {
			mbuf_idx = rx_queue->last_used_idx &
				(rx_queue->count - 1);
		} else {
			mbuf_idx = lsinic_bd_ctx_idx(bd_desc->bd_status);
		}
		mbuf = (struct rte_mbuf *)rx_queue->q_mbuf[mbuf_idx];
		rx_packet_len = LSINIC_READ_REG(&bd_desc->len_cmd) &
			LSINIC_BD_LEN_MASK;
	}

	RTE_ASSERT(mbuf);

#ifdef RTE_ENABLE_ASSERT
	if (rx_desc->bd_status & RING_BD_ADDR_CHECK) {
		RTE_ASSERT(rte_cpu_to_le_64(rte_mbuf_data_iova_default(mbuf)) ==
			rx_desc->pkt_addr);
	}
#endif

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
#ifdef LSXINIC_ASSERT_PKT_SIZE
	RTE_ASSERT(mbuf->pkt_len ==
			(LSXINIC_ASSERT_PKT_SIZE - LSINIC_ETH_FCS_SIZE));
#endif

	return mbuf;
}

static inline void
lxsnic_rx_lbd_fill(struct lxsnic_ring *rx_queue, uint16_t start_idx,
	struct rte_mbuf *mbufs[], int count)
{
	int cnt = 0;
	uint64_t dma_addr = 0;
	uint16_t idx = start_idx;
	uint32_t mbuf_idx;
	struct lsinic_bd_desc *ep_rx_desc = NULL, *rc_rx_desc = NULL;
	struct lsinic_rc_rx_len_cmd *rx_len_cmd;
	struct lsinic_bd_desc local_rx_desc;

	ep_rx_desc = rx_queue->ep_bd_desc;
	while (cnt < count) {
		mbufs[cnt]->data_off = RTE_PKTMBUF_HEADROOM;
		mbufs[cnt]->port = rx_queue->port;
		dma_addr = rte_mbuf_data_iova_default(mbufs[cnt]);

		if (rx_queue->rc_mem_bd_type == RC_MEM_LONG_BD) {
			rc_rx_desc = &rx_queue->rc_bd_desc[idx];
			mbuf_idx = lsinic_bd_ctx_idx(rc_rx_desc->bd_status);
		} else {
			rx_len_cmd = &rx_queue->rx_len_cmd[idx];
			mbuf_idx = EP2RC_TX_CTX_IDX(rx_len_cmd->cnt_idx);
			rc_rx_desc = &local_rx_desc;
			rx_len_cmd->len_cnt_idx = 0;
			memset(rc_rx_desc, 0, sizeof(struct lsinic_bd_desc));
		}
		rc_rx_desc->pkt_addr = dma_addr;
		rc_rx_desc->bd_status = RING_BD_READY |
			(mbuf_idx << LSINIC_BD_CTX_IDX_SHIFT);
		memcpy(&ep_rx_desc[idx], rc_rx_desc,
			sizeof(struct lsinic_bd_desc));
		rx_queue->q_mbuf[mbuf_idx] = mbufs[cnt];
		cnt++;
		idx = (idx + 1) & (rx_queue->count - 1);
	}
}

static inline void
lxsnic_rx_sbd_fill(struct lxsnic_ring *rx_queue, uint16_t start_idx,
	struct rte_mbuf *mbufs[], int count)
{
	int cnt = 0;
	uint64_t dma_addr = 0;
	uint16_t idx = start_idx;
	uint32_t mbuf_idx;
	struct lsinic_ep_tx_dst_addr *ep_rx_addr = NULL;
	struct lsinic_rc_rx_len_cmd *rx_len_cmd;
	struct lsinic_ep_tx_dst_addr local_recv_addr[count];

	ep_rx_addr = local_recv_addr;

	while (cnt < count) {
		mbufs[cnt]->data_off = RTE_PKTMBUF_HEADROOM;
		mbufs[cnt]->port = rx_queue->port;
		dma_addr = rte_mbuf_data_iova_default(mbufs[cnt]);

		mbuf_idx = idx;
		ep_rx_addr[cnt].pkt_addr = dma_addr;
		if (rx_queue->rc_mem_bd_type == RC_MEM_LEN_CMD) {
			rx_len_cmd = &rx_queue->rx_len_cmd[idx];
			rx_len_cmd->len_cnt_idx = 0;
		}
		rx_queue->q_mbuf[mbuf_idx] = mbufs[cnt];
		cnt++;
		idx = (idx + 1) & (rx_queue->count - 1);
	}

	if ((start_idx + cnt) <= rx_queue->count) {
		memcpy(&rx_queue->ep_rx_addr[start_idx],
			local_recv_addr,
			sizeof(uint64_t) * cnt);
	} else {
		memcpy(&rx_queue->ep_rx_addr[start_idx],
			local_recv_addr,
			sizeof(uint64_t) *
			(rx_queue->count - start_idx));
		memcpy(&rx_queue->ep_rx_addr[0],
			&local_recv_addr[rx_queue->count - start_idx],
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
		lxsnic_rx_sbd_fill(rx_queue, start_idx, mbufs, count);
	else
		lxsnic_rx_lbd_fill(rx_queue, start_idx, mbufs, count);
}

static uint16_t
lxsnic_eth_recv_pkts_to_cache(struct lxsnic_ring *rx_queue)
{
	int count = 0;
	uint32_t ret_val = 0;
	uint16_t nb_rx = 0;
	struct lsinic_bd_desc *rx_desc;
	struct lsinic_bd_desc local_desc;
	struct lsinic_rc_rx_len_cmd *rx_len_cmd = NULL;
	struct rte_mbuf *mbuf = NULL;
	uint16_t idx = 0;

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
		rx_len_cmd = rx_queue->rx_len_cmd;

	while (nb_rx < rx_queue->count) {
		idx = rx_queue->last_used_idx & (rx_queue->count - 1);

		if (rx_len_cmd) {
			if (!rx_len_cmd[idx].len_cnt_idx)
				break;
			goto skip_parse_bd;
		}
		rx_desc = &rx_queue->rc_bd_desc[idx];
		mem_cp128b_atomic((uint8_t *)&local_desc, (uint8_t *)rx_desc);
		if ((local_desc.bd_status & RING_BD_STATUS_MASK) !=
			RING_BD_HW_COMPLETE)
			break;
		rx_desc = &local_desc;

skip_parse_bd:
		rx_queue->rx_fill_len++;

		/* This memory barrier is needed to keep us from reading
		 * any other fields out of the rx_desc until we know the
		 * descriptor has been written back
		 */
		count = 0;
		if (rx_len_cmd) {
			count = EP2RC_TX_CTX_CNT(rx_len_cmd[idx].cnt_idx);
			if (count) {
				count = lxsnic_fetch_merge_rx_buffer(rx_queue,
					&rx_len_cmd[idx], count);
			} else {
				mbuf = lxsnic_fetch_rx_buffer(rx_queue,
					&rx_len_cmd[idx]);
				if (mbuf) {
					rx_queue->mcache[rx_queue->mtail] =
						mbuf;
					rx_queue->mtail = (rx_queue->mtail + 1)
						& MCACHE_MASK;
					rx_queue->mcnt++;
					count = 1;
				}
			}
		} else if (lxsnic_test_staterr(rx_desc, LSINIC_BD_CMD_MG)) {
			count = ((rx_desc->len_cmd & LSINIC_BD_MG_NUM_MASK) >>
					LSINIC_BD_MG_NUM_SHIFT);
			count = lxsnic_fetch_merge_rx_buffer(rx_queue,
					rx_desc, count);
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
		if (count == 0) {
			rx_queue->drop_packet_num++;
			break;
		}
		if (rx_queue->mcnt > LSINIC_MERGE_MAX_NUM)
			break;
	}

	if (rx_queue->rx_fill_len > 1) {
		int ret = -ENOMEM, nb;
		struct rte_mbuf *mbufs[2 * LSINIC_MERGE_MAX_NUM];

		if (unlikely(rx_queue->rx_fill_len >
			(2 * LSINIC_MERGE_MAX_NUM)))
			nb = (2 * LSINIC_MERGE_MAX_NUM);
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

static void lxsnic_eth_self_xmit_gen_pkt(uint8_t *payload)
{
	struct rte_ether_hdr *eth_header;
	struct rte_ipv4_hdr *ipv4_header;
	uint64_t rand = rte_rand();

	memcpy(payload, s_self_test_xmit_data_base,
		sizeof(s_self_test_xmit_data_base));
	eth_header = (struct rte_ether_hdr *)payload;
	ipv4_header = (struct rte_ipv4_hdr *)(eth_header + 1);
	ipv4_header->src_addr = (rte_be32_t)(rand & 0xffffffff);
	ipv4_header->dst_addr = (rte_be32_t)((rand >> 32) & 0xffffffff);
	ipv4_header->hdr_checksum = 0;
	ipv4_header->hdr_checksum = rte_ipv4_cksum(ipv4_header);
}

uint8_t s_perf_mode_set[RTE_MAX_LCORE];

uint16_t
lxsnic_eth_recv_pkts(void *queue, struct rte_mbuf **rx_pkts,
		uint16_t nb_pkts)
{
	uint16_t nb_rx = 0;
	uint16_t count = 0;
	struct rte_mbuf *mbuf = NULL;
	struct lxsnic_ring *rx_queue = (struct lxsnic_ring *)queue;
	struct rte_eth_dev *eth_dev = rx_queue->adapter->eth_dev;
	struct lxsnic_ring *tx_queue =
			eth_dev->data->tx_queues[rx_queue->queue_index];

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

	if (tx_queue) {
		if (tx_queue->rc_mem_bd_type == RC_MEM_BD_CNF)
			lxsnic_tx_complete_ring_clean(tx_queue);
		else if (tx_queue->rc_mem_bd_type == RC_MEM_IDX_CNF)
			lxsnic_tx_ring_idx_clean(tx_queue);
		else
			lxsnic_tx_ring_clean(tx_queue);
	}

	if (rx_queue->adapter->self_test && tx_queue) {
		int count = rx_queue->count;
		int i, tx_nb, ret;
		struct rte_mbuf *pkt;
		struct rte_mbuf *tx_pkts[32];
		char ring_nm[64];
		uint8_t *pay_load;

		if (!tx_queue->self_xmit_ring) {
			char env_cnt[64];

			snprintf(env_cnt, 64,
				"LSINIC_RC_SELF_TEST_RING_SIZE");
			if (getenv(env_cnt))
				count = atoi(getenv(env_cnt));
			if (!rte_is_power_of_2(count))
				count = rte_align32pow2(count);
			sprintf(ring_nm, "self_xmit%d_ring%d_r",
				eth_dev->data->port_id, tx_queue->queue_index);
			tx_queue->self_xmit_ring =
				rte_ring_create(ring_nm, count,
					rte_socket_id(), 0);
			for (i = 0; i < count; i++) {
				pkt = rte_pktmbuf_alloc(rx_queue->mb_pool);
				if (!pkt)
					break;
				pkt->data_off = RTE_PKTMBUF_HEADROOM;
				pay_load = (uint8_t *)pkt->buf_addr +
					pkt->data_off;
				lxsnic_eth_self_xmit_gen_pkt(pay_load);
				pkt->pkt_len = rx_queue->adapter->self_test_len;
				pkt->data_len =
					rx_queue->adapter->self_test_len;
				ret = rte_ring_enqueue(tx_queue->self_xmit_ring,
					pkt);
				if (ret)
					break;
			}
			LSXINIC_PMD_INFO("total %d pkts are filled to %s",
				i, ring_nm);
		}

		if (tx_queue->self_xmit_ring) {
			ret = rte_ring_dequeue_burst(tx_queue->self_xmit_ring,
				(void **)tx_pkts, 32, NULL);

			tx_nb = _lxsnic_eth_xmit_pkts(tx_queue, tx_pkts, ret);
			if (tx_nb < ret) {
				rte_ring_enqueue_bulk(tx_queue->self_xmit_ring,
					(void * const *)&tx_pkts[tx_nb],
					ret - tx_nb, NULL);
			}
		}
	}

	lxsnic_eth_recv_pkts_to_cache(rx_queue);

	count = RTE_MIN(nb_pkts, rx_queue->mcnt);
	for (nb_rx = 0; nb_rx < count; nb_rx++) {
		mbuf = rx_queue->mcache[rx_queue->mhead];
		rx_queue->mhead = (rx_queue->mhead + 1) & MCACHE_MASK;
		rx_queue->mcnt--;

		rx_pkts[nb_rx] = mbuf;
		rx_queue->packets++;
		rx_queue->bytes += mbuf->pkt_len;
		rx_queue->bytes_fcs +=	mbuf->pkt_len +
			LSINIC_ETH_FCS_SIZE;
		rx_queue->bytes_overhead += mbuf->pkt_len +
			LSINIC_ETH_OVERHEAD_SIZE;

#ifdef DEBUG_MBUF
		print_mbuf(mbuf);
#endif
	}

	return nb_rx;
}
