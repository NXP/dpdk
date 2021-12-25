/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018-2021 NXP
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

enum lxsnic_mbuf_mg_flag {
	LXSNIC_MBUF_SINGLE = 1,
	LXSNIC_MBUF_MERGED = 2
};

#define FAST_MG_FLAG_OFF (-1)

static void lxsnic_tx_complete_ring_clean(struct lxsnic_ring *tx_ring)
{
	uint16_t bd_idx;
#ifdef LSINIC_BD_CTX_IDX_USED
	uint32_t mbuf_idx;
#endif
	struct lsinic_bd_desc *rc_tx_desc;
	struct rte_mbuf *last_mbuf;
	uint8_t *tx_complete = tx_ring->ep2rc.tx_complete;

	bd_idx = tx_ring->last_used_idx & (tx_ring->count - 1);
	rc_tx_desc = LSINIC_RC_BD_DESC(tx_ring, bd_idx);

	rte_rmb();

	do {
		if (tx_complete[bd_idx] != RING_BD_HW_COMPLETE)
			break;

#ifdef LSINIC_BD_CTX_IDX_USED
		mbuf_idx = lsinic_bd_ctx_idx(rc_tx_desc->bd_status);
		if (mbuf_idx == LSINIC_BD_CTX_IDX_INVALID)
			break;
		last_mbuf = (struct rte_mbuf *)tx_ring->q_mbuf[mbuf_idx];
#else
		last_mbuf = (struct rte_mbuf *)rc_tx_desc->sw_ctx;
		if (!last_mbuf)
			break;
#endif
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

#ifdef LSINIC_BD_CTX_IDX_USED
		rc_tx_desc->bd_status &= (~((uint32_t)RING_BD_STATUS_MASK));
		rc_tx_desc->bd_status |= RING_BD_READY;
#else
		rc_tx_desc->bd_status = RING_BD_READY;
#endif
		tx_complete[bd_idx] = RING_BD_READY;

		tx_ring->last_used_idx++;

		bd_idx = tx_ring->last_used_idx & (tx_ring->count - 1);
		rc_tx_desc = LSINIC_RC_BD_DESC(tx_ring, bd_idx);

		rte_rmb();
	} while (1);
}

static void lxsnic_tx_ring_clean(struct lxsnic_ring *tx_ring)
{
	uint16_t bd_idx;
	uint32_t status;
#ifdef LSINIC_BD_CTX_IDX_USED
	uint32_t mbuf_idx;
#endif
	struct lsinic_bd_desc *rc_tx_desc;
	struct rte_mbuf *last_mbuf;

	bd_idx = tx_ring->last_used_idx & (tx_ring->count - 1);
	rc_tx_desc = LSINIC_RC_BD_DESC(tx_ring, bd_idx);

	status = rc_tx_desc->bd_status & RING_BD_STATUS_MASK;

	rte_rmb();

	do {
		if (status != RING_BD_HW_COMPLETE)
			break;

#ifdef LSINIC_BD_CTX_IDX_USED
		mbuf_idx = lsinic_bd_ctx_idx(rc_tx_desc->bd_status);
		last_mbuf = (struct rte_mbuf *)tx_ring->q_mbuf[mbuf_idx];
#else
		last_mbuf = (struct rte_mbuf *)rc_tx_desc->sw_ctx;
#endif
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

#ifdef LSINIC_BD_CTX_IDX_USED
		rc_tx_desc->bd_status &= (~((uint32_t)RING_BD_STATUS_MASK));
		rc_tx_desc->bd_status |= RING_BD_READY;
#else
		rc_tx_desc->bd_status = RING_BD_READY;
#endif

		tx_ring->last_used_idx++;

		bd_idx = tx_ring->last_used_idx & (tx_ring->count - 1);
		rc_tx_desc = LSINIC_RC_BD_DESC(tx_ring, bd_idx);
		status = rc_tx_desc->bd_status & RING_BD_STATUS_MASK;

		rte_rmb();
	} while (1);
}

static void lxsnic_tx_ring_idx_clean(struct lxsnic_ring *tx_ring)
{
	uint32_t start_free_idx = tx_ring->tx_free_start_idx;
	const uint32_t last_free_idx = *(tx_ring->ep2rc.free_idx);
#ifdef LSINIC_BD_CTX_IDX_USED
	uint32_t mbuf_idx;
#endif
	struct lsinic_bd_desc *rc_tx_desc;
	struct rte_mbuf *last_mbuf;

	if (!tx_ring->tx_free_len)
		return;

	while (start_free_idx != last_free_idx) {
		rc_tx_desc = LSINIC_RC_BD_DESC(tx_ring, start_free_idx);

#ifdef LSINIC_BD_CTX_IDX_USED
		mbuf_idx = lsinic_bd_ctx_idx(rc_tx_desc->bd_status);
		last_mbuf = (struct rte_mbuf *)tx_ring->q_mbuf[mbuf_idx];
#else
		last_mbuf = (struct rte_mbuf *)rc_tx_desc->sw_ctx;
#endif
		if (tx_ring->adapter->self_test &&
			tx_ring->self_xmit_ring)
			rte_ring_enqueue(tx_ring->self_xmit_ring, last_mbuf);
		else
			rte_pktmbuf_free_seg(last_mbuf);

#ifdef LSINIC_BD_CTX_IDX_USED
		rc_tx_desc->bd_status &= (~((uint32_t)RING_BD_STATUS_MASK));
		rc_tx_desc->bd_status |= RING_BD_READY;
#else
		rc_tx_desc->bd_status = RING_BD_READY;
#endif

		tx_ring->last_used_idx++;
		start_free_idx = (start_free_idx + 1) & (tx_ring->count - 1);
		tx_ring->tx_free_len--;
		RTE_ASSERT(tx_ring->tx_free_len >= 0);
	}

	tx_ring->tx_free_start_idx = start_free_idx;
}

static int
lxsnic_xmit_one_pkt_idx(struct lxsnic_ring *tx_ring,
	struct rte_mbuf *tx_pkt,
	struct lsinic_rc_xmit_idx *notify)
{
	dma_addr_t dma;
	uint32_t cmd_type;
	uint16_t bd_idx = 0;
	uint32_t pkt_len = 0, bd_status;
	struct lsinic_rc_xmit_idx *ep_tx_desc = 0;
	struct lsinic_rc_xmit_idx local_desc;
	struct lsinic_bd_desc *rc_tx_desc;
	struct lxsnic_adapter *adapter = tx_ring->adapter;
	uint32_t mbuf_idx = 0;
	char *pdata = NULL;
	uint8_t *tx_complete = tx_ring->ep2rc.tx_complete;
	const uint32_t cap = adapter->cap;
	enum rc_xmit_cnf_type e_type =
		LSINIC_CAP_XFER_RC_XMIT_CNF_TYPE_GET(cap);
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
	ep_tx_desc = &tx_ring->xmit_idx[bd_idx];
	rc_tx_desc = LSINIC_RC_BD_DESC(tx_ring, bd_idx);
	if (e_type == RC_XMIT_INDEX_CNF) {
		if (unlikely(((bd_idx + 1) &
			(tx_ring->count - 1)) ==
			tx_ring->tx_free_start_idx)) {
			/** Make special room, otherwise no way to
			 * identify ring is empty or full.
			 */
			tx_ring->ring_full++;
			return -1;
		}
	}

	bd_status = rc_tx_desc->bd_status;
	if (e_type == RC_XMIT_RING_CNF) {
		if (tx_complete[bd_idx] != RING_BD_READY) {
#ifdef LXSNIC_DEBUG_RX_TX
			tx_ring->adapter->stats.tx_desc_err++;
#endif
			tx_ring->ring_full++;
			return -1;
		}
		tx_complete[bd_idx] = RING_BD_AVAILABLE;
	} else if ((bd_status & RING_BD_STATUS_MASK) != RING_BD_READY) {
#ifdef LXSNIC_DEBUG_RX_TX
		tx_ring->adapter->stats.tx_desc_err++;
#endif
		tx_ring->ring_full++;
		return -1;
	}

	mbuf_idx = lsinic_bd_ctx_idx(bd_status);
	if (unlikely(mbuf_idx == LSINIC_BD_CTX_IDX_INVALID)) {
		mbuf_idx = bd_idx;
		rc_tx_desc->bd_status &= (~LSINIC_BD_CTX_IDX_MASK);
		rc_tx_desc->bd_status |= (mbuf_idx << LSINIC_BD_CTX_IDX_SHIFT);
	}

	pkt_len = tx_pkt->pkt_len;  /* total packet length */
	cmd_type = LSINIC_BD_CMD_EOP;
	dma = rte_mbuf_data_iova(tx_pkt);
	pdata = (char *)rte_pktmbuf_mtod(tx_pkt, char *);
	*((uint8_t *)pdata + pkt_len) =
		LSINIC_XFER_COMPLETE_DONE_FLAG;

	cmd_type |= pkt_len;

	rc_tx_desc->pkt_addr = dma;
	rc_tx_desc->len_cmd = cmd_type;
	rc_tx_desc->bd_status &= (~((uint32_t)RING_BD_STATUS_MASK));
	rc_tx_desc->bd_status |= RING_BD_AVAILABLE;
	tx_ring->q_mbuf[mbuf_idx] = tx_pkt;

	local_desc.pkt_idx = (dma - pkt_addr_base) / pkt_addr_interval;
	RTE_ASSERT((local_desc.pkt_idx * pkt_addr_interval +
		pkt_addr_base) == dma);
	RTE_ASSERT(pkt_len < MAX_U16);
	local_desc.len_cmd = pkt_len;

	if (!notify)
		ep_tx_desc->idx_cmd_len = local_desc.idx_cmd_len;
	else
		notify->idx_cmd_len = local_desc.idx_cmd_len;

	tx_ring->packets++;
	tx_ring->bytes += tx_pkt->pkt_len;
	tx_ring->bytes_fcs += tx_pkt->pkt_len + LSINIC_ETH_FCS_SIZE;
	tx_ring->bytes_overhead += tx_pkt->pkt_len +
		LSINIC_ETH_OVERHEAD_SIZE;

	tx_ring->tx_free_len++;
	tx_ring->last_avail_idx++;

	return 0;
}

static int
lxsnic_xmit_one_pkt_addrl(struct lxsnic_ring *tx_ring,
	struct rte_mbuf *tx_pkt, uint16_t mg_num,
	struct lsinic_rc_xmit_addrl *notify)
{
	dma_addr_t dma;
	uint32_t cmd_type;
	uint16_t bd_idx = 0;
	uint32_t pkt_len = 0, bd_status;
	struct lsinic_rc_xmit_addrl *ep_tx_desc = 0;
	struct lsinic_rc_xmit_addrl local_desc;
	struct lsinic_bd_desc *rc_tx_desc;
#ifdef LSINIC_BD_CTX_IDX_USED
	uint32_t mbuf_idx = 0;
#endif
	char *pdata = NULL;
	uint8_t *tx_complete = tx_ring->ep2rc.tx_complete;
	uint32_t cap = tx_ring->adapter->cap;
	enum rc_xmit_cnf_type e_type =
		LSINIC_CAP_XFER_RC_XMIT_CNF_TYPE_GET(cap);

	if (tx_pkt->nb_segs > 1)
		return -1;

	bd_idx = tx_ring->last_avail_idx & (tx_ring->count - 1);
	ep_tx_desc = &tx_ring->xmit_addrl[bd_idx];
	rc_tx_desc = LSINIC_RC_BD_DESC(tx_ring, bd_idx);
	if (e_type == RC_XMIT_INDEX_CNF) {
		if (unlikely(((bd_idx + 1) &
			(tx_ring->count - 1)) ==
			tx_ring->tx_free_start_idx)) {
			/** Make special room, otherwise no way to
			 * identify ring is empty or full.
			 */
			tx_ring->ring_full++;
			return -1;
		}
	}

	bd_status = rc_tx_desc->bd_status;
	if (e_type == RC_XMIT_RING_CNF) {
		if (tx_complete[bd_idx] != RING_BD_READY) {
#ifdef LXSNIC_DEBUG_RX_TX
			tx_ring->adapter->stats.tx_desc_err++;
#endif
			tx_ring->ring_full++;
			return -1;
		}
		tx_complete[bd_idx] = RING_BD_AVAILABLE;
	} else if ((bd_status & RING_BD_STATUS_MASK) != RING_BD_READY) {
#ifdef LXSNIC_DEBUG_RX_TX
		tx_ring->adapter->stats.tx_desc_err++;
#endif
		tx_ring->ring_full++;
		return -1;
	}

#ifdef LSINIC_BD_CTX_IDX_USED
	mbuf_idx = lsinic_bd_ctx_idx(bd_status);
	if (unlikely(mbuf_idx == LSINIC_BD_CTX_IDX_INVALID)) {
		mbuf_idx = bd_idx;
		rc_tx_desc->bd_status &= (~LSINIC_BD_CTX_IDX_MASK);
		rc_tx_desc->bd_status |= (mbuf_idx << LSINIC_BD_CTX_IDX_SHIFT);
	}
#endif

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
		cmd_type |= LSINIC_BD_CMD_MG |
			(pkt_len - sizeof(struct lsinic_mg_header));
		cmd_type |=
			(((uint32_t)(mg_num - 1)) << LSINIC_BD_MG_NUM_SHIFT);
	} else {
		cmd_type |= pkt_len;
	}

	rc_tx_desc->pkt_addr = dma;
	rc_tx_desc->len_cmd = cmd_type;
	rc_tx_desc->bd_status &= (~((uint32_t)RING_BD_STATUS_MASK));
	rc_tx_desc->bd_status |= RING_BD_AVAILABLE;
	tx_ring->q_mbuf[mbuf_idx] = tx_pkt;

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
	uint16_t mg_num)
{
	dma_addr_t dma;
	uint32_t cmd_type;
	uint16_t bd_idx = 0;
	uint32_t pkt_len = 0, bd_status;
	struct lsinic_bd_desc *ep_tx_desc = 0;
	struct lsinic_bd_desc *rc_tx_desc;
#ifdef LSINIC_BD_CTX_IDX_USED
	uint32_t mbuf_idx = 0;
#endif
	char *pdata = NULL;
	uint8_t *tx_complete = tx_ring->ep2rc.tx_complete;
	uint32_t cap = tx_ring->adapter->cap;
	enum rc_xmit_cnf_type e_type =
		LSINIC_CAP_XFER_RC_XMIT_CNF_TYPE_GET(cap);


	if (tx_pkt->nb_segs > 1)
		return -1;

	bd_idx = tx_ring->last_avail_idx & (tx_ring->count - 1);
	if (!(cap & LSINIC_CAP_XFER_TX_BD_UPDATE))
		ep_tx_desc = LSINIC_EP_BD_DESC(tx_ring, bd_idx);
	rc_tx_desc = LSINIC_RC_BD_DESC(tx_ring, bd_idx);
	if (e_type == RC_XMIT_INDEX_CNF) {
		if (unlikely(((bd_idx + 1) &
			(tx_ring->count - 1)) ==
			tx_ring->tx_free_start_idx)) {
			/** Make special room, otherwise no way to
			 * identify ring is empty or full.
			 */
			tx_ring->ring_full++;
			return -1;
		}
	}

	bd_status = rc_tx_desc->bd_status;
	if (e_type == RC_XMIT_RING_CNF) {
		if (tx_complete[bd_idx] != RING_BD_READY) {
			uint8_t current_ep_status;

			ep_tx_desc = LSINIC_EP_BD_DESC(tx_ring, bd_idx);
			current_ep_status =
				ep_tx_desc->bd_status & RING_BD_STATUS_MASK;
			if (current_ep_status == RING_BD_HW_COMPLETE) {
				/** Workaround to sync with EP BD status.*/
				tx_complete[bd_idx] = RING_BD_HW_COMPLETE;
				tx_ring->sync_err++;
			}
#ifdef LXSNIC_DEBUG_RX_TX
			tx_ring->adapter->stats.tx_desc_err++;
#endif
			tx_ring->ring_full++;
			return -1;
		}
		tx_complete[bd_idx] = RING_BD_AVAILABLE;
	} else if ((bd_status & RING_BD_STATUS_MASK) != RING_BD_READY) {
#ifdef LXSNIC_DEBUG_RX_TX
		tx_ring->adapter->stats.tx_desc_err++;
#endif
		tx_ring->ring_full++;
		return -1;
	}

#ifdef LSINIC_BD_CTX_IDX_USED
	mbuf_idx = lsinic_bd_ctx_idx(bd_status);
	if (unlikely(mbuf_idx == LSINIC_BD_CTX_IDX_INVALID)) {
		mbuf_idx = bd_idx;
		rc_tx_desc->bd_status &= (~LSINIC_BD_CTX_IDX_MASK);
		rc_tx_desc->bd_status |= (mbuf_idx << LSINIC_BD_CTX_IDX_SHIFT);
	}
#endif

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
		cmd_type |= LSINIC_BD_CMD_MG |
			(pkt_len - sizeof(struct lsinic_mg_header));
		cmd_type |=
			(((uint32_t)(mg_num - 1)) << LSINIC_BD_MG_NUM_SHIFT);
	} else {
		cmd_type |= pkt_len;
	}

	rc_tx_desc->pkt_addr = dma;
	rc_tx_desc->len_cmd = cmd_type;
#ifdef LSINIC_BD_CTX_IDX_USED
	rc_tx_desc->bd_status &= (~((uint32_t)RING_BD_STATUS_MASK));
	rc_tx_desc->bd_status |= RING_BD_AVAILABLE;
	tx_ring->q_mbuf[mbuf_idx] = tx_pkt;

	if (ep_tx_desc)
		mem_cp128b_atomic((uint8_t *)ep_tx_desc, (uint8_t *)rc_tx_desc);
#else
	rc_tx_desc->sw_ctx = (uint64_t)tx_pkt;
	rc_tx_desc->bd_status = RING_BD_AVAILABLE;

	if (ep_tx_desc) {
		rte_memcpy(ep_tx_desc, rc_tx_desc,
			offsetof(struct lsinic_bd_desc, desc));
		rte_wmb();
		rc_tx_desc->sw_ctx = LSINIC_READ_REG_64B(&ep_tx_desc->sw_ctx);

		ep_tx_desc->desc = rc_tx_desc->desc;
	}
#endif

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
	struct rte_mbuf **free_pkts, uint16_t *nb_free)
{
	uint16_t i, free_idx = 0;
	int ret = 0;
	uint16_t mg_num;
	uint16_t mg_len = 0, align_len, align_off, pkt_idx;
	uint32_t bytes, overhead, fcs;
	struct rte_mbuf *tx_pkt;
	char *dst_buf, *data = NULL;
	struct lsinic_mg_header *mg_header;
	uint32_t max_data_room;
	const uint32_t cap = txq->adapter->cap;

	if (!(txq->adapter->cap & LSINIC_CAP_XFER_PKT_MERGE))
		return 0;

	if (lxsnic_rc_mg_fast_fwd()) {
		for (pkt_idx = 0; pkt_idx < nb_pkts; pkt_idx++) {
			tx_pkt = tx_pkts[pkt_idx];
			if (*rte_pktmbuf_mtod_offset(tx_pkt, char *,
				FAST_MG_FLAG_OFF) ==
				LXSNIC_MBUF_MERGED) {
				mg_header = rte_pktmbuf_mtod(tx_pkt,
					struct lsinic_mg_header *);
				mg_num = 0;
				bytes = 0;
				overhead = 0;
				fcs = 0;
				while (mg_header->len_cmd[mg_num]) {
					bytes += lsinic_mg_entry_len(mg_header->len_cmd[mg_num]);
					overhead += LSINIC_ETH_OVERHEAD_SIZE;
					fcs += LSINIC_ETH_FCS_SIZE;
					mg_num++;
					if (mg_num == LSINIC_MERGE_MAX_NUM)
						break;
				}
				if (LSINIC_CAP_XFER_RC_XMIT_BD_TYPE_GET(cap) ==
					RC_XMIT_ADDRL_TYPE) {
					ret = lxsnic_xmit_one_pkt_addrl(txq,
						tx_pkt, mg_num, NULL);
				} else {
					ret = lxsnic_xmit_one_pkt(txq,
						tx_pkt, mg_num);
				}
				if (ret)
					return pkt_idx;

				txq->bytes += bytes;
				txq->bytes_fcs += bytes + fcs;
				txq->bytes_overhead += bytes + overhead;
				txq->packets += mg_num;
			} else {
				if (LSINIC_CAP_XFER_RC_XMIT_BD_TYPE_GET(cap) ==
					RC_XMIT_ADDRL_TYPE) {
					ret = lxsnic_xmit_one_pkt_addrl(txq,
						tx_pkt, 0, NULL);
				} else {
					ret = lxsnic_xmit_one_pkt(txq,
						tx_pkt, 0);
				}
				if (ret)
					return pkt_idx;
			}
		}

		return nb_pkts;
	}

	bytes = 0;
	overhead = 0;
	fcs = 0;

	max_data_room = txq->adapter->max_data_room;
	max_data_room -= LSINIC_RC_TX_DATA_ROOM_OVERHEAD;
	if (txq->adapter->cap & LSINIC_CAP_XFER_COMPLETE)
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

	mg_len += sizeof(struct lsinic_mg_header);

	/* The first packet */
	tx_pkt = tx_pkts[0];

	data = (char *)rte_pktmbuf_mtod(tx_pkt, char *);
	data -= sizeof(struct lsinic_mg_header);
	mg_header = (struct lsinic_mg_header *)data;
	align_len = ALIGN(tx_pkt->pkt_len, LSINIC_MG_ALIGN_SIZE);
	align_off = align_len - tx_pkt->pkt_len;
	mg_header->len_cmd[0] =
		lsinic_mg_entry_set(tx_pkt->pkt_len, align_off);

	dst_buf = data + sizeof(struct lsinic_mg_header) + align_len;
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

	tx_pkt = tx_pkts[0];
	tx_pkt->pkt_len = mg_len;
	tx_pkt->data_len = mg_len;
	RTE_ASSERT(tx_pkt->data_off > sizeof(struct lsinic_mg_header));
	tx_pkt->data_off -= sizeof(struct lsinic_mg_header);
	tx_pkt->nb_segs = 1;
	tx_pkt->next = NULL;
	if (LSINIC_CAP_XFER_RC_XMIT_BD_TYPE_GET(cap) ==
		RC_XMIT_ADDRL_TYPE) {
		ret = lxsnic_xmit_one_pkt_addrl(txq,
			tx_pkt, mg_num, NULL);
	} else {
		ret = lxsnic_xmit_one_pkt(txq, tx_pkt, mg_num);
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
	uint16_t tx_num = 0;
	uint16_t total_nb_pkts = nb_pkts;
	struct lxsnic_ring *tx_ring = (struct lxsnic_ring *)tx_queue;
	struct rte_mbuf *free_pkts[LSINIC_MERGE_MAX_NUM];
	uint16_t free_nb = 0;
	const uint32_t cap = tx_ring->adapter->cap;
	enum rc_xmit_cnf_type e_type =
		LSINIC_CAP_XFER_RC_XMIT_CNF_TYPE_GET(cap);
	uint16_t first_idx =
		tx_ring->last_avail_idx & (tx_ring->count - 1);
	struct lsinic_rc_xmit_addrl xmit_addrl[nb_pkts];
	struct lsinic_rc_xmit_idx xmit_idx[nb_pkts];

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

	if (e_type == RC_XMIT_RING_CNF)
		lxsnic_tx_complete_ring_clean(tx_ring);
	else if (e_type == RC_XMIT_INDEX_CNF)
		lxsnic_tx_ring_idx_clean(tx_ring);
	else
		lxsnic_tx_ring_clean(tx_ring);

	nb_pkts = (uint16_t)RTE_MIN(tx_ring->count, total_nb_pkts);
	if (unlikely(!nb_pkts)) {
		tx_num = 0;
		goto end_of_tx;
	}

	if (!(cap & LSINIC_CAP_XFER_PKT_MERGE) &&
		(LSINIC_CAP_XFER_RC_XMIT_BD_TYPE_GET(cap) ==
		RC_XMIT_ADDRL_TYPE)) {
		while (nb_pkts) {
			ret = lxsnic_xmit_one_pkt_addrl(tx_ring,
				tx_pkts[tx_num], 0, &xmit_addrl[tx_num]);
			if (ret)
				goto end_of_tx;

			tx_num++;
			nb_pkts--;
		}
		goto end_of_tx;
	} else if (LSINIC_CAP_XFER_RC_XMIT_BD_TYPE_GET(cap) ==
		RC_XMIT_IDX_TYPE) {
		while (nb_pkts) {
			ret = lxsnic_xmit_one_pkt_idx(tx_ring,
				tx_pkts[tx_num], &xmit_idx[tx_num]);
			if (ret)
				goto end_of_tx;

			tx_num++;
			nb_pkts--;
		}
		goto end_of_tx;
	}

	while (nb_pkts) {
		ret = lxsnic_try_to_merge(tx_ring, &tx_pkts[tx_num],
				nb_pkts, &free_pkts[free_nb], &free_nb);
		if (ret < 0)
			goto end_of_tx;

		if (ret) {
			tx_num += ret;
			nb_pkts -= ret;
		} else {
			if (LSINIC_CAP_XFER_RC_XMIT_BD_TYPE_GET(cap) ==
				RC_XMIT_ADDRL_TYPE) {
				ret = lxsnic_xmit_one_pkt_addrl(tx_ring,
					tx_pkts[tx_num], 0, NULL);
			} else {
				ret = lxsnic_xmit_one_pkt(tx_ring,
					tx_pkts[tx_num], 0);
			}
			if (ret)
				goto end_of_tx;

			tx_num++;
			nb_pkts--;
		}
	}

end_of_tx:
	if (!(cap & LSINIC_CAP_XFER_PKT_MERGE) &&
		(LSINIC_CAP_XFER_RC_XMIT_BD_TYPE_GET(cap) ==
		RC_XMIT_ADDRL_TYPE)) {
		if ((first_idx + tx_num) <= tx_ring->count) {
			memcpy(&tx_ring->xmit_addrl[first_idx],
				&xmit_addrl[0],
				tx_num * sizeof(struct lsinic_rc_xmit_addrl));
		} else {
			memcpy(&tx_ring->xmit_addrl[first_idx],
				&xmit_addrl[0],
				(tx_ring->count - first_idx) *
				sizeof(struct lsinic_rc_xmit_addrl));
			memcpy(&tx_ring->xmit_addrl[0],
				&xmit_addrl[tx_ring->count - first_idx],
				(tx_num + first_idx - tx_ring->count) *
				sizeof(struct lsinic_rc_xmit_addrl));
		}
	} else if (LSINIC_CAP_XFER_RC_XMIT_BD_TYPE_GET(cap) ==
		RC_XMIT_IDX_TYPE) {
		if ((first_idx + tx_num) <= tx_ring->count) {
			memcpy(&tx_ring->xmit_idx[first_idx],
				&xmit_idx[0],
				tx_num * sizeof(struct lsinic_rc_xmit_idx));
		} else {
			memcpy(&tx_ring->xmit_idx[first_idx],
				&xmit_idx[0],
				(tx_ring->count - first_idx) *
				sizeof(struct lsinic_rc_xmit_idx));
			memcpy(&tx_ring->xmit_idx[0],
				&xmit_idx[tx_ring->count - first_idx],
				(tx_num + first_idx - tx_ring->count) *
				sizeof(struct lsinic_rc_xmit_idx));
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

	if (tx_ring->adapter->cap & LSINIC_CAP_XFER_TX_BD_UPDATE) {
		rte_wmb();
		LSINIC_WRITE_REG(&tx_ring->ep_reg->pir,
			tx_ring->last_avail_idx & (tx_ring->count - 1));
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
#ifdef LSINIC_BD_CTX_IDX_USED
	uint32_t mbuf_idx;
	struct ep2rc_notify *rx_notify;

	if (rx_queue->ep2rc.rx_notify) {
		rx_notify = rx_desc;
		mbuf_idx = EP2RC_TX_CTX_IDX(rx_notify->cnt_idx);
		mbuf = (struct rte_mbuf *)rx_queue->q_mbuf[mbuf_idx];
		total_size = rx_notify->total_len;
	} else {
		bd_desc = rx_desc;
		mbuf_idx = lsinic_bd_ctx_idx(bd_desc->bd_status);
		mbuf = (struct rte_mbuf *)rx_queue->q_mbuf[mbuf_idx];
		total_size = LSINIC_READ_REG(&bd_desc->len_cmd) &
			LSINIC_BD_LEN_MASK;
	}
#else
	bd_desc = rx_desc;
	mbuf = (struct rte_mbuf *)bd_desc->sw_ctx;
	total_size = LSINIC_READ_REG(&bd_desc->len_cmd) &
		LSINIC_BD_LEN_MASK;
#endif

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
	mg_header = (struct lsinic_mg_header *)data_base;

	pkt_len = lsinic_mg_entry_len(mg_header->len_cmd[0]);

	if (!lxsnic_rc_mg_fast_fwd()) {
		/* skip mg structure */
		mbuf->data_off += sizeof(struct lsinic_mg_header);
	}
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
	offset = sizeof(struct lsinic_mg_header) + pkt_len + align_off;

	if (lxsnic_rc_mg_fast_fwd()) {
		*rte_pktmbuf_mtod_offset(mbuf, char *,
				FAST_MG_FLAG_OFF) =
				LXSNIC_MBUF_MERGED;
		mbuf->pkt_len += align_off;
		mbuf->data_len += align_off;
		rx_queue->packets++;
		rx_queue->bytes += pkt_len;
		rx_queue->bytes_fcs += pkt_len + LSINIC_ETH_FCS_SIZE;
		rx_queue->bytes_overhead +=
			pkt_len + LSINIC_ETH_OVERHEAD_SIZE;
	}

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

		if (lxsnic_rc_mg_fast_fwd()) {
			rx_queue->packets++;
			rx_queue->bytes += pkt_len;
			rx_queue->bytes_fcs +=
				pkt_len + LSINIC_ETH_FCS_SIZE;
			rx_queue->bytes_overhead +=
				pkt_len + LSINIC_ETH_OVERHEAD_SIZE;
			mbuf->pkt_len += pkt_len + align_off;
			mbuf->data_len = mbuf->pkt_len;
			continue;
		}

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
#ifdef LSINIC_BD_CTX_IDX_USED
	uint32_t mbuf_idx;
	struct ep2rc_notify *rx_notify;

	if (rx_queue->ep2rc.rx_notify) {
		rx_notify = rx_desc;
		mbuf_idx = EP2RC_TX_CTX_IDX(rx_notify->cnt_idx);
		mbuf = (struct rte_mbuf *)rx_queue->q_mbuf[mbuf_idx];
		rx_packet_len = rx_notify->total_len;
	} else {
		bd_desc = rx_desc;
		mbuf_idx = lsinic_bd_ctx_idx(bd_desc->bd_status);
		mbuf = (struct rte_mbuf *)rx_queue->q_mbuf[mbuf_idx];
		rx_packet_len = LSINIC_READ_REG(&bd_desc->len_cmd) &
			LSINIC_BD_LEN_MASK;
	}
#else
	bd_desc = rx_desc;
	mbuf = (struct rte_mbuf *)bd_desc->sw_ctx;
	rx_packet_len = LSINIC_READ_REG(&bd_desc->len_cmd) &
		LSINIC_BD_LEN_MASK;
#endif

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

static int
lxsnic_rx_bd_fill(struct lxsnic_ring *rx_queue, uint16_t start_idx,
	struct rte_mbuf *mbufs[], int count)
{
	struct lsinic_bd_desc *ep_rx_desc, *rc_rx_desc;
	uint64_t dma_addr = 0;
	uint16_t idx = start_idx, cnt = 0;
#ifdef LSINIC_BD_CTX_IDX_USED
	uint32_t mbuf_idx;
#endif

	while (cnt < count) {
		rc_rx_desc = LSINIC_RC_BD_DESC(rx_queue, idx);
		if (rx_queue->adapter->cap & LSINIC_CAP_XFER_RX_BD_UPDATE)
			ep_rx_desc = NULL;
		else
			ep_rx_desc = LSINIC_EP_BD_DESC(rx_queue, idx);

		mbufs[cnt]->data_off = RTE_PKTMBUF_HEADROOM;
		mbufs[cnt]->port = rx_queue->port;
		dma_addr =
			rte_cpu_to_le_64(rte_mbuf_data_iova_default(mbufs[cnt]));

		rc_rx_desc->pkt_addr = dma_addr;
#ifdef LSINIC_BD_CTX_IDX_USED
		mbuf_idx = lsinic_bd_ctx_idx(rc_rx_desc->bd_status);
		rx_queue->q_mbuf[mbuf_idx] = mbufs[cnt];
		rc_rx_desc->bd_status = RING_BD_READY |
					(mbuf_idx << LSINIC_BD_CTX_IDX_SHIFT);
		if (ep_rx_desc) {
			mem_cp128b_atomic((uint8_t *)ep_rx_desc,
				(uint8_t *)rc_rx_desc);
		}
#else
		rc_rx_desc->sw_ctx = (uint64_t)mbufs[cnt];
		rc_rx_desc->bd_status = RING_BD_READY;

		if (ep_rx_desc) {
			rte_memcpy(ep_rx_desc, rc_rx_desc,
				offsetof(struct lsinic_bd_desc, desc));
			rte_wmb();
			rc_rx_desc->sw_ctx = LSINIC_READ_REG_64B(&ep_rx_desc->sw_ctx);
			ep_rx_desc->bd_status = rc_rx_desc->bd_status;
		}
#endif
		cnt++;
		idx = (idx + 1) & rx_queue->count;
	}

	if (rx_queue->adapter->cap & LSINIC_CAP_XFER_RX_BD_UPDATE) {
		rte_wmb();
		LSINIC_WRITE_REG(&rx_queue->ep_reg->pir,
			(idx + 1) & (rx_queue->count - 1));
	}

	return 0;
}

static inline void
lxsnic_rx_bd_mbuf_set(struct lxsnic_ring *rx_queue,
	uint16_t idx, struct rte_mbuf *mbuf)
{
	struct lsinic_bd_desc *ep_rx_desc, *rc_rx_desc;
	uint64_t dma_addr = 0;
#ifdef LSINIC_BD_CTX_IDX_USED
	uint32_t mbuf_idx;
#endif

	rc_rx_desc = LSINIC_RC_BD_DESC(rx_queue, idx);
	if (rx_queue->adapter->cap & LSINIC_CAP_XFER_RX_BD_UPDATE)
		ep_rx_desc = NULL;
	else
		ep_rx_desc = LSINIC_EP_BD_DESC(rx_queue, idx);
	mbuf->data_off = RTE_PKTMBUF_HEADROOM;
	mbuf->port = rx_queue->port;
	dma_addr = rte_cpu_to_le_64(rte_mbuf_data_iova_default(mbuf));
	rc_rx_desc->pkt_addr = dma_addr;
#ifdef LSINIC_BD_CTX_IDX_USED
	if (rx_queue->ep2rc.rx_notify)
		rx_queue->ep2rc.rx_notify[idx].cnt_idx = 0;
	mbuf_idx = lsinic_bd_ctx_idx(rc_rx_desc->bd_status);
	rx_queue->q_mbuf[mbuf_idx] = mbuf;
	rc_rx_desc->bd_status = RING_BD_READY |
					(mbuf_idx << LSINIC_BD_CTX_IDX_SHIFT);
	if (ep_rx_desc)
		mem_cp128b_atomic((uint8_t *)ep_rx_desc, (uint8_t *)rc_rx_desc);
#else
	rc_rx_desc->sw_ctx = (uint64_t)mbuf;
	rc_rx_desc->bd_status = RING_BD_READY;

	if (ep_rx_desc) {
		rte_memcpy(ep_rx_desc, rc_rx_desc,
			offsetof(struct lsinic_bd_desc, desc));
		rte_wmb();
		rc_rx_desc->sw_ctx =
			LSINIC_READ_REG_64B(&ep_rx_desc->sw_ctx);
		ep_rx_desc->desc = rc_rx_desc->desc;
	}
#endif
}

static uint16_t
lxsnic_eth_recv_pkts_to_cache(struct lxsnic_ring *rx_queue)
{
	int count = 0;
	uint32_t ret_val = 0;
	uint16_t nb_rx = 0;
	struct lsinic_bd_desc *rx_desc;
#ifdef LSINIC_BD_CTX_IDX_USED
	struct lsinic_bd_desc local_desc;
	struct ep2rc_notify *rx_notify =
			rx_queue->ep2rc.rx_notify;
#endif
	struct rte_mbuf *mbuf = NULL;
	struct rte_mbuf *new_mbuf;
	uint16_t idx = 0;
	int first_idx = -1;

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

	while (nb_rx < rx_queue->count) {
		idx = rx_queue->last_used_idx & (rx_queue->count - 1);
		if (first_idx < 0)
			first_idx = idx;

#ifdef RC_RING_REG_SHADOW_ENABLE
		rx_desc = LSINIC_RC_BD_DESC(rx_queue, idx);
#else
		rx_desc = LSINIC_EP_BD_DESC(rx_queue, idx);
#endif

#ifdef LSINIC_BD_CTX_IDX_USED
		if (rx_notify) {
			if (!rx_notify[idx].cnt_idx)
				break;
			goto skip_parse_bd;
		}
		mem_cp128b_atomic((uint8_t *)&local_desc, (uint8_t *)rx_desc);
		if ((local_desc.bd_status & RING_BD_STATUS_MASK) !=
			RING_BD_HW_COMPLETE)
			break;
		rx_desc = &local_desc;

skip_parse_bd:
#else
		if ((rx_desc->bd_status & RING_BD_STATUS_MASK) !=
			RING_BD_HW_COMPLETE)
			break;
		rte_rmb();
#endif

		new_mbuf = rte_mbuf_raw_alloc(rx_queue->mb_pool);
		if (unlikely(!new_mbuf)) {
			LSXINIC_PMD_DBG("RX mbuf alloc failed queue_id=%u ",
				(unsigned int)rx_queue->queue_index);
			rte_eth_devices[rx_queue->port].data->rx_mbuf_alloc_failed++;
			break;
		}

		/* This memory barrier is needed to keep us from reading
		 * any other fields out of the rx_desc until we know the
		 * descriptor has been written back
		 */
		count = 0;
#ifdef LSINIC_BD_CTX_IDX_USED
		if (rx_notify) {
			count = EP2RC_TX_CTX_CNT(rx_notify[idx].cnt_idx);
			if (count > 1) {
				count = lxsnic_fetch_merge_rx_buffer(rx_queue,
					&rx_notify[idx], count);
			} else {
				mbuf = lxsnic_fetch_rx_buffer(rx_queue,
					&rx_notify[idx]);
				if (mbuf) {
					rx_queue->mcache[rx_queue->mtail] =
						mbuf;
					rx_queue->mtail = (rx_queue->mtail + 1)
						& MCACHE_MASK;
					rx_queue->mcnt++;
					count = 1;
					if (lxsnic_rc_mg_fast_fwd()) {
						*rte_pktmbuf_mtod_offset(mbuf,
							char *,
							FAST_MG_FLAG_OFF) =
							LXSNIC_MBUF_SINGLE;
					}
				}
			}
		} else
#endif
		if (lxsnic_test_staterr(rx_desc, LSINIC_BD_CMD_MG)) {
			count = ((rx_desc->len_cmd & LSINIC_BD_MG_NUM_MASK) >>
					LSINIC_BD_MG_NUM_SHIFT) + 1;
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
				if (lxsnic_rc_mg_fast_fwd()) {
					*rte_pktmbuf_mtod_offset(mbuf, char *,
						FAST_MG_FLAG_OFF) =
						LXSNIC_MBUF_SINGLE;
				}
			}
		}

		lxsnic_rx_bd_mbuf_set(rx_queue, idx, new_mbuf);
		nb_rx++;

		rx_queue->last_used_idx++;  /* step to next */
		if (count == 0) {
			rx_queue->drop_packet_num++;
			break;
		}
		if (rx_queue->mcnt > LSINIC_MERGE_MAX_NUM)
			break;
	}

	if (0 && nb_rx > 0) {
		int ret = -ENOENT, nb = nb_rx;
		struct rte_mbuf *mbufs[2 * LSINIC_MERGE_MAX_NUM];

		while (ret) {
			ret = rte_pktmbuf_alloc_bulk(rx_queue->mb_pool,
				mbufs, nb);
			if (ret)
				nb = nb / 2;
			if (!nb)
				break;
		}
		lxsnic_rx_bd_fill(rx_queue, first_idx, mbufs, nb);
	} else {
		if (rx_queue->adapter->cap & LSINIC_CAP_XFER_RX_BD_UPDATE) {
			rte_wmb();
			LSINIC_WRITE_REG(&rx_queue->ep_reg->pir,
				rx_queue->last_used_idx &
				(rx_queue->count - 1));
		}
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
	enum rc_xmit_cnf_type e_type;
	const uint32_t cap = tx_queue->adapter->cap;

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
		e_type = LSINIC_CAP_XFER_RC_XMIT_CNF_TYPE_GET(cap);
		if (e_type == RC_XMIT_RING_CNF)
			lxsnic_tx_complete_ring_clean(tx_queue);
		else if (e_type == RC_XMIT_INDEX_CNF)
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
		if (!lxsnic_rc_mg_fast_fwd() ||
			*rte_pktmbuf_mtod_offset(mbuf, char *,
				FAST_MG_FLAG_OFF) ==
				LXSNIC_MBUF_SINGLE) {
			rx_queue->packets++;
			rx_queue->bytes += mbuf->pkt_len;
			rx_queue->bytes_fcs +=	mbuf->pkt_len +
				LSINIC_ETH_FCS_SIZE;
			rx_queue->bytes_overhead += mbuf->pkt_len +
				LSINIC_ETH_OVERHEAD_SIZE;
		}

#ifdef DEBUG_MBUF
		print_mbuf(mbuf);
#endif
	}

	return nb_rx;
}
