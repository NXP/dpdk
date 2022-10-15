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
		rte_pktmbuf_free(last_mbuf);

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
		rte_pktmbuf_free(last_mbuf);

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

		return -EINVAL;
	}

	if (tx_pkt->nb_segs > 1)
		return -EINVAL;

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
				tx_ring->errors++;
				return -EAGAIN;
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
			tx_ring->errors++;
			return -EAGAIN;
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
	RTE_ASSERT(pkt_len < MAX_U16);
	local_desc.len = pkt_len;

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
	struct rte_mbuf *tx_pkt,
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
		return -EINVAL;

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
			tx_ring->errors++;
			return -EAGAIN;
		}
		mbuf_idx = bd_idx;
	} else if (tx_ring->rc_mem_bd_type == RC_MEM_BD_CNF) {
		tx_complete = &tx_ring->tx_complete[bd_idx].bd_complete;
		if (*tx_complete != RING_BD_READY) {
#ifdef LXSNIC_DEBUG_RX_TX
			tx_ring->adapter->stats.tx_desc_err++;
#endif
			tx_ring->ring_full++;
			tx_ring->errors++;
			return -EAGAIN;
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
	cmd_type |= pkt_len;

	local_desc.pkt_addr_low = dma - tx_ring->adapter->pkt_addr_base;
	local_desc.len_cmd = cmd_type;

	if (!notify)
		ep_tx_desc->addr_cmd_len = local_desc.addr_cmd_len;
	else
		notify->addr_cmd_len = local_desc.addr_cmd_len;

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
lxsnic_xmit_one_pkt(struct lxsnic_ring *tx_ring,
	struct rte_mbuf *tx_pkt, struct lsinic_bd_desc *local_desc)
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
		return -EINVAL;

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
			tx_ring->errors++;
			return -EAGAIN;
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
			tx_ring->errors++;
			return -EAGAIN;
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
			tx_ring->errors++;
			return -EAGAIN;
		}
		mbuf_idx = lsinic_bd_ctx_idx(bd_status);
		if (unlikely(mbuf_idx == LSINIC_BD_CTX_IDX_INVALID))
			mbuf_idx = bd_idx;

		tx_ring->q_mbuf[mbuf_idx] = tx_pkt;
		tx_complete_desc->bd_status &=
			(~((uint32_t)RING_BD_STATUS_MASK));
		tx_complete_desc->bd_status |= RING_BD_HW_PROCESSING;
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
	cmd_type |= pkt_len;

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

	tx_ring->packets++;
	tx_ring->bytes += tx_pkt->pkt_len;
	tx_ring->bytes_fcs += tx_pkt->pkt_len + LSINIC_ETH_FCS_SIZE;
	tx_ring->bytes_overhead += tx_pkt->pkt_len +
			LSINIC_ETH_OVERHEAD_SIZE;
	tx_ring->tx_free_len++;
	tx_ring->last_avail_idx++;

	return 0;
}

static uint16_t
_lxsnic_eth_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts,
		uint16_t nb_pkts)
{
	int ret = 0, i;
	uint8_t ret_val = 0;
	uint16_t tx_num = 0, idx_tx_num;
	uint16_t total_nb_pkts = nb_pkts;
	struct lxsnic_ring *tx_ring = tx_queue;
	struct rte_mbuf *free_pkts[LSINIC_MAX_BURST_NUM];
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
			ret = lxsnic_xmit_one_pkt_addrl(tx_ring,
				tx_pkts[tx_num],
				&notify.ep_tx_addrl[notify_idx]);
			if (ret)
				goto end_of_tx;
			notify_idx++;
			tx_num++;
			nb_pkts--;
		}
		goto end_of_tx;
	} else if (tx_ring->ep_mem_bd_type == EP_MEM_SRC_ADDRX_BD) {
		while (nb_pkts) {
			ret = lxsnic_xmit_one_pkt_idx(tx_ring,
				tx_pkts[tx_num],
				&notify.ep_tx_addrx[notify_idx]);
			if (ret)
				goto end_of_tx;
			notify_idx++;
			tx_num++;
			nb_pkts--;
		}
		goto end_of_tx;
	}

	while (nb_pkts) {
		ret = lxsnic_xmit_one_pkt(tx_ring,
			tx_pkts[tx_num],
			&notify.ep_tx_addr[notify_idx]);
		if (ret)
			goto end_of_tx;
		notify_idx++;
		tx_num++;
		nb_pkts--;
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
		int dst_idx;
		struct lsinic_bd_desc *src_desc;
		struct lsinic_bd_desc *dst_desc;

		src_desc = notify.ep_tx_addr;
		dst_desc = tx_ring->ep_bd_desc;
		for (i = 0; i < notify_idx; i++) {
			src = (void *)&src_desc[i];
			dst_idx = (first_idx + i) & (tx_ring->count - 1);
			dst = (void *)&dst_desc[dst_idx];
			mem_cp128b_atomic(dst, src);
		}
	}

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
	uint16_t rx_packet_len;
	struct lsinic_bd_desc *bd_desc;
	uint32_t mbuf_idx;
	struct lsinic_rc_rx_len_idx *rx_len_idx;
	const uint32_t cap = rx_queue->adapter->cap;

	if (rx_queue->rc_mem_bd_type == RC_MEM_LEN_CMD) {
		rx_len_idx = rx_desc;
		if (cap & LSINIC_CAP_XFER_ORDER_PRSV) {
			mbuf_idx = rx_queue->last_used_idx &
				(rx_queue->count - 1);
		} else {
			mbuf_idx = rx_len_idx->idx;
		}
		mbuf = (struct rte_mbuf *)rx_queue->q_mbuf[mbuf_idx];
		rx_packet_len = rx_len_idx->total_len;
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
lxsnic_rx_lbd_fill(struct lxsnic_ring *rx_queue, uint16_t start_idx,
	struct rte_mbuf *mbufs[], int count)
{
	int cnt = 0;
	uint64_t dma_addr = 0;
	uint16_t idx = start_idx;
	uint32_t mbuf_idx;
	struct lsinic_bd_desc *ep_rx_desc = NULL, *rc_rx_desc = NULL;
	struct lsinic_bd_desc local_rx_desc;
	struct lsinic_rc_rx_len_idx *rx_len_idx;

	ep_rx_desc = rx_queue->ep_bd_desc;
	while (cnt < count) {
		mbufs[cnt]->data_off = RTE_PKTMBUF_HEADROOM;
		mbufs[cnt]->port = rx_queue->port;
		dma_addr = rte_mbuf_data_iova_default(mbufs[cnt]);

		if (rx_queue->rc_mem_bd_type == RC_MEM_LONG_BD) {
			rc_rx_desc = &rx_queue->rc_bd_desc[idx];
			mbuf_idx = lsinic_bd_ctx_idx(rc_rx_desc->bd_status);
		} else {
			rx_len_idx = &rx_queue->rx_len_idx[idx];
			mbuf_idx = rx_len_idx->idx;
			rx_len_idx->len_idx = 0;
			rc_rx_desc = &local_rx_desc;
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
	struct lsinic_ep_tx_dst_addr local_recv_addr[count];
	struct lsinic_rc_rx_len_idx *rx_len_idx;

	ep_rx_addr = local_recv_addr;

	while (cnt < count) {
		mbufs[cnt]->data_off = RTE_PKTMBUF_HEADROOM;
		mbufs[cnt]->port = rx_queue->port;
		dma_addr = rte_mbuf_data_iova_default(mbufs[cnt]);

		mbuf_idx = idx;
		ep_rx_addr[cnt].pkt_addr = dma_addr;
		if (rx_queue->rc_mem_bd_type == RC_MEM_LEN_CMD) {
			rx_len_idx = &rx_queue->rx_len_idx[idx];
			rx_len_idx->len_idx = 0;
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
	struct lsinic_rc_rx_len_idx *rx_len_idx = NULL;
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
		rx_len_idx = rx_queue->rx_len_idx;

	while (nb_rx < rx_queue->count) {
		idx = rx_queue->last_used_idx & (rx_queue->count - 1);

		if (rx_len_idx) {
			if (!rx_len_idx[idx].len_idx)
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
		if (rx_len_idx) {
			mbuf = lxsnic_fetch_rx_buffer(rx_queue,
					&rx_len_idx[idx]);
			if (mbuf) {
				rx_queue->mcache[rx_queue->mtail] =
					mbuf;
				rx_queue->mtail = (rx_queue->mtail + 1)
					& MCACHE_MASK;
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

static uint16_t
_lxsnic_eth_recv_pkts(struct lxsnic_ring *rxq,
	struct rte_mbuf **rx_pkts, uint16_t nb_pkts)
{
	uint16_t nb_rx = 0;
	uint16_t count = 0;
	struct rte_mbuf *mbuf = NULL;

	lxsnic_eth_recv_pkts_to_cache(rxq);

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
			lxsnic_eth_self_xmit_gen_pkt(pay_load);
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
