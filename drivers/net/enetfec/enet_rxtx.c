/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2021-2025 NXP
 */

#include <rte_mbuf.h>
#include <rte_io.h>
#include <ethdev_driver.h>
#include "enet_regs.h"
#include "enet_ethdev.h"
#include "enet_pmd_logs.h"
#include "compat.h"

/* This function does enetfec_rx_queue processing. Dequeue packet from Rx queue
 * When update through the ring, just set the empty indicator.
 */
uint16_t
enetfec_recv_pkts(void *queue, struct rte_mbuf **rx_pkts,
		uint16_t nb_pkts)
{
	struct enetfec_priv_rx_q *rxq  = (struct enetfec_priv_rx_q *)queue;
	struct rte_eth_stats *stats = &rxq->fep->stats;
	struct rte_mbuf *mbuf, *new_mbuf = NULL;
	int pkt_received = 0, index = 0;
	unsigned short status, pkt_len;
	struct rte_ether_hdr *eth;
	void *data;
	struct bufdesc *bdp, temp_bdp = {0};

	bdp = rxq->bd.cur;
	uint64_t *dst64 = (uint64_t *)&temp_bdp;
	uint64_t *src64 = (uint64_t *)bdp;
	*dst64 = *src64;

	/* Process the incoming packet */
	status = temp_bdp.bd_sc;
	while ((status & RX_BD_EMPTY) == 0) {
		/* Check for errors. */
		status ^= RX_BD_LAST;
		if (unlikely(status & RX_BD_ERR)) {
			stats->ierrors++;
			if (status & RX_BD_OV) {
				/* FIFO overrun */
				/* enet_dump_rx(rxq); */
				ENETFEC_DP_LOG(DEBUG, "rx_fifo_error");
			}
			if (status & (RX_BD_LG | RX_BD_SH
						| RX_BD_LAST)) {
				/* Frame too long or too short. */
				ENETFEC_DP_LOG(DEBUG, "rx_length_error");
				if (status & RX_BD_LAST)
					ENETFEC_DP_LOG(DEBUG, "rcv is not +last");
			}
			if (status & RX_BD_CR) {     /* CRC Error */
				ENETFEC_DP_LOG(DEBUG, "rx_crc_errors");
			}
			/* Report late collisions as a frame error. */
			if (status & (RX_BD_NO | RX_BD_TR))
				ENETFEC_DP_LOG(DEBUG, "rx_frame_error");

			goto rx_processing_done;
		}

		/* shows data with respect to the data_off field. */
		index = enet_get_bd_index(bdp, &rxq->bd);
		mbuf = rxq->rx_mbuf[index];

		data = rte_pktmbuf_mtod(mbuf, uint8_t *);
		/* SG not supported */
		pkt_len = temp_bdp.bd_datlen;
		mbuf->pkt_len = mbuf->data_len = pkt_len - 4;

		/*Adjustment for RACC */
		data = rte_pktmbuf_adj(mbuf, 2);
		/* Cache invalidate data buffer */
		for (int i = 0; i < mbuf->data_len; i += RTE_CACHE_LINE_SIZE)
			dccivac((uint8_t *)data + i);

		/* prefetch first cache line */
		rte_prefetch0(data);
		rx_pkts[pkt_received] = mbuf;
		pkt_received++;
		stats->ipackets++;
		stats->ibytes += mbuf->data_len;

		/* Assuming Ethernet packets, doing software packet type parsing.
		 * To be replaced by HW packet parsing
		 */
		eth = (struct rte_ether_hdr *)data;
		mbuf->packet_type = RTE_PTYPE_L2_ETHER;
		if (rte_be_to_cpu_16(eth->ether_type) == RTE_ETHER_TYPE_IPV4)
			mbuf->packet_type |= RTE_PTYPE_L3_IPV4;
		else if (rte_be_to_cpu_16(eth->ether_type) == RTE_ETHER_TYPE_IPV6)
			mbuf->packet_type |= RTE_PTYPE_L3_IPV6;

		mbuf->ol_flags = RTE_MBUF_F_RX_IP_CKSUM_GOOD;
		new_mbuf = rte_pktmbuf_alloc(rxq->pool);
		if (unlikely(new_mbuf == NULL)) {
			stats->rx_nombuf++;
			break;
		}
		rxq->rx_mbuf[index] = new_mbuf;
		temp_bdp.bd_bufaddr = (uint32_t)rte_pktmbuf_iova(new_mbuf);
rx_processing_done:
		/* when rx_processing_done clear the status flags
		 * for this buffer
		 */
		status &= ~RX_BD_STATS;

		/* Mark the buffer empty */
		status |= RX_BD_EMPTY;
		temp_bdp.bd_sc = status;
		*src64 = *dst64;

		/* Doing this here will keep the FEC running while we process
		 * incoming frames.
		 */
		rte_write32_relaxed(0, rxq->bd.active_reg_desc);

		/* Update BD pointer to next entry */
		bdp = enet_get_nextdesc(bdp, &rxq->bd);

		dst64 = (uint64_t *)&temp_bdp;
		src64 = (uint64_t *)bdp;
		*dst64 = *src64;
		status = temp_bdp.bd_sc;

		if (pkt_received >= nb_pkts)
			break;
	}
	rxq->bd.cur = bdp;
	return pkt_received;
}

uint16_t
enetfec_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	struct enetfec_priv_tx_q *txq  =
			(struct enetfec_priv_tx_q *)tx_queue;
	struct rte_eth_stats *stats = &txq->fep->stats;
	struct bufdesc *bdp, *last_bdp, temp_bdp;
	struct rte_mbuf *mbuf, *free_buf[256];
	unsigned short status;
	unsigned short buflen;
	unsigned int index;
	unsigned int i, pkt_t = 0, free_cnt = 0;
	uint8_t *data;

	while (pkt_t < nb_pkts) {
		mbuf = tx_pkts[pkt_t];
		if (mbuf->nb_segs > 1) {
			ENETFEC_DP_LOG(DEBUG, "SG not supported");
			stats->opackets += pkt_t;
			rte_pktmbuf_free_bulk(free_buf, free_cnt);
			return pkt_t;
		}

		/* Get current descriptor */
		bdp = txq->bd.cur;
		/* copy local and check status */
		uint64_t *dst64 = (uint64_t *)&temp_bdp;
                uint64_t *src64 = (uint64_t *)bdp;
                *dst64 = *src64;

		index = enet_get_bd_index(bdp, &txq->bd);
		status = temp_bdp.bd_sc;

		if (status & TX_BD_READY) {
			/* Queue is full */
			stats->oerrors++;
			break;
		}
		if (txq->tx_mbuf[index]) {
			free_buf[free_cnt] = txq->tx_mbuf[index];
			free_cnt++;
			txq->tx_mbuf[index] = NULL;
		}
		/* Save mbuf pointer to free next time */
		txq->tx_mbuf[index] = mbuf;

		/* Set buffer length and buffer pointer */
		buflen = rte_pktmbuf_pkt_len(mbuf);
		data = rte_pktmbuf_mtod(mbuf, void *);
		for (i = 0; i < buflen; i += RTE_CACHE_LINE_SIZE)
			dcbf(data + i);

		temp_bdp.bd_bufaddr = rte_pktmbuf_iova(mbuf);
		temp_bdp.bd_datlen = buflen;
		status &= ~TX_BD_STATS;
		status |= TX_BD_LAST;

		last_bdp = bdp;

		/* Make sure the updates to rest of the descriptor are performed
		 * before transferring ownership.
		 */
		status |= (TX_BD_READY | TX_BD_TC);
		temp_bdp.bd_sc = status;

		/* write back to original */
		*src64 = *dst64;

		/* Trigger transmission start */
		rte_write32_relaxed(0, txq->bd.active_reg_desc);
		pkt_t++;
		stats->obytes += buflen;

		/* If this was the last BD in the ring, start at the
		 * beginning again.
		 */
		bdp = enet_get_nextdesc(last_bdp, &txq->bd);
		txq->bd.cur = bdp;
	}
	rte_pktmbuf_free_bulk(free_buf, free_cnt);
	stats->opackets += pkt_t;

	return pkt_t;
}
