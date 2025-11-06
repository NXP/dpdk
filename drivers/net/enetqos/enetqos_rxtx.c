/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2023-2025 NXP
 */

#include <rte_memzone.h>
#include <sys/mman.h>
#include <rte_io.h>
#include <fcntl.h>
#include <unistd.h>
#include <rte_mbuf.h>
#include <rte_io.h>

#include "enetqos_hw.h"
#include "enetqos_ethdev.h"
#include "enetqos_pmd_logs.h"

static int enetqos_get_rx_status(struct dma_desc *p)
{
	unsigned int rdes1 = p->des1;
	unsigned int rdes3 = p->des3;
	int ret = ok_frame;

	if (!likely(rdes3 & ENETQ_RDES_NOTVALID))
		return ret;

	if (unlikely(rdes3 & ENETQ_RDES3_OWN))
		return dma_owner;
	if (unlikely(rdes3 & ENETQ_RDES3_CTX_DESC))
		return discard_frame;

	if (unlikely(!(rdes3 & ENETQ_RDES3_LAST_DESC)))
		return rx_not_ldesc;


	if (unlikely(rdes3 & ENETQ_RDES3_ERR_SUMMARY)) {
		if (unlikely(rdes3 & ENETQ_RDES3_GIANT_PKT))
			ENETQOS_DP_LOG(DEBUG, "rx_fifo_error");
		if (unlikely(rdes3 & ENETQ_RDES3_OVERFLOW_ERR))
			ENETQOS_DP_LOG(DEBUG, "overflow_error");
		if (unlikely(rdes3 & ENETQ_RDES3_RECEIVE_ERR))
			ENETQOS_DP_LOG(DEBUG, "receive_error");
		if (unlikely(rdes3 & ENETQ_RDES3_CRC_ERR))
			ENETQOS_DP_LOG(DEBUG, "crc_error");
		if (unlikely(rdes3 & ENETQ_RDES3_DRIBBLE_ERR))
			ENETQOS_DP_LOG(DEBUG, "dribble_error");

		ret = discard_frame;
	}

	if(unlikely(rdes1 & ENETQ_RDES1_IPHE)) {
		ENETQOS_DP_LOG(DEBUG, "IP Header Error");
		ret = discard_frame;
	}

	if(unlikely(rdes1 & ENETQ_RDES1_IPCE)) {
		ENETQOS_DP_LOG(DEBUG, "IP Payload Error");
		ret = discard_frame;
	}

	return ret;
}

static void enetqos_set_rx_owner(struct dma_desc *p)
{
	p->des3 |= ENETQ_RDES3_OWN | ENETQ_RDES3_BUFFER1_VALID_ADDR;
}

static int enetqos_wrback_get_rx_frame_len(struct dma_desc *p)
{
	return (p->des3 & ENETQ_RDES3_PKT_SZ_MASK);
}

uint16_t
enetqos_recv_pkts(void *queue, struct rte_mbuf **rx_pkts,
	uint16_t nb_pkts)
{
	struct enetqos_rx_queue *rxq = (struct enetqos_rx_queue *)queue;
	struct rte_eth_stats *stats = &rxq->priv_data->stats;
	struct rte_mbuf *mbuf, *new_mbuf = NULL;
	unsigned int next_entry = rxq->cur_rx;
	unsigned short status, pkt_len;
	struct dma_desc *desc, *first, temp_first;
	struct enetqos_priv *priv;
	struct rte_ether_hdr *eth;
	int pkt_received = 0;
	int entry;
	uint8_t *data;

	priv = rxq->priv_data;
	entry = next_entry;

	desc = rxq->dma_rx + entry;
	first = desc;
#ifdef RTE_ARCH_32
	rte_memcpy(&temp_first, first, 16);
#else
	__uint128_t *dst128 = (__uint128_t *)&temp_first;
	__uint128_t *src128 = (__uint128_t *)first;
	*dst128 = *src128;
#endif

	/* Process the incoming packet */
	status = enetqos_get_rx_status(&temp_first);
	while (!(status & dma_owner)) {
		if (pkt_received >= nb_pkts)
			break;

		/* Check for errors. */
		if (unlikely(status == discard_frame)) {
			stats->ierrors++;
			mbuf = rxq->rx_mbuf[entry];
			rte_pktmbuf_free(mbuf);

			goto rx_processing_done;
		}

		/* Process the incoming frame */
		pkt_len = enetqos_wrback_get_rx_frame_len(&temp_first);
		mbuf = rxq->rx_mbuf[entry];
		data = rte_pktmbuf_mtod(mbuf, void *);
		for (int i = 0; i < pkt_len; i += RTE_CACHE_LINE_SIZE)
			dccivac(data + i);
		rte_prefetch0(data);
		rx_pkts[pkt_received] = mbuf;
		stats->ibytes += pkt_len;
		stats->ipackets++;
		pkt_received++;
		mbuf->data_len = pkt_len;
		mbuf->pkt_len = pkt_len;
		mbuf->ol_flags = RTE_MBUF_F_RX_IP_CKSUM_GOOD
				| RTE_MBUF_F_RX_L4_CKSUM_GOOD;

		/* Assuming Ethernet packets, doing software packet type parsing.
		 * To be replaced by HW packet parsing
		 */
		eth = (struct rte_ether_hdr *)data;
		mbuf->packet_type = RTE_PTYPE_L2_ETHER;
		if (rte_be_to_cpu_16(eth->ether_type) == RTE_ETHER_TYPE_IPV4)
			mbuf->packet_type |= RTE_PTYPE_L3_IPV4;
		else if (rte_be_to_cpu_16(eth->ether_type) == RTE_ETHER_TYPE_IPV6)
			mbuf->packet_type |= RTE_PTYPE_L3_IPV6;

rx_processing_done:
		new_mbuf = rte_pktmbuf_alloc(rxq->pool);
		if (unlikely(new_mbuf == NULL)) {
			stats->rx_nombuf++;
			break;
		}

		rxq->rx_mbuf[entry] = new_mbuf;
		enetqos_set_addr(&temp_first, rte_pktmbuf_iova(new_mbuf));

		/* Make sure the updates to rest of the descriptor are
		 * performed before transferring ownership.
		 */
		enetqos_set_rx_owner(&temp_first);

#ifdef RTE_ARCH_32
                rte_memcpy(first, &temp_first, 16);
#else
		*src128 = *dst128;
#endif
		/* Increment the desc to next descriptor
		 * The DMA automatically wraps around the base
		 * address when the end of ring is reached
		 */
		next_entry = STMMAC_GET_ENTRY(entry, priv->dma_rx_size);
		entry = rxq->dirty_rx = rxq->cur_rx = next_entry;
		desc = rxq->dma_rx + next_entry;
		first = desc;

#ifdef RTE_ARCH_32
                rte_memcpy(&temp_first, first, 16);
#else
                dst128 = (__uint128_t *)&temp_first;
                src128 = (__uint128_t *)first;
                *dst128 = *src128;
#endif
		status = enetqos_get_rx_status(&temp_first);
	}

	rxq->rx_tail_addr = rxq->dma_rx_phy +
				(rxq->dirty_rx * sizeof(struct dma_desc));
	enetqos_set_rx_tail_ptr(priv->ioaddr, rxq->rx_tail_addr, rxq->queue_index);

	return pkt_received;
}

static void
enetqos_prepare_tx_desc(struct dma_desc *p, int len, unsigned int tot_pkt_len)
{
	p->des2 = len & ENETQ_TDES2_BUF1_SZ_MASK;

	p->des3	= tot_pkt_len & ENETQ_TDES3_PKT_SZ_MASK;
	p->des3 |= ENETQ_TDES3_FIRST_DESC | ENETQ_TDES3_LAST_DESC;
}

static int enetqos_get_tx_status(struct dma_desc *p)
{
	unsigned int tdes3;
	int ret = tx_comp;

	tdes3 = p->des3;

	/* Verify tx error by looking at the last segment. */
	if (!(tdes3 & ENETQ_TDES3_LAST_DESC))
		return tx_not_ldesc;

	/* Get tx owner first */
	if (tdes3 & ENETQ_TDES3_OWN)
		return tx_dma_owner;

	if (tdes3 & ENETQ_TDES3_ERR_SUMMARY) {
		ret = tx_error;

		if (tdes3 & ENETQ_TDES3_JABBER_TIMEOUT)
			ENETQOS_DP_LOG(DEBUG, "Jabber Timeout");
		if (tdes3 & ENETQ_TDES3_PKT_FLUSHED)
			ENETQOS_DP_LOG(DEBUG, "Packet Flush");
		if (tdes3 & ENETQ_TDES3_LOSS_CARRIER)
			ENETQOS_DP_LOG(DEBUG, "Loss of Carrier");
		if (tdes3 & ENETQ_TDES3_NO_CARRIER)
			ENETQOS_DP_LOG(DEBUG, "No Carrier");
		if ((tdes3 & ENETQ_TDES3_LATE_COLLISION) ||
				(tdes3 & ENETQ_TDES3_EXCESSIVE_COLLISION))
			ENETQOS_DP_LOG(DEBUG, "late or excessive collision");
		if (tdes3 & ENETQ_TDES3_EXCESSIVE_DEFERRAL)
			ENETQOS_DP_LOG(DEBUG, "Excessive Deferral");
		if (tdes3 & ENETQ_TDES3_UNDERFLOW_ERR) {
			ENETQOS_DP_LOG(DEBUG, "Underflow Error");
			ret |= tx_error_bump_tc;
		}

		if (tdes3 & ENETQ_TDES3_IP_HDR_ERR)
			ENETQOS_DP_LOG(DEBUG, "IP Header Error");

		if (tdes3 & ENETQ_TDES3_PL_ERR)
			ENETQOS_DP_LOG(DEBUG, "Payload Checksum Error");
	}

	if (tdes3 & ENETQ_TDES3_DEF)
		ENETQOS_DP_LOG(DEBUG, "Deferred");

	return ret;
}

static void enetqos_flush_tx_descriptors(struct enetqos_priv *priv, int queue)
{
	struct enetqos_tx_queue *tx_q = priv->tx_queue[queue];
	int desc_size;

	desc_size = sizeof(struct dma_desc);

	tx_q->tx_tail_addr = tx_q->dma_tx_phy + (tx_q->cur_tx * desc_size);
	enetqos_set_tx_tail_ptr(priv->ioaddr, tx_q->tx_tail_addr, queue);
}

uint16_t
enetqos_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	struct enetqos_tx_queue *tx_q = (struct enetqos_tx_queue *)tx_queue;
	struct enetqos_priv *priv;
	struct dma_desc *desc, *first, temp_first;
	unsigned int tx_packets = 0;
	int entry;
	struct rte_mbuf *mbuf;
	unsigned short status;
	unsigned short buflen;
	struct rte_eth_stats *stats = &tx_q->priv_data->stats;
	uint8_t *data;

	priv = tx_q->priv_data;
	entry = tx_q->cur_tx;
	desc = tx_q->dma_tx + entry;
	first = desc;

#ifdef RTE_ARCH_32
	rte_memcpy(&temp_first, first, 16);
#else
	__uint128_t *dst128 = (__uint128_t *)&temp_first;
	__uint128_t *src128 = (__uint128_t *)first;
	*dst128 = *src128;
#endif
	while (tx_packets < nb_pkts) {
		mbuf = *(tx_pkts);

		status = enetqos_get_tx_status(&temp_first);
		if (status & (tx_dma_owner | tx_error)) {
			stats->oerrors++;
			break;
		}

		if (tx_q->tx_mbuf[entry])
			rte_pktmbuf_free(tx_q->tx_mbuf[entry]);

		buflen = rte_pktmbuf_pkt_len(mbuf);
		stats->obytes += buflen;
		enetqos_set_addr(&temp_first, rte_pktmbuf_iova(mbuf));

		data = rte_pktmbuf_mtod(mbuf, void *);
		for (int i = 0; i < buflen; i += RTE_CACHE_LINE_SIZE)
			dcbf(data + i);

		enetqos_prepare_tx_desc(&temp_first, buflen, buflen);
		tx_q->tx_mbuf[entry] = mbuf;
		stats->opackets++;
//TBD		stats->q_opackets[tx_q->queue_index]++;
		tx_packets++;
		tx_q->tx_count_frames += tx_packets;

		/* Increment the desc to next descriptor
		 * The DMA automatically wraps around the base
		 * address when the end of ring is reached
		 */

		entry = STMMAC_GET_ENTRY(entry, priv->dma_tx_size);
		tx_q->cur_tx = entry;
		desc = tx_q->dma_tx + entry;
		/* Finally set the OWN bit. Later the DMA will start! */
		temp_first.des3 |= ENETQ_TDES3_OWN;
#ifdef RTE_ARCH_32
                rte_memcpy(first, &temp_first, 16);
#else
		*src128 = *dst128;
#endif
		enetqos_flush_tx_descriptors(priv, tx_q->queue_index);
		first = desc;
#ifdef RTE_ARCH_32
                rte_memcpy(&temp_first, first, 16);
#else
                dst128 = (__uint128_t *)&temp_first;
                src128 = (__uint128_t *)first;
                *dst128 = *src128;
#endif
		tx_pkts++;
	}

	return tx_packets;
}
