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
enetfec_recv_pkts(void *rxq1, struct rte_mbuf **rx_pkts,
		uint16_t nb_pkts)
{
	struct enetfec_priv_rx_q *rxq  = (struct enetfec_priv_rx_q *)rxq1;
	struct rte_eth_conf *eth_conf = &rxq->fep->dev->data->dev_conf;
	uint64_t rx_offloads = eth_conf->rxmode.offloads;
	struct rte_eth_stats *stats = &rxq->fep->stats;
	struct rte_mbuf *mbuf, *new_mbuf = NULL;
	struct  bufdesc_ex *ebdp = NULL;
	int pkt_received = 0, index = 0;
	unsigned short status, pkt_len;
	bool vlan_packet_rcvd = false;
	struct rte_ether_hdr *eth;
	struct rte_mempool *pool;
	void *data, *mbuf_data;
	struct bufdesc *bdp;
	uint16_t vlan_tag;
	pool = rxq->pool;
	bdp = rxq->bd.cur;

	/* Process the incoming packet */
	status = rte_le_to_cpu_16(rte_read16(&bdp->bd_sc));
	while ((status & RX_BD_EMPTY) == 0) {
		if (pkt_received >= nb_pkts)
			break;

		/* Check for errors. */
		status ^= RX_BD_LAST;
		if (status & (RX_BD_LG | RX_BD_SH | RX_BD_NO |
			RX_BD_CR | RX_BD_OV | RX_BD_LAST |
			RX_BD_TR)) {
			stats->ierrors++;
			if (status & RX_BD_OV) {
				/* FIFO overrun */
				/* enet_dump_rx(rxq); */
				ENETFEC_DP_LOG(DEBUG, "rx_fifo_error");
				goto rx_processing_done;
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

		new_mbuf = rte_pktmbuf_alloc(pool);
		if (unlikely(new_mbuf == NULL)) {
			stats->rx_nombuf++;
			break;
		}

		/* Process the incoming frame. */
		stats->ipackets++;
		pkt_len = rte_le_to_cpu_16(rte_read16(&bdp->bd_datlen));
		stats->ibytes += pkt_len;

		/* shows data with respect to the data_off field. */
		index = enet_get_bd_index(bdp, &rxq->bd);
		mbuf = rxq->rx_mbuf[index];

		data = rte_pktmbuf_mtod(mbuf, uint8_t *);
		mbuf_data = data;
		rte_prefetch0(data);
		rte_pktmbuf_append((struct rte_mbuf *)mbuf,
				pkt_len - 4);

		if (rxq->fep->quirks & QUIRK_RACC)
			data = rte_pktmbuf_adj(mbuf, 2);

		rx_pkts[pkt_received] = mbuf;

		/* Assuming Ethernet packets, doing software packet type parsing.
		 * To be replaced by HW packet parsing
		 */
		eth = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
		mbuf->packet_type = RTE_PTYPE_L2_ETHER;
		if (rte_be_to_cpu_16(eth->ether_type) == RTE_ETHER_TYPE_IPV4)
			mbuf->packet_type |= RTE_PTYPE_L3_IPV4;
		if (rte_be_to_cpu_16(eth->ether_type) == RTE_ETHER_TYPE_IPV6)
			mbuf->packet_type |= RTE_PTYPE_L3_IPV6;
		pkt_received++;

		/* Extract the enhanced buffer descriptor */
		ebdp = NULL;
		if (rxq->fep->bufdesc_ex)
			ebdp = (struct bufdesc_ex *)bdp;

		/* If this is a VLAN packet remove the VLAN Tag */
		vlan_packet_rcvd = false;
		if ((rx_offloads & RTE_ETH_RX_OFFLOAD_VLAN) &&
				rxq->fep->bufdesc_ex &&
				(rte_read32(&ebdp->bd_esc) &
				rte_cpu_to_le_32(BD_ENETFEC_RX_VLAN))) {
			/* Push and remove the vlan tag */
			struct rte_vlan_hdr *vlan_header =
				(struct rte_vlan_hdr *)
				((uint8_t *)data + ETH_HLEN);
			vlan_tag = rte_be_to_cpu_16(vlan_header->vlan_tci);

			vlan_packet_rcvd = true;
			memmove((uint8_t *)mbuf_data + RTE_VLAN_HLEN,
				data, RTE_ETHER_ADDR_LEN * 2);
			rte_pktmbuf_adj(mbuf, RTE_VLAN_HLEN);
		}

		if (rxq->fep->bufdesc_ex &&
			(rxq->fep->flag_csum & RX_FLAG_CSUM_EN)) {
			if ((rte_read32(&ebdp->bd_esc) &
				rte_cpu_to_le_32(RX_FLAG_CSUM_ERR)) == 0) {
				/* don't check it */
				mbuf->ol_flags = RTE_MBUF_F_RX_IP_CKSUM_BAD;
			} else {
				mbuf->ol_flags = RTE_MBUF_F_RX_IP_CKSUM_GOOD;
			}
		}

		/* Handle received VLAN packets */
		if (vlan_packet_rcvd) {
			mbuf->vlan_tci = vlan_tag;
			mbuf->ol_flags |= RTE_MBUF_F_RX_VLAN_STRIPPED
						| RTE_MBUF_F_RX_VLAN;
		}

		rxq->rx_mbuf[index] = new_mbuf;
		rte_write32(rte_cpu_to_le_32(rte_pktmbuf_iova(new_mbuf)),
				&bdp->bd_bufaddr);
rx_processing_done:
		/* when rx_processing_done clear the status flags
		 * for this buffer
		 */
		status &= ~RX_BD_STATS;

		/* Mark the buffer empty */
		status |= RX_BD_EMPTY;

		if (rxq->fep->bufdesc_ex) {
			struct bufdesc_ex *ebdp = (struct bufdesc_ex *)bdp;
			rte_write32(rte_cpu_to_le_32(RX_BD_INT),
				    &ebdp->bd_esc);
			rte_write32(0, &ebdp->bd_prot);
			rte_write32(0, &ebdp->bd_bdu);
		}

		/* Make sure the updates to rest of the descriptor are
		 * performed before transferring ownership.
		 */
		rte_wmb();
		rte_write16(rte_cpu_to_le_16(status), &bdp->bd_sc);

		/* Update BD pointer to next entry */
		bdp = enet_get_nextdesc(bdp, &rxq->bd);

		/* Doing this here will keep the FEC running while we process
		 * incoming frames.
		 */
		rte_write32(0, rxq->bd.active_reg_desc);
		status = rte_le_to_cpu_16(rte_read16(&bdp->bd_sc));
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
	struct rte_mbuf *mbuf;
	unsigned short status;
	unsigned short buflen;
	unsigned int index;
	unsigned int i, pkt_t = 0;
	uint8_t *data;

	while (pkt_t < nb_pkts) {
		mbuf = tx_pkts[pkt_t];
		if (mbuf->nb_segs > 1) {
			ENETFEC_DP_LOG(DEBUG, "SG not supported");
			stats->opackets += pkt_t;
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
			rte_pktmbuf_free(txq->tx_mbuf[index]);
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
	stats->opackets += pkt_t;

	return pkt_t;
}
