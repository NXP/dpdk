/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 NXP
 */

#include <rte_mbuf.h>
#include <rte_io.h>
#include "enet_regs.h"
#include "enet_ethdev.h"
#include "enet_pmd_logs.h"

static void
enet_dump(struct enetfec_priv_tx_q *txq)
{
	struct bufdesc *bdp;
	int index = 0;

	ENET_PMD_DEBUG("TX ring dump\n");
	ENET_PMD_DEBUG("Nr     SC     addr       len  MBUF\n");

	bdp = txq->bd.base;
	do {
		ENET_PMD_DEBUG("%3u %c%c 0x%04x 0x%08x %4u %p\n",
			index,
			bdp == txq->bd.cur ? 'S' : ' ',
			bdp == txq->dirty_tx ? 'H' : ' ',
			rte_read16(rte_le_to_cpu_16(&bdp->bd_sc)),
			rte_read32(rte_le_to_cpu_32(&bdp->bd_bufaddr)),
			rte_read16(rte_le_to_cpu_16(&bdp->bd_datlen)),
			txq->tx_mbuf[index]);
		bdp = enet_get_nextdesc(bdp, &txq->bd);
		index++;
	} while (bdp != txq->bd.base);
}

static void
enet_dump_rx(struct enetfec_priv_rx_q *rxq)
{
	struct bufdesc *bdp;
	int index = 0;

	ENET_PMD_DEBUG("RX ring dump\n");
	ENET_PMD_DEBUG("Nr     SC     addr       len  MBUF\n");

	bdp = rxq->bd.base;
	do {
		ENET_PMD_DEBUG("%3u %c 0x%04x 0x%08x %4u %p\n",
			index,
			bdp == rxq->bd.cur ? 'S' : ' ',
			rte_read16(rte_le_to_cpu_16(&bdp->bd_sc)),
			rte_read32(rte_le_to_cpu_32(&bdp->bd_bufaddr)),
			rte_read16(rte_le_to_cpu_16(&bdp->bd_datlen)),
			rxq->rx_mbuf[index]);
		rte_pktmbuf_dump(stdout, rxq->rx_mbuf[index],
				rxq->rx_mbuf[index]->pkt_len);
		bdp = enet_get_nextdesc(bdp, &rxq->bd);
		index++;
	} while (bdp != rxq->bd.base);
}

int
enet_new_rxbdp(struct enetfec_private *fep,
			struct bufdesc *bdp,
			struct rte_mbuf *mbuf)
{
	int off, i;
	void *data;
	uint16_t tail;
	unsigned short buflen;

	off = ((unsigned long)rte_pktmbuf_mtod(mbuf, unsigned long))
			& fep->rx_align;
	if (off) {
		data = rte_pktmbuf_mtod(mbuf, void *);
		tail = rte_pktmbuf_tailroom(mbuf);
		data += (fep->rx_align + 1 - off);
		tail += (fep->rx_align + 1 - off);
	}

	buflen = rte_pktmbuf_pkt_len(mbuf);
	for (i = 0; i <= buflen; i += RTE_CACHE_LINE_SIZE)
		dcbf(rte_pktmbuf_mtod(mbuf, void *) + i);

	rte_write32(rte_cpu_to_le_32(rte_pktmbuf_iova(mbuf)),
		    &bdp->bd_bufaddr);
	return 0;
}

/* This function does fec_rx_queue processing. Dequeue packet from Rx queue
 * When update through the ring, just set the empty indicator.
 */

uint16_t
enetfec_recv_pkts(void *rxq1, __rte_unused struct rte_mbuf **rx_pkts,
		uint16_t nb_pkts)
{
	struct rte_mempool *pool;
	struct bufdesc *bdp;
	struct rte_mbuf *mbuf, *new_mbuf = NULL;
	unsigned short status;
	unsigned short pkt_len;
	int pkt_received = 0, index = 0;
	void *data, *mbuf_data;
	uint16_t vlan_tag;
	char *appended;
	struct  bufdesc_ex *ebdp = NULL;
	bool    vlan_packet_rcvd = false;
	struct enetfec_priv_rx_q *rxq  = (struct enetfec_priv_rx_q *)rxq1;
	struct rte_eth_stats *stats = &rxq->fep->stats;
	struct rte_eth_conf *eth_conf = &rxq->fep->dev->data->dev_conf;
	uint64_t rx_offloads = eth_conf->rxmode.offloads;
	pool = rxq->pool;
	bdp = rxq->bd.cur;

	dccivac(bdp);
	/* Process the incoming packet */
	status = rte_le_to_cpu_16(rte_read16(&bdp->bd_sc));
	while (!(status & RX_BD_EMPTY)) {
		if (pkt_received >= nb_pkts)
			break;

		new_mbuf = rte_pktmbuf_alloc(pool);
		if (unlikely(!new_mbuf)) {
			stats->ierrors++;
			break;
		}
		/* Check for errors. */
		status ^= RX_BD_LAST;
		if (status & (RX_BD_LG | RX_BD_SH | RX_BD_NO |
			RX_BD_CR | RX_BD_OV | RX_BD_LAST |
			RX_BD_TR)) {
			stats->ierrors++;
			if (status & RX_BD_OV) {
				/* FIFO overrun */
				enet_dump_rx(rxq);
				ENET_PMD_ERR("rx_fifo_error\n");
				goto rx_processing_done;
			}
			if (status & (RX_BD_LG | RX_BD_SH
						| RX_BD_LAST)) {
				/* Frame too long or too short. */
				ENET_PMD_ERR("rx_length_error\n");
				if (status & RX_BD_LAST)
					ENET_PMD_ERR("rcv is not +last\n");
			}
			if (status & RX_BD_CR) {     /* CRC Error */
				ENET_PMD_ERR("rx_crc_errors\n");
			}
			/* Report late collisions as a frame error. */
			if (status & (RX_BD_NO | RX_BD_TR))
				ENET_PMD_ERR("rx_frame_error\n");
			goto rx_processing_done;
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
		appended =
			rte_pktmbuf_append((struct rte_mbuf *)mbuf,
					pkt_len - 4);
		if (appended == NULL)
			break;

		if (rxq->fep->quirks & QUIRK_RACC)
			data = rte_pktmbuf_adj(mbuf, 2);

		rx_pkts[pkt_received] = mbuf;
		pkt_received++;
		/* Extract the enhanced buffer descriptor */
		ebdp = NULL;
		if (rxq->fep->bufdesc_ex)
			ebdp = (struct bufdesc_ex *)bdp;

		/* If this is a VLAN packet remove the VLAN Tag */
		vlan_packet_rcvd = false;
		if ((rx_offloads & DEV_RX_OFFLOAD_VLAN) &&
				rxq->fep->bufdesc_ex &&
				(rte_read32(&ebdp->bd_esc) &
				rte_cpu_to_le_32(BD_ENET_RX_VLAN))) {
			/* Push and remove the vlan tag */
			struct rte_vlan_hdr *vlan_header =
				(struct rte_vlan_hdr *)(data + ETH_HLEN);
			vlan_tag = rte_be_to_cpu_16(vlan_header->vlan_tci);

			vlan_packet_rcvd = true;
			memmove(mbuf_data + VLAN_HLEN, data, ETH_ALEN * 2);
			rte_pktmbuf_adj(mbuf, VLAN_HLEN);
		}

		if (rxq->fep->bufdesc_ex &&
				(rxq->fep->flag_csum & RX_FLAG_CSUM_EN)) {
			if (!(rte_read32(&ebdp->bd_esc) &
					rte_cpu_to_le_32(RX_FLAG_CSUM_ERR))) {
				/* don't check it */
				mbuf->ol_flags = PKT_RX_IP_CKSUM_BAD;
			} else {
				mbuf->ol_flags = PKT_RX_IP_CKSUM_GOOD;
			}
		}

		/* Handle received VLAN packets */
		if (vlan_packet_rcvd) {
			mbuf->vlan_tci = vlan_tag;
			mbuf->ol_flags |= PKT_RX_VLAN_STRIPPED | PKT_RX_VLAN;
		}
		rxq->rx_mbuf[index] = new_mbuf;
		enet_new_rxbdp(rxq->fep, bdp, new_mbuf);
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
		dcbf(bdp);
		/* Make sure the updates to rest of the descriptor are
		 * performed before transferring ownership.
		 */
		rte_wmb();
		rte_write16(rte_cpu_to_le_16(status), &bdp->bd_sc);
		dccivac(bdp);

		/* Update BD pointer to next entry */
		bdp = enet_get_nextdesc(bdp, &rxq->bd);

		/* Doing this here will keep the FEC running while we process
		 * incoming frames.
		 */
		rte_write32(0, rxq->bd.active_reg_desc);
		dccivac(bdp);
		status = rte_le_to_cpu_16(rte_read16(&bdp->bd_sc));
	}
	rxq->bd.cur = bdp;
	return pkt_received;
}

static int enet_get_free_txdesc_num(struct enetfec_priv_tx_q *txq)
{
	int entries;

	entries = (((const char *)txq->dirty_tx -
			(const char *)txq->bd.cur) >> txq->bd.d_size_log2) - 1;

	return entries >= 0 ? entries : entries + txq->bd.ring_size;
}

static int
enet_txq_submit_mbuf(struct enetfec_priv_tx_q *txq,
			struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	struct bufdesc *bdp, *last_bdp;
	struct rte_mbuf *mbuf;
	unsigned short status;
	unsigned short buflen;
	unsigned int index, estatus = 0;
	unsigned int i;
	unsigned int entries_free;
	int pkts_queued = 0;

	for (i = 0; i < nb_pkts; i++) {
		entries_free = enet_get_free_txdesc_num(txq);
		if (tx_pkts[i]->nb_segs > entries_free) {
			enet_dump(txq);
			rte_pktmbuf_free(tx_pkts[i]);
			ENET_PMD_DEBUG("entries not enough");
			continue;
		}

		mbuf = *(tx_pkts);
		tx_pkts++;
		pkts_queued++;

		/* Fill in a Tx ring entry */
		bdp = txq->bd.cur;
		last_bdp = bdp;
		status = rte_le_to_cpu_16(rte_read16(&bdp->bd_sc));
		status &= ~TX_BD_STATS;

		/* Set buffer length and buffer pointer */
		buflen = rte_pktmbuf_pkt_len(mbuf);

		index = enet_get_bd_index(bdp, &txq->bd);

		if (mbuf->nb_segs > 1)
			ENET_PMD_DEBUG("SG not supported");
//			return -1;
		else
			status |= (TX_BD_LAST);

		for (i = 0; i <= buflen; i += RTE_CACHE_LINE_SIZE)
			dcbf(rte_pktmbuf_mtod(mbuf, void *) + i);

		rte_write32(rte_cpu_to_le_32(rte_pktmbuf_iova(mbuf)),
			    &bdp->bd_bufaddr);
		rte_write16(rte_cpu_to_le_16(buflen), &bdp->bd_datlen);
		dcbf(&bdp->bd_bufaddr);
		if (txq->fep->bufdesc_ex) {
			struct bufdesc_ex *ebdp = (struct bufdesc_ex *)bdp;

			if (mbuf->ol_flags == PKT_RX_IP_CKSUM_GOOD)
				estatus |= TX_BD_PINS | TX_BD_IINS;

			rte_write32(0, &ebdp->bd_bdu);
			rte_write32(rte_cpu_to_le_32(estatus),
				    &ebdp->bd_esc);
		}

		index = enet_get_bd_index(last_bdp, &txq->bd);
		/* Save mbuf pointer */
		txq->tx_mbuf[index] = mbuf;

		dcbf(bdp);
		/* Make sure the updates to rest of the descriptor are performed
		 * before transferring ownership.
		 */
		rte_wmb();
		status |= (TX_BD_READY | TX_BD_TC);
		rte_write16(rte_cpu_to_le_16(status), &bdp->bd_sc);
		dcbf(bdp);
		/* If this was the last BD in the ring, start at the
		 * beginning again.
		 */
		bdp = enet_get_nextdesc(last_bdp, &txq->bd);

		/* Make sure the update to bdp and tx_skbuff are performed
		 * before txq->bd.cur.
		 */
		rte_wmb();
		txq->bd.cur = bdp;

		/* Trigger transmission start */
		rte_write32(0, txq->bd.active_reg_desc);
	}
	return pkts_queued;
}

static int
enet_tx_queue_cleanup(struct enetfec_priv_tx_q *txq)
{
	struct enetfec_private *fep = txq->fep;
	struct rte_eth_stats *stats = &fep->stats;
	struct bufdesc *bdp;
	unsigned short status;
	struct rte_mbuf *mbuf;
	int timeout = 1000;
	int	index = 0;
	int pkts_cleaned = 0;
	bdp = txq->dirty_tx;

	/* get next bdp of dirty_tx */
	bdp = enet_get_nextdesc(bdp, &txq->bd);

	while (bdp != READ_ONCE(txq->bd.cur)) {
		/* Order the load of bd.cur and bd_sc */
		dccivac(bdp);
		status = rte_le_to_cpu_16(rte_read16(&bdp->bd_sc));
		while (timeout > 0 && (status & TX_BD_READY)) {
			dccivac(bdp);
			timeout--;
			status = rte_le_to_cpu_16(rte_read16(&bdp->bd_sc));
		}
		if (status & TX_BD_READY) {
			ENET_PMD_INFO("\nstatus: %x\n", status);
			break;
		}

		index = enet_get_bd_index(bdp, &txq->bd);

		mbuf = txq->tx_mbuf[index];
		pkts_cleaned++;
		txq->tx_mbuf[index] = NULL;
		rte_write32(rte_cpu_to_le_32(0), &bdp->bd_bufaddr);
		if (!mbuf)
			goto mbuf_done;

		/* Check for errors. */
		if (status & (TX_BD_HB | TX_BD_LC |
				   TX_BD_RL | TX_BD_UN |
				   TX_BD_CSL)) {
			stats->oerrors++;
		} else {
			stats->opackets++;
			stats->obytes += mbuf->pkt_len;
		}
		/* Free the buffer associated with this last transmit */
		rte_pktmbuf_free(mbuf);
mbuf_done:
		/* Make sure the update to bdp and tx_skbuff are performed
		 * before dirty_tx
		 */
		rte_wmb();
		txq->dirty_tx = bdp;

		/* Update pointer to next buffer descriptor to be transmitted */
		bdp = enet_get_nextdesc(bdp, &txq->bd);
	}

	/* ERR006358: Keep the transmitter going */
	if (bdp != txq->bd.cur &&
	    readl(txq->bd.active_reg_desc) == 0)
		writel(0, txq->bd.active_reg_desc);

	return pkts_cleaned;
}

uint16_t
enetfec_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	int i, pkts_queued = 0, pkts_cleaned = 0;
	struct enetfec_priv_tx_q *txq  =
			(struct enetfec_priv_tx_q *)tx_queue;

	for (i = 0; i < nb_pkts; i++) {
		/* FIXME This for loop should be removed */
		pkts_queued += enet_txq_submit_mbuf(txq, tx_pkts, 1);
		pkts_cleaned += enet_tx_queue_cleanup(txq);
	}

	if (pkts_cleaned != pkts_queued)
		ENET_PMD_DEBUG("\npkts_cleaned: %d, pkts_queued: %d\n",
			pkts_cleaned, pkts_queued);
	return pkts_cleaned;
}
