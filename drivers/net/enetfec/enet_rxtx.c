/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 NXP
 */

#include <signal.h>
#include <rte_mbuf.h>
#include <rte_io.h>
#include "enet_regs.h"
#include "enet_ethdev.h"
#include "enet_pmd_logs.h"

#define ENETFEC_LOOPBACK	0
#define ENETFEC_DUMP		0
#define CODE_TO_REMOVE		0

static volatile bool lb_quit;

#if ENETFEC_DUMP
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

static int enet_get_free_txdesc_num(struct enetfec_priv_tx_q *txq)
{
	int entries;

	entries = (((const char *)txq->dirty_tx -
			(const char *)txq->bd.cur) >> txq->bd.d_size_log2) - 1;

	return entries >= 0 ? entries : entries + txq->bd.ring_size;
}
#endif

int
enet_new_rxbdp(__rte_unused struct enetfec_private *fep,
			struct bufdesc *bdp,
			struct rte_mbuf *mbuf)
{
/*
 *	int off, i;
 *	void *data;
 *	uint16_t tail;
 *	unsigned short buflen;
 *
 *	off = ((unsigned long)rte_pktmbuf_mtod(mbuf, unsigned long))
 *			& fep->rx_align;
 *	if (off) {
 *		data = rte_pktmbuf_mtod(mbuf, void *);
 *		tail = rte_pktmbuf_tailroom(mbuf);
 *		data += (fep->rx_align + 1 - off);
 *		tail += (fep->rx_align + 1 - off);
 *	}
 *
 *	buflen = rte_pktmbuf_pkt_len(mbuf);
 *	for (i = 0; i <= buflen; i += RTE_CACHE_LINE_SIZE)
 *		dcbf(rte_pktmbuf_mtod(mbuf, void *) + i);
 */
	rte_write32(rte_cpu_to_le_32(rte_pktmbuf_iova(mbuf)),
		    &bdp->bd_bufaddr);
	return 0;
}

#if ENETFEC_LOOPBACK
static void fec_signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTSTP || signum == SIGTERM) {
		printf("\n\n %s: Signal %d received, preparing to exit...\n",
				__func__, signum);
		lb_quit = true;
	}
}

static void
enetfec_lb_rxtx(void *rxq1)
{
	struct rte_mempool *pool;
	struct bufdesc *rx_bdp = NULL, *tx_bdp = NULL;
	struct rte_mbuf *mbuf = NULL, *new_mbuf = NULL;
	unsigned short status;
	unsigned short pkt_len = 0;
	int index_r = 0, index_t = 0;
	u8 *data;
	struct enetfec_priv_rx_q *rxq  = (struct enetfec_priv_rx_q *)rxq1;
	struct rte_eth_stats *stats = &rxq->fep->stats;
	unsigned int i;
	struct enetfec_private *fep;
	struct enetfec_priv_tx_q *txq;
	fep = rxq->fep->dev->data->dev_private;
	txq = fep->tx_queues[0];

	pool = rxq->pool;
	rx_bdp = rxq->bd.cur;
	tx_bdp = txq->bd.cur;

	signal(SIGTSTP, fec_signal_handler);
	while (!lb_quit) {
chk_again:
		status = rte_le_to_cpu_16(rte_read16(&rx_bdp->bd_sc));
		if (status & RX_BD_EMPTY) {
			if (!lb_quit)
				goto chk_again;
			rxq->bd.cur = rx_bdp;
			txq->bd.cur = tx_bdp;
			return;
		}

		/* Check for errors. */
		status ^= RX_BD_LAST;
		if (status & (RX_BD_LG | RX_BD_SH | RX_BD_NO |
			RX_BD_CR | RX_BD_OV | RX_BD_LAST |
			RX_BD_TR)) {
			stats->ierrors++;
			if (status & RX_BD_OV) {
				/* FIFO overrun */
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
			mbuf = NULL;
			goto rx_processing_done;
		}

		new_mbuf = rte_pktmbuf_alloc(pool);
		if (unlikely(!new_mbuf)) {
			stats->ierrors++;
			break;
		}
		/* Process the incoming frame. */
		pkt_len = rte_le_to_cpu_16(rte_read16(&rx_bdp->bd_datlen));

		/* shows data with respect to the data_off field. */
		index_r = enet_get_bd_index(rx_bdp, &rxq->bd);
		mbuf = rxq->rx_mbuf[index_r];

		/* adjust pkt_len */
		rte_pktmbuf_append((struct rte_mbuf *)mbuf, pkt_len - 4);
		if (rxq->fep->quirks & QUIRK_RACC)
			rte_pktmbuf_adj(mbuf, 2);

		/* Replace Buffer in BD */
		rxq->rx_mbuf[index_r] = new_mbuf;
		enet_new_rxbdp(rxq->fep, rx_bdp, new_mbuf);

rx_processing_done:
		/* when rx_processing_done clear the status flags
		 * for this buffer
		 */
		status &= ~RX_BD_STATS;

		/* Mark the buffer empty */
		status |= RX_BD_EMPTY;

		/*
		 * if (rxq->fep->bufdesc_ex) {
		 *	struct bufdesc_ex *ebdp = (struct bufdesc_ex *)rx_bdp;
		 *	rte_write32(rte_cpu_to_le_32(RX_BD_INT),
		 *		&ebdp->bd_esc);
		 *	rte_write32(0, &ebdp->bd_prot);
		 *	rte_write32(0, &ebdp->bd_bdu);
		 * }
		 */

		/* Make sure the updates to rest of the descriptor are
		 * performed before transferring ownership.
		 */
		rte_wmb();
		rte_write16(rte_cpu_to_le_16(status), &rx_bdp->bd_sc);

		/* Update BD pointer to next entry */
		rx_bdp = enet_get_nextdesc(rx_bdp, &rxq->bd);

		/* Doing this here will keep the FEC running while we process
		 * incoming frames.
		 */
		rte_write32(0, rxq->bd.active_reg_desc);

		/* TX begins: FIXME process single packet */
		/* First clean the ring */
		index_t = enet_get_bd_index(tx_bdp, &txq->bd);
		status = rte_le_to_cpu_16(rte_read16(&tx_bdp->bd_sc));
		if (status & TX_BD_READY)
			printf("\n----> TX BD status ERROR %x, index_t=%d\n",
				status, index_t);
		if (txq->tx_mbuf[index_t]) {
			rte_pktmbuf_free(txq->tx_mbuf[index_t]);
			txq->tx_mbuf[index_t] = NULL;
		}

		if (mbuf == NULL)
			continue; // Nothing to Transmit

		/* Fill in a Tx ring entry */
		status &= ~TX_BD_STATS;

		/* Set buffer length and buffer pointer */
		pkt_len = rte_pktmbuf_pkt_len(mbuf);
		status |= (TX_BD_LAST);
		data = rte_pktmbuf_mtod(mbuf, void *);

		for (i = 0; i <= pkt_len; i += RTE_CACHE_LINE_SIZE)
			dcbf(data + i);
		rte_write32(rte_cpu_to_le_32(rte_pktmbuf_iova(mbuf)),
			&tx_bdp->bd_bufaddr);
		rte_write16(rte_cpu_to_le_16(pkt_len), &tx_bdp->bd_datlen);
		/*
		 * if (txq->fep->bufdesc_ex) {
		 *	struct bufdesc_ex *ebdp = (struct bufdesc_ex *)tx_bdp;
		 *	unsigned int estatus = 0;
		 * if (mbuf->ol_flags == PKT_RX_IP_CKSUM_GOOD)
		 *	estatus |= TX_BD_PINS | TX_BD_IINS;
		 * rte_write32(0, &ebdp->bd_bdu);
		 * rte_write32(rte_cpu_to_le_32(estatus),
		 *		&ebdp->bd_esc);
		 * }
		 */
		/* Make sure the updates to rest of the descriptor are performed
		 * before transferring ownership.
		 */
		status |= (TX_BD_READY | TX_BD_TC);
		rte_wmb();
		rte_write16(rte_cpu_to_le_16(status), &tx_bdp->bd_sc);

		/* Trigger transmission start */
		rte_write32(0, txq->bd.active_reg_desc);

		/* Save mbuf pointer to clean later */
		txq->tx_mbuf[index_t] = mbuf;

		/* If this was the last BD in the ring, start at the
		 * beginning again.
		 */
		tx_bdp = enet_get_nextdesc(tx_bdp, &txq->bd);
	}
}
#endif

/* This function does enetfec_rx_queue processing. Dequeue packet from Rx queue
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
	struct  bufdesc_ex *ebdp = NULL;
	bool    vlan_packet_rcvd = false;
	struct enetfec_priv_rx_q *rxq  = (struct enetfec_priv_rx_q *)rxq1;
	struct rte_eth_stats *stats = &rxq->fep->stats;
	struct rte_eth_conf *eth_conf = &rxq->fep->dev->data->dev_conf;
	uint64_t rx_offloads = eth_conf->rxmode.offloads;
	pool = rxq->pool;
	bdp = rxq->bd.cur;
#if ENETFEC_LOOPBACK
	enetfec_lb_rxtx(rxq1);
#endif
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
//				enet_dump_rx(rxq);
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
		rte_pktmbuf_append((struct rte_mbuf *)mbuf,
				pkt_len - 4);

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
	struct bufdesc *bdp, *last_bdp;
	struct rte_mbuf *mbuf;
	unsigned short status;
	unsigned short buflen;
	unsigned int index, estatus = 0;
	unsigned int i, pkt_transmitted = 0;
	unsigned int entries_free;
	u8 *data;
	int tx_st = 1;

	while (tx_st) {
		if (pkt_transmitted >= nb_pkts) {
			tx_st = 0;
			break;
		}
		bdp = txq->bd.cur;
		/* First clean the ring */
		index = enet_get_bd_index(bdp, &txq->bd);
		status = rte_le_to_cpu_16(rte_read16(&bdp->bd_sc));

		if (status & TX_BD_READY) {
			stats->ierrors++;
			break;
		}
		if (txq->tx_mbuf[index]) {
			rte_pktmbuf_free(txq->tx_mbuf[index]);
			txq->tx_mbuf[index] = NULL;
		}
#if ENETFEC_DUMP
		entries_free = enet_get_free_txdesc_num(txq);
		if (tx_pkts[i]->nb_segs > entries_free) {
			enet_dump(txq);
			rte_pktmbuf_free(tx_pkts[i]);
			ENET_PMD_DEBUG("entries not enough");
			continue;
		}
#endif
		mbuf = *(tx_pkts);
		tx_pkts++;

		/* Fill in a Tx ring entry */
		last_bdp = bdp;
		status &= ~TX_BD_STATS;

		/* Set buffer length and buffer pointer */
		buflen = rte_pktmbuf_pkt_len(mbuf);

		if (mbuf->nb_segs > 1) {
			ENET_PMD_DEBUG("SG not supported");
			return -1;
		}
		status |= (TX_BD_LAST);
		data = rte_pktmbuf_mtod(mbuf, void *);
		for (i = 0; i <= buflen; i += RTE_CACHE_LINE_SIZE)
			dcbf(data + i);

		rte_write32(rte_cpu_to_le_32(rte_pktmbuf_iova(mbuf)),
			    &bdp->bd_bufaddr);
		rte_write16(rte_cpu_to_le_16(buflen), &bdp->bd_datlen);

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

		/* Make sure the updates to rest of the descriptor are performed
		 * before transferring ownership.
		 */
		status |= (TX_BD_READY | TX_BD_TC);
		rte_wmb();
		rte_write16(rte_cpu_to_le_16(status), &bdp->bd_sc);

		/* Trigger transmission start */
		rte_write32(0, txq->bd.active_reg_desc);
		pkt_transmitted++;

		/* If this was the last BD in the ring, start at the
		 * beginning again.
		 */
		bdp = enet_get_nextdesc(last_bdp, &txq->bd);

		/* Make sure the update to bdp and tx_skbuff are performed
		 * before txq->bd.cur.
		 */
		txq->bd.cur = bdp;
	}
	return nb_pkts;
}
#if CODE_TO_REMOVE
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
		status = rte_le_to_cpu_16(rte_read16(&bdp->bd_sc));
		while (timeout > 0 && (status & TX_BD_READY)) {
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
#endif
