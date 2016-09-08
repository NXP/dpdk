/*-
 *   BSD LICENSE
 *
 *   Copyright (c) 2016 Freescale Semiconductor, Inc. All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of  Freescale Semiconductor, Inc nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* System headers */
#include <stdio.h>
#include <inttypes.h>
#include <unistd.h>
#include <stdio.h>
#include <limits.h>
#include <sched.h>
#include <pthread.h>

#include <rte_config.h>
#include <rte_byteorder.h>
#include <rte_common.h>
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
#include <rte_ethdev.h>
#include <rte_atomic.h>
#include <rte_malloc.h>
#include <rte_ring.h>

#include "dpaa_ethdev.h"
#include "dpaa_rxtx.h"

#include <usdpaa/fsl_usd.h>
#include <usdpaa/fsl_qman.h>
#include <usdpaa/fsl_bman.h>
#include <usdpaa/of.h>
#include <usdpaa/usdpaa_netcfg.h>

#define DPAA_MBUF_TO_CONTIG_FD(_mbuf, _fd, _bpid) \
	do { \
		(_fd)->cmd = 0; \
		(_fd)->opaque_addr = 0; \
		(_fd)->format = QM_FD_CONTIG; \
		(_fd)->addr = (_mbuf)->buf_physaddr; \
		(_fd)->offset = (_mbuf)->data_off; \
		(_fd)->bpid = _bpid; \
		(_fd)->length20 = (_mbuf)->pkt_len; \
	} while (0);

void  dpaa_buf_free(struct pool_info_entry *bp_info,
		    uint64_t addr)
{
	struct bm_buffer buf;
	int ret;

	bm_buffer_set64(&buf, addr);
retry:
	ret = bman_release(bp_info->bp, &buf, 1, 0);
	if (ret) {
		cpu_spin(CPU_SPIN_BACKOFF_CYCLES);
		goto retry;
	}
}

#if (defined RTE_LIBRTE_DPAA_DEBUG_DRIVER_DISPLAY)
void dpaa_display_frame(const struct qm_fd *fd)
{
	int ii;
	char *ptr;

	printf("%s::bpid %x addr %08x%08x, format %d off %d, len %d stat %x\n",
	       __func__, fd->bpid, fd->addr_hi, fd->addr_lo, fd->format,
		fd->offset, fd->length20, fd->status);

	ptr = (char *)dpaa_mem_ptov(fd->addr);
	ptr += fd->offset;
	printf("%02x ", *ptr);
	for (ii = 1; ii < fd->length20; ii++) {
		printf("%02x ", *ptr);
		if ((ii % 16) == 0)
			printf("\n");
		ptr++;
	}
	printf("\n");
}
#else
#define dpaa_display_frame(a)
#endif

static inline void dpaa_slow_parsing(struct rte_mbuf *m,
				     uint64_t prs)
{
	/*TBD:XXX: to be implemented*/
}

static inline void dpaa_eth_packet_info(struct rte_mbuf *m,
					uint64_t fd_virt_addr)
{
	struct annotations_t *annot = GET_ANNOTATIONS(fd_virt_addr);
	uint64_t prs = *((uint64_t *)(&annot->parse)) & DPAA_PARSE_MASK;

	switch (prs) {
		case DPAA_PKT_TYPE_NONE:
			m->packet_type = 0;
			break;
		case DPAA_PKT_TYPE_ETHER:
			m->packet_type = RTE_PTYPE_L2_ETHER;
			break;
		case DPAA_PKT_TYPE_IPV4:
			m->packet_type = RTE_PTYPE_L2_ETHER |
				RTE_PTYPE_L3_IPV4;
			break;
		case DPAA_PKT_TYPE_IPV6:
			m->packet_type = RTE_PTYPE_L2_ETHER |
				RTE_PTYPE_L3_IPV6;
			break;
		case DPAA_PKT_TYPE_IPV4_EXT:
			m->packet_type = RTE_PTYPE_L2_ETHER |
				RTE_PTYPE_L3_IPV4_EXT;
			break;
		case DPAA_PKT_TYPE_IPV6_EXT:
			m->packet_type = RTE_PTYPE_L2_ETHER |
				RTE_PTYPE_L3_IPV6_EXT;
			break;
		case DPAA_PKT_TYPE_IPV4_TCP:
			m->packet_type = RTE_PTYPE_L2_ETHER |
				RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L4_TCP;
			break;
		case DPAA_PKT_TYPE_IPV6_TCP:
			m->packet_type = RTE_PTYPE_L2_ETHER |
				RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L4_TCP;
			break;
		case DPAA_PKT_TYPE_IPV4_UDP:
			m->packet_type = RTE_PTYPE_L2_ETHER |
				RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L4_UDP;
			break;
		case DPAA_PKT_TYPE_IPV6_UDP:
			m->packet_type = RTE_PTYPE_L2_ETHER |
				RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L4_UDP;
			break;
		case DPAA_PKT_TYPE_IPV4_SCTP:
			m->packet_type = RTE_PTYPE_L2_ETHER |
				RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L4_SCTP;
			break;
		case DPAA_PKT_TYPE_IPV6_SCTP:
			m->packet_type = RTE_PTYPE_L2_ETHER |
				RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L4_SCTP;
			break;
		/* More switch cases can be added */
		default:
			dpaa_slow_parsing(m, prs);
	}

	m->l2_len = annot->parse.ip_off[0];
	m->l3_len = annot->parse.l4_off - annot->parse.ip_off[0];

	/* Set the hash values */
	m->hash.rss = (uint32_t)(rte_be_to_cpu_64(annot->hash));
	m->ol_flags = PKT_RX_RSS_HASH;

	/* Check if Vlan is present */
	if (prs & DPAA_PARSE_VLAN_MASK)
		m->ol_flags |= PKT_RX_VLAN_PKT;
}

static inline void dpaa_checksum_offload(struct rte_mbuf *mbuf,
					 struct qm_fd *fd)
{
	struct dpaa_eth_parse_results_t *prs;

	if (mbuf->data_off < DEFAULT_TX_ICEOF +
			sizeof(struct dpaa_eth_parse_results_t)) {
		PMD_DRV_LOG(ERROR, "Checksum offload Error: Not enough Headroom "
			"space for correct Checksum offload.");
		return;
	}

	prs = GET_TX_PRS(mbuf->buf_addr);
	prs->l3r = 0;
	prs->l4r = 0;
	if ((mbuf->packet_type & RTE_PTYPE_L3_MASK) == RTE_PTYPE_L3_IPV4)
		prs->l3r = DPAA_L3_PARSE_RESULT_IPV4;
	else if ((mbuf->packet_type & RTE_PTYPE_L3_MASK) == RTE_PTYPE_L3_IPV6)
		prs->l3r = DPAA_L3_PARSE_RESULT_IPV6;

	if ((mbuf->packet_type & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_TCP)
		prs->l4r = DPAA_L4_PARSE_RESULT_TCP;
	else if ((mbuf->packet_type & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_UDP)
		prs->l4r = DPAA_L4_PARSE_RESULT_UDP;

	prs->ip_off[0] = mbuf->l2_len;
	prs->l4_off = mbuf->l3_len + mbuf->l2_len;
	/* Enable L3 (and L4, if TCP or UDP) HW checksum*/
	fd->cmd = 0x50000000;
}

static inline struct rte_mbuf *dpaa_eth_fd_to_mbuf(struct qman_fq *fq,
						   struct qm_fd *fd)
{
	void *ptr;
	struct rte_mbuf *mbuf;
	struct pool_info_entry *bp_info;
	uint32_t tmp;

	if (unlikely(fd->format != qm_fd_contig)) {
		PMD_DRV_LOG(ERROR, "dropping packet in sg form");
		goto errret;
	}
	dpaa_display_frame(fd);
	ptr = dpaa_mem_ptov(fd->addr);
	if (!ptr) {
		PMD_DRV_LOG(ERROR, "unable to convert physical address");
		goto errret;
	}
	/* Prefetch the Parse results and packet data to L1 */
	rte_prefetch0(ptr + DEFAULT_RX_ICEOF);
	rte_prefetch0(ptr + fd->offset);

	bp_info = DPAA_BPID_TO_POOL_INFO(fd->bpid);

	mbuf = (struct rte_mbuf *)((char *)ptr - bp_info->meta_data_size);
	mbuf->buf_addr = ptr;
	mbuf->data_off = fd->offset;
	mbuf->data_len = fd->length20;
	mbuf->pkt_len = fd->length20;

	mbuf->port = fq->ifid;
	mbuf->nb_segs = 1;
	mbuf->ol_flags = 0;
	mbuf->next = NULL;
	rte_mbuf_refcnt_set(mbuf, 1);
	dpaa_eth_packet_info(mbuf, (uint64_t)mbuf->buf_addr);

	return mbuf;
errret:
	dpaa_buf_free(bp_info, qm_fd_addr(fd));
	return NULL;
}

uint16_t dpaa_eth_queue_rx(void *q,
			   struct rte_mbuf **bufs,
		uint16_t nb_bufs)
{
	struct qm_mcr_queryfq_np np;
	enum qman_fq_state state;
	struct qman_fq *fq = q;
	struct qm_dqrr_entry *dq;
	struct qm_fd *fd;
	uint32_t num_rx = 0;
	int ret;

	if (unlikely(!thread_portal_init)) {
		ret = dpaa_portal_init((void *)0);
		if (ret) {
			PMD_DRV_LOG(ERROR, "Failure in affining portal");
			return 0;
		}
	}

	ret = qman_set_vdq(fq, nb_bufs);
	if (ret)
		return 0;

	do {
		dq = qman_dequeue(fq);
		if (!dq)
			continue;

		bufs[num_rx++] = dpaa_eth_fd_to_mbuf(fq, &dq->fd);
		qman_dqrr_consume(fq, dq);
	} while (fq->flags & QMAN_FQ_STATE_VDQCR);

	return num_rx;
}

static void *dpaa_get_pktbuf(struct pool_info_entry *bp_info)
{
	int ret;
	uint64_t buf = 0;
	struct bm_buffer bufs;

	ret = bman_acquire(bp_info->bp, &bufs, 1, 0);
	if (ret <= 0) {
		PMD_DRV_LOG(WARNING, "Failed to allocate buffers %d", ret);
		return (void *)buf;
	}

	PMD_DRV_LOG(DEBUG, "located pool sz %d , bpid %d",
		    bp_info->size, bufs.bpid);
	PMD_DRV_LOG(DEBUG, "got buffer 0x%llx from pool %d",
		    bufs.addr, bufs.bpid);

	buf = (uint64_t)dpaa_mem_ptov(bufs.addr) - bp_info->meta_data_size;
	if (!buf)
		goto out;

out:
	return (void *)buf;
}

static struct rte_mbuf *dpaa_get_dmable_mbuf(struct rte_mbuf *mbuf,
					     struct dpaa_if *iface,
		struct qman_fq *fq)
{
	struct rte_mbuf *dpaa_mbuf;

	/* allocate pktbuffer on bpid for dpaa port */
	dpaa_mbuf = dpaa_get_pktbuf(iface->bp_info);
	if (!dpaa_mbuf)
		return NULL;

	memcpy(dpaa_mbuf->buf_addr + mbuf->data_off, (void *)
		(mbuf->buf_addr + mbuf->data_off), mbuf->pkt_len);

	/* Copy only the required fields */
	dpaa_mbuf->data_off = mbuf->data_off;
	dpaa_mbuf->pkt_len = mbuf->pkt_len;
	dpaa_mbuf->ol_flags = mbuf->ol_flags;
	dpaa_mbuf->packet_type = mbuf->packet_type;
	dpaa_mbuf->tx_offload = mbuf->tx_offload;
	rte_pktmbuf_free(mbuf);
	return dpaa_mbuf;
}
int dpaa_get_flow_control(uint32_t portid, struct rte_eth_fc_conf *fc_conf)
{
	struct dpaa_if *iface = &dpaa_ifacs[portid];
	int ret = fman_if_get_fc_threshold(iface->fif);
	if (ret) {
		fc_conf->mode = RTE_FC_TX_PAUSE;
		fc_conf->pause_time = fman_if_get_fc_quanta(iface->fif);
	} else
		fc_conf->mode = RTE_FC_NONE;

	return 0;
}

int dpaa_set_flow_control(uint32_t portid, struct rte_eth_fc_conf *fc_conf)
{
	struct dpaa_if *iface = &dpaa_ifacs[portid];

	if (!iface->bp_info) {
		printf("\n ??? ERR - %s buffer pool info not found",
			__func__);
		return -1;
	}
	if (fc_conf->high_water < fc_conf->low_water) {
		printf("\nERR - %s Incorrect Flow Control Configuration\n",
			__func__);
		return -1;
	}
	/*TBD:XXX: Implementation for RTE_FC_RX_PAUSE mode*/
	if (fc_conf->mode == RTE_FC_NONE)
		return 0;
	else if (fc_conf->mode == RTE_FC_TX_PAUSE ||
				fc_conf->mode == RTE_FC_FULL) {
		fman_if_set_fc_threshold(iface->fif,
			fc_conf->high_water, fc_conf->low_water,
			iface->bp_info->bpid);
		if (fc_conf->pause_time)
			fman_if_set_fc_quanta(iface->fif, fc_conf->pause_time);
	}

	return 0;
}

uint16_t dpaa_eth_queue_tx(void *q,
			   struct rte_mbuf **bufs,
			uint16_t nb_bufs)
{
	struct rte_mbuf *mbuf;
	struct rte_mempool *mp;
	struct pool_info_entry *bp_info;
	struct qm_fd fd_arr[MAX_TX_RING_SLOTS];
	uint32_t frames_to_send, loop, i = 0;

	while (nb_bufs) {
		frames_to_send = (nb_bufs >> 3) ? MAX_TX_RING_SLOTS : nb_bufs;

		for (loop = 0; loop < frames_to_send; loop++, i++) {
			mbuf = bufs[i];
			mp = mbuf->pool;
			if (mp && (mp->flags & MEMPOOL_F_HW_PKT_POOL)) {
				bp_info = DPAA_MEMPOOL_TO_POOL_INFO(mp);
				DPAA_MBUF_TO_CONTIG_FD(mbuf,
						       &fd_arr[loop], bp_info->bpid);
			} else {
				struct qman_fq *txq = q;
				struct dpaa_if *iface = &dpaa_ifacs[txq->ifid];

				mbuf = dpaa_get_dmable_mbuf(mbuf, iface, q);
				if (!mbuf) {
					PMD_DRV_LOG(DEBUG, "no dpaa buffers.\n");
					/* Set frames_to_send & nb_bufs so that packets
					 * are transmitted till previous frame */
					frames_to_send = loop;
					nb_bufs = loop;
					goto send_pkts;
				}

				DPAA_MBUF_TO_CONTIG_FD(mbuf,
						       &fd_arr[loop], iface->bp_info->bpid);
			}

			if (mbuf->ol_flags & DPAA_TX_CKSUM_OFFLOAD_MASK)
				dpaa_checksum_offload(mbuf, &fd_arr[loop]);
		}

send_pkts:
		loop = 0;
		while (loop < frames_to_send) {
			loop += qman_enqueue_multi(q, &fd_arr[loop],
					frames_to_send - loop);
		}
		nb_bufs -= frames_to_send;
	}

	return i;
}

