/*-
 *   BSD LICENSE
 *
 *   Copyright (c) 2014 Freescale Semiconductor, Inc. All rights reserved.
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
#include "dpaa_logs.h"
#include "dpaa_pkt_annot.h"

#include <usdpaa/fsl_usd.h>
#include <usdpaa/fsl_qman.h>
#include <usdpaa/fsl_bman.h>
#include <usdpaa/of.h>
#include <usdpaa/usdpaa_netcfg.h>

/* #define DPAAETHDRV_DEBUG  1 */

#define FSL_VENDOR_ID		0x1957
#define FSL_DEVICE_ID		0x410	 /* custom */
#define FSL_FMAN_ETH_CLASS	0x020000 /* ethernet */
#define FSL_SUBSYSTEM_VENDOR	0
#define FSL_SUBSYSTEM_DEVICE	0

#define FSL_USDPAA_DOMAIN	2
#define FSL_USDPAA_BUSID	16
#define FSL_USDPAA_FUNC		0
#define USDPAA_DRV_NAME		"usdpaa_pci_driver"

#define FSL_USDPAA_MAX_RXS	8
#define FSL_USDPAA_MAX_TXS	RTE_MAX_LCORE

#define DPAA_MIN_RX_BUF_SIZE 512
#define DPAA_MAX_RX_PKT_LEN  9600 /* FMAN support*/

#define DPAA_RSS_OFFLOAD_ALL ( \
	ETH_RSS_FRAG_IPV4 | \
	ETH_RSS_NONFRAG_IPV4_TCP | \
	ETH_RSS_NONFRAG_IPV4_UDP | \
	ETH_RSS_NONFRAG_IPV4_SCTP | \
	ETH_RSS_FRAG_IPV6 | \
	ETH_RSS_NONFRAG_IPV6_TCP | \
	ETH_RSS_NONFRAG_IPV6_UDP | \
	ETH_RSS_NONFRAG_IPV6_SCTP)

#define QBMAN_MULTI_TX

static int usdpaa_pci_devinit(struct rte_pci_driver *,
			      struct rte_pci_device *);

static uint16_t usdpaa_eth_tx_drop_all(void *q,
				       struct rte_mbuf **bufs,
			uint16_t nb_bufs);

static struct rte_pci_id usdpaa_pci_id[2] = {
	{0, FSL_VENDOR_ID, FSL_DEVICE_ID, FSL_SUBSYSTEM_VENDOR,
		FSL_SUBSYSTEM_DEVICE},
	{0, 0, 0, 0}
};

static struct rte_pci_driver usdpaa_pci_driver = {
	.name = USDPAA_DRV_NAME,
	.id_table = usdpaa_pci_id,
	.devinit = usdpaa_pci_devinit
};

#define PCI_DEV_ADDR(dev) \
		((dev->addr.domain << 24) | (dev->addr.bus << 16) | \
		 (dev->addr.devid << 8) | (dev->addr.function))

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

struct pool_info_entry {
	struct rte_mempool *mp;
	struct bman_pool *bp;

	uint32_t bpid;
	uint32_t size;
	uint32_t meta_data_size;
};

struct net_if_admin {
	struct qman_fq fq;
	int idx; /* ADMIN_FQ_<x> */
};

struct net_if_queue {
	struct qman_fq fq;
	uint32_t ifid;
};

/* Each network interface is represented by one of these */
#define NETIF_ETHER_DEV_NAME_SIZE 32
struct net_if {
	int valid;
	char name[NETIF_ETHER_DEV_NAME_SIZE];
	char mac_addr[ETHER_ADDR_LEN];
	const struct fm_eth_port_cfg *cfg;
	struct net_if_admin admin[ADMIN_FQ_NUM];
	struct net_if_queue *rx_queues;
	struct net_if_queue *tx_queues;
	uint16_t nb_rx_queues;
	uint16_t nb_tx_queues;
	uint32_t ifid;
	const struct fman_if *fif;
	struct pool_info_entry *bp_info;
};

struct fman_if_internal {
	struct fman_if itif;
	char node_path[PATH_MAX];
	uint64_t regs_size;
	void *ccsr_map;
	struct list_head node;
};

#define USDPAA_MAX_BPOOLS	64 /* total number of bpools on SOC */

static struct net_if *dpaa_ifacs;
static struct usdpaa_netcfg_info *netcfg;

static inline int mempool_to_bpid(struct rte_mempool *mp)
{
	struct pool_info_entry *bp_info;

	bp_info = (struct pool_info_entry *)mp->pool_data;
	return bp_info->bpid;
}

__thread bool thread_portal_init;
static unsigned int num_usdpaa_ports;
static int usdpaa_init(void);
static int net_if_init(struct net_if *dpaa_intf,
		       const struct fm_eth_port_cfg *cfg);
static void *usdpaa_get_pktbuf(struct pool_info_entry *bp_info);
static struct bman_pool *init_bpid(int bpid);

/* Static BPID index allocator, increments continuously */
rte_atomic32_t bpid_alloc = RTE_ATOMIC64_INIT(0);
/* Define pool_table for entries USDPAA_MAX_BPOOLS+1 because
 * the atomic operations supported give only atomic_add_and_return()
 * so it causes 0th entry empty always
 * */
#define NUM_BP_POOL_ENTRIES (USDPAA_MAX_BPOOLS + 1)

static struct pool_info_entry dpaa_pool_table[NUM_BP_POOL_ENTRIES];

static inline struct pool_info_entry *bpid_to_pool_info(int bpid)
{
	return &dpaa_pool_table[bpid];
}

static inline
struct pool_info_entry *mempool_to_pool_info(struct rte_mempool *mp)
{
	return (struct pool_info_entry *)mp->pool_data;
}

static inline
struct net_if *portid_to_iface(uint32_t portid)
{
	return &dpaa_ifacs[portid];
}

uint32_t usdpaa_get_num_rx_queue(uint32_t portid)
{
/* todo add error checks */
	return dpaa_ifacs[portid].nb_rx_queues;
}

uint32_t usdpaa_get_num_tx_queue(uint32_t portid)
{
	return dpaa_ifacs[portid].nb_tx_queues;
}

static inline void  usdpaa_buf_free(struct pool_info_entry *bp_info, uint64_t addr)
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
void display_frame(const struct qm_fd *fd)
{
	int ii;
	char *ptr;

	printf("%s::bpid %x addr %08x%08x, format %d off %d, len %d stat %x\n",
	       __func__, fd->bpid, fd->addr_hi, fd->addr_lo, fd->format,
		fd->offset, fd->length20, fd->status);

	ptr = (char *)usdpaa_mem_ptov(fd->addr);
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
#endif

/* todo - this is costly, need to write a fast coversion routine */
static void *usdpaa_mem_ptov(phys_addr_t paddr)
{
	const struct rte_memseg *memseg = rte_eal_get_physmem_layout();
	int i;

	for (i = 0; i < RTE_MAX_MEMSEG && memseg[i].addr != NULL; i++) {
		if (paddr >= memseg[i].phys_addr && paddr <
			memseg[i].phys_addr + memseg[i].len)
			return memseg[i].addr + (paddr - memseg[i].phys_addr);
	}

	return NULL;
}

static inline void usdpaa_slow_parsing(struct rte_mbuf *m,
		uint64_t prs)
{
	/* To be implemented */
}

static inline void usdpaa_eth_packet_info(struct rte_mbuf *m,
					  uint64_t fd_virt_addr)
{
	struct annotations_t *annot = GET_ANNOTATIONS(fd_virt_addr);;
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
				RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L3_IPV4_EXT;
			break;
		case DPAA_PKT_TYPE_IPV6_EXT:
			m->packet_type = RTE_PTYPE_L2_ETHER |
				RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L3_IPV6_EXT;
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
		/* More switch cases can also be added */
		default:
			usdpaa_slow_parsing(m, prs);
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

static inline void usdpaa_checksum_offload(struct rte_mbuf *mbuf,
		struct qm_fd *fd)
{
	struct dpaa_eth_parse_results_t *prs;

	if (mbuf->data_off < DEFAULT_TX_ICEOF +
			sizeof(struct dpaa_eth_parse_results_t)) {
		printf("Checksum offload Error: Not enough Headroom "
			"space for correct Checksum offload.\n");
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

static inline struct rte_mbuf *usdpaa_eth_fd_to_mbuf(struct qman_fq *fq,
		struct qm_fd *fd)
{
	struct net_if_queue *rx;
	void *ptr;
	struct rte_mbuf *mbuf;
	struct pool_info_entry *bp_info;
	uint32_t tmp;

	if (unlikely(fd->format != qm_fd_contig)) {
		printf("%s::dropping packet in sg form\n", __func__);
		goto errret;
	}
	display_frame(fd);

	rx = container_of(fq, struct net_if_queue, fq);
	ptr = usdpaa_mem_ptov(fd->addr);
	if (!ptr) {
		printf("%s::unable to convert physical address\n", __func__);
		goto errret;
	}
	/* Prefetch the Parse results and packet data to L1 */
	rte_prefetch0(ptr + DEFAULT_RX_ICEOF);
	rte_prefetch0(ptr + fd->offset);

	bp_info = bpid_to_pool_info(fd->bpid);

	mbuf = (struct rte_mbuf *)((char *)ptr - bp_info->meta_data_size);
	mbuf->buf_addr = ptr;
	mbuf->data_off = fd->offset;
	mbuf->data_len = fd->length20;
	mbuf->pkt_len = fd->length20;

	mbuf->port = rx->ifid;
	mbuf->nb_segs = 1;
	mbuf->ol_flags = 0;
	mbuf->next = NULL;
	rte_mbuf_refcnt_set(mbuf, 1);
	usdpaa_eth_packet_info(mbuf, (uint64_t)mbuf->buf_addr);

	return mbuf;
errret:
	usdpaa_buf_free(bp_info, qm_fd_addr(fd));
	return NULL;
}

uint16_t usdpaa_eth_queue_rx(void *q,
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
		ret = usdpaa_portal_init((void *)0);
		if (ret) {
			printf("Failure in affining portal\n");
			return 0;
		}
	}

	if (unlikely(nb_bufs > MAX_PKTS_BURST))
		nb_bufs = MAX_PKTS_BURST;

	if (!qman_query_fq_has_pkts(fq))
		return 0;

	ret = qman_set_vdq(fq, nb_bufs);
	if (ret)
		return 0;

	do {
		dq = qman_dequeue(fq);
		if (!dq)
			continue;

		bufs[num_rx++] = usdpaa_eth_fd_to_mbuf(fq, &dq->fd);
		qman_dqrr_consume(fq, dq);
	} while (fq->flags & QMAN_FQ_STATE_VDQCR);

	return num_rx;
}

static struct rte_mbuf *usdpaa_get_dmable_mbuf(struct rte_mbuf *mbuf,
		struct net_if *iface,
		struct qman_fq *fq)
{
	struct rte_mbuf *usdpaa_mbuf;

	/* allocate pktbuffer on bpid for usdpaa port */
	usdpaa_mbuf = usdpaa_get_pktbuf(iface->bp_info);
	if (!usdpaa_mbuf)
		return NULL;

	memcpy(usdpaa_mbuf->buf_addr + mbuf->data_off, (void *)
		(mbuf->buf_addr + mbuf->data_off), mbuf->pkt_len);

	/* Copy only the required fields */
	usdpaa_mbuf->data_off = mbuf->data_off;
	usdpaa_mbuf->pkt_len = mbuf->pkt_len;
	usdpaa_mbuf->ol_flags = mbuf->ol_flags;
	usdpaa_mbuf->packet_type = mbuf->packet_type;
	usdpaa_mbuf->tx_offload = mbuf->tx_offload;
	rte_pktmbuf_free(mbuf);
	return usdpaa_mbuf;
}

uint16_t usdpaa_eth_queue_tx(void *q,
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
				bp_info = mempool_to_pool_info(mp);
				DPAA_MBUF_TO_CONTIG_FD(mbuf,
					&fd_arr[loop], bp_info->bpid);
			} else {
				struct net_if_queue *txq =
					container_of(q, struct net_if_queue, fq);
				struct net_if *iface = &dpaa_ifacs[txq->ifid];
				mbuf = usdpaa_get_dmable_mbuf(mbuf, iface, q);
				if (!mbuf) {
					PMD_DRV_LOG(DEBUG, "no usdpaa buffers.\n");
					/* Set frames_to_send & nb_bufs so that packets
					 * are transmitted till previous frame */
					frames_to_send = loop;
					nb_bufs = loop;
					goto send_pkts;
				}

				DPAA_MBUF_TO_CONTIG_FD(mbuf,
					&fd_arr[loop], iface->bp_info->bpid);
			}

			if (mbuf->ol_flags & NET_TX_CKSUM_OFFLOAD_MASK)
				usdpaa_checksum_offload(mbuf, &fd_arr[loop]);
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

/* Helper to determine whether an admin FQ is used on the given interface */
static int usdpaa_admin_is_used(struct net_if *dpaa_intf, int idx)
{
	if ((idx < 0) || (idx >= ADMIN_FQ_NUM))
		return 0;
	/* Offline ports don't support tx_error nor tx_confirm */
	if ((idx <= ADMIN_FQ_RX_DEFAULT) ||
	    (dpaa_intf->cfg->fman_if->mac_type != fman_offline))
		return 1;
	return 0;
}

/* Initialise a admin FQ ([rt]x_error, rx_default, tx_confirm). */
static int usdpaa_admin_queue_init(struct net_if_admin *a, uint32_t fqid, int idx)
{
	struct qm_mcc_initfq opts;
	int ret;

	ret = qman_reserve_fqid(fqid);
	if (ret)
		return -EINVAL;
	a->idx = idx;

	ret = qman_create_fq(fqid, QMAN_FQ_FLAG_NO_ENQUEUE, &a->fq);
	if (ret)
		return ret;
	opts.we_mask = QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL;
	opts.fqd.dest.wq = NET_IF_ADMIN_PRIORITY;
	return qman_init_fq(&a->fq, 0, &opts);
}

/* Initialise an Rx FQ */
static int usdpaa_rx_queue_init(struct qman_fq *fq,
		uint32_t fqid)
{
	struct qm_mcc_initfq opts;
	int ret;

	ret = qman_reserve_fqid(fqid);
	if (ret) {
		printf("%s::reserve rx fqid %d failed\n",
		       __func__, fqid);
		return -EINVAL;
	}
	/* "map" this Rx FQ to one of the interfaces Tx FQID */
	PMD_DRV_LOG(DEBUG, "%s::creating rx fq %p, fqid %d\n",
		__func__, fq, fqid);
	ret = qman_create_fq(fqid, QMAN_FQ_FLAG_NO_ENQUEUE, fq);
	if (ret) {
		printf("%s::create rx fqid %d failed\n", __func__, fqid);
		return ret;
	}
	opts.we_mask = QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL |
		       QM_INITFQ_WE_CONTEXTA;

	PMD_DRV_LOG(DEBUG, "fqid %x, wq %d ifid %d\n", fqid,
		    NET_IF_RX_PRIORITY, dpaa_intf->ifid);

	opts.fqd.dest.wq = NET_IF_RX_PRIORITY;
	opts.fqd.fq_ctrl = QM_FQCTRL_AVOIDBLOCK | QM_FQCTRL_CTXASTASHING |
			   QM_FQCTRL_PREFERINCACHE;
	opts.fqd.context_a.stashing.exclusive = 0;
	opts.fqd.context_a.stashing.annotation_cl = NET_IF_RX_ANNOTATION_STASH;
	opts.fqd.context_a.stashing.data_cl = NET_IF_RX_DATA_STASH;
	opts.fqd.context_a.stashing.context_cl = NET_IF_RX_CONTEXT_STASH;
	ret = qman_init_fq(fq, 0, &opts);
	if (ret)
		printf("%s::init rx fqid %d failed %d\n",
		       __func__, fqid, ret);
	return ret;
}

/* Initialise a Tx FQ */
static int usdpaa_tx_queue_init(struct qman_fq *fq,
		const struct fman_if *fif)
{
	struct qm_mcc_initfq opts;
	int ret;

	ret = qman_create_fq(0, QMAN_FQ_FLAG_DYNAMIC_FQID |
			     QMAN_FQ_FLAG_TO_DCPORTAL, fq);
	if (ret)
		return ret;
	opts.we_mask = QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL |
		       QM_INITFQ_WE_CONTEXTB | QM_INITFQ_WE_CONTEXTA;
	opts.fqd.dest.channel = fif->tx_channel_id;
	opts.fqd.dest.wq = NET_IF_TX_PRIORITY;
	opts.fqd.fq_ctrl = QM_FQCTRL_PREFERINCACHE;
	opts.fqd.context_b = 0;
	/* no tx-confirmation */
	opts.fqd.context_a.hi = 0x80000000 | fman_dealloc_bufs_mask_hi;
	opts.fqd.context_a.lo = 0 | fman_dealloc_bufs_mask_lo;
	PMD_DRV_LOG(DEBUG, "%s::initializing fqid %d for iface fm%d-gb%d chanl %d\n",
		    __func__, fq->fqid, (fif->fman_idx + 1), fif->mac_idx,
		fif->tx_channel_id);
	return qman_init_fq(fq, QMAN_INITFQ_FLAG_SCHED, &opts);
}

int hw_mbuf_create_pool(struct rte_mempool *mp)
{
	uint32_t bpid;
	struct bman_pool *bp;

	/*XXX: bpid_alloc needs to be changed to a bitmap, so that
	 * we can take care of destroy_pool kind of API too. Current
	 * implementation doesn't allow deallocation of entry
	 */
	bpid = rte_atomic32_add_return(&bpid_alloc, 1);

	if (bpid > NUM_BP_POOL_ENTRIES) {
		fprintf(stderr, "error: exceeding bpid requirements\n");
		return -2;
	}

	bp = init_bpid(bpid);
	if (!bp) {
		fprintf(stderr, "error: init_bpid failed\n");
		return -2;
	}

	dpaa_pool_table[bpid].mp = mp;
	dpaa_pool_table[bpid].bpid = bpid;
	dpaa_pool_table[bpid].size = mp->elt_size;
	dpaa_pool_table[bpid].bp = bp;
	dpaa_pool_table[bpid].meta_data_size =
		sizeof(struct rte_mbuf) + rte_pktmbuf_priv_size(mp);
	mp->pool_data = (void *)&dpaa_pool_table[bpid];

	/* TODO: Replace with mp->pool_data->flags after creating appropriate
	 * pool_data structure
	 */
	mp->flags |= MEMPOOL_F_HW_PKT_POOL;

	PMD_DRV_LOG(INFO, "BP List created for bpid =%d\n", bpid);
	return 0;
}

void hw_mbuf_free_pool(struct rte_mempool *mp __rte_unused)
{
	/* TODO:
	 * 1. Release bp_list memory allocation
	 * 2. opposite of dpbp_enable()
	 * <More>
	 */

	PMD_DRV_LOG(DEBUG, "(%s) called\n", __func__);
	return;
}

int hw_mbuf_alloc_bulk(struct rte_mempool *pool,
			void **obj_table,
			unsigned count)
{
#ifdef RTE_LIBRTE_DPAA_DEBUG_DRIVER
	static int alloc;
#endif
	void *bufaddr;
	int ret;
	unsigned int i = 0, n = 0;
	struct rte_mbuf **m = (struct rte_mbuf **)obj_table;
	struct bm_buffer bufs[RTE_MEMPOOL_CACHE_MAX_SIZE + 1];
	struct pool_info_entry *bp_info;

	bp_info = mempool_to_pool_info(pool);

	if (!netcfg || !bp_info) {
		PMD_DRV_LOG(WARNING, "DPAA2 buffer pool not configured\n");
		return -2;
	}

	if (!thread_portal_init) {
		ret = usdpaa_portal_init((void *)0);
		if (ret) {
			printf("Failure in affining portal\n");
			return 0;
		}
	}

	if (count < DPAA_MBUF_MAX_ACQ_REL) {
		ret = bman_acquire(bp_info->bp,
				   &bufs[n], count, 0);
		if (ret <= 0) {
			PMD_DRV_LOG(WARNING, "Failed to allocate buffers %d", ret);
			return -1;
		}
		n = ret;
		goto set_buf;
	}

	while (n < count) {
		ret = 0;
		/* Acquire is all-or-nothing, so we drain in 7s,
		 * then in 1s for the remainder. */
		if ((count - n) >= DPAA_MBUF_MAX_ACQ_REL) {
			ret = bman_acquire(bp_info->bp,
					   &bufs[n], DPAA_MBUF_MAX_ACQ_REL, 0);
			if (ret == DPAA_MBUF_MAX_ACQ_REL) {
				n += ret;
			}
		} else {
			ret =  bman_acquire(bp_info->bp,
					    &bufs[n], count - n, 0);
			if (ret > 0) {
				PMD_DRV_LOG(DEBUG, "ret = %d bpid =%d alloc %d,"
					"count=%d Drained buffer: %x",
					ret, bp_info->bpid,
					alloc, count - n, bufs[n]);
				n += ret;
			}
		}
		/* In case of less than requested number of buffers available
		 * in pool, bman_acquire can return 0
		 */
		if (ret <= 0) {
			PMD_DRV_LOG(WARNING, "Buffer acquire failed with"
				"err code: %d", ret);
			break;
		}
	}
	if (count != n)
		goto free_buf;

	if (ret < 0 || n == 0) {
		PMD_DRV_LOG(WARNING, "Failed to allocate buffers %d", ret);
		return -1;
	}
set_buf:
	while (i < count) {
		bufaddr = (void *)usdpaa_mem_ptov(bufs[i].addr);
		m[i] = (struct rte_mbuf *)((char *)bufaddr
			- bp_info->meta_data_size);
		RTE_ASSERT(rte_mbuf_refcnt_read(m[i]) == 0);
		rte_mbuf_refcnt_set(m[i], 1);
		i = i + 1;
	}
#ifdef RTE_LIBRTE_DPAA_DEBUG_DRIVER
	alloc += n;
	PMD_DRV_LOG(DEBUG, "Total = %d , req = %d done = %d bpid =%d",
		    alloc, count, n, bp_info->bpid);
#endif
	return 0;
free_buf:
	PMD_DRV_LOG(WARNING, "unable alloc required bufs count =%d n=%d",
		    count, n);
	i = 0;
	while (i < n) {
retry:
		ret = bman_release(bp_info->bp, &bufs[i], 1, 0);
		if (ret) {
			cpu_spin(CPU_SPIN_BACKOFF_CYCLES);
			goto retry;
		}
		i++;
	}
	return -1;
}

int hw_mbuf_free_bulk(struct rte_mempool *pool,
			void *const *obj_table,
			unsigned n)
{
	struct rte_mbuf **mb = (struct rte_mbuf **)obj_table;
	struct pool_info_entry *bp_info;
	unsigned i = 0;
	int ret;

	if (!thread_portal_init) {
		ret = usdpaa_portal_init((void *)0);
		if (ret) {
			printf("Failure in affining portal\n");
			return 0;
		}
	}

	if (!netcfg) {
		PMD_DRV_LOG(WARNING, "DPAA2 buffer pool not configured\n");
		return -1;
	}
	while (i < n) {
		bp_info = mempool_to_pool_info(pool);
		usdpaa_buf_free(bp_info,
			(uint64_t)rte_mempool_virt2phy(pool, obj_table[i])
				+ bp_info->meta_data_size);
		i = i + 1;
	}

	return 0;
}

unsigned int hw_mbuf_get_count(const struct rte_mempool *mp __rte_unused)
{
	/* TODO: incomplete */
	return 0;
}

struct rte_mempool_ops dpaa_mpool_ops = {
	.name = "dpaa",
	.alloc = hw_mbuf_create_pool,
	.free = hw_mbuf_free_pool,
	.enqueue = hw_mbuf_free_bulk,
	.dequeue = hw_mbuf_alloc_bulk,
	.get_count = hw_mbuf_get_count,
};

MEMPOOL_REGISTER_OPS(dpaa_mpool_ops);

static void *usdpaa_get_pktbuf(struct pool_info_entry *bp_info)
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

	buf = (uint64_t)usdpaa_mem_ptov(bufs.addr) - bp_info->meta_data_size;
	if (!buf)
		goto out;

out:
	return (void *)buf;
}

/* Initialise a network interface */
static int net_if_init(struct net_if *dpaa_intf,
		       const struct fm_eth_port_cfg *cfg)
{
	const struct fman_if *fif = cfg->fman_if;
	struct fm_eth_port_fqrange *fq_range;
	int num_cores, ret, loop;

	dpaa_intf->cfg = cfg;
	/* give the interface a name */
	sprintf(&dpaa_intf->name[0], "fm%d-gb%d", (cfg->fman_if->fman_idx + 1),
		cfg->fman_if->mac_idx);

	/* get the mac address */
	memcpy(&dpaa_intf->mac_addr, &cfg->fman_if->mac_addr.addr_bytes,
	       ETHER_ADDR_LEN);

	printf("%s::interface %s macaddr::", __func__, dpaa_intf->name);
	for (loop = 0; loop < ETHER_ADDR_LEN; loop++) {
		if (loop != (ETHER_ADDR_LEN - 1))
			printf("%02x:", dpaa_intf->mac_addr[loop]);
		else
			printf("%02x\n", dpaa_intf->mac_addr[loop]);
	}

	/* Initialise admin FQs */
	if (!ret && usdpaa_admin_is_used(dpaa_intf, ADMIN_FQ_RX_ERROR))
		ret = usdpaa_admin_queue_init(&dpaa_intf->admin[ADMIN_FQ_RX_ERROR],
					fif->fqid_rx_err,
					ADMIN_FQ_RX_ERROR);
	if (!ret && usdpaa_admin_is_used(dpaa_intf, ADMIN_FQ_RX_DEFAULT))
		ret = usdpaa_admin_queue_init(&dpaa_intf->admin[ADMIN_FQ_RX_DEFAULT],
					cfg->rx_def,
					ADMIN_FQ_RX_DEFAULT);
	if (!ret && usdpaa_admin_is_used(dpaa_intf, ADMIN_FQ_TX_ERROR))
		ret = usdpaa_admin_queue_init(&dpaa_intf->admin[ADMIN_FQ_TX_ERROR],
					fif->fqid_tx_err,
					ADMIN_FQ_TX_ERROR);
	if (!ret && usdpaa_admin_is_used(dpaa_intf, ADMIN_FQ_TX_CONFIRM))
		ret = usdpaa_admin_queue_init(&dpaa_intf->admin[ADMIN_FQ_TX_CONFIRM],
					fif->fqid_tx_confirm,
					ADMIN_FQ_TX_CONFIRM);
	if (ret) {
		printf("%s::admin create FQ failed\n", __func__);
		return ret;
	}

	loop = 0;
	list_for_each_entry(fq_range, cfg->list, list) {
		dpaa_intf->rx_queues = rte_zmalloc(NULL, sizeof(struct net_if_queue) *
			fq_range->count, MAX_CACHELINE);
		if (!dpaa_intf->rx_queues)
			return -ENOMEM;

		/* Initialise each Rx FQ within the range */
		for (loop = 0; loop < fq_range->count; loop++) {
			ret = usdpaa_rx_queue_init(&dpaa_intf->rx_queues[loop].fq,
				fq_range->start + loop);
			if (ret) {
				printf("%s::net_if_rx_init failed for %d\n",
				       __func__, fq_range->start);
				return ret;
			}
			dpaa_intf->rx_queues[loop].ifid = dpaa_intf->ifid;
		}
		dpaa_intf->nb_rx_queues = fq_range->count;

		/* We support only one fm_eth_port_fqrange entry
		 * from fm_eth_port_cfg */
		break;
	}

	/* Initialise Tx FQs. Have as many Tx FQ's as number of cores */
	num_cores = rte_lcore_count();
	dpaa_intf->tx_queues = rte_zmalloc(NULL, sizeof(struct net_if_queue) *
		num_cores, MAX_CACHELINE);
	if (!dpaa_intf->tx_queues)
		return -ENOMEM;

	for (loop = 0; loop < num_cores; loop++) {
		ret = usdpaa_tx_queue_init(&dpaa_intf->tx_queues[loop].fq, fif);
		if (ret)
			return ret;
		PMD_DRV_LOG(DEBUG, "%s::tx_fqid %x\n",
			    __func__, dpaa_intf->tx_queues[loop].fq.fqid);
		dpaa_intf->tx_queues[loop].ifid = dpaa_intf->ifid;
	}
	dpaa_intf->nb_tx_queues = num_cores;

	/* save fif in the interface struture */
	dpaa_intf->fif = fif;
	PMD_DRV_LOG(DEBUG, "%s::all rxfqs created\n", __func__);

	/* Disable RX, disable promiscous mode */
	fman_if_disable_rx(fif);
	fman_if_promiscuous_disable(fif);
	return 0;
}

void usdpaa_set_promisc_mode(uint32_t port_id, uint32_t op)
{
	struct net_if *net_if;

	net_if = &dpaa_ifacs[port_id];
	if (op == ENABLE_OP)
		fman_if_promiscuous_enable(net_if->fif);
	else
		fman_if_promiscuous_disable(net_if->fif);
}

void usdpaa_port_control(uint32_t port_id, uint32_t op)
{
	struct net_if *net_if;

	net_if = &dpaa_ifacs[port_id];
	if (op == ENABLE_OP)
		fman_if_enable_rx(net_if->fif);
	else
		fman_if_disable_rx(net_if->fif);
}

void usdpaa_get_iface_link(uint32_t port_id, struct rte_eth_link *link)
{
	struct net_if *net_if =  &dpaa_ifacs[port_id];

	if (net_if->fif->mac_type == fman_mac_1g)
		link->link_speed = 1000;
	else if (net_if->fif->mac_type == fman_mac_10g)
		link->link_speed = 10000;
	else
		printf("%s:: invalid link_speed %d\n", net_if->name, net_if->fif->mac_type);

	link->link_status = net_if->valid;
	link->link_duplex = ETH_LINK_FULL_DUPLEX;
	link->link_autoneg = ETH_LINK_AUTONEG;
}

static inline void usdpaa_memac_status(struct memac_regs *regs,
				       struct rte_eth_stats *stats)
{
	/* read recved packet count */
	stats->ipackets = ((u64)in_be32(&regs->rfrm_u)) << 32 | in_be32(&regs->rfrm_l);
	stats->ibytes = ((u64)in_be32(&regs->roct_u)) << 32 | in_be32(&regs->roct_l);
	stats->ierrors = ((u64)in_be32(&regs->rerr_u)) << 32 | in_be32(&regs->rerr_l);

	/* read xmited packet count */
	stats->opackets = ((u64)in_be32(&regs->tfrm_u)) << 32 | in_be32(&regs->tfrm_l);
	stats->obytes = ((u64)in_be32(&regs->toct_u)) << 32 | in_be32(&regs->toct_l);
	stats->oerrors = ((u64)in_be32(&regs->terr_u)) << 32 | in_be32(&regs->terr_l);
}

static inline void usdpaa_dtsec_status(struct dtsec_regs *regs,
				       struct rte_eth_stats *stats)
{
	stats->ipackets = in_be32(&regs->rpkt);
	stats->ibytes = in_be32(&regs->rbyt);
	stats->ierrors = in_be32(&regs->rdrp);
	stats->opackets = in_be32(&regs->tpkt);
	stats->obytes = in_be32(&regs->tbyt);
	stats->oerrors = in_be32(&regs->tdrp);
}

void usdpaa_get_iface_stats(uint32_t port_id, struct rte_eth_stats *stats)
{
	struct net_if *net_if = &dpaa_ifacs[port_id];
	struct fman_if_internal *itif;
	void *regs;

	itif = container_of((struct fman_if *)(net_if->fif),
			    struct fman_if_internal, itif);
	regs = itif->ccsr_map;

	if (net_if->fif->is_memac)
		usdpaa_memac_status(regs, stats);
	else
		usdpaa_dtsec_status(regs, stats);
}

static struct bman_pool *init_bpid(int bpid)
{
	struct bm_buffer bufs[8];
	struct bman_pool *bp = NULL;
	unsigned int num_bufs = 0;
	int ret = 0;

#ifdef RTE_LIBRTE_DPAA_DEBUG_DRIVER
	printf("request bman pool: bpid %d\n", bpid);
#endif

	/* Drain (if necessary) then seed buffer pools */
	struct bman_pool_params params = {
		.bpid = bpid
	};

	bp = bman_new_pool(&params);
	if (!bp) {
		fprintf(stderr, "error: bman_new_pool() failed\n");
		return NULL;
	}

	/* Drain the pool of anything already in it. */
	do {
		/* Acquire is all-or-nothing, so we drain in 8s, then in 1s for
		 * the remainder.
		 */
		if (ret != 1)
			ret = bman_acquire(bp, bufs, 8, 0);
		if (ret < 8)
			ret = bman_acquire(bp, bufs, 1, 0);
		if (ret > 0)
			num_bufs += ret;
	} while (ret > 0);
	if (num_bufs)
		fprintf(stderr, "Warn: drained %u bufs from BPID %d\n",
			num_bufs, bpid);

	return bp;
}

static int do_global_init(void)
{
	unsigned int loop;

	/* Create and initialise the network interfaces */
#ifdef RTE_LIBRTE_DPAA_DEBUG_DRIVER
	printf("%s::creating %d ifaces\n", __func__, netcfg->num_ethports);
#endif
	for (loop = 0; loop < netcfg->num_ethports; loop++) {
		struct fman_if_bpool *bp, *tmp_bp;
		struct fm_eth_port_cfg *pcfg;
		int ret;

		pcfg = &netcfg->port_cfg[loop];
		dpaa_ifacs[loop].ifid = loop;

		ret = net_if_init(&dpaa_ifacs[loop], pcfg);
		if (ret) {
			fprintf(stderr, "Fail: net_if_init(%d)\n", loop);
			return ret;
		}
		/* reset bpool list, initialize bpool dynamically */
		list_for_each_entry_safe(bp, tmp_bp, &pcfg->fman_if->bpool_list, node) {
			list_del(&bp->node);
			free(bp);
		}
	}
	return 0;
}

int usdpaa_portal_init(void *arg)
{
	cpu_set_t cpuset;
	pthread_t id;
	uint32_t cpu;
	int ret;

	if (thread_portal_init)
		return 0;

	if ((uint64_t)arg == 1)
		cpu = rte_get_master_lcore();
	else
		cpu = rte_lcore_id();

	PMD_DRV_LOG(DEBUG, "%s::arg %p, cpu %d\n", __func__, arg, cpu);
	/* Set CPU affinity for this thread */
	CPU_ZERO(&cpuset);
	CPU_SET(cpu, &cpuset);
	id = pthread_self();
	ret = pthread_setaffinity_np(id, sizeof(cpu_set_t), &cpuset);
	if (ret) {
		fprintf(stderr, "(%d): Fail: %s\n", cpu,
			"pthread_setaffinity_np()");
		return -1;
	}

	/* Initialise bman thread portals */
	ret = bman_thread_init();
	if (ret) {
		printf("%s::bman_thread_init failed on core %d\n",
		       __func__, cpu);
		return -1;
	}
	/* Initialise qman thread portals */
	ret = qman_thread_init();
	if (ret) {
		printf("%s::bman_thread_init failed on core %d\n",
		       __func__, cpu);
		return -1;
	}
	thread_portal_init = true;

	return 0;
}

static int usdpaa_init(void)
{
	/* Determine number of cores (==number of threads) */
	/* Load the device-tree driver */
	int ii, ret;

	char	*cfg_file;
	char	*pcd_file;

	pcd_file = getenv("DEF_PCD_PATH");
	cfg_file = getenv("DEF_CFG_PATH");

	if (!cfg_file || !pcd_file) {
		RTE_LOG(ERR, EAL, "dpaa pcd & cfg not set in env\n");
		return -1;
	}
#ifdef RTE_LIBRTE_DPAA_DEBUG_DRIVER
	printf("cfgpath %s, pcdpath %s\n", cfg_file, pcd_file);
#endif
	ret = of_init();
	if (ret) {
		printf("of_init Failed %d\n", ret);
		return -1;
	}
	/* Parse FMC policy and configuration files for the network
	 * configuration. This also "extracts" other settings into 'netcfg' that
	 * are not necessarily from the XML files, such as the pool channels
	 * that the application is allowed to use (these are currently
	 * hard-coded into the netcfg code). */
	netcfg = usdpaa_netcfg_acquire(pcd_file, cfg_file);
	if (!netcfg) {
		fprintf(stderr, "Fail: usdpaa_netcfg_acquire(%s,%s)\n",
			pcd_file, cfg_file);
		return -1;
	}
#ifdef RTE_LIBRTE_DPAA_DEBUG_DRIVER
	printf("%d ethports available\n", netcfg->num_ethports);
	dump_usdpaa_netcfg(netcfg);
#endif
	if (!netcfg->num_ethports) {
		fprintf(stderr, "Fail: no network interfaces available\n");
		return -1;
	}
	dpaa_ifacs = calloc(netcfg->num_ethports, sizeof(*dpaa_ifacs));
	if (!dpaa_ifacs)
		return -ENOMEM;

	for (ii = 0; ii < netcfg->num_ethports; ii++) {
		struct fm_eth_port_cfg *cfg;
		struct fman_if *fman_if;

		cfg = &netcfg->port_cfg[ii];
		fman_if = cfg->fman_if;
		sprintf(&dpaa_ifacs->name[0], "fm%d-gb%d",
			(fman_if->fman_idx + 1),
				fman_if->mac_idx);
	}
	/* Load the Qman/Bman drivers */
	ret = qman_global_init();
	if (ret) {
		fprintf(stderr, "Fail: %s: %d\n", "qman_global_init()", ret);
		return -1;
	}
	ret = bman_global_init();
	if (ret) {
		fprintf(stderr, "Fail: %s: %d\n", "bman_global_init()", ret);
		return -1;
	}
	return netcfg->num_ethports;
}

int usdpaa_set_rx_queue(uint32_t portid, uint32_t queue_id,
			 void **rx_queues, struct rte_mempool *mp)
{
	struct net_if *iface = &dpaa_ifacs[portid];

	if (!iface->bp_info || iface->bp_info->mp != mp) {
		struct fman_if_ic_params icp;
		uint32_t fd_offset;

		if (!mp->pool_data) {
			printf("\n ??? ERR - %s not a offloaded buffer pool",
			       __func__);
			return -1;
		}
		iface->bp_info = mempool_to_pool_info(mp);

		memset(&icp, 0, sizeof(icp));
		/* set ICEOF for to the default value , which is 0*/
		icp.iciof = DEFAULT_ICIOF;
		icp.iceof = DEFAULT_RX_ICEOF;
		icp.icsz = DEFAULT_ICSZ;
		fman_if_set_ic_params(iface->fif, &icp);

		fd_offset = RTE_PKTMBUF_HEADROOM + DPAA_HW_BUF_RESERVE;
		fman_if_set_fdoff(iface->fif, fd_offset);
		fman_if_set_bp(iface->fif, mp->size,
			       iface->bp_info->bpid, mp->elt_size);
		iface->valid = 1;
		PMD_DRV_LOG(INFO, "if =%s - fd_offset = %d offset = %d",
			iface->name, fd_offset,
			fman_if_get_fdoff(iface->fif));
	}
	rx_queues[queue_id] = &iface->rx_queues[queue_id].fq;

	return 0;
}

int usdpaa_set_tx_queue(uint32_t portid,
		uint32_t queue_id,
		void **tx_queues)
{
	struct net_if *iface = &dpaa_ifacs[portid];;
	tx_queues[queue_id] = &iface->tx_queues[queue_id].fq;
	return 0;
}

char *usdpaa_get_iface_macaddr(uint32_t portid)
{
	struct net_if *iface;

	iface = &dpaa_ifacs[portid];

	return &iface->mac_addr[0];
}

int usdpaa_get_num_ports(void)
{
	return num_usdpaa_ports;
}

int usdpaa_pre_rte_eal_init(void)
{
	int ret = 0;

	ret = usdpaa_init();
	if (ret <= 0) {
		printf("Cannot init usdpaa\n");
		return -1;
	}

	num_usdpaa_ports = ret;

	if (usdpaa_portal_init((void *)1)) {
		printf("usdpaa portal init failed\n");
		return -1;
	}
	PMD_DRV_LOG(DEBUG, "%s::global init, net portals\n", __func__);
	if (do_global_init()) {
		printf("%s::global init failed\n", __func__);
		return -1;
	}
	if (add_usdpaa_devices_to_pcilist(num_usdpaa_ports)) {
		printf("Cannot init non pci dev list\n");
		return -1;
	}

	return 0;
}
static int
usdpaa_eth_dev_configure(struct rte_eth_dev *dev __rte_unused)
{
	return 0;
}

static const uint32_t *
usdpaa_supported_ptypes_get(struct rte_eth_dev *dev)
{
	static const uint32_t ptypes[] = {
		/*todo -= add more types */
		RTE_PTYPE_L2_ETHER,
		RTE_PTYPE_L3_IPV4,
		RTE_PTYPE_L3_IPV6,
		RTE_PTYPE_L3_IPV6_EXT,
		RTE_PTYPE_L4_TCP,
		RTE_PTYPE_L4_UDP,
		RTE_PTYPE_L4_SCTP
	};

	if (dev->rx_pkt_burst == usdpaa_eth_queue_rx)
		return ptypes;
	return NULL;
}

static int usdpaa_eth_dev_start(struct rte_eth_dev *dev)
{
	uint32_t port_id;
	int ret = 0;

	if (!thread_portal_init) {
		ret = usdpaa_portal_init((void *)0);
		if (ret) {
			printf("Failure in affining portal\n");
			return ret;
		}
	}

	port_id = dev->data->port_id;

	/* Change tx callback to the real one */
	dev->tx_pkt_burst = usdpaa_eth_queue_tx;

	usdpaa_port_control(port_id, ENABLE_OP);
	return ret;
}

static void usdpaa_eth_dev_stop(struct rte_eth_dev *dev)
{
	uint32_t port_id;

	port_id = dev->data->port_id;
	usdpaa_port_control(port_id, DISABLE_OP);
	dev->tx_pkt_burst = usdpaa_eth_tx_drop_all;
}

static void usdpaa_eth_dev_close(struct rte_eth_dev *dev)
{
	usdpaa_eth_dev_stop(dev);
}

static void usdpaa_eth_dev_info(struct rte_eth_dev *dev,
				struct rte_eth_dev_info *dev_info)
{
	dev_info->max_rx_queues = usdpaa_get_num_rx_queue(dev->data->port_id);
	dev_info->max_tx_queues = FSL_USDPAA_MAX_TXS/* iface->nb_tx_queues*/;
	dev_info->min_rx_bufsize = DPAA_MIN_RX_BUF_SIZE;
	dev_info->max_rx_pktlen = DPAA_MAX_RX_PKT_LEN;
	dev_info->max_mac_addrs = 0;
	dev_info->max_hash_mac_addrs = 0;
	dev_info->max_vfs = dev->pci_dev->max_vfs;
	dev_info->max_vmdq_pools = ETH_16_POOLS;
	dev_info->flow_type_rss_offloads = DPAA_RSS_OFFLOAD_ALL;
	dev_info->rx_offload_capa =
		(DEV_RX_OFFLOAD_IPV4_CKSUM |
		DEV_RX_OFFLOAD_UDP_CKSUM  |
		DEV_RX_OFFLOAD_TCP_CKSUM);
	dev_info->tx_offload_capa =
		(DEV_TX_OFFLOAD_IPV4_CKSUM  |
		DEV_TX_OFFLOAD_UDP_CKSUM   |
		DEV_TX_OFFLOAD_TCP_CKSUM);
}

static int usdpaa_eth_link_update(struct rte_eth_dev *dev,
				  int wait_to_complete __rte_unused)
{
	struct rte_eth_link *link = &dev->data->dev_link;

	usdpaa_get_iface_link(dev->data->port_id, link);

	return 0;
}

static void usdpaa_eth_stats_get(struct rte_eth_dev *dev,
				 struct rte_eth_stats *stats)
{
	usdpaa_get_iface_stats(dev->data->port_id, stats);
}

static void usdpaa_eth_stats_reset(struct rte_eth_dev *dev)
{
	printf("%s::needs implementation dev %p\n", __func__, dev);
}

static void usdpaa_eth_promiscuous_enable(struct rte_eth_dev *dev)
{
	uint32_t port_id;

	port_id = dev->data->port_id;
	usdpaa_set_promisc_mode(port_id, ENABLE_OP);
}

static void usdpaa_eth_promiscuous_disable(struct rte_eth_dev *dev)
{
	uint32_t port_id;

	port_id = dev->data->port_id;
	usdpaa_set_promisc_mode(port_id, DISABLE_OP);
}

static uint16_t usdpaa_eth_tx_drop_all(void *q  __rte_unused,
				       struct rte_mbuf **bufs __rte_unused,
				uint16_t nb_bufs __rte_unused)
{
	/* Drop all incoming packets. No need to free packets here
	 * because the rte_eth f/w frees up the packets through tx_buffer
	 * callback in case this functions returns count less than nb_bufs
	 */
	return 0;
}

int usdpaa_eth_rx_queue_setup(struct rte_eth_dev *dev, uint16_t queue_idx,
			      uint16_t nb_desc __rte_unused,
			      unsigned int socket_id __rte_unused,
			      const struct rte_eth_rxconf *rx_conf __rte_unused,
			      struct rte_mempool *mp)
{
	return usdpaa_set_rx_queue(dev->data->port_id, queue_idx,
			     dev->data->rx_queues, mp);
}

void usdpaa_eth_rx_queue_release(void *rxq)
{
	printf("\n(%s) called for 1=%p\n", __func__, rxq);
	return;
}

int usdpaa_eth_tx_queue_setup(struct rte_eth_dev *dev, uint16_t queue_idx,
			      uint16_t nb_desc __rte_unused,
			      unsigned int socket_id __rte_unused,
			      const struct rte_eth_txconf *tx_conf __rte_unused)
{
	return usdpaa_set_tx_queue(dev->data->port_id, queue_idx,
			     dev->data->tx_queues);
}

void usdpaa_eth_tx_queue_release(void *txq)
{
	printf("\n(%s) called for 1=%p\n", __func__, txq);
}

int usdpaa_mtu_set(struct rte_eth_dev *dev __rte_unused,
		   uint16_t mtu __rte_unused)
{
	/* Currently we don't need to set anything specefic
	 * in hardware for MTU (to be checked again). So just return zero in
	 * order to make sure that setting mtu from Applicaiton doesn't return
	 * any error
	 */
	return 0;
}

int usdpaa_link_down(struct rte_eth_dev *dev)
{
	usdpaa_eth_dev_stop(dev);
	return 0;
}

int usdpaa_link_up(struct rte_eth_dev *dev)
{
	usdpaa_eth_dev_start(dev);
	return 0;
}

static int
usdpaa_flow_ctrl_set(struct rte_eth_dev *dev  __rte_unused,
		     struct rte_eth_fc_conf *fc_conf  __rte_unused)
{
	/*TBD:XXX: to be implemented*/
	PMD_DRV_LOG(NOTICE, "%s:: Empty place holder, no action taken\n",
		    __func__);

	return 0;
}

static struct eth_dev_ops usdpaa_devops = {
	.dev_configure		  = usdpaa_eth_dev_configure,
	.dev_start		  = usdpaa_eth_dev_start,
	.dev_stop		  = usdpaa_eth_dev_stop,
	.dev_close		  = usdpaa_eth_dev_close,
	.dev_infos_get		  = usdpaa_eth_dev_info,
	.dev_supported_ptypes_get = usdpaa_supported_ptypes_get,

	.rx_queue_setup		  = usdpaa_eth_rx_queue_setup,
	.tx_queue_setup		  = usdpaa_eth_tx_queue_setup,
	.rx_queue_release	  = usdpaa_eth_rx_queue_release,
	.tx_queue_release	  = usdpaa_eth_tx_queue_release,

	.flow_ctrl_set		  = usdpaa_flow_ctrl_set,

	.link_update		  = usdpaa_eth_link_update,
	.stats_get		  = usdpaa_eth_stats_get,
	.stats_reset		  = usdpaa_eth_stats_reset,
	.promiscuous_enable	  = usdpaa_eth_promiscuous_enable,
	.promiscuous_disable	  = usdpaa_eth_promiscuous_disable,
	.mtu_set		  = usdpaa_mtu_set,
	.dev_set_link_down	  = usdpaa_link_down,
	.dev_set_link_up	  = usdpaa_link_up,
};

static int usdpaa_pci_devinit(struct rte_pci_driver *pci_drv __rte_unused,
			      struct rte_pci_device *pci_dev)
{
	struct rte_eth_dev *ethdev;
	char devname[MAX_ETHDEV_NAME];
	char *mac_addr;

	PMD_DRV_LOG(DEBUG, "%s::drv %p, dev %p\n", __func__, pci_drv, pci_dev);

	/* alloc ethdev entry */
	sprintf(devname, "%s%d\n", ETHDEV_NAME_PREFIX, pci_dev->addr.devid);
	ethdev = rte_eth_dev_allocate(devname, RTE_ETH_DEV_VIRTUAL);
	if (!ethdev) {
		printf("%s::unable to allocate ethdev\n", __func__);
		return -1;
	}

	PMD_DRV_LOG(DEBUG, "%s::allocated eth device port id %d\n", __func__,
		    ethdev->data->port_id);

	ethdev->dev_ops = &usdpaa_devops;
	ethdev->pci_dev = pci_dev;

	/* assign rx and tx ops */
	ethdev->rx_pkt_burst = usdpaa_eth_queue_rx;
	ethdev->tx_pkt_burst = usdpaa_eth_tx_drop_all;

	mac_addr = usdpaa_get_iface_macaddr(ethdev->data->port_id);
	ethdev->data->mac_addrs = (struct ether_addr *)mac_addr;

	return 0;
}

static inline void insert_devices_into_pcilist(struct rte_pci_device *dev)
{
	uint32_t devaddr;
	uint32_t newdevaddr;
	struct rte_pci_device *dev2 = NULL;

	if (!(TAILQ_EMPTY(&pci_device_list))) {
		newdevaddr = PCI_DEV_ADDR(dev);
		TAILQ_FOREACH(dev2, &pci_device_list, next) {
			devaddr = PCI_DEV_ADDR(dev2);

			if (newdevaddr < devaddr) {
				TAILQ_INSERT_BEFORE(dev2, dev, next);
				return;
			}
		}
	}
	TAILQ_INSERT_TAIL(&pci_device_list, dev, next);
}

int add_usdpaa_devices_to_pcilist(int num_ethports)
{
	int ii;
	struct rte_pci_device *dev;

	for (ii = 0; ii < num_ethports; ii++) {
		dev = calloc(1, sizeof(struct rte_pci_device));
		if (!dev) {
			printf("%s::unable to allocate dev for %d\n",
			       __func__, ii);
			return -1;
		}
		dev->addr.domain = FSL_USDPAA_DOMAIN;
		dev->addr.bus = FSL_USDPAA_BUSID;
		dev->addr.devid = ii;
		dev->id.class_id = 0;
		dev->id.vendor_id = FSL_VENDOR_ID;
		dev->id.device_id = FSL_DEVICE_ID;
		dev->id.subsystem_vendor_id = FSL_SUBSYSTEM_VENDOR;
		dev->id.subsystem_device_id = FSL_SUBSYSTEM_DEVICE;
		dev->numa_node = 0;

		/* device is valid, add in list (sorted) */
		insert_devices_into_pcilist(dev);
	}
	printf("%s::%d devices added to pci list\n", __func__, ii);
	rte_eal_pci_register(&usdpaa_pci_driver);

	return 0;
}
