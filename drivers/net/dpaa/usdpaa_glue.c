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

#include <usdpaa/fsl_usd.h>
#include <usdpaa/fsl_qman.h>
#include <usdpaa/fsl_bman.h>
#include <usdpaa/of.h>
#include <usdpaa/usdpaa_netcfg.h>

#include <rte_config.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include <rte_memzone.h>
#include <rte_malloc.h>
#include <rte_byteorder.h>

#include "rte_eth_dpaa.h"
#include "dpaa_logs.h"
#include "dpaa_pkt_annot.h"

#define USDPAA_ETH_AUTONEG_DUPLEX 0       /**< Auto-negotiate duplex. */
#define USDPAA_ETH_HALF_DUPLEX    1       /**< Half-duplex connection. */
#define USDPAA_ETH_FULL_DUPLEX    2       /**< Full-duplex connection. */

/* Alignment to use for cpu-local structs to avoid coherency problems. */
#define MAX_CACHELINE			64

#define NET_IF_TX_PRIORITY		3
#define NET_IF_ADMIN_PRIORITY		4

#define NET_IF_NUM_TX			1
#define NET_IF_RX_PRIORITY		4
#define NET_IF_RX_ANNOTATION_STASH	0
#define NET_IF_RX_DATA_STASH		1
#define NET_IF_RX_CONTEXT_STASH		0
#define CPU_SPIN_BACKOFF_CYCLES		512

/* Each "admin" FQ is represented by one of these */
#define ADMIN_FQ_RX_ERROR   0
#define ADMIN_FQ_RX_DEFAULT 1
#define ADMIN_FQ_TX_ERROR   2
#define ADMIN_FQ_TX_CONFIRM 3
#define ADMIN_FQ_NUM	4 /* Upper limit for loops */

/* Maximum release/acquire from BMAN */
#define DPAA_MBUF_MAX_ACQ_REL  7
struct net_if_admin {
	struct qman_fq fq;
	int idx; /* ADMIN_FQ_<x> */
};

/* Each "rx_hash" (PCD) FQ is represented by one of these */
struct net_if_rx {
	struct qman_fq fq;
	/* Each Rx FQ is "pre-mapped" to a Tx FQ. Eg. if there are 32 Rx FQs and
	 * 2 Tx FQs for each interface, then each Tx FQ will be reflecting
	 * frames from 16 Rx FQs.
	 */
	uint32_t tx_fqid;
	uint32_t ifid;
} __attribute__((aligned(MAX_CACHELINE)));

/* Each PCD FQ-range within an interface is represented by one of these */
struct net_if_rx_fqrange {
	struct net_if_rx *rx; /* array size ::rx_count */
	unsigned int rx_count;
	struct list_head list;
};

/* Each network interface is represented by one of these */
#define NETIF_ETHER_DEV_NAME_SIZE 32
struct net_if {
	int valid;
	char name[NETIF_ETHER_DEV_NAME_SIZE];
	char mac_addr[ETH_ALEN];
	const struct fm_eth_port_cfg *cfg;
	struct qman_fq *tx_fqs; /* array size NET_IF_NUM_TX */
	struct net_if_admin admin[ADMIN_FQ_NUM];
	struct list_head rx_list; /* list of "struct net_if_rx_fqrange" */
	uint32_t ifid;
	const struct fman_if *fif;
};

struct fman_if_internal {
	struct fman_if itif;
	char node_path[PATH_MAX];
	uint64_t regs_size;
	void *ccsr_map;
	struct list_head node;
};


#define USDPAA_MAX_BPOOLS	64 /* total number of bpools on SOC */

static struct net_if *interfaces;
static struct usdpaa_netcfg_info *netcfg;

struct pool_info_entry {
	uint32_t bpid;
	uint32_t size;
	struct rte_mempool *mp;
	struct bman_pool *bp;
};

static inline int mempool_to_bpid(struct rte_mempool *mp)
{
	struct pool_info_entry *pool_info;

	pool_info = (struct pool_info_entry *)mp->hw_pool_priv;
	return pool_info->bpid;
}

__thread bool thread_portal_init;
static unsigned int num_usdpaa_ports;
static int usdpaa_init(void);
static int net_if_init(struct net_if *interface,
			const struct fm_eth_port_cfg *cfg);

static struct bman_pool* init_bpid(int bpid, uint32_t sz);
static inline void * __usdpaa_get_pktbuf(struct pool_info_entry *pool_info);
void usdpaa_send_packet(struct rte_mbuf *mbuf, struct net_if *iface,
			struct qm_fd *fd);

/* Static BPID index allocator, increments continously */
rte_atomic32_t bpid_alloc = RTE_ATOMIC64_INIT(0);
/* Define pool_table for entries USDPAA_MAX_BPOOLS+1 because
 * the atomic operations supported give only atomic_add_and_return()
 * so it causes 0th entry empty always
 * */
#define NUM_BP_POOL_ENTRIES (USDPAA_MAX_BPOOLS+1)

static struct pool_info_entry dpaa_pool_table[NUM_BP_POOL_ENTRIES];

/* Environment variable to check if polling of packets is to be
 * done on default Rx Queues */
char *def_rx_flag;

#define DPAA1_HW_ANNOTATION	256
#define DPAA1_FD_PTA_SIZE	64
#define DPAA1_HEADER_SIZE_NDATA \
	((sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM) + \
	DPAA1_FD_PTA_SIZE + DPAA1_HW_ANNOTATION)
#define DPAA1_FD_BUF_TO_MBUF(data) \
	(struct rte_mbuf *)((char *)data - DPAA1_HEADER_SIZE_NDATA)

static inline struct pool_info_entry* bpid_to_pool_info(int bpid)
{
	return &dpaa_pool_table[bpid];
}

static inline
struct pool_info_entry* mempool_to_pool_info(struct rte_mempool *mp)
{
	int i;

	return (struct pool_info_entry *) mp->hw_pool_priv;
}

static inline void  usdpaa_buf_free(struct pool_info_entry *e, uint64_t addr)
{
	struct bm_buffer buf;
	int ret;

	bm_buffer_set64(&buf, addr);
retry:
	ret = bman_release(e->bp, &buf, 1, 0);
	if (ret) {
		cpu_spin(CPU_SPIN_BACKOFF_CYCLES);
		goto retry;
	}
}

/* Drop a frame (releases buffers to Bman) */
static inline void drop_frame(const struct qm_fd *fd)
{
	struct pool_info_entry *e;
	struct bm_buffer buf;
	int ret;

	BUG_ON(fd->format != qm_fd_contig);
	bm_buffer_set64(&buf, qm_fd_addr(fd));
retry:
	e = bpid_to_pool_info(fd->bpid);
	ret = bman_release(e->bp, &buf, 1, 0);
	if (ret) {
		cpu_spin(CPU_SPIN_BACKOFF_CYCLES);
		goto retry;
	}
}

#ifdef RTE_LIBRTE_DPAA_DEBUG_DRIVER
static void display_frame(uint32_t fqid, struct qm_fd *fd)
{
	int ii;
	char *ptr;

	printf("%s::fqid %x\n", __func__, fqid);
	printf("%s::bpid %x addr %08x%08x, format %d off %d, len %d stat %x\n",
		__func__, fd->bpid, fd->addr_hi, fd->addr_lo, fd->format,
		fd->offset, fd->length20, fd->status);

	ptr = (char *) usdpaa_mem_ptov(fd->addr);
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
#define display_frame(a, b)
#endif
/* DQRR callback used by Tx FQs (used when retiring and draining) as well as
 * admin FQs ([rt]x_error, rx_default, tx_confirm). */
static enum qman_cb_dqrr_result cb_drop(struct qman_portal *qm __always_unused,
				      struct qman_fq *fq __always_unused,
				      const struct qm_dqrr_entry *dqrr)
{
	display_frame(dqrr->fqid, &dqrr->fd);
	drop_frame(&dqrr->fd);
	return qman_cb_dqrr_consume;
}

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


static inline void usdpaa_eth_packet_type(struct rte_mbuf *m)
{
	uint32_t pkt_type = 0;
	fm_prs_result_t *prs = GET_PRS_RESULT((uint8_t *)m->buf_addr, prs);

	if (L2_ETH_MAC_PRESENT(prs))
		pkt_type |= RTE_PTYPE_L2_ETHER;

	if (L3_IPV4_PRESENT(prs))
		pkt_type |= RTE_PTYPE_L3_IPV4;

	if (L3_IPV6_PRESENT(prs))
		pkt_type |= RTE_PTYPE_L3_IPV6;

	if (L3_OPT_PRESENT(prs))
		pkt_type |= RTE_PTYPE_L3_IPV4_EXT;

	if (L4_TCP_PRESENT(prs))
		pkt_type |= RTE_PTYPE_L4_TCP;

	if (L4_UDP_PRESENT(prs))
		pkt_type |= RTE_PTYPE_L4_UDP;

	if (L4_SCTP_PRESENT(prs))
		pkt_type |= RTE_PTYPE_L4_SCTP;

	m->packet_type = pkt_type;

}

/* DQRR callback for Rx FQs */
static enum qman_cb_dqrr_result cb_rx(struct qman_portal *qm __always_unused,
				      struct qman_fq *fq,
				      const struct qm_dqrr_entry *dqrr)
{
	const struct qm_fd *fd;
	struct net_if_rx *rx;
	void *ptr;
	struct rte_mbuf *usdpaa_mbuf, **p;
	struct pool_info_entry *e;
	uint32_t tmp;

	p = usdpaa_get_mbuf_slot();
	if (!p)
		return qman_cb_dqrr_defer;

	fd = &dqrr->fd;
	if (unlikely(fd->format != qm_fd_contig)) {
		printf("%s::dropping packet in sg form\n", __func__);
		usdpaa_mbuf = NULL;
		goto errret;
	}
	display_frame(dqrr->fqid, fd);

	rx = container_of(fq, struct net_if_rx, fq);
	ptr = usdpaa_mem_ptov(fd->addr);
	e = bpid_to_pool_info(fd->bpid);
	tmp = sizeof(struct rte_mbuf) + rte_pktmbuf_priv_size(e->mp);
	
	usdpaa_mbuf = (struct rte_mbuf *)((char *)ptr - tmp);
	usdpaa_mbuf->buf_addr = ptr;
	usdpaa_mbuf->data_off = fd->offset;
	if (def_rx_flag)
		usdpaa_mbuf->packet_type |= RTE_PTYPE_L3_IPV4;
	else
		usdpaa_eth_packet_type(usdpaa_mbuf);

	usdpaa_mbuf->data_len = fd->length20;
	usdpaa_mbuf->pkt_len = fd->length20;

	usdpaa_mbuf->port = rx->ifid;
	usdpaa_mbuf->nb_segs = 1;
	usdpaa_mbuf->ol_flags = 0;
	usdpaa_mbuf->next = NULL;
	rte_mbuf_refcnt_set(usdpaa_mbuf, 1);
	*p = usdpaa_mbuf;

	return qman_cb_dqrr_consume;
errret:
	usdpaa_buf_free(e, qm_fd_addr(fd));
	return qman_cb_dqrr_consume;
}

/* Helper to determine whether an admin FQ is used on the given interface */
static int net_if_admin_is_used(struct net_if *interface, int idx)
{
	if ((idx < 0) || (idx >= ADMIN_FQ_NUM))
		return 0;
	/* Offline ports don't support tx_error nor tx_confirm */
	if ((idx <= ADMIN_FQ_RX_DEFAULT) ||
			(interface->cfg->fman_if->mac_type != fman_offline))
		return 1;
	return 0;
}

/* Initialise a admin FQ ([rt]x_error, rx_default, tx_confirm). */
static int net_if_admin_init(struct net_if_admin *a, uint32_t fqid, int idx)
{
	struct qm_mcc_initfq opts;
	int ret;

	ret = qman_reserve_fqid(fqid);
	if (ret)
		return -EINVAL;
	a->idx = idx;
	if (idx == ADMIN_FQ_RX_DEFAULT)
		a->fq.cb.dqrr = cb_rx;
	else
		a->fq.cb.dqrr = cb_drop;
	ret = qman_create_fq(fqid, QMAN_FQ_FLAG_NO_ENQUEUE, &a->fq);
	if (ret)
		return ret;
	opts.we_mask = QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL;
	opts.fqd.dest.wq = NET_IF_ADMIN_PRIORITY;
	return qman_init_fq(&a->fq, 0, &opts);
}

/* Initialise a Tx FQ */
static int net_if_tx_init(struct qman_fq *fq, const struct fman_if *fif)
{
	struct qm_mcc_initfq opts;
	int ret;

	fq->cb.dqrr = cb_drop;
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
void usdpaa_buf_release(uint32_t bpid, uint64_t addr)
{
	struct pool_info_entry *e;

	e = bpid_to_pool_info(bpid);
	usdpaa_buf_free(e, addr);
}

int hw_mbuf_create_pool(struct rte_mempool *mp)
{
	int i;
	uint32_t bpid;
	struct bman_pool *bp;


	/*XXX: bpid_alloc needs to be changed to a bitmap, so that
	 * we can take care of destroy_pool kind of API too. Current
	 * implementation doesn't allow deallocation of entry
	 */
	bpid = rte_atomic32_add_return(&bpid_alloc, 1);

	if (bpid > NUM_BP_POOL_ENTRIES)
		return -2;

	bp = init_bpid(bpid, mp->elt_size);
	if (!bp)
		return -2;

	dpaa_pool_table[bpid].mp = mp;
	dpaa_pool_table[bpid].bpid = bpid;
	dpaa_pool_table[bpid].size = mp->elt_size;
	dpaa_pool_table[bpid].bp = bp;
	mp->hw_pool_priv = (void *) &dpaa_pool_table[bpid];

	/* populate the pool to the fman interfaces */
	for (i = 0; i < netcfg->num_ethports; i++) {
		struct fm_eth_port_cfg *pcfg;
		const struct fman_if *fif;

		pcfg = &netcfg->port_cfg[i];
		fif = pcfg->fman_if;
		fman_if_set_bp(fif, mp->size, bpid, mp->elt_size);
		interfaces[i].valid = 1;
	}

	return 0;
}

/* hw generated buffer layout:
 *
 *   [struct rte_mbuf][priv_size][HW_ANNOTATION][FD_OFFSET][HEADROOM][DATA]
 */
int hw_mbuf_init(struct rte_mempool *mp, void *_m)
{
	int ret;
	struct pool_info_entry *e;
	struct rte_mbuf *m = _m;
	uint32_t buf_len, mbuf_desc_size, head_room;
	uint32_t sz, bpid;
	struct bm_buffer bufs;

	if (!netcfg) {
		PMD_DRV_LOG(WARNING, "DPAA buffer pool not configured\n");
		return -1;
	}

	memset(m, 0, mp->elt_size);

	head_room = RTE_PKTMBUF_HEADROOM + DPAA1_FD_PTA_SIZE +
			DPAA1_HW_ANNOTATION;

	buf_len = head_room + rte_pktmbuf_data_room_size(mp);
	mbuf_desc_size = sizeof(struct rte_mbuf) + rte_pktmbuf_priv_size(mp);

	m->buf_addr = (char *)_m + mbuf_desc_size; /*ptr points to fd->offset and packet*/
	m->buf_physaddr = rte_mempool_virt2phy(mp, m) + mbuf_desc_size;
	bm_buffer_set64(&bufs, m->buf_physaddr);

#ifdef RTE_LIBRTE_DPAA_DEBUG_DRIVER
	printf("%s::released buffer : Physical address = %p\t"
		"Virtual Address = %p into pool %p\n", __func__,
		m->buf_physaddr, m->buf_addr, mp);
#endif
	e = mempool_to_pool_info(mp);
	do {
		ret = bman_release(e->bp, &bufs, 1, 0);
	} while (ret == -EBUSY);

	/* start of buffer is after mbuf structure and priv data */
	m->priv_size = rte_pktmbuf_priv_size(mp);
	m->buf_len = buf_len;

	m->packet_type |= RTE_PTYPE_L3_IPV4; //todo - this should be set rx packet.
	m->data_len = rte_pktmbuf_data_room_size(mp);
	m->pkt_len = rte_pktmbuf_data_room_size(mp);
	m->data_off = head_room;

	m->pool = mp;
	m->nb_segs = 1;
	m->port = 0xff;

	return 0;
}

int hw_mbuf_alloc_bulk(struct rte_mempool *pool,
			void **obj_table,
			unsigned count)
{
	void *bufaddr;
	int bpid, ret;
	unsigned ii, i = 0, n = 0;
	struct rte_mbuf **m = (struct rte_mbuf **)obj_table;
	int32_t priv_size;
	struct bm_buffer bufs[64];
	struct pool_info_entry *pool_info;

	if (!thread_portal_init) {
		ret = usdpaa_portal_init((void *)0);
		if (ret) {
			printf("Failure in affining portal\n");
			return 0;
		}
	}

	if (!netcfg) {
		PMD_DRV_LOG(WARNING, "DPAA2 buffer pool not configured\n");
		return -2;
	}

	pool_info = mempool_to_pool_info(pool);

	if (count < DPAA_MBUF_MAX_ACQ_REL) {
		ret = bman_acquire(pool_info->bp,
					&bufs[n], count, 0);
		if (ret <= 0) {
			PMD_DRV_LOG(WARNING,"Failed to allocate buffers %d", ret);
			return -1;
		}
		n = ret;
		goto set_buf;
	}

	while (n < count) {
		ret = 0;
		/* Acquire is all-or-nothing, so we drain in 7s,
		 * then in 1s for the remainder. */
		if ((count - n) > DPAA_MBUF_MAX_ACQ_REL) {
			ret = bman_acquire(pool_info->bp,
				&bufs[n], DPAA_MBUF_MAX_ACQ_REL, 0);
			if (ret == DPAA_MBUF_MAX_ACQ_REL) {
				n += ret;
			}
		}
		if (ret < DPAA_MBUF_MAX_ACQ_REL) {
			ret = bman_acquire(pool_info->bp,
				&bufs[n], 1, 0);
			if (ret > 0) {
				PMD_DRV_LOG(DEBUG, "Drained buffer: %x",
					bufs[n]);
				n += ret;
			}
		}
		if (ret < 0) {
			PMD_DRV_LOG(WARNING, "Buffer aquire failed with"
				"err code: %d", ret);
			break;
		}
	}
	if (ret < 0 || n == 0) {
		PMD_DRV_LOG(WARNING,"Failed to allocate buffers %d", ret);
		return -1;
	}
set_buf:
	while (i < count) {
		bufaddr = (void *)usdpaa_mem_ptov(bufs[i].addr);
		priv_size = sizeof(struct rte_mbuf) +
				rte_pktmbuf_priv_size(pool);
		m[i] = (struct rte_mbuf *)((char *)bufaddr - priv_size);
		RTE_MBUF_ASSERT(rte_mbuf_refcnt_read(m[i]) == 0);
		rte_mbuf_refcnt_set(m[i], 1);
		i = i + 1;
	}
	return 0;
}

int hw_mbuf_free_bulk(struct rte_mempool *mp,
			void *const *obj_table,
			unsigned n)
{
	struct rte_mbuf **mb = (struct rte_mbuf **)obj_table;
	struct pool_info_entry *e;
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
		e = mempool_to_pool_info(mb[i]->pool);
		usdpaa_buf_free(e, mb[i]->buf_physaddr);
		i = i + 1;
	}

	return 0;
}

/* Initialise an Rx FQ */
static int net_if_rx_init(struct net_if *interface,
			  struct net_if_rx_fqrange *fqrange,
			  int offset, int overall,
			  uint32_t fqid)
{
	struct net_if_rx *rx = &fqrange->rx[offset];
	struct qm_mcc_initfq opts;
	int ret;

	ret = qman_reserve_fqid(fqid);
	if (ret) {
		printf("%s::reserve rx fqid %d for ifid %d failed\n", __func__,
			fqid, rx->ifid);
		return -EINVAL;
	}
	/* "map" this Rx FQ to one of the interfaces Tx FQID */
	rx->tx_fqid = interface->tx_fqs[overall % NET_IF_NUM_TX].fqid;
	rx->fq.cb.dqrr = cb_rx;
	rx->ifid = interface->ifid;
	PMD_DRV_LOG(DEBUG, "%s::creating rx fq %p, fqid %d for ifid %d\n", __func__,
			&rx->fq, fqid, rx->ifid);
	ret = qman_create_fq(fqid, QMAN_FQ_FLAG_NO_ENQUEUE, &rx->fq);
	if (ret) {
		printf("%s::create rx fqid %d for ifid %d failed\n", __func__,
			fqid, rx->ifid);
		return ret;
	}
	opts.we_mask = QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL |
		       QM_INITFQ_WE_CONTEXTA;
#ifdef RTE_LIBRTE_DPAA_DEBUG_DRIVER
	printf("%s::fqid %x, wq %d ifid %d\n", __func__, fqid,
			NET_IF_RX_PRIORITY, interface->ifid);
#endif
	opts.fqd.dest.wq = NET_IF_RX_PRIORITY;
	opts.fqd.fq_ctrl = QM_FQCTRL_AVOIDBLOCK | QM_FQCTRL_CTXASTASHING |
			   QM_FQCTRL_PREFERINCACHE;
	opts.fqd.context_a.stashing.exclusive = 0;
	opts.fqd.context_a.stashing.annotation_cl = NET_IF_RX_ANNOTATION_STASH;
	opts.fqd.context_a.stashing.data_cl = NET_IF_RX_DATA_STASH;
	opts.fqd.context_a.stashing.context_cl = NET_IF_RX_CONTEXT_STASH;
	ret = qman_init_fq(&rx->fq, 0, &opts);
	if (ret)
		printf("%s::init rx fqid %d for ifid %d failed %d\n", __func__,
			fqid, rx->ifid, ret);
	return ret;
}

/* Initialise a network interface */
static int net_if_init(struct net_if *interface,
		       const struct fm_eth_port_cfg *cfg)
{
	const struct fman_if *fif = cfg->fman_if;
	struct fm_eth_port_fqrange *fq_range;
	int ret, loop;

	interface->cfg = cfg;
	/* give the interface a name */
	sprintf(&interface->name[0], "fm%d-gb%d", (cfg->fman_if->fman_idx + 1),
				cfg->fman_if->mac_idx);

	/* get the mac address */
	memcpy(&interface->mac_addr, &cfg->fman_if->mac_addr.ether_addr_octet,
		ETH_ALEN);

	printf("%s::interface %s macaddr::", __func__, interface->name);
	for (loop = 0; loop < ETH_ALEN; loop++) {
		if (loop != (ETH_ALEN - 1))
			printf("%02x:", interface->mac_addr[loop]);
		else
			printf("%02x\n", interface->mac_addr[loop]);
	}
	/* Initialise Tx FQs */
	interface->tx_fqs = calloc(NET_IF_NUM_TX, sizeof(interface->tx_fqs[0]));
	if (!interface->tx_fqs)
		return -ENOMEM;
	for (loop = 0; loop < NET_IF_NUM_TX; loop++) {
		ret = net_if_tx_init(&interface->tx_fqs[loop], fif);
		if (ret)
			return ret;
	PMD_DRV_LOG(DEBUG, "%s::tx_fqid %x\n", __func__, interface->tx_fqs[loop].fqid);
	}

	/* Initialise admin FQs */
	if (!ret && net_if_admin_is_used(interface, ADMIN_FQ_RX_ERROR))
		ret = net_if_admin_init(&interface->admin[ADMIN_FQ_RX_ERROR],
					fif->fqid_rx_err,
					ADMIN_FQ_RX_ERROR);
	if (!ret && net_if_admin_is_used(interface, ADMIN_FQ_RX_DEFAULT))
		ret = net_if_admin_init(&interface->admin[ADMIN_FQ_RX_DEFAULT],
					cfg->rx_def,
					ADMIN_FQ_RX_DEFAULT);
	if (!ret && net_if_admin_is_used(interface, ADMIN_FQ_TX_ERROR))
		ret = net_if_admin_init(&interface->admin[ADMIN_FQ_TX_ERROR],
					fif->fqid_tx_err,
					ADMIN_FQ_TX_ERROR);
	if (!ret && net_if_admin_is_used(interface, ADMIN_FQ_TX_CONFIRM))
		ret = net_if_admin_init(&interface->admin[ADMIN_FQ_TX_CONFIRM],
					fif->fqid_tx_confirm,
					ADMIN_FQ_TX_CONFIRM);
	if (ret) {
		printf("%s::admin create FQ failed\n", __func__);
		return ret;
	}

	/* Initialise each Rx FQ-range for the interface */
	INIT_LIST_HEAD(&interface->rx_list);
	loop = 0;
	list_for_each_entry(fq_range, cfg->list, list) {
		unsigned int tmp;
		struct net_if_rx_fqrange *newrange;

		newrange = rte_malloc(NULL, sizeof(*newrange), MAX_CACHELINE);
		if (!newrange)
			return -ENOMEM;

		newrange->rx_count = fq_range->count;
		tmp = newrange->rx_count * sizeof(newrange->rx[0]);
		newrange->rx = rte_zmalloc(NULL, tmp, MAX_CACHELINE);
		if (!newrange->rx)
			return -ENOMEM;
		/* Initialise each Rx FQ within the range */
		for (tmp = 0; tmp < fq_range->count; tmp++, loop++) {
			ret = net_if_rx_init(interface, newrange, tmp, loop,
					     fq_range->start + tmp);
			if (ret) {
				printf("%s::net_if_rx_init failed for %d\n",
					__func__, fq_range->start);
				return ret;
			}
		}
		/* Range initialised, at it to the interface's rx-list */
		list_add_tail(&newrange->list, &interface->rx_list);
	}
	/* save fif in the interface struture */
	interface->fif = fif;
	PMD_DRV_LOG(DEBUG, "%s::all rxfqs created\n", __func__);

	/* Disable RX, disable promiscous mode */
	fman_if_disable_rx(fif);
	fman_if_promiscuous_disable(fif);
	return 0;
}

void usdpaa_set_promisc_mode(uint32_t port_id, uint32_t op)
{
	struct net_if *net_if;

	net_if = &interfaces[port_id];
	if (op == ENABLE_OP)
		fman_if_promiscuous_enable(net_if->fif);
	else
		fman_if_promiscuous_disable(net_if->fif);
}


void usdpaa_port_control(uint32_t port_id, uint32_t op)
{
	struct net_if *net_if;

	net_if = &interfaces[port_id];
	if (op == ENABLE_OP)
		fman_if_enable_rx(net_if->fif);
	else
		fman_if_disable_rx(net_if->fif);

}

void usdpaa_get_iface_link(uint32_t port_id, struct usdpaa_eth_link *link)
{
	struct net_if *net_if =  &interfaces[port_id];

	if (net_if->fif->mac_type == fman_mac_1g)
		link->link_speed = 1000;
	else if (net_if->fif->mac_type == fman_mac_10g)
		link->link_speed = 10000;
	else
		printf("%s:: invalid link_speed %d\n", net_if->name, net_if->fif->mac_type);

	link->link_status = net_if->valid;
	link->link_duplex = USDPAA_ETH_FULL_DUPLEX;
}

static inline void usdpaa_memac_status(struct memac_regs *regs,
				       struct usdpaa_eth_stats *stats)
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
				       struct usdpaa_eth_stats *stats)
{
	stats->ipackets = in_be32(&regs->rpkt);
	stats->ibytes = in_be32(&regs->rbyt);
	stats->ierrors = in_be32(&regs->rdrp);
	stats->opackets = in_be32(&regs->tpkt);
	stats->obytes = in_be32(&regs->tbyt);
	stats->oerrors = in_be32(&regs->tdrp);
}

void usdpaa_get_iface_stats(uint32_t port_id, struct usdpaa_eth_stats *stats)
{
	struct net_if *net_if = &interfaces[port_id];
	struct fman_if_internal *itif;
	void* regs;

	itif = container_of(net_if->fif, struct fman_if_internal, itif);
	regs = itif->ccsr_map;

	if (net_if->fif->is_memac)
		usdpaa_memac_status(regs, stats);
	else
		usdpaa_dtsec_status(regs, stats);
}

static struct bman_pool* init_bpid(int bpid, uint32_t sz)
{
	struct bm_buffer bufs[8];
	struct bman_pool *bp = NULL;
	unsigned int num_bufs = 0;
	int ret = 0;

#ifdef RTE_LIBRTE_DPAA_DEBUG_DRIVER
	printf("request bman pool: bpid %d, size %d\n", bpid, sz);
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
		int bp_idx = 0;
		int ret;

		pcfg = &netcfg->port_cfg[loop];
		interfaces[loop].ifid = loop;

		ret = net_if_init(&interfaces[loop], pcfg);
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
	def_rx_flag = getenv("DPAA_DEF_RX");

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
	interfaces = calloc(netcfg->num_ethports, sizeof(*interfaces));
	if (!interfaces)
		return -ENOMEM;

	for (ii = 0; ii < netcfg->num_ethports; ii++) {
		struct fm_eth_port_cfg *cfg;
		struct fman_if *fman_if;

		cfg = &netcfg->port_cfg[ii];
		fman_if = cfg->fman_if;
		sprintf(&interfaces->name[0], "fm%d-gb%d",
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
void usdpaa_set_rx_queues(uint32_t portid, uint32_t queue_id,
		void **rx_queues)
{
	struct net_if *iface = &interfaces[portid];
	struct net_if_rx_fqrange *fqrange;

	if (def_rx_flag) {
		rx_queues[0] = &(iface->admin[ADMIN_FQ_RX_DEFAULT].fq);
		return 0;
	}
	list_for_each_entry(fqrange, &(iface->rx_list), list) {
		rx_queues[0] = &(fqrange->rx[queue_id].fq);
		break;
	}
	return 0;
}

unsigned usdpaa_volatile_deq(struct qman_fq *fq, unsigned len, bool exact)
{
	unsigned pkts = 0;
	int ret;
	struct qm_mcr_queryfq_np np;
	enum qman_fq_state state;
	uint32_t flags;
	uint32_t vdqcr;

	qman_query_fq_np(fq, &np);
	if (np.frm_cnt) {
		vdqcr = QM_VDQCR_NUMFRAMES_SET(len);
		if (exact)
			vdqcr |= QM_VDQCR_EXACT;
		ret = qman_volatile_dequeue(fq, 0, vdqcr);
		if (ret)
			return 0;
		do {
			pkts += qman_poll_dqrr(len);
			qman_fq_state(fq, &state, &flags);
		} while (flags & QMAN_FQ_STATE_VDQCR);
	}
	return pkts;
}

static inline void * __usdpaa_get_pktbuf(struct pool_info_entry *pool_info)
{
	uint32_t ii;
	struct bm_buffer bufs;

	bman_acquire(pool_info->bp, &bufs, 1, 0);

#ifdef RTE_LIBRTE_DPAA_DEBUG_DRIVER
	printf("%s::located pool sz %d , bpid %d\n", __func__,
		dpaa_pool_table[ii].size, bufs.bpid);
	printf("%s::got buffer 0x%llx from pool %d\n", __func__,
		bufs.addr, bufs.bpid);
#endif
	return ((void *)usdpaa_mem_ptov(bufs.addr));

}

void *usdpaa_get_pktbuf(uint32_t size, uint32_t *bpid)
{
	uint32_t ii;
	struct pool_info_entry *pool_info = NULL;
	void *buf = NULL;

	for (ii = 0; ii < USDPAA_MAX_BPOOLS; ii++) {
		if (size <= dpaa_pool_table[ii].size) {
			pool_info = &dpaa_pool_table[ii];
			break;
		}
	}

	if (!pool_info)
		return NULL;

	buf = (void *)__usdpaa_get_pktbuf(pool_info);
	if (!buf)
		goto out;

	*bpid = pool_info->bpid;

out:
	return buf;
}

struct net_if *portid_to_iface(uint32_t portid)
{

	return &interfaces[portid];
}

uint16_t usdpaa_eth_ring_tx(void *q,
				   struct rte_mbuf **bufs,
				   uint16_t nb_bufs)
{
	int ii, ret;
	struct dpaaeth_txq *txq = q;
	struct qm_fd fd;
	struct net_if *iface;

	iface = portid_to_iface(txq->port_id);
	memset(&fd, 0, sizeof(struct qm_fd));
	fd.format = QM_FD_CONTIG;

	for (ii = 0; ii < nb_bufs; ii++) {
		usdpaa_send_packet(bufs[ii], iface, &fd);
	}

	return ii;
}

/* usdpaa transmit function */
void usdpaa_send_packet(struct rte_mbuf *mbuf, struct net_if *iface,
			struct qm_fd *fd)
{
	int ret;
	struct rte_mbuf *usdpaa_pktbuf;
	struct rte_mempool *mp;
	static int retry_cnt = 0;


	mp = mbuf->pool;
	if (mp && (mp->flags & MEMPOOL_F_HW_PKT_POOL)) {
		struct pool_info_entry *e;

		e = mempool_to_pool_info(mbuf->pool);
		fd->addr = mbuf->buf_physaddr;
		fd->offset = mbuf->data_off;
		fd->bpid = e->bpid;
		fd->length20 = mbuf->pkt_len;
	} else {
		uint32_t bpid;
		/* allocate pktbuffer on bpid for usdpaa port */
		usdpaa_pktbuf = usdpaa_get_pktbuf(mbuf->pkt_len, &bpid);
		if (unlikely(!usdpaa_pktbuf)) {
			printf("%s::no usdpaa buffers\n", __func__);
			rte_pktmbuf_free(mbuf);
			return;
		}
		memcpy(usdpaa_pktbuf->buf_addr + mbuf->data_off,
			(void *)(mbuf->buf_addr + mbuf->data_off),
			mbuf->pkt_len);

		fd->addr = rte_mempool_virt2phy(mp, usdpaa_pktbuf->buf_addr);
		fd->bpid = bpid;
		fd->offset = mbuf->data_off;
		fd->length20 = mbuf->pkt_len;
		rte_pktmbuf_free(mbuf);
	}
	display_frame((iface->tx_fqs)->fqid, fd);
retry:
#ifdef RTE_LIBRTE_DPAA_DEBUG_DRIVER
	printf("%s::Enqueing packet %p bufaddr %llx  to fqid %x\n",
		__func__, mbuf, fd.addr, (iface->tx_fqs)->fqid);
#endif
	ret = qman_enqueue(iface->tx_fqs, fd, 0);
	if (ret) {
		cpu_spin(CPU_SPIN_BACKOFF_CYCLES);
		if (retry_cnt == 10) {
			printf("\n");
			retry_cnt = 0;
		} else {
			printf("*");
			retry_cnt++;
		}
		goto retry;
	}
}

char *usdpaa_get_iface_macaddr(uint32_t portid)
{
	struct net_if *iface;

	iface = &interfaces[portid];

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
