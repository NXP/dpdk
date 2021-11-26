/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2021 NXP
 */

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
#include <rte_string_fns.h>
#include <rte_errno.h>
#include <rte_lsx_pciep_bus.h>

#include "lsxinic_ep_tool.h"
#include "lsxinic_common_pmd.h"
#include "lsxinic_common.h"
#include "lsxinic_common_reg.h"
#include "lsxinic_ep_ethdev.h"
#include "lsxinic_ep_rxtx.h"
#include "lsxinic_common_helper.h"
#include "lsxinic_ep_dma.h"
#include <dpaa2_hw_pvt.h>
#include <rte_pmd_dpaa2_qdma.h>

#include <fsl_qbman_portal.h>
#include <portal/dpaa2_hw_dpio.h>
#include <dpaa2_hw_mempool.h>
#include <dpaa2_ethdev.h>

#include "base/dpaa2_hw_dpni_annot.h"

/* Default RS bit threshold values */
#ifndef DEFAULT_TX_RS_THRESH
#define DEFAULT_TX_RS_THRESH   32
#endif
#ifndef DEFAULT_TX_FREE_THRESH
#define DEFAULT_TX_FREE_THRESH 32
#endif

#define NIC_RX_BUFFER_SIZE 0x200

/* Rings setup and release.
 *
 * TDBA/RDBA should be aligned on 16 byte boundary. But TDLEN/RDLEN should be
 * multiple of 128 bytes. So we align TDBA/RDBA on 128 byte boundary. This will
 * also optimize cache line size effect. H/W supports up to cache line size 128.
 */
#define LSINIC_ALIGN 128

/* Maximum number of Ring Descriptors.
 *
 * Since RDLEN/TDLEN should be multiple of 128 bytes, the number of ring
 * descriptors should meet the following condition:
 *      (num_ring_desc * sizeof(rx/tx descriptor)) % 128 == 0
 */
#define LSINIC_MIN_RING_DESC 64
#define LSINIC_MAX_RING_DESC 1024

/* TX queues list */
TAILQ_HEAD(lsinic_tx_queue_list, lsinic_queue);

/* per thread TX queue list */
RTE_DEFINE_PER_LCORE(uint8_t, lsinic_txq_list_initialized);
RTE_DEFINE_PER_LCORE(uint8_t, lsinic_txq_deqeue_from_rxq);
RTE_DEFINE_PER_LCORE(uint8_t, lsinic_txq_num_in_list);
RTE_DEFINE_PER_LCORE(struct lsinic_tx_queue_list, lsinic_txq_list);

struct lsinic_recycle_dev {
	TAILQ_ENTRY(lsinic_recycle_dev) next;
	struct rte_eth_dev *recycle_dev;
	int used;
};

TAILQ_HEAD(lsinic_recycle_dev_list, lsinic_recycle_dev);

static struct lsinic_recycle_dev_list recycle_dev_list = \
	TAILQ_HEAD_INITIALIZER(recycle_dev_list);

static rte_spinlock_t recycle_dev_list_lock = \
	RTE_SPINLOCK_INITIALIZER;

static int
lsinic_queue_start(struct lsinic_queue *q);

static inline int
lsinic_tx_bd_available(struct lsinic_queue *txq,
	uint16_t bd_idx);

static bool
lsinic_timeout(struct lsinic_queue *q)
{
	uint64_t timer_period;

	if (!q->new_time_thresh)
		return false;
	timer_period = rte_rdtsc() - q->new_tsc;
	if (timer_period >= q->new_time_thresh)
		return true;
	else
		return false;
}

static bool
lsinic_queue_running(struct lsinic_queue *q)
{
	return q->status == LSINIC_QUEUE_RUNNING;
}

static bool
lsinic_queue_msi_masked(struct lsinic_queue *q)
{
	struct lsinic_rcs_reg *rcs_reg =
		LSINIC_REG_OFFSET(q->adapter->hw_addr, LSINIC_RCS_REG_OFFSET);

	return rcs_reg->msix_mask[q->msix_irq];
}

static inline void lsinic_mbuf_reset(struct rte_mbuf *m)
{
	struct rte_mempool *mp = m->pool;
	uint32_t mbuf_size, buf_len;
	uint16_t priv_size;

	priv_size = rte_pktmbuf_priv_size(mp);
	mbuf_size = (uint32_t)(sizeof(struct rte_mbuf) + priv_size);
	buf_len = rte_pktmbuf_data_room_size(mp);

	m->priv_size = priv_size;
	m->buf_addr = (char *)m + mbuf_size;
	m->buf_iova = rte_mempool_virt2iova(m) + mbuf_size;
	m->buf_len = (uint16_t)buf_len;
	rte_pktmbuf_reset_headroom(m);
	m->data_len = 0;
	m->ol_flags = 0;
}

static __rte_always_inline void
lsinic_bd_dma_start_update(struct lsinic_queue *queue,
	uint16_t used_idx)
{
#ifdef LSINIC_BD_CTX_IDX_USED
	queue->ep_bd_desc[used_idx].bd_status &=
		~((uint32_t)RING_BD_STATUS_MASK);
	queue->ep_bd_desc[used_idx].bd_status |=
		RING_BD_HW_PROCESSING;
#else
	queue->ep_bd_desc[used_idx].bd_status =
		RING_BD_HW_PROCESSING;
#endif
}

static void
lsinic_queue_dma_release(struct lsinic_queue *q)
{
	uint32_t i;

	if (q->qdma_pool) {
		for (i = 0; i < q->nb_desc; i++) {
			if (q->dma_jobs[i].usr_elem)
				rte_mempool_put(q->qdma_pool,
					q->dma_jobs[i].usr_elem);
			if (q->e2r_bd_dma_jobs[i].usr_elem)
				rte_mempool_put(q->qdma_pool,
					q->e2r_bd_dma_jobs[i].usr_elem);
			if (q->r2e_bd_dma_jobs[i].usr_elem)
				rte_mempool_put(q->qdma_pool,
					q->r2e_bd_dma_jobs[i].usr_elem);
		}
		rte_mempool_free(q->qdma_pool);
		q->qdma_pool = NULL;
	}

	if (q->dma_vq >= 0)
		rte_rawdev_queue_release(q->dma_id, q->dma_vq);
}

static int
lsinic_queue_dma_create(struct lsinic_queue *q)
{
	uint32_t lcore_id = rte_lcore_id(), i, sg_enable = 0;
	int pcie_id = q->adapter->pcie_idx;
	int pf_id = q->adapter->pf_idx;
	int is_vf = q->adapter->is_vf;
	int vf_id = q->adapter->vf_idx;
	uint32_t vq_flags = RTE_QDMA_VQ_EXCLUSIVE_PQ;
	struct lsinic_dev_reg *cfg =
		LSINIC_REG_OFFSET(q->adapter->hw_addr, LSINIC_DEV_REG_OFFSET);
	enum PEX_TYPE pex_type = lsx_pciep_type_get(pcie_id);
	char *penv;
	int sim = lsx_pciep_hw_sim_get(pcie_id);

	if (q->dma_vq >= 0)
		return 0;

	q->wdma_bd_start = -1;

	penv = getenv("LSINIC_QDMA_SG_ENABLE");
	if (penv)
		sg_enable = atoi(penv);

	if (cfg->rbp_enable && sg_enable) {
		if (pex_type != PEX_LX2160_REV2 &&
			pex_type != PEX_LS208X) {
			LSXINIC_PMD_WARN("RBP does not support qDMA SG");
			sg_enable = 0;
		}
	}
	if (cfg->rbp_enable && q->type == LSINIC_QUEUE_TX &&
		q->adapter->ep_cap & LSINIC_EP_CAP_TXQ_DMA_NO_RSP) {
		if (pex_type != PEX_LX2160_REV2 &&
			pex_type != PEX_LS208X) {
			LSXINIC_PMD_WARN("TXQ qDMA no response depends on SG,"
				" which is not supported with RBP");
			q->adapter->ep_cap &=
				(~(uint32_t)LSINIC_EP_CAP_TXQ_DMA_NO_RSP);
		}
	}

	if (sg_enable)
		vq_flags |= RTE_QDMA_VQ_FD_LONG_FORMAT |
					RTE_QDMA_VQ_FD_SG_FORMAT;

	if ((q->adapter->ep_cap & LSINIC_EP_CAP_TXQ_DMA_NO_RSP &&
		q->type == LSINIC_QUEUE_TX) ||
		(q->adapter->cap & LSINIC_CAP_XFER_COMPLETE &&
		q->type == LSINIC_QUEUE_RX)) {
		vq_flags |=
			(RTE_QDMA_VQ_FD_LONG_FORMAT |
			RTE_QDMA_VQ_FD_SG_FORMAT |
			RTE_QDMA_VQ_NO_RESPONSE);
	}

	/* Avoid memory address conflicting with PCIe base in short format.*/
	if (pex_type == PEX_LS208X || sim)
		vq_flags |= RTE_QDMA_VQ_FD_LONG_FORMAT;

	if (q->dma_vq >= 0) {
		if (q->core_id == lcore_id)
			return 0;

		rte_rawdev_queue_release(q->dma_id, q->dma_vq);
	}

	q->core_id = lcore_id;

	memset(&q->rbp, 0, sizeof(struct rte_qdma_rbp));

	q->qdma_config.lcore_id = lcore_id;
	q->qdma_config.flags = 0;

	if (cfg->rbp_enable) {
		q->rbp.enable = 1;
		if (vq_flags & RTE_QDMA_VQ_FD_LONG_FORMAT)
			q->rbp.use_ultrashort = 0;
		else
			q->rbp.use_ultrashort = 1;

		if (q->type == LSINIC_QUEUE_RX) {
			q->rbp.srbp = 1;
			q->rbp.sportid = pcie_id;
			q->rbp.spfid = pf_id;
			if (is_vf) {
				q->rbp.svfid = vf_id;
				q->rbp.svfa = 1;
			} else {
				q->rbp.svfa = 0;
			}
			q->rbp.drbp = 0;
		} else {
			q->rbp.drbp = 1;
			q->rbp.dportid = pcie_id;
			q->rbp.dpfid = pf_id;
			if (is_vf) {
				q->rbp.dvfid = vf_id;
				q->rbp.dvfa = 1;
			} else {
				q->rbp.dvfa = 0;
			}
			q->rbp.srbp = 0;
		}
		q->qdma_config.flags = vq_flags;
		q->qdma_config.rbp = &q->rbp;
		q->dma_vq = rte_qdma_queue_setup(q->dma_id,
						-1, &q->qdma_config);
	} else {
		q->qdma_config.flags = vq_flags;
		q->qdma_config.rbp = NULL;
		q->dma_vq = rte_qdma_queue_setup(q->dma_id,
						-1, &q->qdma_config);
	}
	LSXINIC_PMD_DBG("lcore_id=%d dma_vq=%d rbp=%d",
		     lcore_id, q->dma_vq, q->rbp.enable);
	if (q->dma_vq < 0)
		LSXINIC_PMD_ERR("Failed to create DMA");

	if (q->dma_vq >= 0) {
		char qdma_pool_name[32];

		/* Only used for qdma no response.*/
		if (is_vf) {
			sprintf(qdma_pool_name, "pool_%d:pf%d_vf%d_%d_%d",
				pcie_id, pf_id, vf_id,
				q->type, q->queue_id);
		} else {
			sprintf(qdma_pool_name, "pool_%d:pf%d_%d_%d",
				pcie_id, pf_id,
				q->type, q->queue_id);
		}
		q->qdma_pool = rte_mempool_create(qdma_pool_name,
			3 * q->nb_desc, 4096, q->nb_desc / 4, 0,
			NULL, NULL, NULL, NULL, SOCKET_ID_ANY, 0);
		if (!q->qdma_pool) {
			LSXINIC_PMD_ERR("qdma_pool:%s create failed!",
				qdma_pool_name);

			return -1;
		}
		for (i = 0; i < q->nb_desc; i++) {
			q->dma_jobs[i].usr_elem = NULL;
			q->e2r_bd_dma_jobs[i].usr_elem = NULL;
			q->r2e_bd_dma_jobs[i].usr_elem = NULL;
			rte_mempool_get(q->qdma_pool,
				&q->dma_jobs[i].usr_elem);
			rte_mempool_get(q->qdma_pool,
				&q->e2r_bd_dma_jobs[i].usr_elem);
			rte_mempool_get(q->qdma_pool,
				&q->r2e_bd_dma_jobs[i].usr_elem);
			if (!q->dma_jobs[i].usr_elem ||
				!q->e2r_bd_dma_jobs[i].usr_elem ||
				!q->r2e_bd_dma_jobs[i].usr_elem) {
				rte_rawdev_queue_release(q->dma_id, q->dma_vq);
				q->dma_vq = -1;

				LSXINIC_PMD_ERR("User elem of qdma job alloc failed!");

				return -1;
			}
		}
	}

	return q->dma_vq;
}

static uint16_t
lsinic_queue_dma_clean(struct lsinic_queue *q)
{
	struct rte_qdma_job *jobs[LSINIC_QDMA_DQ_MAX_NB];
	int ret = 0;
	struct rte_qdma_enqdeq context;

	context.vq_id = q->dma_vq;
	context.job = jobs;

	if (q->pkts_eq == q->pkts_dq ||
		(q->type == LSINIC_QUEUE_TX &&
		q->adapter->ep_cap & LSINIC_EP_CAP_TXQ_DMA_NO_RSP) ||
		(q->type == LSINIC_QUEUE_RX &&
		q->adapter->cap & LSINIC_CAP_XFER_COMPLETE))
		return 0;

	ret = rte_qdma_dequeue_buffers(q->dma_id, NULL,
					LSINIC_QDMA_DQ_MAX_NB, &context);

	q->pkts_dq += ret;

	if (q->pkts_eq != q->pkts_dq) {
		LSXINIC_PMD_WARN("port%d %sq%d %ld pkts in dma",
			q->port_id,
			q->type == LSINIC_QUEUE_TX ? "tx" : "rx",
			q->reg_idx, q->pkts_eq - q->pkts_dq);
	}

	return (uint16_t)(q->pkts_eq - q->pkts_dq);
}

/* (Re)set dynamic lsinic queue fields to defaults */
void
lsinic_queue_reset(struct lsinic_queue *q)
{
	struct lsinic_sw_bd *xe = q->sw_ring;
	struct rte_qdma_job *dma_jobs = q->dma_jobs;
	uint32_t i;

	q->ep_reg->cir = 0;
	LSINIC_WRITE_REG(&q->rc_reg->cir, 0);
	lsinic_sw_bd_reset(q);
	/* Initialize SW ring entries */
	for (i = 0; i < q->nb_desc; i++) {
		xe[i].mbuf = NULL;
		dma_jobs[i].cnxt = (uint64_t)(&xe[i]);
		dma_jobs[i].flags = RTE_QDMA_JOB_SRC_PHY |
				   RTE_QDMA_JOB_DEST_PHY;
		dma_jobs[i].vq_id = q->dma_vq;
	}
	lsinic_sw_bd_push_array(q, q->sw_ring, q->nb_desc);

	q->next_dma_idx = 0;
	q->next_avail_idx = 0;
	q->next_used_idx = 0;
	q->new_desc = 0;
	q->errors = 0;
	q->drop_packet_num = 0;
	q->ring_full = 0;
	q->loop_total = 0;
	q->loop_avail = 0;

	q->jobs_pending = 0;
	q->jobs_avail_idx = 0;
	q->mhead = 0;
	q->mtail = 0;
	q->mcnt = 0;
	q->sw_bd_head = 0;
	q->sw_bd_tail = 0;
	q->sw_bd_cnt = 0;
}

static inline void
lsinic_qdma_rx_multiple_enqueue(struct lsinic_queue *queue, bool append)
{
	int ret = 0;
	uint16_t nb_jobs = 0, jobs_idx, i, jobs_avail_idx;
	struct rte_qdma_job *jobs[LSINIC_QDMA_EQ_MAX_NB];
	struct rte_qdma_enqdeq e_context;
	uint16_t rxq_pir = queue->ep_reg->pir;
	uint16_t rxq_bd_dma_idx = queue->rdma_idx;
	uint16_t rxq_bd_dma_jobs = 0, max_jobs_nb;

	int txq_pir = -1;
	int txq_bd_dma_idx = -1;
	uint16_t txq_bd_dma_jobs = 0;

	struct lsinic_queue *txq = queue->pair;

	if (txq) {
		txq_pir = txq->ep_reg->pir;
		txq_bd_dma_idx = txq->rdma_idx;
	}

	/* Qdma multi-enqueue support, max enqueue 32 entries once.
	 * if there are 32 entries or time out, handle them in batch
	 */

	jobs_avail_idx = queue->jobs_avail_idx;

	if (rxq_pir == rxq_bd_dma_idx && txq_pir == txq_bd_dma_idx)
		max_jobs_nb = LSINIC_QDMA_EQ_MAX_NB;
	else if (rxq_pir != rxq_bd_dma_idx && txq_pir != txq_bd_dma_idx)
		max_jobs_nb = LSINIC_QDMA_EQ_MAX_NB - 4;
	else
		max_jobs_nb = LSINIC_QDMA_EQ_MAX_NB - 2;

	if (!append) {
		nb_jobs = queue->jobs_pending;
		if (nb_jobs > max_jobs_nb)
			nb_jobs = max_jobs_nb;
	} else {
		if (queue->jobs_pending >= max_jobs_nb)
			nb_jobs = max_jobs_nb;
	}

	if (!nb_jobs && append)
		return;

	for (i = 0; i < nb_jobs; i++, jobs_avail_idx++) {
		jobs_idx = jobs_avail_idx & (queue->nb_desc - 1);
		jobs[i] = &queue->dma_jobs[jobs_idx];
	}

	if (rxq_pir > rxq_bd_dma_idx) {
		jobs[nb_jobs] = &queue->r2e_bd_dma_jobs[rxq_bd_dma_idx];
		jobs[nb_jobs]->len = (rxq_pir - rxq_bd_dma_idx) *
					sizeof(struct lsinic_bd_desc);
		rxq_bd_dma_jobs = 1;
	} else if (rxq_pir < rxq_bd_dma_idx) {
		jobs[nb_jobs] = &queue->r2e_bd_dma_jobs[rxq_bd_dma_idx];
		jobs[nb_jobs]->len = (queue->nb_desc - rxq_bd_dma_idx) *
					sizeof(struct lsinic_bd_desc);
		rxq_bd_dma_jobs = 1;
		if (rxq_pir > 0) {
			jobs[nb_jobs + 1] = &queue->r2e_bd_dma_jobs[0];
			jobs[nb_jobs + 1]->len = rxq_pir *
					sizeof(struct lsinic_bd_desc);
			rxq_bd_dma_jobs = 2;
		}
	}

	nb_jobs += rxq_bd_dma_jobs;

	if (txq_pir > txq_bd_dma_idx) {
		jobs[nb_jobs] = &txq->r2e_bd_dma_jobs[txq_bd_dma_idx];
		jobs[nb_jobs]->len = (txq_pir - txq_bd_dma_idx) *
					sizeof(struct lsinic_bd_desc);
		txq_bd_dma_jobs = 1;
	} else if (txq_pir < txq_bd_dma_idx) {
		jobs[nb_jobs] = &txq->r2e_bd_dma_jobs[txq_bd_dma_idx];
		jobs[nb_jobs]->len = (queue->nb_desc - txq_bd_dma_idx) *
					sizeof(struct lsinic_bd_desc);
		txq_bd_dma_jobs = 1;
		if (txq_pir > 0) {
			jobs[nb_jobs + 1] = &txq->r2e_bd_dma_jobs[0];
			jobs[nb_jobs + 1]->len = txq_pir *
					sizeof(struct lsinic_bd_desc);
			txq_bd_dma_jobs = 2;
		}
	}

	nb_jobs += txq_bd_dma_jobs;

	if (!nb_jobs)
		return;

	e_context.vq_id = queue->dma_vq;
	e_context.job = jobs;
	ret = rte_qdma_enqueue_buffers(queue->dma_id, NULL, nb_jobs,
			&e_context);
	if (likely(ret > 0)) {
		queue->jobs_pending -=
			(ret - rxq_bd_dma_jobs - txq_bd_dma_jobs);
		queue->jobs_avail_idx +=
			(uint16_t)(ret - rxq_bd_dma_jobs - txq_bd_dma_jobs);
		for (i = 0; i < (ret - rxq_bd_dma_jobs - txq_bd_dma_jobs); i++)
			queue->bytes_eq += jobs[i]->len;
		queue->pkts_eq +=
			(ret - rxq_bd_dma_jobs - txq_bd_dma_jobs);
	} else {
		queue->errors++;
	}

	queue->rdma_idx = rxq_pir;
	if (txq)
		txq->rdma_idx = txq_pir;
}

static inline void
lsinic_qdma_tx_multiple_enqueue(struct lsinic_queue *queue, bool append)
{
	int ret = 0;
	uint16_t nb_jobs = 0, jobs_idx, i, jobs_avail_idx;
	struct rte_qdma_job *jobs[LSINIC_QDMA_EQ_MAX_NB];
	struct rte_qdma_enqdeq e_context;
	uint16_t txq_bd_jobs_num = 0, rxq_bd_jobs_num = 0;
	uint16_t bd_jobs_len, max_jobs_nb;
	int txq_dma_bd_start = queue->wdma_bd_start;
	int rxq_dma_bd_start = -1;
	int rxq_dma_bd_nb = 0;
	struct lsinic_queue *rxq = queue->pair;
	uint16_t rxq_bd_step = 0, txq_bd_step = queue->bd_dma_step;

	if (likely(rxq)) {
		rxq_dma_bd_start = rxq->wdma_bd_start;
		rxq_dma_bd_nb = rxq->wdma_bd_nb;
		rxq_bd_step = rxq->bd_dma_step;
	}

	if ((queue->adapter->ep_cap & LSINIC_EP_CAP_TXQ_DMA_NO_RSP) &&
		rxq_dma_bd_start >= 0) {
		/* At most 2 TX DMA bd jobs and 2 RX DMA bd jobs.*/
		max_jobs_nb = LSINIC_QDMA_EQ_MAX_NB - 4;
	} else if ((queue->adapter->ep_cap & LSINIC_EP_CAP_TXQ_DMA_NO_RSP) &&
		rxq_dma_bd_start < 0) {
		/* At most 2 TX DMA bd jobs.*/
		max_jobs_nb = LSINIC_QDMA_EQ_MAX_NB - 2;
	} else if (!(queue->adapter->ep_cap & LSINIC_EP_CAP_TXQ_DMA_NO_RSP) &&
		rxq_dma_bd_start >= 0) {
		/* At most 2 RX DMA bd jobs.*/
		max_jobs_nb = LSINIC_QDMA_EQ_MAX_NB - 2;
	} else {
		max_jobs_nb = LSINIC_QDMA_EQ_MAX_NB;
	}

	jobs_avail_idx = queue->jobs_avail_idx;

	if (!append) {
		nb_jobs = queue->jobs_pending;
		if (nb_jobs > max_jobs_nb)
			nb_jobs = max_jobs_nb;
	} else if (queue->jobs_pending >= max_jobs_nb) {
		nb_jobs = max_jobs_nb;
	}

	if (!nb_jobs && append)
		return;

	if ((queue->ep2rc_update == EP2RC_BD_DMA_UPDATE ||
		queue->ep2rc_update == EP2RC_RING_DMA_UPDATE) &&
		nb_jobs) {
		bd_jobs_len = txq_bd_step * nb_jobs;
		jobs_idx = jobs_avail_idx & (queue->nb_desc - 1);
		jobs[nb_jobs] = &queue->e2r_bd_dma_jobs[txq_dma_bd_start];
		if ((txq_dma_bd_start + nb_jobs) <= (int)queue->nb_desc) {
			txq_bd_jobs_num = 1;
			jobs[nb_jobs]->len = bd_jobs_len;
		} else {
			jobs[nb_jobs]->len = txq_bd_step *
				(queue->nb_desc - txq_dma_bd_start);
			jobs[nb_jobs + 1] =	&queue->e2r_bd_dma_jobs[0];
			jobs[nb_jobs + 1]->len =
				bd_jobs_len - jobs[nb_jobs]->len;
			txq_bd_jobs_num = 2;
		}

		for (i = 0; i < nb_jobs; i++, jobs_avail_idx++) {
			jobs_idx = jobs_avail_idx & (queue->nb_desc - 1);
			jobs[i] = &queue->dma_jobs[jobs_idx];
#ifdef LSINIC_BD_CTX_IDX_USED
			queue->ep_bd_desc[jobs_idx].bd_status &=
				~((uint32_t)RING_BD_STATUS_MASK);
			queue->ep_bd_desc[jobs_idx].bd_status |=
				RING_BD_HW_COMPLETE;
#else
			queue->ep_bd_desc[jobs_idx].bd_status =
				RING_BD_HW_COMPLETE;
#endif
		}
	} else if (nb_jobs) {
		for (i = 0; i < nb_jobs; i++, jobs_avail_idx++) {
			jobs_idx = jobs_avail_idx & (queue->nb_desc - 1);
			jobs[i] = &queue->dma_jobs[jobs_idx];
			jobs[i]->flags |= LSINIC_QDMA_JOB_USING_FLAG;
		}
	}

	nb_jobs += txq_bd_jobs_num;

	if (rxq_dma_bd_nb > 0) {
		jobs[nb_jobs] = &rxq->e2r_bd_dma_jobs[rxq_dma_bd_start];
		bd_jobs_len = rxq_bd_step * rxq_dma_bd_nb;
		if ((rxq_dma_bd_start + rxq_dma_bd_nb) <= (int)rxq->nb_desc) {
			jobs[nb_jobs]->len = bd_jobs_len;
			rxq_bd_jobs_num = 1;
		} else {
			jobs[nb_jobs]->len = rxq_bd_step *
				(rxq->nb_desc - rxq_dma_bd_start);
			jobs[nb_jobs + 1] =	&rxq->e2r_bd_dma_jobs[0];
			jobs[nb_jobs + 1]->len =
				bd_jobs_len - jobs[nb_jobs]->len;
			rxq_bd_jobs_num = 2;
		}
		nb_jobs += rxq_bd_jobs_num;
	}

	if (!nb_jobs)
		return;

	e_context.vq_id = queue->dma_vq;
	e_context.job = jobs;
	ret = rte_qdma_enqueue_buffers(queue->dma_id, NULL, nb_jobs,
			&e_context);
	if (likely(ret > 0)) {
		queue->jobs_pending -=
			(ret - rxq_bd_jobs_num - txq_bd_jobs_num);
		queue->jobs_avail_idx +=
			(ret - rxq_bd_jobs_num - txq_bd_jobs_num);
		for (i = 0; i < (ret - rxq_bd_jobs_num - txq_bd_jobs_num); i++)
			queue->bytes_eq += jobs[i]->len;
		queue->pkts_eq += (ret - rxq_bd_jobs_num - txq_bd_jobs_num);
		if (txq_bd_jobs_num) {
			queue->wdma_bd_start = -1;
			queue->wdma_bd_nb = 0;
		}
		if (rxq_bd_jobs_num) {
			rxq->wdma_bd_start = -1;
			rxq->wdma_bd_nb = 0;
		}
	} else {
		LSXINIC_PMD_ERR("LSINIC QDMA enqueue failed!");
		queue->errors++;
	}
}

static int
lsinic_add_recycle_dev_list(struct rte_eth_dev *eth_dev)
{
	struct lsinic_recycle_dev *dev = NULL;
	struct lsinic_recycle_dev *tdev = NULL;

	rte_spinlock_lock(&recycle_dev_list_lock);
	TAILQ_FOREACH_SAFE(dev, &recycle_dev_list, next, tdev) {
		if (dev->recycle_dev == eth_dev) {
			LSXINIC_PMD_WARN("Recycle dev %s has been occupied",
				eth_dev->data->name);
			rte_spinlock_unlock(&recycle_dev_list_lock);
			return -EEXIST;
		}
	}

	dev = rte_malloc(NULL, sizeof(struct lsinic_recycle_dev),
			RTE_CACHE_LINE_SIZE);
	if (!dev) {
		LSXINIC_PMD_ERR("recycle dev alloc failed");
		rte_spinlock_unlock(&recycle_dev_list_lock);
		return -ENOMEM;
	}
	dev->recycle_dev = eth_dev;
	TAILQ_INSERT_TAIL(&recycle_dev_list, dev, next);
	rte_spinlock_unlock(&recycle_dev_list_lock);

	return 0;
}

static int
lsinic_remove_recycle_dev_list(struct rte_eth_dev *eth_dev)
{
	struct lsinic_recycle_dev *dev = NULL;
	struct lsinic_recycle_dev *tdev = NULL;

	rte_spinlock_lock(&recycle_dev_list_lock);
	TAILQ_FOREACH_SAFE(dev, &recycle_dev_list, next, tdev) {
		if (dev->recycle_dev == eth_dev) {
			TAILQ_REMOVE(&recycle_dev_list, dev, next);
			rte_free(dev);
			rte_spinlock_unlock(&recycle_dev_list_lock);
			return 0;
		}
	}

	rte_spinlock_unlock(&recycle_dev_list_lock);
	return -ENXIO;
}

static int lsinic_add_txq_to_list(struct lsinic_queue *txq)
{
	struct lsinic_queue *queue = NULL;

	if (!RTE_PER_LCORE(lsinic_txq_list_initialized)) {
		TAILQ_INIT(&RTE_PER_LCORE(lsinic_txq_list));
		RTE_PER_LCORE(lsinic_txq_list_initialized) = 1;
		RTE_PER_LCORE(lsinic_txq_num_in_list) = 0;
	}

	/* Check if txq already added to list */
	TAILQ_FOREACH(queue, &RTE_PER_LCORE(lsinic_txq_list), next) {
		if (queue == txq)
			return 0;
	}

	TAILQ_INSERT_TAIL(&RTE_PER_LCORE(lsinic_txq_list), txq, next);
	RTE_PER_LCORE(lsinic_txq_num_in_list)++;

	LSXINIC_PMD_DBG("Add port%d txq%d to list NUM%d",
		txq->port_id, txq->queue_id,
		RTE_PER_LCORE(lsinic_txq_num_in_list));

	return 0;
}

static int
lsinic_remove_txq_from_list(struct lsinic_queue *txq)
{
	struct lsinic_queue *q, *tq;

	TAILQ_FOREACH_SAFE(q, &RTE_PER_LCORE(lsinic_txq_list), next, tq) {
		if (q == txq) {
			TAILQ_REMOVE(&RTE_PER_LCORE(lsinic_txq_list),
				q, next);
			RTE_PER_LCORE(lsinic_txq_num_in_list)--;
			LSXINIC_PMD_DBG("Remove port%d txq%d from list NUM%d",
				txq->port_id, txq->queue_id,
				RTE_PER_LCORE(lsinic_txq_num_in_list));
			break;
		}
	}

	return 0;
}

static void
lsinic_queue_status_update(struct lsinic_queue *q)
{
	int ret;

	if (likely(q->status == LSINIC_QUEUE_RUNNING))
		return;

	if (q->status == LSINIC_QUEUE_UNAVAILABLE)
		return;

	if (q->status == LSINIC_QUEUE_START) {
		ret = lsinic_queue_start(q);
		if (ret < 0) {
			q->status = LSINIC_QUEUE_UNAVAILABLE;
			q->ep_reg->sr = q->status;
			LSINIC_WRITE_REG(&q->rc_reg->sr, q->status);
			return;
		}

		if (q->type == LSINIC_QUEUE_TX)
			lsinic_add_txq_to_list(q);
		else
			RTE_PER_LCORE(lsinic_txq_deqeue_from_rxq) = 1;

		q->status = LSINIC_QUEUE_RUNNING;
		q->ep_reg->sr = q->status;
		LSINIC_WRITE_REG(&q->rc_reg->sr, q->status);

		return;
	}

	if (q->status == LSINIC_QUEUE_STOP) {
		if (lsinic_queue_dma_clean(q) != 0) {
			/* Wait to the next loop to clean dma queue */
			return;
		}

		if (q->type == LSINIC_QUEUE_TX)
			lsinic_remove_txq_from_list(q);
		else
			RTE_PER_LCORE(lsinic_txq_deqeue_from_rxq) = 0;

		q->status = LSINIC_QUEUE_UNAVAILABLE;
		q->ep_reg->sr = q->status;
		LSINIC_WRITE_REG(&q->rc_reg->sr, q->status);

		return;
	}
}

static uint16_t
lsinic_xmit_merged_one_pkt(struct lsinic_queue *txq,
	struct rte_mbuf *tx_pkt,
	int is_merged, struct rte_mbuf **free_pkt)
{
	struct lsinic_bd_desc *ep_txd;
	struct lsinic_sw_bd *txe;
	uint16_t bd_idx, mg_num = 0;
	struct rte_qdma_job *dma_job;
	struct lsinic_mg_header *mg_header = NULL;

	if (unlikely(!lsinic_queue_running(txq))) {
		lsinic_queue_status_update(txq);
		if (!lsinic_queue_running(txq))
			return 0;
	}

	if (is_merged) {
		mg_header =
		rte_pktmbuf_mtod_offset(tx_pkt,
			struct lsinic_mg_header *,
			-sizeof(struct lsinic_mg_header));
		rte_memcpy(mg_header,
			&txq->mg_dsc[txq->mg_dsc_head].mg_header,
			sizeof(struct lsinic_mg_header));
	}

	bd_idx = txq->next_avail_idx & (txq->nb_desc - 1);
	ep_txd = LSINIC_EP_BD_DESC(txq, bd_idx);

	/* Make sure there are enough TX descriptors available to
	 * transmit the entire packet.
	 * nb_used better be less than or equal to txq->tx_rs_thresh
	 */
	if (unlikely(!lsinic_tx_bd_available(txq, bd_idx))) {
		txq->ring_full++;
		txq->drop_packet_num++;
		LSXINIC_PMD_DBG("%s:TXQ%d:bd[%d]:0x%08x unavailable",
			txq->adapter->lsinic_dev->name,
			txq->queue_id, bd_idx, ep_txd->bd_status);

		return 0;
	}

	dma_job = &txq->dma_jobs[bd_idx];

	txe = NULL;
	if (txq->ep2rc_update == EP2RC_BD_DMA_UPDATE ||
		txq->ep2rc_update == EP2RC_RING_DMA_UPDATE)
		txe = &txq->sw_ring[bd_idx];
	else
		lsinic_sw_bd_pop(txq, (void **)&txe, 1);

	if (mg_header) {
		while (mg_num < LSINIC_MERGE_MAX_NUM) {
			uint16_t len =
				lsinic_mg_entry_len(mg_header->len_cmd[mg_num]);

			if (!len)
				break;
			txq->bytes += len;
			txq->bytes_fcs += len +
				LSINIC_ETH_FCS_SIZE;
			txq->bytes_overhead += len +
				LSINIC_ETH_OVERHEAD_SIZE;
			mg_num++;
		}
	}

	if (txe->mbuf) {
		if (free_pkt)
			*free_pkt = txe->mbuf;
		else
			rte_pktmbuf_free_seg(txe->mbuf);
	}
	txe->mbuf = tx_pkt;

	if (mg_header) {
		dma_job->src = rte_mbuf_data_iova(tx_pkt) -
			sizeof(struct lsinic_mg_header);
		dma_job->len = tx_pkt->pkt_len +
			sizeof(struct lsinic_mg_header);
		ep_txd->len_cmd = LSINIC_BD_CMD_EOP | LSINIC_BD_CMD_MG |
			tx_pkt->pkt_len;
		ep_txd->len_cmd |=
			(((uint32_t)(mg_num - 1)) << LSINIC_BD_MG_NUM_SHIFT);

		txq->packets += mg_num;
	} else {
		dma_job->src = rte_mbuf_data_iova(tx_pkt);
		dma_job->len = tx_pkt->pkt_len;
		ep_txd->len_cmd = LSINIC_BD_CMD_EOP | tx_pkt->pkt_len;
		txq->packets++;

		txq->bytes += tx_pkt->pkt_len;
		txq->bytes_fcs += tx_pkt->pkt_len + LSINIC_ETH_FCS_SIZE;
		txq->bytes_overhead +=
			tx_pkt->pkt_len + LSINIC_ETH_OVERHEAD_SIZE;
	}

#ifdef LSINIC_BD_CTX_IDX_USED
	if (txq->ep2rc_update == EP2RC_RING_UPDATE ||
		txq->ep2rc_update == EP2RC_RING_DMA_UPDATE) {
		txq->local_notify[bd_idx].total_len = tx_pkt->pkt_len;
		EP2RC_TX_IDX_CNT_SET(txq->local_notify[bd_idx].cnt_idx,
			lsinic_bd_ctx_idx(ep_txd->bd_status),
			(mg_num ? mg_num : 1));
	}
#endif
	if (txq->ep2rc_update == EP2RC_BD_UPDATE ||
		txq->ep2rc_update == EP2RC_RING_UPDATE)
		rte_memcpy(&txe->bd, ep_txd, sizeof(struct lsinic_bd_desc));

	dma_job->dest = txq->ob_base + ep_txd->pkt_addr;
	dma_job->cnxt = (uint64_t)txe;

	txq->jobs_pending++;

	lsinic_bd_dma_start_update(txq, bd_idx);
	if (txq->wdma_bd_start < 0)
		txq->wdma_bd_start = bd_idx;
	txq->wdma_bd_nb++;
	lsinic_qdma_tx_multiple_enqueue(txq, true);
	txq->next_avail_idx++;

	return 1;
}

static void
lsinic_tx_merge_one_to_txq(struct lsinic_queue *txq,
	struct rte_mbuf *buf, struct rte_mbuf **free_pkt)
{
	struct lsinic_dpni_mg_dsc *mg_dsc =
		&txq->mg_dsc[txq->mg_dsc_head];
	uint16_t ret;

	if (mg_dsc->attach_mbuf) {
		lsinic_mbuf_reset(mg_dsc->attach_mbuf);
		rte_mempool_put_bulk(mg_dsc->attach_mbuf->pool,
			(void * const *)&mg_dsc->attach_mbuf, 1);
	}

	ret = lsinic_xmit_merged_one_pkt(txq,
			buf, 1, free_pkt);
	if (unlikely(ret != 1)) {
		rte_pktmbuf_free(buf);
	} else {
		if (txq->new_desc == 0)
			txq->new_tsc = rte_rdtsc();
	}
	txq->mg_dsc_head = (txq->mg_dsc_head + 1) & (txq->nb_desc - 1);

	txq->recycle_pending--;
}

static void
lsinic_tx_burst_merge_cb(struct rte_mbuf **bufs,
	uint16_t num, struct dpaa2_queue *recycle_rxq)
{
	struct lsinic_queue *txq =
		(struct lsinic_queue *)recycle_rxq->lpbk_cntx;
	int i, free_idx = 0;
	struct rte_mbuf *free_pkts[num];
	const int bulk_free = 1;

	if (!num) {
		lsinic_qdma_tx_multiple_enqueue(txq, false);

		return;
	}

	if (!bulk_free) {
		for (i = 0; i < num; i++)
			lsinic_tx_merge_one_to_txq(txq, bufs[i], NULL);
	} else {
		for (i = 0; i < num; i++) {
			free_pkts[free_idx] = NULL;
			lsinic_tx_merge_one_to_txq(txq, bufs[i],
				&free_pkts[free_idx]);
			if (free_pkts[free_idx])
				free_idx++;
		}
		if (free_idx > 0) {
			rte_mempool_put_bulk(free_pkts[0]->pool,
				(void * const *)free_pkts, free_idx);
		}
	}
}

static void
lsinic_rx_burst_split_cb(struct rte_mbuf **bufs,
	uint16_t num, struct dpaa2_queue *split_rxq)
{
	struct lsinic_queue *rx_queue =
		(struct lsinic_queue *)split_rxq->lpbk_cntx;
	int i;

	if (!num)
		return;

	for (i = 0; i < num; i++) {
		rx_queue->recycle_pending--;
		rx_queue->mcache[rx_queue->mtail] = bufs[i];
		rx_queue->mtail = (rx_queue->mtail + 1) & MCACHE_MASK;

		rx_queue->mcnt++;
	}
}


static void
lsinic_tx_merge_cb(struct rte_mbuf *buf,
	struct dpaa2_queue *recycle_rxq)
{
	struct lsinic_queue *txq =
		(struct lsinic_queue *)recycle_rxq->lpbk_cntx;

	if (!buf) {
		lsinic_qdma_tx_multiple_enqueue(txq, false);

		return;
	}

	lsinic_tx_merge_one_to_txq(txq, buf, NULL);
}

static void
lsinic_rx_split_cb(struct rte_mbuf *mbuf,
	struct dpaa2_queue *split_rxq)
{
	struct lsinic_queue *rx_queue =
		(struct lsinic_queue *)split_rxq->lpbk_cntx;

	if (!mbuf)
		return;

	rx_queue->recycle_pending--;
	rx_queue->mcache[rx_queue->mtail] = mbuf;
	rx_queue->mtail = (rx_queue->mtail + 1) & MCACHE_MASK;

	rx_queue->mcnt++;
}

static inline uint32_t
lsinic_dpaa2_rx_parse_slow(struct rte_mbuf *mbuf,
	struct dpaa2_annot_hdr *annotation)
{
	uint32_t pkt_type = RTE_PTYPE_UNKNOWN;
	uint16_t *vlan_tci;

	if (BIT_ISSET_AT_POS(annotation->word3, L2_VLAN_1_PRESENT)) {
		vlan_tci = rte_pktmbuf_mtod_offset(mbuf, uint16_t *,
			(VLAN_TCI_OFFSET_1(annotation->word5) >> 16));
		mbuf->vlan_tci = rte_be_to_cpu_16(*vlan_tci);
		mbuf->ol_flags |= PKT_RX_VLAN;
		pkt_type |= RTE_PTYPE_L2_ETHER_VLAN;
	} else if (BIT_ISSET_AT_POS(annotation->word3, L2_VLAN_N_PRESENT)) {
		vlan_tci = rte_pktmbuf_mtod_offset(mbuf, uint16_t *,
			(VLAN_TCI_OFFSET_1(annotation->word5) >> 16));
		mbuf->vlan_tci = rte_be_to_cpu_16(*vlan_tci);
		mbuf->ol_flags |= PKT_RX_VLAN | PKT_RX_QINQ;
		pkt_type |= RTE_PTYPE_L2_ETHER_QINQ;
	}

	if (BIT_ISSET_AT_POS(annotation->word3, L2_ARP_PRESENT)) {
		pkt_type |= RTE_PTYPE_L2_ETHER_ARP;
		goto parse_done;
	} else if (BIT_ISSET_AT_POS(annotation->word3, L2_ETH_MAC_PRESENT)) {
		pkt_type |= RTE_PTYPE_L2_ETHER;
	} else {
		goto parse_done;
	}

	if (BIT_ISSET_AT_POS(annotation->word3, L2_MPLS_1_PRESENT |
				L2_MPLS_N_PRESENT))
		pkt_type |= RTE_PTYPE_L2_ETHER_MPLS;

	if (BIT_ISSET_AT_POS(annotation->word4, L3_IPV4_1_PRESENT |
			     L3_IPV4_N_PRESENT)) {
		pkt_type |= RTE_PTYPE_L3_IPV4;
		if (BIT_ISSET_AT_POS(annotation->word4, L3_IP_1_OPT_PRESENT |
			L3_IP_N_OPT_PRESENT))
			pkt_type |= RTE_PTYPE_L3_IPV4_EXT;

	} else if (BIT_ISSET_AT_POS(annotation->word4, L3_IPV6_1_PRESENT |
		  L3_IPV6_N_PRESENT)) {
		pkt_type |= RTE_PTYPE_L3_IPV6;
		if (BIT_ISSET_AT_POS(annotation->word4, L3_IP_1_OPT_PRESENT |
		    L3_IP_N_OPT_PRESENT))
			pkt_type |= RTE_PTYPE_L3_IPV6_EXT;
	} else {
		goto parse_done;
	}

	if (BIT_ISSET_AT_POS(annotation->word8, DPAA2_ETH_FAS_L3CE))
		mbuf->ol_flags |= PKT_RX_IP_CKSUM_BAD;
	else if (BIT_ISSET_AT_POS(annotation->word8, DPAA2_ETH_FAS_L4CE))
		mbuf->ol_flags |= PKT_RX_L4_CKSUM_BAD;

	if (BIT_ISSET_AT_POS(annotation->word4, L3_IP_1_FIRST_FRAGMENT |
	    L3_IP_1_MORE_FRAGMENT |
	    L3_IP_N_FIRST_FRAGMENT |
	    L3_IP_N_MORE_FRAGMENT)) {
		pkt_type |= RTE_PTYPE_L4_FRAG;
		goto parse_done;
	} else {
		pkt_type |= RTE_PTYPE_L4_NONFRAG;
	}

	if (BIT_ISSET_AT_POS(annotation->word4, L3_PROTO_UDP_PRESENT))
		pkt_type |= RTE_PTYPE_L4_UDP;

	else if (BIT_ISSET_AT_POS(annotation->word4, L3_PROTO_TCP_PRESENT))
		pkt_type |= RTE_PTYPE_L4_TCP;

	else if (BIT_ISSET_AT_POS(annotation->word4, L3_PROTO_SCTP_PRESENT))
		pkt_type |= RTE_PTYPE_L4_SCTP;

	else if (BIT_ISSET_AT_POS(annotation->word4, L3_PROTO_ICMP_PRESENT))
		pkt_type |= RTE_PTYPE_L4_ICMP;

	else if (BIT_ISSET_AT_POS(annotation->word4, L3_IP_UNKNOWN_PROTOCOL))
		pkt_type |= RTE_PTYPE_UNKNOWN;

parse_done:
	return pkt_type;
}

static inline void
lsinic_lxdpaa2_rx_parse(struct rte_mbuf *m,
	const struct qbman_fd *fd, void *hw_annot_addr)
{
	uint16_t frc = DPAA2_GET_FD_FRC_PARSE_SUM(fd);
	struct dpaa2_annot_hdr *annotation =
			(struct dpaa2_annot_hdr *)hw_annot_addr;

	m->packet_type = RTE_PTYPE_UNKNOWN;
	switch (frc) {
	case DPAA2_PKT_TYPE_ETHER:
		m->packet_type = RTE_PTYPE_L2_ETHER;
		break;
	case DPAA2_PKT_TYPE_IPV4:
		m->packet_type = RTE_PTYPE_L2_ETHER |
			RTE_PTYPE_L3_IPV4;
		break;
	case DPAA2_PKT_TYPE_IPV6:
		m->packet_type = RTE_PTYPE_L2_ETHER |
			RTE_PTYPE_L3_IPV6;
		break;
	case DPAA2_PKT_TYPE_IPV4_EXT:
		m->packet_type = RTE_PTYPE_L2_ETHER |
			RTE_PTYPE_L3_IPV4_EXT;
		break;
	case DPAA2_PKT_TYPE_IPV6_EXT:
		m->packet_type = RTE_PTYPE_L2_ETHER |
			RTE_PTYPE_L3_IPV6_EXT;
		break;
	case DPAA2_PKT_TYPE_IPV4_TCP:
		m->packet_type = RTE_PTYPE_L2_ETHER |
			RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L4_TCP;
		break;
	case DPAA2_PKT_TYPE_IPV6_TCP:
		m->packet_type = RTE_PTYPE_L2_ETHER |
			RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L4_TCP;
		break;
	case DPAA2_PKT_TYPE_IPV4_UDP:
		m->packet_type = RTE_PTYPE_L2_ETHER |
			RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L4_UDP;
		break;
	case DPAA2_PKT_TYPE_IPV6_UDP:
		m->packet_type = RTE_PTYPE_L2_ETHER |
			RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L4_UDP;
		break;
	case DPAA2_PKT_TYPE_IPV4_SCTP:
		m->packet_type = RTE_PTYPE_L2_ETHER |
			RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L4_SCTP;
		break;
	case DPAA2_PKT_TYPE_IPV6_SCTP:
		m->packet_type = RTE_PTYPE_L2_ETHER |
			RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L4_SCTP;
		break;
	case DPAA2_PKT_TYPE_IPV4_ICMP:
		m->packet_type = RTE_PTYPE_L2_ETHER |
			RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L4_ICMP;
		break;
	case DPAA2_PKT_TYPE_IPV6_ICMP:
		m->packet_type = RTE_PTYPE_L2_ETHER |
			RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L4_ICMP;
		break;
	default:
		m->packet_type = lsinic_dpaa2_rx_parse_slow(m, annotation);
	}
	m->hash.rss = fd->simple.flc_hi;
	m->ol_flags |= PKT_RX_RSS_HASH;
}

static inline uint32_t
lsinic_lsdpaa2_rx_parse(struct rte_mbuf *mbuf,
	void *hw_annot_addr)
{
	struct dpaa2_annot_hdr *annotation =
			(struct dpaa2_annot_hdr *)hw_annot_addr;

	if (BIT_ISSET_AT_POS(annotation->word8, DPAA2_ETH_FAS_L3CE))
		mbuf->ol_flags |= PKT_RX_IP_CKSUM_BAD;
	else if (BIT_ISSET_AT_POS(annotation->word8, DPAA2_ETH_FAS_L4CE))
		mbuf->ol_flags |= PKT_RX_L4_CKSUM_BAD;

	mbuf->ol_flags |= PKT_RX_TIMESTAMP;
	mbuf->timestamp = annotation->word2;

	/* Check detailed parsing requirement */
	if (annotation->word3 & 0x7FFFFC3FFFF)
		return lsinic_dpaa2_rx_parse_slow(mbuf, annotation);

	/* Return some common types from parse processing */
	switch (annotation->word4) {
	case DPAA2_L3_IPv4:
		return RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4;
	case DPAA2_L3_IPv6:
		return  RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6;
	case DPAA2_L3_IPv4_TCP:
		return  RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4 |
				RTE_PTYPE_L4_TCP;
	case DPAA2_L3_IPv4_UDP:
		return  RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4 |
				RTE_PTYPE_L4_UDP;
	case DPAA2_L3_IPv6_TCP:
		return  RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6 |
				RTE_PTYPE_L4_TCP;
	case DPAA2_L3_IPv6_UDP:
		return  RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6 |
				RTE_PTYPE_L4_UDP;
	default:
		break;
	}

	return lsinic_dpaa2_rx_parse_slow(mbuf, annotation);
}

static inline struct rte_mbuf *
lsinic_dpaa2_fd_to_mbuf(const struct qbman_fd *fd,
	int port_id, enum LSINIC_QEUE_TYPE lsinic_qtype)
{
	void *v_addr = DPAA2_IOVA_TO_VADDR(DPAA2_GET_FD_ADDR(fd));
	uint32_t offset;
	uint16_t bpid;
	struct rte_mbuf *mbuf;

	bpid = DPAA2_GET_FD_BPID(fd);
	offset = rte_dpaa2_bpid_info[bpid].meta_data_size;
	mbuf = DPAA2_INLINE_MBUF_FROM_BUF(v_addr, offset);
	/* need to repopulated some of the fields,
	 * as they may have changed in last transmission
	 */
	mbuf->nb_segs = 1;
	mbuf->ol_flags = 0;
	mbuf->data_off = DPAA2_GET_FD_OFFSET(fd);
	mbuf->data_len = DPAA2_GET_FD_LEN(fd);
	mbuf->pkt_len = mbuf->data_len;
	mbuf->port = port_id;
	mbuf->next = NULL;

	if (lsinic_qtype == LSINIC_QUEUE_RX) {
		void *hw_annot_addr =
			(void *)((size_t)v_addr + DPAA2_FD_PTA_SIZE);

		if (dpaa2_svr_family == SVR_LX2160A) {
			lsinic_lxdpaa2_rx_parse(mbuf, fd, hw_annot_addr);
		} else {
			mbuf->packet_type =
				lsinic_lsdpaa2_rx_parse(mbuf, hw_annot_addr);
		}
	}

	return mbuf;
}

static uint16_t
lsinic_dpaa2_rx_lpbk(void *queue,
	struct rte_mbuf **bufs, uint16_t nb_pkts)
{
	/* Function receive frames for a given device and VQ*/
	struct dpaa2_queue *dpaa2_q = (struct dpaa2_queue *)queue;
	struct qbman_result *dq_storage, *dq_storage1 = NULL;
	uint32_t fqid = dpaa2_q->fqid;
	int ret, num_rx = 0, pull_size;
	uint8_t pending, status;
	struct qbman_swp *swp;
	const struct qbman_fd *fd;
	struct qbman_pull_desc pulldesc;
	struct queue_storage_info_t *q_storage = dpaa2_q->q_storage;
	struct rte_eth_dev_data *eth_data = dpaa2_q->eth_data;
	struct lsinic_queue *lsinic_q;

	if (unlikely(!DPAA2_PER_LCORE_ETHRX_DPIO)) {
		ret = dpaa2_affine_qbman_ethrx_swp();
		if (ret) {
			LSXINIC_PMD_ERR("Failure in affining portal");
			return 0;
		}
	}

	if (unlikely(!rte_dpaa2_bpid_info &&
		     rte_eal_process_type() == RTE_PROC_SECONDARY))
		rte_dpaa2_bpid_info = dpaa2_q->bp_array;

	swp = DPAA2_PER_LCORE_ETHRX_PORTAL;
	pull_size = (nb_pkts > dpaa2_dqrr_size) ? dpaa2_dqrr_size : nb_pkts;
	if (unlikely(!q_storage->active_dqs)) {
		q_storage->toggle = 0;
		dq_storage = q_storage->dq_storage[q_storage->toggle];
		q_storage->last_num_pkts = pull_size;
		qbman_pull_desc_clear(&pulldesc);
		qbman_pull_desc_set_numframes(&pulldesc,
					      q_storage->last_num_pkts);
		qbman_pull_desc_set_fq(&pulldesc, fqid);
		qbman_pull_desc_set_storage(&pulldesc, dq_storage,
			(uint64_t)(DPAA2_VADDR_TO_IOVA(dq_storage)), 1);
		if (check_swp_active_dqs(DPAA2_PER_LCORE_ETHRX_DPIO->index)) {
			while (!qbman_check_command_complete(
			       get_swp_active_dqs(
			       DPAA2_PER_LCORE_ETHRX_DPIO->index)))
				;
			clear_swp_active_dqs(DPAA2_PER_LCORE_ETHRX_DPIO->index);
		}
		while (1) {
			if (qbman_swp_pull(swp, &pulldesc))
				continue;
			break;
		}
		q_storage->active_dqs = dq_storage;
		q_storage->active_dpio_id = DPAA2_PER_LCORE_ETHRX_DPIO->index;
		set_swp_active_dqs(DPAA2_PER_LCORE_ETHRX_DPIO->index,
				   dq_storage);
	}

	dq_storage = q_storage->active_dqs;
	rte_prefetch0((void *)(size_t)(dq_storage));
	rte_prefetch0((void *)(size_t)(dq_storage + 1));

	/* Prepare next pull descriptor. This will give space for the
	 * prefething done on DQRR entries
	 */
	q_storage->toggle ^= 1;
	dq_storage1 = q_storage->dq_storage[q_storage->toggle];
	qbman_pull_desc_clear(&pulldesc);
	qbman_pull_desc_set_numframes(&pulldesc, pull_size);
	qbman_pull_desc_set_fq(&pulldesc, fqid);
	qbman_pull_desc_set_storage(&pulldesc, dq_storage1,
		(uint64_t)(DPAA2_VADDR_TO_IOVA(dq_storage1)), 1);

	while (!qbman_check_command_complete(dq_storage))
		;
	if (dq_storage == get_swp_active_dqs(q_storage->active_dpio_id))
		clear_swp_active_dqs(q_storage->active_dpio_id);

	pending = 1;

	lsinic_q = (struct lsinic_queue *)dpaa2_q->lpbk_cntx;

	do {
		/* Loop until the dq_storage is updated with
		 * new token by QBMAN
		 */
		while (!qbman_check_new_result(dq_storage))
			;
		rte_prefetch0((void *)((size_t)(dq_storage + 2)));
		/* Check whether Last Pull command is Expired and
		 * setting Condition for Loop termination
		 */
		if (qbman_result_DQ_is_pull_complete(dq_storage)) {
			pending = 0;
			/* Check for valid frame. */
			status = qbman_result_DQ_flags(dq_storage);
			if (unlikely((status & QBMAN_DQ_STAT_VALIDFRAME) == 0))
				continue;
		}
		fd = qbman_result_DQ_fd(dq_storage);

		if (likely(lsinic_q)) {
			bufs[num_rx] = lsinic_dpaa2_fd_to_mbuf(fd,
							eth_data->port_id,
							lsinic_q->type);
		} else {
			bufs[num_rx] = lsinic_dpaa2_fd_to_mbuf(fd,
							eth_data->port_id,
							LSINIC_QUEUE_TX);
		}

		dq_storage++;
		num_rx++;
	} while (pending);

	if (check_swp_active_dqs(DPAA2_PER_LCORE_ETHRX_DPIO->index)) {
		while (!qbman_check_command_complete(
		       get_swp_active_dqs(DPAA2_PER_LCORE_ETHRX_DPIO->index)))
			;
		clear_swp_active_dqs(DPAA2_PER_LCORE_ETHRX_DPIO->index);
	}
	/* issue a volatile dequeue command for next pull */
	while (1) {
		if (qbman_swp_pull(swp, &pulldesc))
			continue;
		break;
	}
	q_storage->active_dqs = dq_storage1;
	q_storage->active_dpio_id = DPAA2_PER_LCORE_ETHRX_DPIO->index;
	set_swp_active_dqs(DPAA2_PER_LCORE_ETHRX_DPIO->index, dq_storage1);

	dpaa2_q->rx_pkts += num_rx;

	if (!num_rx) {
		if (lsinic_q && !lsinic_q->recycle_rxq) {
			if (lsinic_q->type == LSINIC_QUEUE_TX)
				lsinic_tx_merge_cb(NULL, dpaa2_q);
			else
				lsinic_rx_split_cb(NULL, dpaa2_q);
		}
	}

	if (lsinic_q && lsinic_q->recycle_rxq)
		return num_rx;

	if (lsinic_q && !lsinic_q->recycle_rxq) {
		if (lsinic_q->type == LSINIC_QUEUE_TX)
			lsinic_tx_burst_merge_cb(bufs, num_rx, dpaa2_q);
		else
			lsinic_rx_burst_split_cb(bufs, num_rx, dpaa2_q);
	}

	return 0;
}

#define LSINIC_DPAA2_SG_MAX_OFFSET \
	(4096 - \
	(sizeof(struct qbman_sge) * LSINIC_MERGE_MAX_NUM))

static uint16_t
lsinic_dpaa2_merge_sg(struct rte_mbuf **tx_pkts,
	uint16_t nb_pkts,
	struct qbman_fd *fd_gather,
	struct lsinic_dpni_mg_dsc *mg_dsc,
	uint16_t data_room)
{
	uint16_t seg_len, align_off, sg_num = 0;
	uint16_t i, total_len = 0;
	struct lsinic_mg_header *mg_header;
	struct rte_mempool *mp = tx_pkts[0]->pool;

	uint16_t bpid, sg_offset, merge_max;
	struct qbman_sge *sgt, *sge = NULL;
	struct rte_mbuf *direct_mbuf = NULL;
	struct rte_mbuf *attach_mbuf = NULL;
	struct rte_mbuf *tmp_mbuf;
	uint64_t fd_iova;
	char *fd_va;
	struct rte_mbuf *free_bufs[LSINIC_MERGE_MAX_NUM];
	uint16_t free_nb = 0;

	for (i = 0; i < nb_pkts; i++) {
		if (!(tx_pkts[i]->ol_flags & LSINIC_SHARED_MBUF)) {
			direct_mbuf = tx_pkts[i];
			break;
		}
		if ((tx_pkts[i]->ol_flags & IND_ATTACHED_MBUF)) {
			attach_mbuf = tx_pkts[i];
			break;
		}
	}

	if (direct_mbuf) {
		tmp_mbuf = direct_mbuf;
		fd_iova = (uint64_t)DPAA2_MBUF_VADDR_TO_IOVA(tmp_mbuf);
		fd_va = DPAA2_IOVA_TO_VADDR(fd_iova);
	} else if (attach_mbuf) {
		tmp_mbuf = attach_mbuf;
		fd_va = (char *)tmp_mbuf +
				(uint32_t)(sizeof(struct rte_mbuf) +
				rte_pktmbuf_priv_size(mp));
		fd_iova = DPAA2_VADDR_TO_IOVA(fd_va);
	} else {
		tmp_mbuf = rte_pktmbuf_alloc(mp);
		fd_iova = (uint64_t)DPAA2_MBUF_VADDR_TO_IOVA(tmp_mbuf);
		fd_va = DPAA2_IOVA_TO_VADDR(fd_iova);
	}

	mg_header = &mg_dsc->mg_header;
	sg_offset = RTE_PKTMBUF_HEADROOM + data_room -
		(sizeof(struct qbman_sge) * LSINIC_MERGE_MAX_NUM);
	if (sg_offset > LSINIC_DPAA2_SG_MAX_OFFSET)
		sg_offset = LSINIC_DPAA2_SG_MAX_OFFSET;
	merge_max = sg_offset - RTE_PKTMBUF_HEADROOM;

	bpid = mempool_to_bpid(mp);
	DPAA2_SET_FD_ADDR(fd_gather, fd_iova);
	DPAA2_SET_ONLY_FD_BPID(fd_gather, bpid);
	if (attach_mbuf)
		DPAA2_SET_FD_IVP(fd_gather);

	DPAA2_SET_FD_OFFSET(fd_gather, sg_offset);
	DPAA2_FD_SET_FORMAT(fd_gather, qbman_fd_sg);
	DPAA2_RESET_FD_FRC(fd_gather);
	DPAA2_RESET_FD_CTRL(fd_gather);
	/*Set Scatter gather table and Scatter gather entries*/
	sgt = (struct qbman_sge *)(fd_va + sg_offset);

	for (i = 0; i < nb_pkts; i++) {
		seg_len = ALIGN(tx_pkts[i]->pkt_len, LSINIC_MG_ALIGN_SIZE);
		if ((tmp_mbuf->data_off + total_len + seg_len) >= sg_offset)
			break;
		if (total_len + seg_len >= merge_max)
			break;
		align_off = seg_len - tx_pkts[i]->pkt_len;
		mg_header->len_cmd[i] =
			lsinic_mg_entry_set(tx_pkts[i]->pkt_len,
				align_off);

		sge = &sgt[i];
		/*Resetting the buffer pool id and offset field*/
		sge->fin_bpid_offset = 0;
		DPAA2_SET_FLE_ADDR(sge, DPAA2_MBUF_VADDR_TO_IOVA(tx_pkts[i]));
		DPAA2_SET_FLE_OFFSET(sge, tx_pkts[i]->data_off);
		if (!(tx_pkts[i]->ol_flags & LSINIC_SHARED_MBUF)) {
			if (likely(tx_pkts[i] != tmp_mbuf))
				DPAA2_SET_FLE_BPID(sge,
					mempool_to_bpid(tx_pkts[i]->pool));
			else
				DPAA2_SET_FLE_IVP(sge);
		} else {
			DPAA2_SET_FLE_BPID(sge,
				mempool_to_bpid(tx_pkts[i]->pool));
			if (unlikely(RTE_MBUF_DIRECT(tx_pkts[i]))) {
				if (tx_pkts[i]->refcnt > 1) {
					DPAA2_SET_FLE_IVP(sge);
					tx_pkts[i]->refcnt--;
				}
				tx_pkts[i]->ol_flags = 0;
			} else {
				struct rte_mbuf *mi;

				mi = rte_mbuf_from_indirect(tx_pkts[i]);
				if (mi->refcnt > 1) {
					DPAA2_SET_FLE_IVP(sge);
					mi->refcnt--;
				}
				if (likely(tx_pkts[i] != attach_mbuf)) {
					free_bufs[free_nb] = tx_pkts[i];
					free_nb++;
				}
			}
		}

		sge->length = seg_len;
		total_len += seg_len;
		sg_num++;
	}

	if (unlikely(!sg_num))
		return 0;

	if (sg_num < LSINIC_MERGE_MAX_NUM)
		mg_header->len_cmd[sg_num] = 0;

	mg_dsc->attach_mbuf = attach_mbuf;

	DPAA2_SET_FD_LEN(fd_gather, total_len);
	DPAA2_SG_SET_FINAL(sge, true);

	if (free_nb > 0) {
		for (i = 0; i < free_nb; i++)
			lsinic_mbuf_reset(free_bufs[i]);
		rte_mempool_put_bulk(mp, (void * const *)free_bufs, free_nb);
	}

	return sg_num;
}
static void
lsinic_dpaa2_enqueue(struct dpaa2_queue *txq,
	struct qbman_fd *fd_arr, int fd_nb)
{
	int ret;
	uint16_t loop = 0;
	struct qbman_eq_desc eqdesc;
	struct qbman_swp *swp;

	if (unlikely(!DPAA2_PER_LCORE_DPIO)) {
		ret = dpaa2_affine_qbman_swp();
		if (ret) {
			LSXINIC_PMD_ERR("Failure in affining portal");
			return;
		}
	}
	swp = DPAA2_PER_LCORE_PORTAL;

	while (qbman_result_SCN_state(txq->cscn))
		;

	qbman_eq_desc_clear(&eqdesc);
	qbman_eq_desc_set_no_orp(&eqdesc, DPAA2_EQ_RESP_ERR_FQ);
	qbman_eq_desc_set_fq(&eqdesc, txq->fqid);

	while (loop < fd_nb) {
		ret = qbman_swp_enqueue_multiple(swp, &eqdesc,
				&fd_arr[loop], 0,
				fd_nb - loop);
		if (likely(ret >= 0))
			loop += ret;
	}
}

static uint16_t
lsinic_xmit_directly(struct rte_mbuf **tx_pkts,
	uint16_t nb_pkts, struct lsinic_queue *txq,
	struct rte_mbuf **mg_pkts);

static uint16_t
lsinic_dpaa2_merge_tx_lpbk(void *queue,
	struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	struct dpaa2_queue *dpaa2_q = (struct dpaa2_queue *)queue;
	struct qbman_fd fd_gather[LSINIC_MERGE_MAX_NUM];
	uint16_t fd_num = 0, tx_num = 0, ret, direct_nb;
	struct rte_mbuf *mg_pkts[LSINIC_MERGE_MAX_NUM];
	struct lsinic_dpni_mg_dsc *mg_dsc;
	struct lsinic_queue *lsinic_q =
			(struct lsinic_queue *)dpaa2_q->lpbk_cntx;

	direct_nb = lsinic_xmit_directly(tx_pkts, nb_pkts, lsinic_q, mg_pkts);
	nb_pkts -= direct_nb;

	while (nb_pkts) {
		if (((lsinic_q->mg_dsc_tail + 1) & (lsinic_q->nb_desc - 1)) ==
			lsinic_q->mg_dsc_head)
			break;
		mg_dsc = &lsinic_q->mg_dsc[lsinic_q->mg_dsc_tail];
		ret = lsinic_dpaa2_merge_sg(&mg_pkts[tx_num],
				nb_pkts, &fd_gather[fd_num], mg_dsc,
				lsinic_q->adapter->data_room_size);
		if (ret > 0) {
			lsinic_q->mg_dsc_tail = (lsinic_q->mg_dsc_tail + 1) & (lsinic_q->nb_desc - 1);
			fd_num++;
		}
		tx_num += ret;
		nb_pkts -= ret;
	}
	if (fd_num > 0) {
		lsinic_dpaa2_enqueue(dpaa2_q, fd_gather, fd_num);
		lsinic_q->recycle_pending += fd_num;
	}
	return tx_num + direct_nb;
}

static uint16_t lsinic_dpaa2_split_mbuf_to_fd(
	struct rte_mbuf *mbuf, struct qbman_fd *fd_arr,
	uint16_t num, uint32_t *total_size)
{
	uint16_t idx = 0, offset = 0;
	char *data_base = rte_pktmbuf_mtod(mbuf, char *);
	struct lsinic_mg_header *mg_header = 0;
	uint32_t bpid = mempool_to_bpid(mbuf->pool);
	uint32_t size = 0;

	if (num <= 1) {
		DPAA2_SET_FD_ADDR(&fd_arr[0], mbuf->buf_iova);
		DPAA2_SET_FD_LEN(&fd_arr[0], mbuf->pkt_len);
		DPAA2_SET_ONLY_FD_BPID(&fd_arr[0], bpid);
		DPAA2_SET_FD_OFFSET(&fd_arr[0], mbuf->data_off);
		DPAA2_SET_FD_FRC(&fd_arr[0], 0);
		DPAA2_RESET_FD_CTRL(&fd_arr[0]);
		DPAA2_RESET_FD_FLC(&fd_arr[0]);
		if (total_size)
			*total_size = mbuf->pkt_len;
		return 1;
	}

	mg_header = (struct lsinic_mg_header *)data_base;

	for (idx = 0; idx < num; idx++) {
		DPAA2_SET_FD_ADDR(&fd_arr[idx], mbuf->buf_iova);
		DPAA2_SET_FD_LEN(&fd_arr[idx],
			lsinic_mg_entry_len(mg_header->len_cmd[idx]));
		size += lsinic_mg_entry_len(mg_header->len_cmd[idx]);
		/* Just for clear bpid_offset*/
		DPAA2_SET_ONLY_FD_BPID(&fd_arr[idx], 0);
		DPAA2_SET_FD_IVP(&fd_arr[idx]);
		DPAA2_SET_FD_OFFSET(&fd_arr[idx],
			mbuf->data_off + offset +
			sizeof(struct lsinic_mg_header));
		DPAA2_SET_FD_FRC(&fd_arr[idx], 0);
		DPAA2_RESET_FD_CTRL(&fd_arr[idx]);
		DPAA2_RESET_FD_FLC(&fd_arr[idx]);

		if ((idx + 1) == num) {
			DPAA2_SET_ONLY_FD_BPID(&fd_arr[idx], bpid);
			DPAA2_SET_FD_OFFSET(&fd_arr[idx],
				mbuf->data_off + offset +
				sizeof(struct lsinic_mg_header));
			break;
		}
		offset += lsinic_mg_entry_len(mg_header->len_cmd[idx]);
		offset += lsinic_mg_entry_align_offset(mg_header->len_cmd[idx]);
	}

	if (total_size)
		*total_size = size;

	return (idx + 1);
}

static uint16_t
lsinic_dpaa2_split_tx_lpbk(void *queue,
	struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	struct dpaa2_queue *txq = (struct dpaa2_queue *)queue;
	struct lsinic_queue *lsinic_q =
		(struct lsinic_queue *)txq->lpbk_cntx;
	struct qbman_fd *fd_arr = lsinic_q->recycle_fd;
	uint32_t i, fd_idx = 0, count, len = 0, total_size = 0;

	for (i = 0; i < nb_pkts; i++) {
		count = lsinic_dpaa2_split_mbuf_to_fd(tx_pkts[i],
				&fd_arr[fd_idx],
				lsinic_q->split_cnt[i], &len);
		total_size += len;
		fd_idx += count;
	}

	lsinic_q->bytes += total_size;
	lsinic_q->bytes_fcs +=
		len + LSINIC_ETH_FCS_SIZE * fd_idx;
	lsinic_q->bytes_overhead +=
		len + LSINIC_ETH_OVERHEAD_SIZE * fd_idx;

	lsinic_q->packets += fd_idx;
	lsinic_q->new_desc += fd_idx;

	if (fd_idx > 0) {
		lsinic_dpaa2_enqueue(txq, fd_arr, fd_idx);
		lsinic_q->recycle_pending += fd_idx;
	}

	return nb_pkts;
}

static int s_use_split_tx_cb;

static int
lsinic_hw_offload_queue_setup(struct lsinic_queue *q)
{
	struct lsinic_adapter *adapter = q->adapter;
	struct dpaa2_queue *dpaa2_txq = NULL;
	struct dpaa2_queue *dpaa2_rxq = NULL;
	struct rte_dpaa2_device *dpaa2_dev = NULL;
	int ret = -1;
	eth_rx_burst_t rx_lpbk = NULL;
	eth_tx_burst_t tx_lpbk = NULL;

	if (q->type == LSINIC_QUEUE_TX &&
		adapter->merge_dev) {
		dpaa2_dev = adapter->merge_dev;
		rx_lpbk = lsinic_dpaa2_rx_lpbk;
		tx_lpbk = lsinic_dpaa2_merge_tx_lpbk;
	} else if (q->type == LSINIC_QUEUE_RX &&
		adapter->split_dev) {
		dpaa2_dev = adapter->split_dev;
		if (!(adapter->ep_cap &
			LSINIC_EP_CAP_HW_DIRECT_EGRESS)) {
			rx_lpbk = lsinic_dpaa2_rx_lpbk;
			tx_lpbk = lsinic_dpaa2_split_tx_lpbk;
		}
		if (getenv("LSINIC_HW_SPLIT_TX_CB"))
			s_use_split_tx_cb = atoi("LSINIC_HW_SPLIT_TX_CB");
	}

	if (dpaa2_dev) {
		ret = dpaa2_dev_recycle_qp_setup(dpaa2_dev,
				q->queue_id, (uint64_t)q,
				tx_lpbk, rx_lpbk,
				&dpaa2_txq, &dpaa2_rxq);
		if (!ret) {
			q->recycle_txq = dpaa2_txq;
			if (q->type == LSINIC_QUEUE_TX &&
				adapter->ep_cap & LSINIC_EP_CAP_RCV_MERGE_RECYCLE_RX)
				q->recycle_rxq = dpaa2_rxq;
			else if (q->type == LSINIC_QUEUE_RX &&
				adapter->ep_cap & LSINIC_EP_CAP_RCV_SPLIT_RECYCLE_RX)
				q->recycle_rxq = dpaa2_rxq;
			else
				q->recycle_rxq = NULL;
		}
	}

	return ret;
}

static void
lsinic_txq_hw_offload_cfg(struct lsinic_queue *txq)
{
	struct lsinic_adapter *adapter = txq->adapter;
	struct rte_eth_dev *recycle_dev;
	int ret;

	if (adapter->ep_cap & LSINIC_EP_CAP_HW_MERGE_PKTS) {
		rte_spinlock_lock(&adapter->merge_dev_cfg_lock);
		if (!adapter->merge_dev_cfg_done) {
			recycle_dev = adapter->merge_dev->eth_dev;
			ret = lsinic_add_recycle_dev_list(recycle_dev);
			if (ret) {
				LSXINIC_PMD_WARN("Recycle dev %s add list failed",
					recycle_dev->data->name);
				adapter->merge_dev = NULL;
				adapter->ep_cap &= ~LSINIC_EP_CAP_HW_MERGE_PKTS;
				adapter->merge_dev_cfg_done = 1;
				rte_spinlock_unlock(&adapter->merge_dev_cfg_lock);

				return;
			}
			recycle_dev->data->dev_conf.lpbk_mode = 1;
			ret = recycle_dev->dev_ops->dev_configure(recycle_dev);
			if (ret) {
				LSXINIC_PMD_WARN("Recycle dev %s cfg failed",
					recycle_dev->data->name);
				recycle_dev->data->dev_conf.lpbk_mode = 0;

				lsinic_remove_recycle_dev_list(recycle_dev);

				adapter->merge_dev = NULL;
				adapter->ep_cap &= ~LSINIC_EP_CAP_HW_MERGE_PKTS;
				adapter->merge_dev_cfg_done = 1;
				rte_spinlock_unlock(&adapter->merge_dev_cfg_lock);

				return;
			} else {
				LSXINIC_PMD_INFO("%s uses %s to merge packets"
					" smaller than %d Bytes",
					adapter->lsinic_dev->eth_dev->data->name,
					recycle_dev->data->name,
					adapter->merge_threshold);
			}
			adapter->merge_dev_cfg_done = 1;
		}
		rte_spinlock_unlock(&adapter->merge_dev_cfg_lock);
		lsinic_hw_offload_queue_setup(txq);
	}
}

static void
lsinic_txq_hw_offload_decfg(struct lsinic_queue *txq)
{
	struct lsinic_adapter *adapter = txq->adapter;
	struct rte_eth_dev *recycle_dev;
	int ret;

	if (adapter->ep_cap & LSINIC_EP_CAP_HW_MERGE_PKTS) {
		rte_spinlock_lock(&adapter->merge_dev_cfg_lock);
		if (adapter->merge_dev) {
			recycle_dev = adapter->merge_dev->eth_dev;
			lsinic_remove_recycle_dev_list(recycle_dev);
			recycle_dev->data->dev_conf.lpbk_mode = 0;
			ret = recycle_dev->dev_ops->dev_configure(recycle_dev);
			if (ret) {
				LSXINIC_PMD_WARN("Recycle dev %s cfg failed",
						recycle_dev->data->name);
			}
			adapter->merge_dev = NULL;
		}
		txq->recycle_txq = NULL;
		txq->recycle_rxq = NULL;
		rte_spinlock_unlock(&adapter->merge_dev_cfg_lock);
	}
}

static void
lsinic_rxq_hw_offload_cfg(struct lsinic_queue *rxq)
{
	struct lsinic_adapter *adapter = rxq->adapter;
	struct rte_eth_dev *recycle_dev;
	int ret;

	if (adapter->ep_cap & LSINIC_EP_CAP_MBUF_CLONE_SPLIT_PKTS) {
		rxq->split_type = LSINIC_MBUF_CLONE_SPLIT;
	} else if (adapter->ep_cap & LSINIC_EP_CAP_HW_SPLIT_PKTS) {
		rxq->split_type = LSINIC_HW_SPLIT;
		if (adapter->ep_cap & LSINIC_EP_CAP_HW_DIRECT_EGRESS) {
			lsinic_hw_offload_queue_setup(rxq);
		} else {
			rte_spinlock_lock(&adapter->split_dev_cfg_lock);
			if (!adapter->split_dev_cfg_done) {
				recycle_dev = adapter->split_dev->eth_dev;
				ret = lsinic_add_recycle_dev_list(recycle_dev);
				if (ret) {
					LSXINIC_PMD_WARN("Recycle dev %s add list failed",
						recycle_dev->data->name);
					adapter->split_dev = NULL;
					adapter->ep_cap &= ~LSINIC_EP_CAP_HW_SPLIT_PKTS;
					adapter->split_dev_cfg_done = 1;
					rte_spinlock_unlock(&adapter->split_dev_cfg_lock);

					return;
				}
				recycle_dev->data->dev_conf.lpbk_mode = 1;
				ret = recycle_dev->dev_ops->dev_configure(recycle_dev);
				if (ret) {
					LSXINIC_PMD_WARN("Recycle dev %s cfg failed",
						recycle_dev->data->name);
					recycle_dev->data->dev_conf.lpbk_mode = 0;
					lsinic_remove_recycle_dev_list(recycle_dev);

					adapter->split_dev = NULL;
					adapter->ep_cap &= ~LSINIC_EP_CAP_HW_SPLIT_PKTS;
					adapter->split_dev_cfg_done = 1;
					rte_spinlock_unlock(&adapter->split_dev_cfg_lock);

					return;
				}
				lsinic_split_dev_flow_create(adapter);
				adapter->split_dev_cfg_done = 1;
			}
			rte_spinlock_unlock(&adapter->split_dev_cfg_lock);
			lsinic_hw_offload_queue_setup(rxq);
		}
		rxq->recycle_fd = rte_malloc(NULL,
			sizeof(struct qbman_fd) *
			rxq->nb_desc *
			LSINIC_MERGE_MAX_NUM, 64);
	} else {
		rxq->split_type = LSINIC_CPU_SPLIT;
	}
}

static void
lsinic_rxq_hw_offload_decfg(struct lsinic_queue *rxq)
{
	struct lsinic_adapter *adapter = rxq->adapter;
	struct rte_eth_dev *recycle_dev;
	int ret;

	if (!(adapter->ep_cap & LSINIC_EP_CAP_HW_DIRECT_EGRESS) &&
		adapter->ep_cap & LSINIC_EP_CAP_HW_SPLIT_PKTS) {
		rte_spinlock_lock(&adapter->split_dev_cfg_lock);
		if (adapter->split_dev) {
			recycle_dev = adapter->split_dev->eth_dev;
			lsinic_remove_recycle_dev_list(recycle_dev);
			recycle_dev->data->dev_conf.lpbk_mode = 0;
			ret = recycle_dev->dev_ops->dev_configure(recycle_dev);
			if (ret) {
				LSXINIC_PMD_WARN("Recycle dev %s cfg failed",
					recycle_dev->data->name);
			}
			adapter->split_dev = NULL;
		}
		rxq->recycle_txq = NULL;
		rxq->recycle_rxq = NULL;
		rte_spinlock_unlock(&adapter->split_dev_cfg_lock);
	}
}

static void
lsinic_queue_hw_offload_cfg(struct lsinic_queue *q)
{
	if (q->type == LSINIC_QUEUE_TX)
		lsinic_txq_hw_offload_cfg(q);
	else
		lsinic_rxq_hw_offload_cfg(q);
}

static void
lsinic_queue_hw_offload_decfg(struct lsinic_queue *q)
{
	if (q->type == LSINIC_QUEUE_TX)
		lsinic_txq_hw_offload_decfg(q);
	else
		lsinic_rxq_hw_offload_decfg(q);
}

static __rte_always_inline struct lsinic_sw_bd *
lsinic_recv_rxe_no_dq(struct lsinic_queue *rxq,
	uint16_t bd_idx)
{
	struct rte_qdma_job *dma_job;
	struct lsinic_sw_bd *rxe = &rxq->sw_ring[bd_idx];
	struct lsinic_sw_bd *next_rxe =
		&rxq->sw_ring[(bd_idx + 1) & (rxq->nb_desc - 1)];

	if (likely(next_rxe->complete))
		rte_lsinic_prefetch(next_rxe->complete);

	if ((*rxe->complete) != LSINIC_XFER_COMPLETE_DONE_FLAG)
		return NULL;
	dma_job = &rxq->dma_jobs[bd_idx];
	dma_job->flags &= ~LSINIC_QDMA_JOB_USING_FLAG;
	rxe->complete = NULL;

	return rxe;
}

static __rte_always_inline struct lsinic_sw_bd *
lsinic_recv_rxe_orp(struct lsinic_queue *rxq,
	uint16_t bd_idx)
{
	struct lsinic_sw_bd *rxe = &rxq->sw_ring[bd_idx];

	if (!rxe->dma_complete)
		return NULL;
	rxe->dma_complete = 0;

	return rxe;
}

static __rte_always_inline struct lsinic_sw_bd *
lsinic_recv_rxe(struct lsinic_queue *rxq,
	uint16_t bd_idx __rte_unused)
{
	struct lsinic_sw_bd *rxe = rxq->sw_bd[rxq->sw_bd_head];

	return rxe;
}

static __rte_always_inline void
lsinic_recv_index_update(struct lsinic_queue *rxq __rte_unused,
	uint16_t bd_idx __rte_unused, void *rxe __rte_unused)
{
}

static __rte_always_inline void
lsinic_recv_ring_update(struct lsinic_queue *rxq,
	uint16_t bd_idx, void *rxe)
{
	struct lsinic_adapter *adapter = rxq->adapter;
	struct lsinic_bd_desc *rxdp = LSINIC_EP_BD_DESC(rxq, bd_idx);

	if ((adapter->cap & LSINIC_CAP_XFER_COMPLETE) ||
		(adapter->ep_cap & LSINIC_EP_CAP_RXQ_ORP)) {
#ifdef LSINIC_BD_CTX_IDX_USED
		rxdp->bd_status &= ~((uint32_t)RING_BD_STATUS_MASK);
		rxdp->bd_status |= RING_BD_ADDR_CHECK;
		rxdp->bd_status |= RING_BD_HW_COMPLETE;
#else
		rxdp->bd_status =
			RING_BD_HW_COMPLETE | RING_BD_ADDR_CHECK;
#endif
	} else {
		rxq->sw_bd_head = (rxq->sw_bd_head + 1) & MCACHE_MASK;
		rxq->sw_bd_cnt--;
		RTE_ASSERT(rxq->sw_bd_cnt >= 0);
		lsinic_sw_bd_push(rxq, (void **)&rxe, 1);
	}
}

static __rte_always_inline void
lsinic_recv_rxbd_update(struct lsinic_queue *rxq,
	uint16_t bd_idx, void *rxe)
{
	struct lsinic_adapter *adapter = rxq->adapter;
	struct lsinic_bd_desc *rxdp = LSINIC_EP_BD_DESC(rxq, bd_idx);

	if ((adapter->cap & LSINIC_CAP_XFER_COMPLETE) ||
		(adapter->ep_cap & LSINIC_EP_CAP_RXQ_ORP)) {
#ifdef LSINIC_BD_CTX_IDX_USED
		rxdp->bd_status &= ~((uint32_t)RING_BD_STATUS_MASK);
		rxdp->bd_status |= RING_BD_ADDR_CHECK;
		rxdp->bd_status |= RING_BD_HW_COMPLETE;
#else
		rxdp->bd_status =
			RING_BD_HW_COMPLETE | RING_BD_ADDR_CHECK;
#endif
	} else {
		rxq->sw_bd_head = (rxq->sw_bd_head + 1) & MCACHE_MASK;
		rxq->sw_bd_cnt--;
		RTE_ASSERT(rxq->sw_bd_cnt >= 0);
		lsinic_sw_bd_push(rxq, (void **)&rxe, 1);
	}

	lsinic_bd_update_used_to_rc(rxq, bd_idx);
}

static __rte_always_inline void
lsinic_recv_dma_update(struct lsinic_queue *rxq,
	uint16_t bd_idx, void *rxe)
{
	struct lsinic_adapter *adapter = rxq->adapter;
	struct lsinic_bd_desc *rxdp = LSINIC_EP_BD_DESC(rxq, bd_idx);

	if ((adapter->cap & LSINIC_CAP_XFER_COMPLETE) ||
		(adapter->ep_cap & LSINIC_EP_CAP_RXQ_ORP)) {
#ifdef LSINIC_BD_CTX_IDX_USED
		rxdp->bd_status &= ~((uint32_t)RING_BD_STATUS_MASK);
		rxdp->bd_status |= RING_BD_ADDR_CHECK;
		rxdp->bd_status |= RING_BD_HW_COMPLETE;
#else
		rxdp->bd_status =
			RING_BD_HW_COMPLETE | RING_BD_ADDR_CHECK;
#endif
	} else {
		rxq->sw_bd_head = (rxq->sw_bd_head + 1) & MCACHE_MASK;
		rxq->sw_bd_cnt--;
		RTE_ASSERT(rxq->sw_bd_cnt >= 0);
		lsinic_sw_bd_push(rxq, (void **)&rxe, 1);
	}

	if (rxq->wdma_bd_start < 0)
		rxq->wdma_bd_start = bd_idx;
	rxq->wdma_bd_nb++;
}

static int
lsinic_queue_ep2rc_update_cfg(struct lsinic_queue *q)
{
	struct lsinic_adapter *adapter = q->adapter;
	enum egress_cnf_type e_type;
	enum ingress_notify_type i_type;
	const char *err_msg = NULL;
	int ret = 0;

	e_type = LSINIC_CAP_XFER_EGRESS_CNF_GET(adapter->cap);
	i_type = LSINIC_CAP_XFER_INGRESS_NOTIFY_GET(adapter->cap);

	q->ep2rc_update = EP2RC_INVALID_UPDATE;
	if (q->type == LSINIC_QUEUE_RX) {
		if (e_type == EGRESS_INDEX_CNF) {
			if (!q->ep2rc.free_idx) {
				ret = -EINVAL;
				err_msg = "No indexing mem";
				goto configure_done;
			}
			q->ep2rc_update = EP2RC_INDEX_UPDATE;
			q->local_free_idx = (void *)
				((char *)q->ep_bd_desc +
					LSINIC_BD_RING_SIZE);
		} else {
			if (adapter->ep_cap & LSINIC_EP_CAP_RXQ_WBD_DMA) {
				if (e_type == EGRESS_RING_CNF) {
					if (!q->ep2rc.rx_complete) {
						ret = -EINVAL;
						err_msg = "No DMA ring mem";
						goto configure_done;
					}
					q->ep2rc_update = EP2RC_RING_DMA_UPDATE;
				} else if (e_type == EGRESS_BD_CNF) {
					q->ep2rc_update = EP2RC_BD_DMA_UPDATE;
				} else {
					ret = -EINVAL;
					err_msg = "Invalid DMA confirm";
					goto configure_done;
				}
			} else {
				if (e_type == EGRESS_RING_CNF) {
					if (!q->ep2rc.rx_complete) {
						ret = -EINVAL;
						err_msg = "No ring mem";
						goto configure_done;
					}
					q->ep2rc_update = EP2RC_RING_UPDATE;
				} else if (e_type == EGRESS_BD_CNF) {
					q->ep2rc_update = EP2RC_BD_UPDATE;
				} else {
					ret = -EINVAL;
					err_msg = "Invalid confirm";
					goto configure_done;
				}
			}
		}
	} else {
		if (adapter->ep_cap & LSINIC_EP_CAP_TXQ_DMA_NO_RSP) {
			if (i_type == INGRESS_RING_NOTIFY) {
#ifdef LSINIC_BD_CTX_IDX_USED
				if (!q->ep2rc.tx_notify) {
					ret = -EINVAL;
					err_msg = "No DMA notify mem";
					goto configure_done;
				}
				q->ep2rc_update = EP2RC_RING_DMA_UPDATE;
#else
				ret = -EINVAL;
				err_msg = "DMA Notify needs CTX IDX enabled";
				goto configure_done;
#endif
			} else if (i_type == INGRESS_BD_NOTIFY) {
				q->ep2rc_update = EP2RC_BD_DMA_UPDATE;
			} else {
				ret = -EINVAL;
				err_msg = "Invalid DMA notify";
				goto configure_done;
			}
		} else {
			if (i_type == INGRESS_RING_NOTIFY) {
#ifdef LSINIC_BD_CTX_IDX_USED
				if (!q->ep2rc.tx_notify) {
					ret = -EINVAL;
					err_msg = "No notify mem";
					goto configure_done;
				}
				q->ep2rc_update = EP2RC_RING_UPDATE;
#else
				ret = -EINVAL;
				err_msg = "Notify needs CTX IDX enabled";
				goto configure_done;
#endif
			} else if (i_type == INGRESS_BD_NOTIFY) {
				q->ep2rc_update = EP2RC_BD_UPDATE;
			} else {
				ret = -EINVAL;
				err_msg = "Invalid notify";
				goto configure_done;
			}
		}
#ifdef LSINIC_BD_CTX_IDX_USED
		if (i_type == INGRESS_RING_NOTIFY) {
			q->local_notify = (void *)
				((char *)q->ep_bd_desc +
					LSINIC_BD_RING_SIZE);
		}
#endif
	}

configure_done:

	if (q->ep2rc_update == EP2RC_BD_UPDATE &&
		q->type == LSINIC_QUEUE_RX) {
		LSXINIC_PMD_INFO("port%d rxq%d BD cnf",
			q->port_id, q->reg_idx);
	} else if (q->ep2rc_update == EP2RC_RING_UPDATE &&
		q->type == LSINIC_QUEUE_RX) {
		LSXINIC_PMD_INFO("port%d rxq%d RING cnf",
			q->port_id, q->reg_idx);
	} else if (q->ep2rc_update == EP2RC_BD_DMA_UPDATE &&
		q->type == LSINIC_QUEUE_RX) {
		LSXINIC_PMD_INFO("port%d rxq%d BD DMA cnf",
			q->port_id, q->reg_idx);
	} else if (q->ep2rc_update == EP2RC_RING_DMA_UPDATE &&
		q->type == LSINIC_QUEUE_RX) {
		LSXINIC_PMD_INFO("port%d rxq%d RING DMA cnf",
			q->port_id, q->reg_idx);
	} else if (q->ep2rc_update == EP2RC_INDEX_UPDATE &&
		q->type == LSINIC_QUEUE_RX) {
		LSXINIC_PMD_INFO("port%d rxq%d INDEX cnf",
			q->port_id, q->reg_idx);
	} else if (q->ep2rc_update == EP2RC_BD_UPDATE &&
		q->type == LSINIC_QUEUE_TX) {
		LSXINIC_PMD_INFO("port%d txq%d BD notify",
			q->port_id, q->reg_idx);
	} else if (q->ep2rc_update == EP2RC_RING_UPDATE &&
		q->type == LSINIC_QUEUE_TX) {
		LSXINIC_PMD_INFO("port%d txq%d RING notify",
			q->port_id, q->reg_idx);
	} else if (q->ep2rc_update == EP2RC_BD_DMA_UPDATE &&
		q->type == LSINIC_QUEUE_TX) {
		LSXINIC_PMD_INFO("port%d txq%d BD DMA notify",
			q->port_id, q->reg_idx);
	} else if (q->ep2rc_update == EP2RC_RING_DMA_UPDATE &&
		q->type == LSINIC_QUEUE_TX) {
		LSXINIC_PMD_INFO("port%d txq%d RING DMA notify",
			q->port_id, q->reg_idx);
	} else if (q->ep2rc_update == EP2RC_INDEX_UPDATE &&
		q->type == LSINIC_QUEUE_TX) {
		LSXINIC_PMD_INFO("port%d txq%d INDEX notify",
			q->port_id, q->reg_idx);
	} else {
		LSXINIC_PMD_ERR("Invalid %s%d port%d ep2rc:%d",
			q->type == LSINIC_QUEUE_TX ?
			"TXQ" : "RXQ", q->reg_idx, q->port_id,
			q->ep2rc_update);
	}

	if (err_msg) {
		LSXINIC_PMD_ERR("Invalid EP2RC update: %s",
			err_msg);
	}

	return ret;
}

static int
lsinic_queue_start(struct lsinic_queue *q)
{
	struct lsinic_ring_reg *ring_reg = q->ep_reg;
	uint32_t msix_vector, i, cap;
	uint64_t bd_bus_addr, ring_bus_addr, ob_offset;
	uint64_t dma_src_base, dma_dst_base, step;
	int ret;
	uint32_t queue_idx = q->queue_id;
	struct lsinic_adapter *adapter = q->adapter;
	struct rte_lsx_pciep_device *lsinic_dev = adapter->lsinic_dev;
	struct lsinic_bdr_reg *rc_bdr_reg =
		LSINIC_REG_OFFSET(adapter->rc_ring_virt_base,
			LSINIC_RING_REG_OFFSET);
	struct rte_qdma_job *e2r_bd_dma_jobs = q->e2r_bd_dma_jobs;
	struct rte_qdma_job *r2e_bd_dma_jobs = q->r2e_bd_dma_jobs;
	struct lsinic_eth_reg *reg =
		LSINIC_REG_OFFSET(adapter->hw_addr,
			LSINIC_ETH_REG_OFFSET);

	LSXINIC_PMD_INFO("port%d %sq%d start, nb_desc:%d",
		q->port_id,
		q->type == LSINIC_QUEUE_TX ? "tx" : "rx",
		q->reg_idx, q->nb_desc);

	q->new_time_thresh =
		LSINIC_READ_REG(&ring_reg->iir) *
		rte_get_timer_hz() / 1000000; /* ns->s */
	q->new_desc_thresh = LSINIC_READ_REG(&ring_reg->icr);
	q->new_desc_thresh &= LSINIC_INT_THRESHOLD_MASK;

	if (lsinic_dev->mmsi_flag != LSINIC_DONT_INT) {
		msix_vector =
			(LSINIC_READ_REG(&ring_reg->icr) >>
			LSINIC_INT_VECTOR_SHIFT);
		q->msix_irq = msix_vector;
		if (!lsx_pciep_hw_sim_get(adapter->pcie_idx)) {
			q->msix_cmd =
				lsx_pciep_msix_get_cmd(q->adapter->lsinic_dev,
					msix_vector);
			q->msix_vaddr =
				lsx_pciep_msix_get_vaddr(q->adapter->lsinic_dev,
					msix_vector);
			if (q->msix_vaddr == 0) {
				LSXINIC_PMD_ERR("q->msix_vaddr == NULL");
				return -EINVAL;
			}
		}
	}

	bd_bus_addr = LSINIC_READ_REG_64B((uint64_t *)(&q->ep_reg->r_descl));
	if (bd_bus_addr) {
		ob_offset = bd_bus_addr - adapter->lsinic_dev->ob_map_bus_base;
		q->rc_bd_desc = (struct lsinic_bd_desc *)
			(lsinic_dev->ob_virt_base + ob_offset);
	} else {
		q->rc_bd_desc = q->ep_bd_desc;
	}

	ring_bus_addr =
		LSINIC_READ_REG_64B((uint64_t *)(&q->ep_reg->r_ep2rcl));
	if (ring_bus_addr) {
		ob_offset = ring_bus_addr -
			adapter->lsinic_dev->ob_map_bus_base;
		q->ep2rc.union_ring = lsinic_dev->ob_virt_base +
			ob_offset;
	} else {
		q->ep2rc.union_ring = NULL;
	}

	if (!q->ep2rc.union_ring) {
		/** Slow path*/
		rte_spinlock_lock(&adapter->cap_lock);
		cap = q->adapter->cap;
		if (q->type == LSINIC_QUEUE_RX)
			LSINIC_CAP_XFER_EGRESS_CNF_SET(cap,
				EGRESS_BD_CNF);
		else
			LSINIC_CAP_XFER_INGRESS_NOTIFY_SET(cap,
				INGRESS_BD_NOTIFY);
		q->adapter->cap = cap;
		LSINIC_WRITE_REG(&reg->cap, adapter->cap);
		rte_spinlock_unlock(&adapter->cap_lock);
	}

	ret = lsinic_queue_ep2rc_update_cfg(q);
	if (ret)
		return ret;

	if (q->ep2rc_update == EP2RC_RING_DMA_UPDATE &&
		q->type == LSINIC_QUEUE_RX) {
		dma_src_base = DPAA2_VADDR_TO_IOVA(adapter->complete_src);
		dma_dst_base = q->ob_base + ring_bus_addr;
		step = sizeof(uint8_t);
	}
#ifdef LSINIC_BD_CTX_IDX_USED
	else if (q->ep2rc_update == EP2RC_RING_DMA_UPDATE &&
		q->type == LSINIC_QUEUE_TX) {
		dma_src_base = DPAA2_VADDR_TO_IOVA(q->local_notify);
		dma_dst_base = q->ob_base + ring_bus_addr;
		step = sizeof(struct ep2rc_notify);
	}
#endif
	else {
		dma_src_base = DPAA2_VADDR_TO_IOVA(&q->ep_bd_desc[0]);
		dma_dst_base = q->ob_base + bd_bus_addr;
		step = sizeof(struct lsinic_bd_desc);
	}
	q->bd_dma_step = step;

	for (i = 0; i < q->nb_desc; i++) {
		memset(&e2r_bd_dma_jobs[i], 0, sizeof(struct rte_qdma_job));
		e2r_bd_dma_jobs[i].src = dma_src_base + i * step;
		e2r_bd_dma_jobs[i].dest = dma_dst_base + i * step;
		e2r_bd_dma_jobs[i].flags = RTE_QDMA_JOB_SRC_PHY |
			RTE_QDMA_JOB_DEST_PHY;
		if (q->type == LSINIC_QUEUE_TX)
			e2r_bd_dma_jobs[i].vq_id = q->dma_vq;
		else
			e2r_bd_dma_jobs[i].vq_id = q->pair->dma_vq;
	}

	dma_src_base = q->ob_base + bd_bus_addr;
	dma_dst_base = DPAA2_VADDR_TO_IOVA(&q->ep_bd_desc[0]);
	step = sizeof(struct lsinic_bd_desc);

	for (i = 0; i < q->nb_desc; i++) {
		memset(&r2e_bd_dma_jobs[i], 0, sizeof(struct rte_qdma_job));
		r2e_bd_dma_jobs[i].src = dma_src_base + i * step;
		r2e_bd_dma_jobs[i].dest = dma_dst_base + i * step;
		r2e_bd_dma_jobs[i].flags =
			RTE_QDMA_JOB_SRC_PHY |
			RTE_QDMA_JOB_DEST_PHY;
		if (q->type == LSINIC_QUEUE_RX)
			r2e_bd_dma_jobs[i].vq_id = q->dma_vq;
		else
			r2e_bd_dma_jobs[i].vq_id = q->pair->dma_vq;
	}

	if (q->type == LSINIC_QUEUE_RX) {
		if (adapter->cap & LSINIC_CAP_XFER_COMPLETE)
			q->recv_rxe = lsinic_recv_rxe_no_dq;
		else if (adapter->ep_cap & LSINIC_EP_CAP_RXQ_ORP)
			q->recv_rxe = lsinic_recv_rxe_orp;
		else
			q->recv_rxe = lsinic_recv_rxe;

		if (q->ep2rc_update == EP2RC_INDEX_UPDATE)
			q->recv_update = lsinic_recv_index_update;
		else if (q->ep2rc_update == EP2RC_BD_UPDATE)
			q->recv_update = lsinic_recv_rxbd_update;
		else if (q->ep2rc_update == EP2RC_RING_UPDATE)
			q->recv_update = lsinic_recv_ring_update;
		else
			q->recv_update = lsinic_recv_dma_update;
	}

	/* Note: ep-rx == rc-tx */
	if (q->type == LSINIC_QUEUE_TX) {
		if (adapter->rc_ring_virt_base)
			q->rc_reg = &rc_bdr_reg->rx_ring[queue_idx];
		else
			q->rc_reg = q->ep_reg;
	} else {
		if (adapter->rc_ring_virt_base)
			q->rc_reg = &rc_bdr_reg->tx_ring[queue_idx];
		else
			q->rc_reg = q->ep_reg;
	}

	if (!q->rc_bd_desc) {
		LSXINIC_PMD_ERR("q->rc_bd_desc == NULL");
		return -ENOMEM;
	}

	ret = lsinic_queue_dma_create(q);
	if (ret < 0) {
		LSXINIC_PMD_ERR("dma create for port%d %s%d failed",
			q->port_id,
			q->type == LSINIC_QUEUE_RX ? "rxq" : "txq",
			q->queue_id);

		return ret;
	}

	lsinic_queue_hw_offload_cfg(q);

	lsinic_queue_reset(q);

	if (q->type == LSINIC_QUEUE_RX) {
		rte_memcpy(q->rc_bd_desc, q->ep_bd_desc,
			q->nb_desc * sizeof(struct lsinic_bd_desc));
		if (LSINIC_CAP_XFER_EGRESS_CNF_GET(adapter->cap) ==
			EGRESS_RING_CNF) {
			for (i = 0; i < q->nb_desc; i++)
				q->ep2rc.rx_complete[i] = RING_BD_READY;
		}
	}

	if (q->type == LSINIC_QUEUE_RX &&
		(adapter->rx_pcidma_dbg || adapter->tx_pcidma_dbg)) {
		struct lsinic_queue *txq = q->pair;

		if (adapter->rx_pcidma_dbg) {
			q->dma_test.pci_addr =
				adapter->rx_pcidma_dbg +
				queue_idx * q->nb_desc *
				LSINIC_QDMA_TEST_PKT_MAX_LEN;
		}

		if (adapter->tx_pcidma_dbg) {
			txq->dma_test.pci_addr =
				adapter->tx_pcidma_dbg +
				queue_idx * txq->nb_desc *
				LSINIC_QDMA_TEST_PKT_MAX_LEN;
		}
	}

	return ret;
}

static int
lsinic_cloned_mbuf_to_fd(struct rte_mbuf *mbuf,
	struct qbman_fd *fd, uint16_t bpid,
	struct rte_mbuf **free_buf)
{
	/* Assert the mbuf to be sent has NOT been migrated between cores.*/
	if (unlikely(!(mbuf->ol_flags & LSINIC_SHARED_MBUF)))
		return -1;

	RTE_ASSERT(*((uint8_t *)mbuf->dynfield1) == rte_lcore_id());
	DPAA2_SET_FD_ADDR(fd, DPAA2_MBUF_VADDR_TO_IOVA(mbuf));
	DPAA2_SET_FD_LEN(fd, mbuf->data_len);
	DPAA2_SET_ONLY_FD_BPID(fd, bpid);
	DPAA2_SET_FD_OFFSET(fd, mbuf->data_off);
	DPAA2_SET_FD_FRC(fd, 0);
	DPAA2_RESET_FD_CTRL(fd);
	DPAA2_RESET_FD_FLC(fd);

	if (unlikely(RTE_MBUF_DIRECT(mbuf))) {
		if (mbuf->refcnt > 1) {
			DPAA2_SET_FD_IVP(fd);
			mbuf->refcnt--;
		}
		mbuf->ol_flags = 0;
	} else {
		struct rte_mbuf *mi;

		mi = rte_mbuf_from_indirect(mbuf);
		RTE_ASSERT(*((uint8_t *)mi->dynfield1) == rte_lcore_id());
		if (mi->refcnt > 1) {
			DPAA2_SET_FD_IVP(fd);
			mi->refcnt--;
		}
		lsinic_mbuf_reset(mbuf);
		*free_buf = mbuf;

		return 1;
	}

	return 0;
}

static void
lsinic_queue_stop(struct lsinic_queue *q)
{
	struct lsinic_ring_reg *ring_reg = q->ep_reg;

	q->status = LSINIC_QUEUE_STOP;
	ring_reg->sr = q->status;
	LSINIC_WRITE_REG(&q->rc_reg->sr, q->status);
	lsinic_queue_hw_offload_decfg(q);
}

static int
lsinic_queue_init(struct lsinic_queue *q)
{
	struct lsinic_ring_reg *ring_reg = q->ep_reg;

	ring_reg->barl = q->nb_desc;
	LSINIC_WRITE_REG(&q->rc_reg->barl, q->nb_desc);

	q->status = LSINIC_QUEUE_UNAVAILABLE;
	ring_reg->sr = q->status;
	LSINIC_WRITE_REG(&q->rc_reg->sr, q->status);

	return 0;
}

static void
lsinic_queue_enable_start(struct lsinic_queue *q)
{
	struct lsinic_ring_reg *ring_reg = q->ep_reg;

	q->status = LSINIC_QUEUE_START;
	ring_reg->sr = q->status;
	LSINIC_WRITE_REG(&q->rc_reg->sr, q->status);
}

static void
lsinic_queue_release_mbufs(struct lsinic_queue *q)
{
	unsigned int i;

	if (q->sw_ring) {
		for (i = 0; i < q->nb_desc; i++) {
			if (q->sw_ring[i].mbuf) {
				rte_pktmbuf_free_seg(q->sw_ring[i].mbuf);
				q->sw_ring[i].mbuf = NULL;
			}
		}
	}
}

static void
lsinic_queue_free_swring(struct lsinic_queue *q)
{
	if (!q)
		return;

	if (q->sw_ring)
		rte_free(q->sw_ring);
	if (q->dma_jobs)
		rte_free(q->dma_jobs);
}

void
lsinic_queue_release(struct lsinic_queue *q)
{
	if (!q)
		return;

	lsinic_queue_release_mbufs(q);
	lsinic_queue_free_swring(q);
	lsinic_queue_dma_release(q);
	rte_free(q);
}

struct lsinic_queue *
lsinic_queue_alloc(struct lsinic_adapter *adapter,
	uint16_t queue_idx,
	int socket_id, uint32_t nb_desc,
	enum LSINIC_QEUE_TYPE type)
{
	struct lsinic_queue *q;
	uint32_t tx_rs_thresh;
	struct lsinic_dev_reg *cfg =
		LSINIC_REG_OFFSET(adapter->hw_addr, LSINIC_DEV_REG_OFFSET);

	RTE_SET_USED(lsinic_cloned_mbuf_to_fd);

	/* Validate number of transmit descriptors.
	 * It must not exceed hardware maximum, and must be multiple
	 * of LSINIC_ALIGN.
	 */
	if (((nb_desc * sizeof(struct lsinic_bd_desc)) % LSINIC_ALIGN) != 0 ||
	    nb_desc > LSINIC_MAX_RING_DESC ||
	    nb_desc < LSINIC_MIN_RING_DESC) {
		LSXINIC_PMD_ERR("lsinic queue cannot support %d descs",
			     nb_desc);
		return NULL;
	}

	tx_rs_thresh = DEFAULT_TX_RS_THRESH;

	/* First allocate the tx queue data structure */
	if (type == LSINIC_QUEUE_RX)
		q = &adapter->rxqs[queue_idx];
	else
		q = &adapter->txqs[queue_idx];

	q->adapter = adapter;
	q->type = type;

	if (cfg->rbp_enable)
		q->ob_base = 0;
	else
		q->ob_base = adapter->lsinic_dev->ob_phy_base;

	q->ob_virt_base = adapter->lsinic_dev->ob_virt_base;
	q->nb_desc = nb_desc;
	q->new_desc_thresh = tx_rs_thresh;
	q->queue_id = queue_idx;
	q->reg_idx = queue_idx;
	q->nb_q = 1;
	q->dma_vq = -1;

	/* Allocate software ring */
	q->sw_ring = rte_zmalloc_socket("q->sw_ring",
		sizeof(struct lsinic_sw_bd) * nb_desc,
		RTE_CACHE_LINE_SIZE, socket_id);
	if (!q->sw_ring) {
		LSXINIC_PMD_ERR("Failed to create sw_ring");
		goto _err;
	}
	q->sw_bd_pool = rte_malloc(NULL, sizeof(void *) * nb_desc, 64);
	if (!q->sw_bd_pool) {
		LSXINIC_PMD_ERR("Failed to create entry_pool");
		goto _err;
	}
	q->sw_bd_pool_size = nb_desc;
	q->sw_bd_pool_cnt = 0;

	/* Allocate DMA jobs ring */
	q->dma_jobs = rte_zmalloc_socket("q->dma_jobs",
				sizeof(struct rte_qdma_job) * nb_desc,
				RTE_CACHE_LINE_SIZE, socket_id);
	if (!q->dma_jobs) {
		LSXINIC_PMD_ERR("Failed to create dma_jobs");
		goto _err;
	}

	q->e2r_bd_dma_jobs = rte_zmalloc_socket(NULL,
					sizeof(struct rte_qdma_job) * nb_desc,
					RTE_CACHE_LINE_SIZE, socket_id);
	if (!q->e2r_bd_dma_jobs) {
		LSXINIC_PMD_ERR("Failed to create EP to RC bd_dma_jobs");
		goto _err;
	}

	q->r2e_bd_dma_jobs = rte_zmalloc_socket(NULL,
					sizeof(struct rte_qdma_job) * nb_desc,
					RTE_CACHE_LINE_SIZE, socket_id);
	if (!q->r2e_bd_dma_jobs) {
		LSXINIC_PMD_ERR("Failed to create RC to EP bd_dma_jobs");
		goto _err;
	}

	q->mg_dsc = rte_zmalloc_socket(NULL,
			sizeof(struct lsinic_dpni_mg_dsc) * nb_desc,
			RTE_CACHE_LINE_SIZE, socket_id);
	if (!q->mg_dsc) {
		LSXINIC_PMD_ERR("Failed to alloc merge descriptors");
		goto _err;
	}
	q->mg_dsc_head = 0;
	q->mg_dsc_tail = 0;

	return q;

_err:
	lsinic_queue_release(q);
	return NULL;
}

static void
lsinic_queue_trigger_interrupt(struct lsinic_queue *q)
{
	if (!q->new_desc_thresh) {
		q->new_desc = 0;
		return;
	}
	if (lsinic_queue_msi_masked(q))
		return;

	if (!q->new_desc)
		return;

	if (!lsx_pciep_hw_sim_get(q->adapter->pcie_idx)) {
		if (q->new_desc_thresh && (q->new_desc >= q->new_desc_thresh ||
			(lsinic_timeout(q)))) {
			/* MSI */
			lsx_pciep_msix_cmd_send(q->msix_vaddr, q->msix_cmd);
			q->new_desc = 0;
		}
	}
}

/*********************************************************************
 *
 *  TX functions
 *
 **********************************************************************/
#ifdef LSINIC_BD_CTX_IDX_USED
static void
lsinic_tx_notify_burst_to_rc(struct lsinic_queue *txq)
{
	uint16_t pending, burst1 = 0, burst2 = 0;
	uint16_t bd_idx, bd_idx_first;
	int i;
	struct ep2rc_notify *tx_notify =
		txq->ep2rc.tx_notify;

	pending = txq->next_dma_idx - txq->next_used_idx;
	bd_idx_first = txq->next_used_idx & (txq->nb_desc - 1);
	if ((bd_idx_first + pending) > txq->nb_desc) {
		burst1 = txq->nb_desc - bd_idx_first;
		burst2 = pending - burst1;
	} else {
		burst1 = pending;
		burst2 = 0;
	}
	for (i = 0; i < pending; i++) {
		bd_idx = txq->next_used_idx & (txq->nb_desc - 1);
		lsinic_ep_notify_to_rc(txq, bd_idx, 0);
	}
	lsinic_pcie_memcp_align((uint8_t *)&tx_notify[bd_idx_first],
		(uint8_t *)&txq->local_notify[bd_idx_first],
		burst1 * sizeof(struct ep2rc_notify));
	if (burst2) {
		lsinic_pcie_memcp_align((uint8_t *)&tx_notify[0],
			(uint8_t *)&txq->local_notify[0],
			burst2 * sizeof(struct ep2rc_notify));
	}
	txq->next_used_idx += pending;
	txq->new_desc += pending;
	lsinic_queue_trigger_interrupt(txq);
}
#endif

static void
lsinic_tx_update_to_rc(struct lsinic_queue *txq)
{
	uint16_t pending;
	uint16_t bd_idx;
	int i;

#ifdef LSINIC_BD_CTX_IDX_USED
	if (txq->ep2rc_update == EP2RC_RING_UPDATE) {
		lsinic_tx_notify_burst_to_rc(txq);

		return;
	}
#endif

	pending = txq->next_dma_idx - txq->next_used_idx;
	for (i = 0; i < pending; i++) {
		bd_idx = txq->next_used_idx & (txq->nb_desc - 1);
#ifdef LSINIC_BD_CTX_IDX_USED
		if (txq->ep2rc_update == EP2RC_RING_UPDATE)
			lsinic_ep_notify_to_rc(txq, bd_idx, 1);
		else
#endif
			lsinic_bd_update_used_to_rc(txq, bd_idx);
		txq->next_used_idx++;
	}

	txq->new_desc += pending;

	lsinic_queue_trigger_interrupt(txq);
}

static void lsinic_tx_dma_clean(struct lsinic_queue *txq)
{
	struct rte_qdma_job *jobs[LSINIC_QDMA_DQ_MAX_NB];
	struct rte_qdma_job *dma_job;
	struct lsinic_sw_bd *txe = NULL;
	uint16_t dma_idx, pkts_dq = 0;
	int i, ret = 0, clean_count = 100;
	struct rte_qdma_enqdeq context;

clean_again:
	if (txq->pkts_eq == txq->pkts_dq)
		return;

	LSXINIC_PMD_ERR("TXQ clean eq:%ld, dq:%ld",
		txq->pkts_eq, txq->pkts_dq);

	context.vq_id = txq->dma_vq;
	context.job = jobs;
	ret = rte_qdma_dequeue_buffers(txq->dma_id, NULL,
			LSINIC_QDMA_DQ_MAX_NB,
			&context);
	LSXINIC_PMD_ERR("TXQ clean dq ret:%d", ret);
	if (!ret)
		clean_count--;

	if (clean_count <= 0)
		rte_panic("TXQ qDMA job en-queued missed!!!!, have to quit!");

	for (i = 0; i < ret; i++) {
		dma_job = jobs[i];
		RTE_ASSERT(dma_job);
		dma_job->flags &= ~LSINIC_QDMA_JOB_USING_FLAG;
		txq->bytes_dq += dma_job->len;
		txe = (struct lsinic_sw_bd *)dma_job->cnxt;
		if (dma_job->status != 0) {
			LSXINIC_PMD_ERR("QDMA fd returned err: %d",
				dma_job->status);
		}
		if (!txe)
			continue;
		pkts_dq++;
		dma_idx = txq->next_dma_idx
				& (txq->nb_desc - 1);
		lsinic_bd_dma_complete_update(txq, dma_idx, &txe->bd);
		if (likely(!(txe->mbuf->ol_flags & LSINIC_SHARED_MBUF))) {
			rte_pktmbuf_free(txe->mbuf);
		} else {
			if ((RTE_MBUF_DIRECT(txe->mbuf))) {
				txe->mbuf->ol_flags = 0;
				if (txe->mbuf->refcnt > 1)
					txe->mbuf->refcnt--;
				else
					rte_pktmbuf_free(txe->mbuf);
			} else {
				struct rte_mbuf *mi =
					rte_mbuf_from_indirect(txe->mbuf);

				if (mi->refcnt > 1)
					mi->refcnt--;
				else
					rte_pktmbuf_free(mi);
				lsinic_mbuf_reset(txe->mbuf);
				rte_pktmbuf_free(txe->mbuf);
			}
		}
		txe->mbuf = NULL;
		txq->next_dma_idx++;
		lsinic_sw_bd_push(txq, (void **)&txe, 1);
	}
	txq->pkts_dq += pkts_dq;

	lsinic_tx_update_to_rc(txq);
	LSXINIC_PMD_ERR("TXQ clean avail:%d, dma:%d, used:%d",
		txq->next_avail_idx, txq->next_dma_idx, txq->next_used_idx);
	goto clean_again;
}

static uint16_t
lsinic_tx_dma_dequeue(struct lsinic_queue *txq)
{
	struct rte_qdma_job *jobs[LSINIC_QDMA_DQ_MAX_NB];
	struct rte_qdma_job *dma_job;
	struct lsinic_sw_bd *txe = NULL;
	uint16_t dma_idx, pkts_dq = 0;
	int i, ret = 0, need_clean = 0;
	struct rte_qdma_enqdeq context;

	if (txq->pkts_eq == txq->pkts_dq && txq->recycle_txq)
		return 0;

	context.vq_id = txq->dma_vq;
	context.job = jobs;
	ret = rte_qdma_dequeue_buffers(txq->dma_id, NULL,
			LSINIC_QDMA_DQ_MAX_NB,
			&context);
	if (!txq->recycle_txq && !ret)
		lsinic_qdma_tx_multiple_enqueue(txq, false);

	for (i = 0; i < ret; i++) {
		dma_job = jobs[i];
		RTE_ASSERT(dma_job);
		if (unlikely(dma_job->cnxt &&
			!(dma_job->flags & LSINIC_QDMA_JOB_USING_FLAG))) {
			LSXINIC_PMD_ERR("TX duplicated jobs[%d]", i);
			need_clean++;
			continue;
		}
		dma_job->flags &= ~LSINIC_QDMA_JOB_USING_FLAG;
		txq->bytes_dq += dma_job->len;
		txe = (struct lsinic_sw_bd *)dma_job->cnxt;
		if (dma_job->status != 0) {
			LSXINIC_PMD_DBG("QDMA fd returned err: %d\n",
				dma_job->status);
		}
		if (!txe)
			continue;
		pkts_dq++;
		dma_idx = txq->next_dma_idx
				& (txq->nb_desc - 1);
		lsinic_bd_dma_complete_update(txq, dma_idx, &txe->bd);
#ifdef LSXINIC_ASSERT_PKT_SIZE
		if (lxsnic_test_staterr(&txe->bd, LSINIC_BD_CMD_MG)) {
			int count =
				((txe->bd.len_cmd & LSINIC_BD_MG_NUM_MASK) >>
				LSINIC_BD_MG_NUM_SHIFT) + 1, j, pktlen;
			struct lsinic_mg_header *mg_header =
				(struct lsinic_mg_header *)
				((char *)txe->mbuf->buf_addr +
				txe->mbuf->data_off -
				sizeof(struct lsinic_mg_header));

			for (j = 0; j < count; j++) {
				pktlen =
				lsinic_mg_entry_len(mg_header->len_cmd[j]);
				RTE_ASSERT(pktlen == (LSXINIC_ASSERT_PKT_SIZE -
					LSINIC_ETH_FCS_SIZE));
			}
		}
#endif
		if (likely(!(txe->mbuf->ol_flags & LSINIC_SHARED_MBUF))) {
			rte_pktmbuf_free(txe->mbuf);
		} else {
			if ((RTE_MBUF_DIRECT(txe->mbuf))) {
				txe->mbuf->ol_flags = 0;
				if (txe->mbuf->refcnt > 1)
					txe->mbuf->refcnt--;
				else
					rte_pktmbuf_free(txe->mbuf);
			} else {
				struct rte_mbuf *mi =
					rte_mbuf_from_indirect(txe->mbuf);

				if (mi->refcnt > 1)
					mi->refcnt--;
				else
					rte_pktmbuf_free(mi);
				lsinic_mbuf_reset(txe->mbuf);
				rte_pktmbuf_free(txe->mbuf);
			}
		}
		txe->mbuf = NULL;
		txq->next_dma_idx++;
		lsinic_sw_bd_push(txq, (void **)&txe, 1);
	}
	txq->pkts_dq += pkts_dq;

	if (need_clean)
		lsinic_tx_dma_clean(txq);

	return i;
}

static uint16_t
lsinic_try_to_merge(struct lsinic_queue *txq,
	struct rte_mbuf **tx_pkts,
	uint16_t nb_pkts, uint16_t bd_idx)
{
	struct lsinic_bd_desc *ep_txd;
	struct rte_qdma_job *dma_job;
	struct lsinic_sw_bd *txe;
	struct rte_mbuf *tx_pkt, *free_pkt = NULL;

	uint16_t mg_num;
	uint16_t mg_len = 0, data_len;
	uint16_t i;

	char *buf, *data = NULL;
	uint64_t buf_dma_addr = 0;
	struct lsinic_mg_header *mg_header;
	uint16_t align_len, align_off;

	if (tx_pkts[0]->nb_segs > 1)
		return 0;

	/* how many packets can be merged */
	for (mg_num = 0; mg_num < nb_pkts; mg_num++) {
		tx_pkt = tx_pkts[mg_num];
		mg_len += ALIGN(tx_pkt->pkt_len, LSINIC_MG_ALIGN_SIZE);
		/* todo calculate sg mbuf */
		if (mg_len > txq->adapter->data_room_size)
			break;
		if (mg_num == LSINIC_MERGE_MAX_NUM)
			break;
		if (tx_pkt->pkt_len > txq->adapter->merge_threshold)
			break;
	}

	/* Not need to merge */
	if (mg_num <= 1)
		return 0;

	mg_len += sizeof(struct lsinic_mg_header);

	ep_txd = LSINIC_EP_BD_DESC(txq, bd_idx);
	dma_job = &txq->dma_jobs[bd_idx];

	if (txq->adapter->ep_cap & LSINIC_EP_CAP_TXQ_DMA_NO_RSP)
		txe = &txq->sw_ring[bd_idx];
	else
		lsinic_sw_bd_pop(txq, (void **)&txe, 1);

	/* The first packet */
	if (!(tx_pkts[0]->ol_flags & LSINIC_SHARED_MBUF)) {
		tx_pkt = tx_pkts[0];
	} else {
		tx_pkt = rte_pktmbuf_alloc(tx_pkts[0]->pool);
		tx_pkt->nb_segs = 1;
		tx_pkt->next = NULL;
		tx_pkt->data_off = RTE_PKTMBUF_HEADROOM;
		rte_memcpy((char *)tx_pkt->buf_addr + tx_pkt->data_off,
			(char *)tx_pkts[0]->buf_addr + tx_pkts[0]->data_off,
			tx_pkts[0]->pkt_len);
		tx_pkt->pkt_len = tx_pkts[0]->pkt_len;
		tx_pkt->data_len = tx_pkts[0]->data_len;

		if ((RTE_MBUF_DIRECT(tx_pkts[0]))) {
			tx_pkts[0]->ol_flags = 0;
			if (tx_pkts[0]->refcnt > 1)
				tx_pkts[0]->refcnt--;
			else
				rte_pktmbuf_free(tx_pkts[0]);
		} else {
			struct rte_mbuf *mi;

			mi = rte_mbuf_from_indirect(tx_pkts[0]);
			if (mi->refcnt > 1)
				mi->refcnt--;
			else
				rte_pktmbuf_free(mi);

			lsinic_mbuf_reset(tx_pkts[0]);
			rte_pktmbuf_free(tx_pkts[0]);
		}
	}
	if (txe->mbuf)
		free_pkt = txe->mbuf;

	txe->mbuf = tx_pkt;
	buf_dma_addr = rte_mbuf_data_iova(tx_pkt);
	buf_dma_addr -= sizeof(struct lsinic_mg_header);

	data = (char *)rte_pktmbuf_mtod(tx_pkt, char *);
	data -= sizeof(struct lsinic_mg_header);
	mg_header = (struct lsinic_mg_header *)data;
	align_len = ALIGN(tx_pkt->pkt_len, LSINIC_MG_ALIGN_SIZE);
	align_off = align_len - tx_pkt->pkt_len;
	mg_header->len_cmd[0] =
		lsinic_mg_entry_set(tx_pkt->pkt_len, align_off);

	buf = data + sizeof(struct lsinic_mg_header) + tx_pkt->data_len;
	mg_len = ALIGN(tx_pkt->pkt_len, LSINIC_MG_ALIGN_SIZE) +
					sizeof(struct lsinic_mg_header);
	buf = data + mg_len;

	txq->bytes += tx_pkt->pkt_len;
	txq->bytes_fcs += tx_pkt->pkt_len + LSINIC_ETH_FCS_SIZE;
	txq->bytes_overhead += tx_pkt->pkt_len + LSINIC_ETH_OVERHEAD_SIZE;

	for (i = 1; i < mg_num; i++) {
		if ((i + 2) < mg_num) {
			char *p = rte_pktmbuf_mtod(tx_pkts[i + 1], char *);

			/* Prefetch mbuf for the next */
			rte_lsinic_prefetch(p);
			p = rte_pktmbuf_mtod(tx_pkts[i + 2], char *);
			/* Prefetch data for the next next data*/
			rte_lsinic_prefetch(p);
		}

		tx_pkt = tx_pkts[i];

		align_len = ALIGN(tx_pkt->pkt_len, LSINIC_MG_ALIGN_SIZE);
		align_off = align_len - tx_pkt->pkt_len;
		mg_header->len_cmd[i] =
			lsinic_mg_entry_set(tx_pkt->pkt_len, align_off);
		rte_memcpy(buf, rte_pktmbuf_mtod(tx_pkt, char *),
			tx_pkt->pkt_len);
		mg_len += align_len;
		buf = data + mg_len;
		txq->bytes += tx_pkt->pkt_len;
		txq->bytes_fcs += tx_pkt->pkt_len + LSINIC_ETH_FCS_SIZE;
		txq->bytes_overhead += tx_pkt->pkt_len +
			LSINIC_ETH_OVERHEAD_SIZE;
	}

	if (i < LSINIC_MERGE_MAX_NUM)
		mg_header->len_cmd[i] = 0;

	for (i = 1; i < mg_num; i++) {
		if (tx_pkts[i]->ol_flags & LSINIC_SHARED_MBUF) {
			if ((RTE_MBUF_DIRECT(tx_pkts[i]))) {
				tx_pkts[i]->ol_flags = 0;
				if (tx_pkts[i]->refcnt > 1)
					tx_pkts[i]->refcnt--;
			} else {
				struct rte_mbuf *mi;

				mi = rte_mbuf_from_indirect(tx_pkts[i]);
				if (mi->refcnt > 1)
					mi->refcnt--;
				else
					rte_pktmbuf_free(mi);
				lsinic_mbuf_reset(tx_pkts[i]);
			}
		}
	}

	data_len = mg_len - sizeof(struct lsinic_mg_header);

	if (free_pkt) {
		tx_pkts[0] = free_pkt;
		rte_mempool_put_bulk(tx_pkts[0]->pool,
			(void *)&tx_pkts[0], mg_num);
	} else {
		rte_mempool_put_bulk(tx_pkts[0]->pool,
			(void *)&tx_pkts[1], mg_num - 1);
	}
	txq->packets += mg_num;
	ep_txd->len_cmd = LSINIC_BD_CMD_EOP | LSINIC_BD_CMD_MG;
	ep_txd->len_cmd |= data_len;
	ep_txd->len_cmd |= (((uint32_t)(mg_num - 1)) << LSINIC_BD_MG_NUM_SHIFT);
	rte_memcpy(&txe->bd, ep_txd, sizeof(struct lsinic_bd_desc));

#ifdef LSINIC_BD_CTX_IDX_USED
	if (txq->local_notify) {
		txq->local_notify[bd_idx].total_len = data_len;
		EP2RC_TX_IDX_CNT_SET(txq->local_notify[bd_idx].cnt_idx,
			lsinic_bd_ctx_idx(ep_txd->bd_status),
			mg_num);
	}
#endif
	dma_job->src = buf_dma_addr;
	dma_job->dest = txq->ob_base + ep_txd->pkt_addr;
	dma_job->len = mg_len;
	dma_job->cnxt = (uint64_t)txe;

	if (txq->wdma_bd_start < 0)
		txq->wdma_bd_start = bd_idx;
	txq->wdma_bd_nb++;

	LSXINIC_PMD_DBG("port%d txq%d BD%d src:0x%llx dst:0x%llx CB:%d len:%d",
		   txq->port_id,
		   txq->queue_id,
		   bd_idx,
		   (unsigned long long)dma_job->src,
		   (unsigned long long)dma_job->dest,
		   mg_num,
		   mg_len);

	return mg_num;
}

static inline int lsinic_tx_bd_available(struct lsinic_queue *txq,
	uint16_t bd_idx)
{
	struct lsinic_bd_desc *ep_txd = LSINIC_EP_BD_DESC(txq, bd_idx);
	int full_count = 0;

	if (!(((uint64_t)ep_txd) & RTE_CACHE_LINE_MASK))
		rte_lsinic_prefetch((uint8_t *)ep_txd + RTE_CACHE_LINE_SIZE);

	while (unlikely((ep_txd->bd_status & RING_BD_STATUS_MASK) !=
					RING_BD_READY)) {
		if (!(txq->adapter->ep_cap & LSINIC_EP_CAP_TXQ_DMA_NO_RSP)) {
			if (txq->pkts_eq > txq->pkts_dq) {
				lsinic_tx_dma_dequeue(txq);
				lsinic_tx_update_to_rc(txq);
			}
		}
		full_count++;
		if (full_count > LSINIC_RING_FULL_THRESH_COUNT)
			return 0;
	}

	return 1;
}

static uint16_t
lsinic_cpu_merge_xmit(struct lsinic_queue *txq,
	struct rte_mbuf **tx_pkts,
	uint16_t nb_pkts)
{
	int ret;
	uint16_t bd_idx;

	bd_idx = txq->next_avail_idx & (txq->nb_desc - 1);

	/* Make sure there are enough TX descriptors available to
	 * transmit the entire packet.
	 * nb_used better be less than or equal to txq->tx_rs_thresh
	 */
	if (unlikely(!lsinic_tx_bd_available(txq, bd_idx))) {
#ifdef LSXINIC_PMD_DBG_ENABLE
		struct lsinic_bd_desc *ep_txd = LSINIC_EP_BD_DESC(txq, bd_idx);

		LSXINIC_PMD_DBG("%s, Status of TX bd[%d]:%d on cpu(%d)",
			__func__, bd_idx, ep_txd->bd_status,
			rte_lcore_id());
#endif
		txq->ring_full++;
		txq->drop_packet_num += nb_pkts;
		ret = 0;
		goto xmit_quit;
	}

	LSXINIC_PMD_DBG("port%d txq%d next_avail_idx=%d bd_idx=%d",
		txq->port_id, txq->queue_id,
		txq->next_avail_idx, bd_idx);

	ret = lsinic_try_to_merge(txq, tx_pkts, nb_pkts, bd_idx);
	if (ret) {
		lsinic_bd_dma_start_update(txq, bd_idx);
		txq->jobs_pending++;
		lsinic_qdma_tx_multiple_enqueue(txq, true);
		txq->next_avail_idx++;
	}

xmit_quit:
	return ret;
}

static uint16_t
lsinic_xmit_pkts_burst(struct lsinic_queue *txq,
	struct rte_mbuf **tx_pkts,
	uint16_t nb_pkts, int mg_enable)
{
	uint16_t tx_num = 0;
	int ret, free_idx = 0;
	const int bulk_free = 1;
	struct rte_mbuf *free_pkts[nb_pkts];
	struct rte_mbuf *free_pkt = NULL;
	struct rte_mbuf **ppkt = NULL;

	if (bulk_free)
		ppkt = &free_pkt;

	while (nb_pkts) {
		ret = 0;
		if (mg_enable)
			ret = lsinic_cpu_merge_xmit(txq, &tx_pkts[tx_num],
					nb_pkts);
		if (ret) {
			tx_num += ret;
			nb_pkts -= ret;
		} else {
			ret = lsinic_xmit_merged_one_pkt(txq, tx_pkts[tx_num],
					0, ppkt);
			if (ppkt && *ppkt) {
				free_pkts[free_idx] = *ppkt;
				free_idx++;
				*ppkt = NULL;
			}
			if (ret != 1) {
				rte_pktmbuf_free_seg(tx_pkts[tx_num]);
				txq->errors++;
				tx_num++;
				nb_pkts--;
				continue;
			}

			tx_num++;
			nb_pkts--;
		}
	}

	if (free_idx > 0)
		rte_pktmbuf_free_bulk(free_pkts, free_idx);

	if (!txq->new_desc)
		txq->new_tsc = rte_rdtsc();

	return tx_num;
}

#undef LSINIC_TX_DIRECT_ASYNC

static uint16_t
lsinic_xmit_directly(struct rte_mbuf **tx_pkts,
	uint16_t nb_pkts, struct lsinic_queue *txq,
	struct rte_mbuf **mg_pkts)
{
	uint16_t i, direct_nb = 0, mg_nb = 0, ret;
	struct rte_mbuf *direct_pkts[LSINIC_MERGE_MAX_NUM];
#ifdef LSINIC_TX_DIRECT_ASYNC
	struct lsinic_dpni_mg_dsc *pmg_dsc;
#endif

	for (i = 0; i < nb_pkts; i++) {
		if (tx_pkts[i]->pkt_len > txq->adapter->merge_threshold) {
#ifdef LSINIC_TX_DIRECT_ASYNC
			pmg_dsc = rte_pktmbuf_mtod_offset(tx_pkts[i],
					struct lsinic_dpni_mg_dsc *,
					tx_pkts[i]->pkt_len);
			pmg_dsc->mg_num = 0;
			tx_pkts[i]->pkt_len +=
				sizeof(struct lsinic_dpni_mg_dsc);
			tx_pkts[i]->data_len +=
				sizeof(struct lsinic_dpni_mg_dsc);
#endif
			direct_pkts[direct_nb] = tx_pkts[i];
			direct_nb++;
		} else {
			mg_pkts[mg_nb] = tx_pkts[i];
			mg_nb++;
		}
	}

	if (mg_nb == 1) {
#ifdef LSINIC_TX_DIRECT_ASYNC
		pmg_dsc = rte_pktmbuf_mtod_offset(mg_pkts[0],
					struct lsinic_dpni_mg_dsc *,
					mg_pkts[0]->pkt_len);
		pmg_dsc->mg_num = 0;
		mg_pkts[0]->pkt_len += sizeof(struct lsinic_dpni_mg_dsc);
		mg_pkts[0]->data_len += sizeof(struct lsinic_dpni_mg_dsc);
#endif
		direct_pkts[direct_nb] = mg_pkts[0];
		direct_nb++;
		mg_nb = 0;
	}

	if (direct_nb > 0) {
#ifdef LSINIC_TX_DIRECT_ASYNC
		ret = rte_ring_enqueue_burst(txq->dispatch_ring[txq->queue_id],
				(void **)direct_pkts, direct_nb, NULL);
#else
		ret = lsinic_xmit_pkts_burst(txq, direct_pkts,
				direct_nb, 0);
#endif
		if (unlikely(ret < direct_nb))
			rte_pktmbuf_free_bulk(&direct_pkts[ret],
				direct_nb - ret);
	}

	return direct_nb;
}

uint16_t
lsinic_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts,
	uint16_t nb_pkts)
{
	struct lsinic_queue *txq;
	struct rte_eth_dev *recycle_dev;

	txq = tx_queue;
#ifdef LSXINIC_LATENCY_TEST
	{
		int i, j;
		uint64_t tick = rte_get_timer_cycles();
		uint8_t *tick_8 = (uint8_t *)&tick;
		uint8_t *tick_save;

		for (i = 0; i < nb_pkts; i++) {
			tick_save = rte_pktmbuf_mtod_offset(tx_pkts[i],
				uint8_t *, tx_pkts[i]->pkt_len);
			for (j = 0; j < (int)sizeof(uint64_t); j++)
				tick_save[j] = tick_8[j];
			tx_pkts[i]->pkt_len += sizeof(uint64_t);
			tx_pkts[i]->data_len += sizeof(uint64_t);
		}
	}
#endif

	if (!lsinic_queue_running(txq)) {
		lsinic_queue_status_update(txq);
		if (!lsinic_queue_running(txq))
			return 0;
	}

	if (txq->recycle_txq) {
		recycle_dev = txq->adapter->merge_dev->eth_dev;
		return recycle_dev->tx_pkt_burst(txq->recycle_txq,
				tx_pkts, nb_pkts);
	}

	txq->loop_avail++;

	/* TX loop */
	return lsinic_xmit_pkts_burst(txq, tx_pkts, nb_pkts,
				txq->adapter->cap & LSINIC_CAP_XFER_PKT_MERGE);
}

/*********************************************************************
 *
 *  RX functions
 *
 **********************************************************************/

static void lsinic_rx_dma_clean(struct lsinic_queue *rxq)
{
	struct rte_qdma_job *jobs[LSINIC_QDMA_DQ_MAX_NB];
	struct lsinic_sw_bd *rxe;
	struct rte_qdma_job *dma_job;
	uint16_t dma_idx, dq_total, rx_count, nb_rx, bd_idx;
	int i, ret = 0, clean_count = 100;
	struct rte_qdma_enqdeq context;
	struct lsinic_bd_desc *rxdp;
	struct rte_mbuf *rxm;

clean_again:
	nb_rx = 0;
	dq_total = 0;
	if (rxq->pkts_eq == rxq->pkts_dq)
		return;

	if ((MCACHE_NUM - rxq->sw_bd_cnt) < LSINIC_QDMA_DQ_MAX_NB)
		return;

	LSXINIC_PMD_ERR("RXQ clean eq:%ld, dq:%ld",
		rxq->pkts_eq, rxq->pkts_dq);
	context.vq_id = rxq->dma_vq;
	context.job = jobs;
	ret = rte_qdma_dequeue_buffers(rxq->dma_id, NULL,
			LSINIC_QDMA_DQ_MAX_NB,
			&context);
	LSXINIC_PMD_ERR("RXQ clean dq ret:%d", ret);

	for (i = 0; i < ret; i++) {
		dma_job = jobs[i];
		RTE_ASSERT(dma_job);
		rxq->bytes_dq += dma_job->len;
		dma_job->flags &= ~LSINIC_QDMA_JOB_USING_FLAG;
		rxe = (struct lsinic_sw_bd *)dma_job->cnxt;
		RTE_ASSERT(rxe);
		rxq->sw_bd[rxq->sw_bd_tail] = rxe;
		rxq->sw_bd_tail = (rxq->sw_bd_tail + 1) & MCACHE_MASK;
		rxq->sw_bd_cnt++;
		RTE_ASSERT(rxq->sw_bd_cnt < MCACHE_NUM);
		if (rxq->adapter->ep_cap & LSINIC_EP_CAP_RXQ_ORP) {
			rxe->dma_complete = 1;
		} else {
			dma_idx = rxq->next_dma_idx & (rxq->nb_desc - 1);
			lsinic_bd_dma_complete_update(rxq, dma_idx, &rxe->bd);
			rxq->next_dma_idx++;
		}
		rte_lsinic_prefetch(rte_pktmbuf_mtod(rxe->mbuf, void *));
		dq_total++;
	}

	rxq->pkts_dq += dq_total;

	if (rxq->adapter->ep_cap & LSINIC_EP_CAP_RXQ_ORP)
		rx_count = rxq->next_avail_idx - rxq->next_used_idx;
	else
		rx_count = rxq->next_dma_idx - rxq->next_used_idx;

	LSXINIC_PMD_ERR("RXQ clean dq count:%d, dma:%d, avail:%d, used:%d",
		rx_count, rxq->next_dma_idx, rxq->next_avail_idx,
		rxq->next_used_idx);

	if (!rx_count)
		clean_count--;

	if (clean_count <= 0)
		rte_panic("RXQ qDMA job en-queued missed!!!!, have to quit!");

	while (nb_rx < rx_count) {
		bd_idx = rxq->next_used_idx & (rxq->nb_desc - 1);
		rxdp = LSINIC_EP_BD_DESC(rxq, bd_idx);
		if (rxq->adapter->ep_cap & LSINIC_EP_CAP_RXQ_ORP) {
			rxe = &rxq->sw_ring[bd_idx];
			if (!rxe->dma_complete)
				break;
			rxe->dma_complete = 0;
		} else {
			rxe = rxq->sw_bd[rxq->sw_bd_head];
		}
		nb_rx++;

		/* rxm is ret_mbuf passed to upper layer */
		rxm = rxe->mbuf;
		if (rxm)
			rte_pktmbuf_free_seg(rxm);
		rxe->mbuf = NULL;

		/* Only after setting mbuf to dpdk, then we can set USED
		 * flag to notify RC or the mbuf address may be overwritten
		 * by RC.
		 */
		if (rxq->adapter->ep_cap & LSINIC_EP_CAP_RXQ_ORP) {
#ifdef LSINIC_BD_CTX_IDX_USED
			rxdp->bd_status &= ~((uint32_t)RING_BD_STATUS_MASK);
			rxdp->bd_status |= RING_BD_ADDR_CHECK;
			rxdp->bd_status |= RING_BD_HW_COMPLETE;
#else
			rxdp->bd_status =
				RING_BD_HW_COMPLETE | RING_BD_ADDR_CHECK;
#endif
		} else {
			rxq->sw_bd_head = (rxq->sw_bd_head + 1) & MCACHE_MASK;
			rxq->sw_bd_cnt--;
			RTE_ASSERT(rxq->sw_bd_cnt >= 0);
		}
		lsinic_bd_update_used_to_rc(rxq, bd_idx);
		rxq->next_used_idx++;
		lsinic_sw_bd_push(rxq, (void **)&rxe, 1);
	}

	goto clean_again;
}

static uint16_t
lsinic_rx_dma_dequeue(struct lsinic_queue *rxq)
{
	struct rte_qdma_job *jobs[LSINIC_QDMA_DQ_MAX_NB];
	struct lsinic_sw_bd *rxe;
	struct rte_qdma_job *dma_job;
	uint16_t dma_idx;
	int i, ret = 0, need_clean = 0;
	struct rte_qdma_enqdeq context;

	if (rxq->pkts_eq == rxq->pkts_dq)
		return 0;

	if ((MCACHE_NUM - rxq->sw_bd_cnt) < LSINIC_QDMA_DQ_MAX_NB)
		return 0;

	context.vq_id = rxq->dma_vq;
	context.job = jobs;
	ret = rte_qdma_dequeue_buffers(rxq->dma_id, NULL,
			LSINIC_QDMA_DQ_MAX_NB,
			&context);
	if (likely(ret > 0)) {
		rxq->sw_bd_cnt += ret;
		rxq->pkts_dq += ret;
		RTE_ASSERT(rxq->sw_bd_cnt <= MCACHE_NUM);
	} else {
		return 0;
	}

	for (i = 0; i < ret; i++) {
		dma_job = jobs[i];
		RTE_ASSERT(dma_job);
		if (unlikely(!(dma_job->flags & LSINIC_QDMA_JOB_USING_FLAG) ||
			!dma_job->cnxt)) {
			LSXINIC_PMD_ERR("RX duplicated jobs[%d]", i);
			need_clean++;
			rxq->sw_bd_cnt--;
			rxq->pkts_dq--;
			continue;
		}
		rxq->bytes_dq += dma_job->len;
		dma_job->flags &= ~LSINIC_QDMA_JOB_USING_FLAG;
		rxe = (struct lsinic_sw_bd *)dma_job->cnxt;
		rxq->sw_bd[rxq->sw_bd_tail] = rxe;
		rxq->sw_bd_tail = (rxq->sw_bd_tail + 1) & MCACHE_MASK;
		if (rxq->adapter->ep_cap & LSINIC_EP_CAP_RXQ_ORP) {
			rxe->dma_complete = 1;
		} else {
			dma_idx = rxq->next_dma_idx & (rxq->nb_desc - 1);
			lsinic_bd_dma_complete_update(rxq, dma_idx, &rxe->bd);
			rxq->next_dma_idx++;
		}
		rte_lsinic_prefetch(rte_pktmbuf_mtod(rxe->mbuf, void *));
	}

	if (need_clean) {
		lsinic_rx_dma_clean(rxq);
		return 0;
	}

	return ret;
}

static int
lsinic_pci_dma_test_init(struct lsinic_queue *queue)
{
	struct lsinic_pci_dma_test *dma_test = &queue->dma_test;
	int ret;
	uint32_t i;
	struct rte_mempool *pool =
		(queue->type == LSINIC_QUEUE_RX) ?
		queue->mb_pool :
		queue->pair->mb_pool;
	char ring_name[64];
	struct rte_qdma_job *jobs;
	int sim = lsx_pciep_hw_sim_get(queue->adapter->pcie_idx);
	struct lsinic_dev_reg *reg =
		LSINIC_REG_OFFSET(queue->adapter->hw_addr,
			LSINIC_DEV_REG_OFFSET);
	uint16_t pkt_len = RTE_ETHER_MIN_LEN - RTE_ETHER_CRC_LEN;
	char *penv = getenv("LSINIC_PCIE_DMA_TEST_PKT_SIZE");

	if (!dma_test->pci_addr)
		return 0;

	if (penv)
		pkt_len = atoi(penv);

#ifdef LSXINIC_LATENCY_TEST
	penv = getenv("LSINIC_PCIE_DMA_TEST_LATENCY_BURST");
	if (penv) {
		dma_test->latency_burst = atoi(penv);
		if (!dma_test->latency_burst)
			dma_test->latency_burst = 1;
	} else {
		dma_test->latency_burst = 1;
	}
#else
	dma_test->latency_burst = 0;
#endif

	penv = getenv("LSINIC_PCIE_CPU_TEST");
	if (penv && atoi(penv) > 0) {
		if (reg->rbp_enable) {
			LSXINIC_PMD_WARN("%s can only used with RBP disabled",
				penv);
			dma_test->dma_vq = 0;
		} else {
			dma_test->dma_vq = -1;
		}
	} else {
		dma_test->dma_vq = 0;
	}

	if (pkt_len < (RTE_ETHER_MIN_LEN - RTE_ETHER_CRC_LEN) ||
		pkt_len > (RTE_ETHER_MAX_LEN - RTE_ETHER_CRC_LEN))
		pkt_len = (RTE_ETHER_MIN_LEN - RTE_ETHER_CRC_LEN);

	if (dma_test->dma_vq < 0) {
		/** Align len to 16B for CPU copy*/
		while (pkt_len & 0xf)
			pkt_len++;
	}

	dma_test->mbufs = rte_zmalloc(NULL,
		sizeof(struct rte_mbuf *) * queue->nb_desc, 64);
	if (!dma_test->mbufs)
		return -ENOMEM;

	ret = rte_pktmbuf_alloc_bulk(pool, dma_test->mbufs, queue->nb_desc);
	if (ret)
		return ret;

	sprintf(ring_name, "pci_dma_test_%d:%d:%d:%d_%d_%d",
		queue->adapter->pcie_idx,
		queue->adapter->pf_idx,
		queue->adapter->is_vf,
		queue->adapter->is_vf ? queue->adapter->vf_idx :
		0,
		queue->type, queue->queue_id);
	dma_test->jobs_ring = rte_ring_create(ring_name,
				queue->nb_desc * 2, rte_socket_id(), 0);

	if (dma_test->dma_vq < 0)
		goto skip_qdma_vq_setup;

	memcpy(&dma_test->qdma_cfg, &queue->qdma_config,
		sizeof(struct rte_qdma_queue_config));
	if (sim && dma_test->latency_burst)
		dma_test->qdma_cfg.flags |= RTE_QDMA_VQ_NO_RESPONSE;
	else
		dma_test->qdma_cfg.flags &= ~RTE_QDMA_VQ_NO_RESPONSE;
	dma_test->dma_vq = rte_qdma_queue_setup(queue->dma_id,
						-1, &dma_test->qdma_cfg);

skip_qdma_vq_setup:
	jobs = queue->dma_jobs;
	for (i = 0; i < queue->nb_desc; i++) {
		if (queue->type == LSINIC_QUEUE_RX) {
			jobs[i].src = queue->ob_base +
				dma_test->pci_addr + pkt_len * i;
			jobs[i].dest = rte_pktmbuf_iova(dma_test->mbufs[i]);
		} else {
			jobs[i].dest = queue->ob_base +
				dma_test->pci_addr + pkt_len * i;
			jobs[i].src = rte_pktmbuf_iova(dma_test->mbufs[i]);
		}
		jobs[i].len = pkt_len;
		jobs[i].flags = RTE_QDMA_JOB_SRC_PHY |
						RTE_QDMA_JOB_DEST_PHY;
		rte_ring_enqueue(dma_test->jobs_ring, &jobs[i]);
	}

	dma_test->pkt_len = pkt_len;
	dma_test->status = LSINIC_PCI_DMA_TEST_START;
#ifdef LSXINIC_LATENCY_TEST
	LSXINIC_PMD_INFO("qDMA-PCIe benchmark latency pkt(%dB) burst(%d) %s",
		pkt_len,
		dma_test->latency_burst,
		queue->type == LSINIC_QUEUE_RX ?
		"from RC to EP" : "from EP to RC");
#else
	LSXINIC_PMD_INFO("qDMA-PCIe benchmark throughput pkt(%dB) %s",
		pkt_len,
		queue->type == LSINIC_QUEUE_RX ?
		"from RC to EP" : "from EP to RC");
#endif

	return 0;
}

static int
lsinic_pci_dma_rx_tx_init(struct lsinic_queue *rx_queue)
{
	int ret;
	struct lsinic_queue *tx_queue = rx_queue->pair;

	if (rx_queue->dma_test.pci_addr) {
		ret = lsinic_queue_dma_create(rx_queue);
		if (ret < 0)
			return ret;
		ret = lsinic_pci_dma_test_init(rx_queue);
		if (ret)
			return ret;
	} else {
		rx_queue->dma_test.status = LSINIC_PCI_DMA_TEST_INIT;
	}

	if (tx_queue->dma_test.pci_addr) {
		ret = lsinic_queue_dma_create(tx_queue);
		if (ret < 0)
			return ret;

		ret = lsinic_pci_dma_test_init(tx_queue);
		if (ret)
			return ret;
	} else {
		tx_queue->dma_test.status = LSINIC_PCI_DMA_TEST_INIT;
	}

	return 0;
}

static int
lsinic_pci_dma_rx_tx_test(struct lsinic_queue *rx_queue)
{
	int ret, eq_ret = 0, dq_ret = 0, dma_rxq, dma_txq;
	struct lsinic_queue *tx_queue = rx_queue->pair;
	uint16_t burst_nb = 0, i;
	struct lsinic_pci_dma_test *rx_dma_test = &rx_queue->dma_test;
	struct lsinic_pci_dma_test *tx_dma_test = &tx_queue->dma_test;
	struct rte_qdma_job *eq_jobs[LSINIC_QDMA_EQ_MAX_NB];
	struct rte_qdma_job *dq_jobs[LSINIC_QDMA_DQ_MAX_NB];
	struct lsinic_dev_reg *reg =
		LSINIC_REG_OFFSET(rx_queue->adapter->hw_addr,
			LSINIC_DEV_REG_OFFSET);
	struct rte_qdma_enqdeq context;
	uint64_t eq_tick = 0, dq_tick = 0, len, psrc, pdst;
	uint8_t *v_src = 0, *v_dst = 0;
	uint8_t *v_src_start, *v_dst_start;
	uint8_t *src_cp, *dst_cp;
	int sim = lsx_pciep_hw_sim_get(rx_queue->adapter->pcie_idx);
	struct rte_lsx_pciep_device *lsinic_dev =
		rx_queue->adapter->lsinic_dev;
	uint8_t *ob_vbase = lsinic_dev->ob_virt_base;
	uint64_t ob_pbase = lsinic_dev->ob_phy_base, off;

	if (unlikely(rx_dma_test->status == LSINIC_PCI_DMA_TEST_UNINIT ||
		tx_dma_test->status == LSINIC_PCI_DMA_TEST_UNINIT)) {
		ret = lsinic_pci_dma_rx_tx_init(rx_queue);
		if (ret < 0)
			return ret;
	}

	dma_rxq = rx_dma_test->dma_vq;
	dma_txq = tx_dma_test->dma_vq;

	if (LSINIC_READ_REG(&reg->command) == PCIDEV_COMMAND_STOP) {
		if (rx_dma_test->status == LSINIC_PCI_DMA_TEST_START)
			rx_dma_test->status = LSINIC_PCI_DMA_TEST_STOP;
		if (tx_dma_test->status == LSINIC_PCI_DMA_TEST_START)
			tx_dma_test->status = LSINIC_PCI_DMA_TEST_STOP;
	}

	if (rx_dma_test->status == LSINIC_PCI_DMA_TEST_START ||
		rx_dma_test->status == LSINIC_PCI_DMA_TEST_STOP) {
		if (rx_dma_test->status == LSINIC_PCI_DMA_TEST_START) {
			if (rx_dma_test->latency_burst)
				burst_nb = rx_dma_test->latency_burst;
			else
				burst_nb = LSINIC_QDMA_EQ_MAX_NB;
			ret = rte_ring_dequeue_burst(rx_dma_test->jobs_ring,
					(void **)eq_jobs,
					burst_nb,
					NULL);
			if (ret > 0) {
				context.vq_id = dma_rxq;
				context.job = eq_jobs;
				psrc = eq_jobs[ret - 1]->src;
				pdst = eq_jobs[ret - 1]->dest;
				len = eq_jobs[ret - 1]->len - 1;
				v_dst_start = DPAA2_IOVA_TO_VADDR(pdst);
				if (sim && rx_dma_test->latency_burst) {
					v_src_start = DPAA2_IOVA_TO_VADDR(psrc);
					v_src = v_src_start + len;
					v_dst = v_dst_start + len;
					*v_src = 1; *v_dst = 0;
				} else if (dma_rxq < 0) {
					v_src = ob_vbase +
						psrc - ob_pbase +
						len;
					v_dst = v_dst_start + len;
					*v_src = 1; *v_dst = 0;
				}
				eq_tick = rte_get_timer_cycles();
				if (dma_rxq < 0) {
					for (i = 0; i < ret; i++) {
						psrc = eq_jobs[i]->src;
						pdst = eq_jobs[i]->dest;
						len = eq_jobs[i]->len;
						off = psrc - ob_pbase;
						src_cp = ob_vbase + off;
						dst_cp =
						DPAA2_IOVA_TO_VADDR(pdst);
						memcpy(dst_cp, src_cp, len);
					}
					rx_queue->pkts_eq += ret;
					rx_queue->loop_avail++;
					eq_ret = ret;
					goto rx_dq_again;
				}
				ret = rte_qdma_enqueue_buffers(rx_queue->dma_id,
						NULL, ret, &context);
				if (ret < 0) {
					LSXINIC_PMD_ERR("PCIe benchmark rx error: %d",
						ret);
					return ret;
				}
				rx_queue->pkts_eq += ret;
				rx_queue->loop_avail++;
				eq_ret = ret;
			}
		}

rx_dq_again:
		if (v_dst) {
			while (*v_dst == 0)
				rte_rmb();
			dq_tick = rte_get_timer_cycles();
			dq_ret = eq_ret;

			rx_queue->bytes += dq_ret * rx_dma_test->pkt_len;
			rx_queue->bytes_fcs +=
				dq_ret * (rx_dma_test->pkt_len +
				LSINIC_ETH_FCS_SIZE);
			rx_queue->bytes_overhead +=
				dq_ret * (rx_dma_test->pkt_len +
				LSINIC_ETH_OVERHEAD_SIZE);
			rte_ring_enqueue_burst(rx_dma_test->jobs_ring,
				(void **)eq_jobs, dq_ret, NULL);
			rx_queue->pkts_dq += dq_ret;
			rx_queue->packets += dq_ret;
			goto rx_latency_calculation;
		}
		context.vq_id = dma_rxq;
		context.job = dq_jobs;
		ret = rte_qdma_dequeue_buffers(rx_queue->dma_id, NULL,
				LSINIC_QDMA_DQ_MAX_NB,
				&context);
		if (ret > 0) {
			dq_ret += ret;
			dq_tick = rte_get_timer_cycles();
			rx_queue->bytes += ret * rx_dma_test->pkt_len;
			rx_queue->bytes_fcs +=
				ret * (rx_dma_test->pkt_len +
				LSINIC_ETH_FCS_SIZE);
			rx_queue->bytes_overhead +=
				ret * (rx_dma_test->pkt_len +
				LSINIC_ETH_OVERHEAD_SIZE);
			rte_ring_enqueue_burst(rx_dma_test->jobs_ring,
				(void **)dq_jobs, ret, NULL);
			rx_queue->pkts_dq += ret;
			rx_queue->packets += ret;
		}
		if (dq_ret < eq_ret && rx_queue->dma_test.latency_burst)
			goto rx_dq_again;
rx_latency_calculation:
		if (rx_queue->dma_test.latency_burst && eq_ret > 0) {
			rx_queue->cyc_diff_total += (dq_tick - eq_tick) *
				rx_queue->dma_test.latency_burst;
			rx_queue->cyc_diff_curr = (dq_tick - eq_tick);
		}
	}

	eq_tick = 0;
	dq_tick = 0;
	eq_ret = 0;
	dq_ret = 0;
	v_src = NULL;
	v_dst = NULL;
	if (tx_dma_test->status == LSINIC_PCI_DMA_TEST_START ||
		tx_dma_test->status == LSINIC_PCI_DMA_TEST_STOP) {
		if (tx_dma_test->status == LSINIC_PCI_DMA_TEST_START) {
			if (tx_dma_test->latency_burst)
				burst_nb = tx_dma_test->latency_burst;
			else
				burst_nb = LSINIC_QDMA_EQ_MAX_NB;
			ret = rte_ring_dequeue_burst(tx_dma_test->jobs_ring,
					(void **)eq_jobs,
					burst_nb, NULL);
			if (ret > 0) {
				context.vq_id = dma_txq;
				context.job = eq_jobs;
				eq_tick = rte_get_timer_cycles();
				psrc = eq_jobs[ret - 1]->src;
				pdst = eq_jobs[ret - 1]->dest;
				len = eq_jobs[ret - 1]->len - 1;
				v_src_start = DPAA2_IOVA_TO_VADDR(psrc);
				if (sim && tx_dma_test->latency_burst) {
					v_dst_start = DPAA2_IOVA_TO_VADDR(pdst);
					v_src = v_src_start + len;
					v_dst = v_dst_start + len;
					v_src = v_src_start + len;
					v_dst = v_dst_start + len;
					*v_src = 1; *v_dst = 0;
				} else if (dma_txq < 0) {
					v_src = v_src_start + len;
					v_dst = ob_vbase +
						pdst - ob_pbase +
						len;
					*v_src = 1; *v_dst = 0;
				}

				if (dma_txq < 0) {
					for (i = 0; i < ret; i++) {
						psrc = eq_jobs[i]->src;
						pdst = eq_jobs[i]->dest;
						len = eq_jobs[i]->len;
						off = pdst - ob_pbase;
						src_cp =
						DPAA2_IOVA_TO_VADDR(psrc);
						dst_cp = ob_vbase + off;
						memcpy(dst_cp, src_cp, len);
					}
					tx_queue->pkts_eq += ret;
					tx_queue->loop_avail++;
					eq_ret = ret;
					goto tx_dq_again;
				}
				ret = rte_qdma_enqueue_buffers(tx_queue->dma_id,
						NULL, ret,
						&context);
				if (ret < 0) {
					LSXINIC_PMD_ERR("PCIe benchmark tx error: %d",
						ret);
					return ret;
				}
				tx_queue->pkts_eq += ret;
				tx_queue->loop_avail++;
				eq_ret = ret;
			}
		}

tx_dq_again:
		if (v_dst) {
			while (*v_dst == 0)
				rte_rmb();
			dq_tick = rte_get_timer_cycles();
			dq_ret = eq_ret;

			tx_queue->bytes += dq_ret * rx_dma_test->pkt_len;
			tx_queue->bytes_fcs +=
				dq_ret * (rx_dma_test->pkt_len +
				LSINIC_ETH_FCS_SIZE);
			tx_queue->bytes_overhead +=
				dq_ret * (rx_dma_test->pkt_len +
				LSINIC_ETH_OVERHEAD_SIZE);
			rte_ring_enqueue_burst(tx_dma_test->jobs_ring,
				(void **)eq_jobs, dq_ret, NULL);
			tx_queue->pkts_dq += dq_ret;
			tx_queue->packets += dq_ret;
			goto tx_latency_calculation;
		}
		context.vq_id = dma_txq;
		context.job = dq_jobs;
		ret = rte_qdma_dequeue_buffers(tx_queue->dma_id,
				NULL, LSINIC_QDMA_DQ_MAX_NB,
				&context);
		if (ret > 0) {
			dq_ret += ret;
			dq_tick = rte_get_timer_cycles();
			tx_queue->bytes += ret * tx_dma_test->pkt_len;
			tx_queue->bytes_fcs +=
				ret * (tx_dma_test->pkt_len +
				LSINIC_ETH_FCS_SIZE);
			tx_queue->bytes_overhead +=
				ret * (tx_dma_test->pkt_len +
				LSINIC_ETH_OVERHEAD_SIZE);
			rte_ring_enqueue_burst(tx_dma_test->jobs_ring,
				(void **)dq_jobs, ret, NULL);
			tx_queue->pkts_dq += ret;
			tx_queue->packets += ret;
		}
		if (dq_ret < eq_ret && tx_queue->dma_test.latency_burst)
			goto tx_dq_again;

tx_latency_calculation:
		if (tx_queue->dma_test.latency_burst && eq_ret > 0) {
			tx_queue->cyc_diff_total += (dq_tick - eq_tick) *
				rx_queue->dma_test.latency_burst;
			tx_queue->cyc_diff_curr = (dq_tick - eq_tick);
		}
	}

	return 0;
}

static __rte_always_inline void
lsinic_recv_mbuf_dma_set(struct rte_qdma_job *dma_job,
	struct rte_mbuf *mbuf, uint32_t pkt_len, uint32_t port_id)
{
	struct lsinic_sw_bd *rxe;

	dma_job->dest = rte_mbuf_data_iova_default(mbuf);
	mbuf->nb_segs = 1;
	mbuf->next = NULL;
	mbuf->pkt_len = pkt_len;
	mbuf->data_len = pkt_len;
	mbuf->port = port_id;
	rxe = (struct lsinic_sw_bd *)dma_job->cnxt;
	mbuf->data_off = RTE_PKTMBUF_HEADROOM + rxe->align_dma_offset;
	rxe->mbuf = mbuf;
}

static __rte_always_inline void
lsinic_local_bd_status_update(struct lsinic_queue *q,
	uint16_t bd_idx, uint32_t bd_status)
{
	struct lsinic_bd_desc *rxdp = LSINIC_EP_BD_DESC(q, bd_idx);

#ifdef LSINIC_BD_CTX_IDX_USED
	rxdp->bd_status &= ~((uint32_t)RING_BD_STATUS_MASK);
	rxdp->bd_status |= bd_status;
#else
	rxdp->bd_status = bd_status;
#endif
}

static uint16_t
lsinic_recv_bd_bulk_alloc_buf(struct lsinic_queue *rx_queue)
{
	struct lsinic_queue *rxq;
	struct lsinic_bd_desc *rxdp;
	struct rte_qdma_job *dma_job[DEFAULT_TX_RS_THRESH];
	struct lsinic_sw_bd *rxe = NULL;
	struct rte_mbuf *rxm[DEFAULT_TX_RS_THRESH];

	uint32_t pkt_len[DEFAULT_TX_RS_THRESH];
	uint16_t bd_idx, first_bd_idx;
	uint32_t size;
	uint32_t len_cmd;
	uint16_t bd_num = 0, idx;

	rxq = rx_queue;
	first_bd_idx = rxq->next_avail_idx & (rxq->nb_desc - 1);

	do {
		bd_idx = rxq->next_avail_idx & (rxq->nb_desc - 1);
		rxdp = LSINIC_EP_BD_DESC(rxq, bd_idx);

		if (!(((uint64_t)rxdp) & RTE_CACHE_LINE_MASK)) {
			rte_lsinic_prefetch((uint8_t *)rxdp +
				RTE_CACHE_LINE_SIZE);
		}

		if ((rxdp->bd_status & RING_BD_STATUS_MASK) !=
			RING_BD_AVAILABLE) {
			lsinic_qdma_rx_multiple_enqueue(rxq, false);
			break;
		}

		len_cmd = rxdp->len_cmd;
		size = len_cmd & LSINIC_BD_LEN_MASK;
		if (unlikely(size > rx_queue->adapter->data_room_size)) {
			LSXINIC_PMD_ERR("port%d rxq%d BD%d len_cmd:0x%08x",
				rxq->port_id, rxq->queue_id, bd_idx, len_cmd);
			rxq->errors++;
			rte_panic("line %d\tassert \"%s\" failed\n",
				__LINE__, "size err");
			/* to do skip this bd */
			/* TODO
			 * dma_job for this entry should also be skipped
			 */

			break;
		}

		dma_job[bd_num] = &rxq->dma_jobs[bd_idx];
		if (unlikely(dma_job[bd_num]->flags &
			LSINIC_QDMA_JOB_USING_FLAG &&
			(!(rxq->adapter->cap & LSINIC_CAP_XFER_COMPLETE)))) {
			/* Workaround,
			 * need further investigation for this situation.
			 */
			LSXINIC_PMD_DBG("RXQ%d: dma_jobs[%d] is in DMA",
				rx_queue->queue_id, bd_idx);
			break;
		}

		if ((rxq->adapter->cap & LSINIC_CAP_XFER_COMPLETE) ||
			(rxq->adapter->ep_cap & LSINIC_EP_CAP_RXQ_ORP)) {
			rxe = &rxq->sw_ring[bd_idx];
		} else {
			lsinic_sw_bd_pop(rxq, (void **)&rxe, 1);
			rte_memcpy(&rxe->bd, rxdp,
				sizeof(struct lsinic_bd_desc));
		}

		dma_job[bd_num]->cnxt = (uint64_t)rxe;

		LSXINIC_PMD_DBG("port%d rxq%d bd_idx=%d pkt_len=%d",
			rxq->port_id, rxq->queue_id,
			bd_idx, size);

		dma_job[bd_num]->src = rxdp->pkt_addr + rxq->ob_base;
		/* qdma read memory must be aligned 64 */
		rxe->align_dma_offset =
			LSINIC_ALIGN_DMA_CALC_OFFSET(dma_job[bd_num]->src);
		dma_job[bd_num]->src -= rxe->align_dma_offset;
#ifdef LSINIC_CHECK_DMA_ALIGNED
		if (!rte_is_aligned((void *)dma_job[bd_num]->src,
			64)) {
			LSXINIC_PMD_DBG("BD%d src:0x%lx %s",
				bd_num,
				dma_job->src,
				"not aligned with 64");
		}
#endif

		pkt_len[bd_num] = size - rxq->crc_len;
		dma_job[bd_num]->len = pkt_len[bd_num] +
			rxe->align_dma_offset;
		if (len_cmd & LSINIC_BD_CMD_MG)
			dma_job[bd_num]->len += sizeof(struct lsinic_mg_header);

		dma_job[bd_num]->flags |= LSINIC_QDMA_JOB_USING_FLAG;

		bd_num++;
		rxq->next_avail_idx++;

		if (bd_num >= DEFAULT_TX_RS_THRESH)
			break;
	} while (1);

	rxq->loop_total++;

	if (unlikely(!bd_num))
		return 0;

	if (likely(!rte_pktmbuf_alloc_bulk(rxq->mb_pool,
		rxm, bd_num))) {
		if (rx_queue->adapter->cap & LSINIC_CAP_XFER_COMPLETE) {
			for (idx = 0; idx < bd_num; idx++) {
				lsinic_local_bd_status_update(rxq,
					(first_bd_idx + idx) &
					(rxq->nb_desc - 1),
					RING_BD_ADDR_CHECK |
					RING_BD_HW_COMPLETE);
				lsinic_recv_mbuf_dma_set(dma_job[idx],
					rxm[idx], pkt_len[idx], rxq->port_id);
				rxe = (struct lsinic_sw_bd *)dma_job[idx]->cnxt;
				rxe->complete =
					rte_pktmbuf_mtod_offset(rxm[idx],
					char *, dma_job[idx]->len);
				(*rxe->complete) =
					LSINIC_XFER_COMPLETE_INIT_FLAG;
				dma_job[idx]->len++;
			}
		} else if (rx_queue->adapter->ep_cap & LSINIC_EP_CAP_RXQ_ORP) {
			for (idx = 0; idx < bd_num; idx++) {
				lsinic_local_bd_status_update(rxq,
					(first_bd_idx + idx) &
					(rxq->nb_desc - 1),
					RING_BD_ADDR_CHECK |
					RING_BD_HW_COMPLETE);
				lsinic_recv_mbuf_dma_set(dma_job[idx],
					rxm[idx], pkt_len[idx], rxq->port_id);
				rxe = (struct lsinic_sw_bd *)dma_job[idx]->cnxt;
				rxe->dma_complete = 0;
			}
		} else {
			for (idx = 0; idx < bd_num; idx++) {
				lsinic_local_bd_status_update(rxq,
					(first_bd_idx + idx) &
					(rxq->nb_desc - 1),
					RING_BD_ADDR_CHECK |
					RING_BD_HW_COMPLETE);
				lsinic_recv_mbuf_dma_set(dma_job[idx],
					rxm[idx], pkt_len[idx], rxq->port_id);
			}
		}
		rxq->jobs_pending += bd_num;
		lsinic_qdma_rx_multiple_enqueue(rxq, true);
		if (rxq->new_desc == 0)
			rxq->new_tsc = rte_rdtsc();
	} else {
		if (!(rxq->adapter->cap & LSINIC_CAP_XFER_COMPLETE) &&
			!(rxq->adapter->ep_cap & LSINIC_EP_CAP_RXQ_ORP)) {
			idx = bd_num - 1;
			while (1) {
				lsinic_sw_bd_push(rxq,
					(void **)&dma_job[idx]->cnxt, 1);
				if (idx == 0)
					break;
				idx--;
			}
		}
		rxq->next_avail_idx -= bd_num;
	}

	if (bd_num > 0)
		rxq->loop_avail++;

	return bd_num;
}

static uint16_t
lsinic_recv_bd(struct lsinic_queue *rx_queue)
{
	struct lsinic_queue *rxq;
	struct lsinic_bd_desc *rxdp;
	struct rte_qdma_job *dma_job;
	struct lsinic_sw_bd *rxe = NULL;
	struct rte_mbuf *rxm;

	uint32_t pkt_len;
	uint16_t bd_idx;
	uint32_t size;
	uint32_t len_cmd;
	uint16_t bd_num = 0;

	rxq = rx_queue;

	do {
		bd_idx = rxq->next_avail_idx & (rxq->nb_desc - 1);
		rxdp = LSINIC_EP_BD_DESC(rxq, bd_idx);

		if (!(((uint64_t)rxdp) & RTE_CACHE_LINE_MASK)) {
			rte_lsinic_prefetch((uint8_t *)rxdp +
				RTE_CACHE_LINE_SIZE);
		}

		if ((rxdp->bd_status & RING_BD_STATUS_MASK) !=
			RING_BD_AVAILABLE) {
			lsinic_qdma_rx_multiple_enqueue(rxq, false);
			break;
		}

		len_cmd = rxdp->len_cmd;
		size = len_cmd & LSINIC_BD_LEN_MASK;
		if (unlikely(size > rx_queue->adapter->data_room_size)) {
			LSXINIC_PMD_ERR("port%d rxq%d BD%d len_cmd:0x%08x",
				rxq->port_id, rxq->queue_id, bd_idx, len_cmd);
			rxq->errors++;
			rte_panic("line %d\tassert \"%s\" failed\n",
				__LINE__, "size err");

			break;
		}

		dma_job = &rxq->dma_jobs[bd_idx];
		if (unlikely(dma_job->flags & LSINIC_QDMA_JOB_USING_FLAG &&
			(!(rxq->adapter->cap & LSINIC_CAP_XFER_COMPLETE)))) {
			/* Workaround,
			 * need further investigation for this situation.
			 */
			LSXINIC_PMD_DBG("RXQ%d: dma_jobs[%d] is in DMA",
				rx_queue->queue_id, bd_idx);
			break;
		}

		if ((rxq->adapter->cap & LSINIC_CAP_XFER_COMPLETE) ||
			(rxq->adapter->ep_cap & LSINIC_EP_CAP_RXQ_ORP)) {
			rxe = &rxq->sw_ring[bd_idx];
			lsinic_local_bd_status_update(rxq, bd_idx,
				RING_BD_ADDR_CHECK | RING_BD_HW_COMPLETE);
		} else {
			lsinic_sw_bd_pop(rxq, (void **)&rxe, 1);
			rte_memcpy(&rxe->bd, rxdp,
				sizeof(struct lsinic_bd_desc));
			lsinic_bd_dma_start_update(rxq, bd_idx);
		}

		dma_job->cnxt = (uint64_t)rxe;

		LSXINIC_PMD_DBG("port%d rxq%d bd_idx=%d pkt_len=%d",
			rxq->port_id, rxq->queue_id,
			bd_idx, size);

		rxm = rte_mbuf_raw_alloc(rxq->mb_pool);
		if (unlikely(!rxm)) {
			struct rte_eth_dev_data *dev_data;

			LSXINIC_PMD_DBG("Port%d RXQ%d mbuf alloc failed",
				rxq->port_id, rxq->queue_id);
			dev_data = rte_eth_devices[rxq->port_id].data;
			dev_data->rx_mbuf_alloc_failed++;
			break;
		}

		/* rxm is ret_mbuf passed to upper layer */
		rxe->mbuf = rxm;

		dma_job->dest = rte_mbuf_data_iova_default(rxm);
		dma_job->src = rxdp->pkt_addr + rxq->ob_base;
		/* qdma read memory must be aligned 64 */
		rxe->align_dma_offset =
			LSINIC_ALIGN_DMA_CALC_OFFSET(dma_job->src);
		dma_job->src -= rxe->align_dma_offset;
#ifdef LSINIC_CHECK_DMA_ALIGNED
		if (!rte_is_aligned((void *)dma_job->src, 64)) {
			LSXINIC_PMD_DBG("RXQ%d dma src(0x%lx) not aligned",
				rxq->queue_id, dma_job->src);
		}
#endif
		pkt_len = size - rxq->crc_len;
		dma_job->len = pkt_len + rxe->align_dma_offset;
		if (len_cmd & LSINIC_BD_CMD_MG)
			dma_job->len += sizeof(struct lsinic_mg_header);

		rxm->nb_segs = 1;
		rxm->next = NULL;
		rxm->pkt_len = pkt_len;
		rxm->data_len = pkt_len;
		rxm->port = rxq->port_id;
		rxm->data_off = RTE_PKTMBUF_HEADROOM +
			rxe->align_dma_offset;

		if (rx_queue->adapter->cap &
			LSINIC_CAP_XFER_COMPLETE) {
			rxe->complete =
				rte_pktmbuf_mtod_offset(rxm,
					char *, dma_job->len);
			(*rxe->complete) =
				LSINIC_XFER_COMPLETE_INIT_FLAG;
			dma_job->len++;
		} else if (rx_queue->adapter->ep_cap &
			LSINIC_EP_CAP_RXQ_ORP) {
			rxe->dma_complete = 0;
		}

		dma_job->flags |= LSINIC_QDMA_JOB_USING_FLAG;

		rxq->next_avail_idx++;
		bd_num++;

		if (bd_num >= DEFAULT_TX_RS_THRESH)
			break;
	} while (1);

	if (unlikely(!bd_num))
		return 0;

	rxq->jobs_pending += bd_num;
	lsinic_qdma_rx_multiple_enqueue(rxq, true);
	if (rxq->new_desc == 0)
		rxq->new_tsc = rte_rdtsc();

	rxq->loop_avail++;

	return bd_num;
}

static void
lsinic_txq_loop(struct lsinic_queue *rxq)
{
	struct lsinic_queue *q, *tq;

	if (rxq && rxq->pair) {
		struct lsinic_queue *txq = rxq->pair;
		struct lsinic_adapter *adapter = txq->adapter;

		if (txq->recycle_rxq) {
			uint16_t ret, i;
			struct rte_eth_dev *offload_dev;
			struct rte_mbuf *mbuf_merged[DEFAULT_TX_RS_THRESH];

			offload_dev = adapter->merge_dev->eth_dev;
			ret = offload_dev->rx_pkt_burst(txq->recycle_rxq,
					mbuf_merged,
					DEFAULT_TX_RS_THRESH);
			if (likely(ret > 0)) {
				for (i = 0; i < ret; i++) {
					lsinic_tx_merge_cb(mbuf_merged[i],
						txq->recycle_rxq);
				}
			} else {
				lsinic_tx_merge_cb(NULL, txq->recycle_rxq);
			}
		}
	}

	if (RTE_PER_LCORE(lsinic_txq_num_in_list) == 0)
		return;

	/* Check if txq already added to list */
	TAILQ_FOREACH_SAFE(q, &RTE_PER_LCORE(lsinic_txq_list), next, tq) {
		if (!lsinic_queue_running(q)) {
			lsinic_queue_status_update(q);
			if (!lsinic_queue_running(q))
				continue;
		}

		if (!(q->adapter->ep_cap & LSINIC_EP_CAP_TXQ_DMA_NO_RSP)) {
			lsinic_tx_dma_dequeue(q);
			lsinic_tx_update_to_rc(q);
		} else if (!q->recycle_txq) {
			if (likely(q->packets_old == q->packets ||
				(q->adapter->ep_cap &
				LSINIC_EP_CAP_RXQ_WBD_DMA)))
				lsinic_qdma_tx_multiple_enqueue(q, false);
			q->packets_old = q->packets;
		}

		q->loop_total++;
	}
}

static void
lsinic_rxq_loop(struct lsinic_queue *rxq)
{
	const int bulk_alloc = 1;

	if (!lsinic_queue_running(rxq)) {
		lsinic_queue_status_update(rxq);
		if (!lsinic_queue_running(rxq))
			return;
		if (rxq->pair)
			lsinic_add_txq_to_list(rxq->pair);
	}

	if (unlikely(rxq->dma_test.pci_addr ||
		rxq->pair->dma_test.pci_addr)) {
		lsinic_pci_dma_rx_tx_test(rxq);

		return;
	}

	if (bulk_alloc)
		lsinic_recv_bd_bulk_alloc_buf(rxq);
	else
		lsinic_recv_bd(rxq);
	if (!(rxq->adapter->cap & LSINIC_CAP_XFER_COMPLETE)) {
		lsinic_rx_dma_dequeue(rxq);
		lsinic_queue_trigger_interrupt(rxq);
	}

	if (rxq->recycle_rxq) {
		uint16_t ret, i;
		struct rte_mbuf *mbuf_split[DEFAULT_TX_RS_THRESH];
		struct rte_eth_dev *offload_dev =
			rxq->adapter->split_dev->eth_dev;

		if (likely(offload_dev->data->dev_started)) {
			ret = offload_dev->rx_pkt_burst(rxq->recycle_rxq,
					mbuf_split,
					DEFAULT_TX_RS_THRESH);
			if (likely(ret > 0)) {
				for (i = 0; i < ret; i++)
					lsinic_rx_split_cb(mbuf_split[i], rxq->recycle_rxq);
			}
		}
	}
}

static int
lsinic_fetch_merge_rx_buffer(struct lsinic_queue *rx_queue,
	struct lsinic_bd_desc *rx_desc, struct rte_mbuf *mbuf, int mg_num)
{
	char *data = NULL;
	char *data_base = NULL;
	uint16_t pkt_len, align_off, idx, offset, total_size;
	struct lsinic_mg_header *mg_header;

	rte_lsinic_prefetch(mbuf);

	total_size = LSINIC_READ_REG(&rx_desc->len_cmd);
	total_size &= LSINIC_BD_LEN_MASK;
	if (total_size  > rx_queue->adapter->data_room_size) {
		LSXINIC_PMD_ERR("packet(%d) is too bigger!",
			total_size);
		return 0;
	}

	data_base = rte_pktmbuf_mtod(mbuf, char *);

	mg_header = (struct lsinic_mg_header *)data_base;
	pkt_len = lsinic_mg_entry_len(mg_header->len_cmd[0]);
	if ((pkt_len + sizeof(struct lsinic_mg_header)) > total_size)
		return 0;

	mbuf->data_off +=
		sizeof(struct lsinic_mg_header); /* skip mg structure */
	mbuf->nb_segs = 1;
	mbuf->next = NULL;
	mbuf->pkt_len = pkt_len;
	mbuf->data_len = pkt_len;
	mbuf->port = rx_queue->port_id;
	mbuf->packet_type = RTE_PTYPE_L3_IPV4;
	rx_queue->mcache[rx_queue->mtail] = mbuf;
	rx_queue->mtail = (rx_queue->mtail + 1) & MCACHE_MASK;
	rx_queue->mcnt++;

	align_off = lsinic_mg_entry_align_offset(mg_header->len_cmd[0]);
	data_base = data_base + sizeof(struct lsinic_mg_header);
	offset = pkt_len + align_off;

	LSXINIC_PMD_DBG("EP MGD0: len=%d next_off=%d",
		pkt_len, offset);

	for (idx = 1; idx < mg_num; idx++) {
		pkt_len =
			lsinic_mg_entry_len(mg_header->len_cmd[idx]);
		align_off =
			lsinic_mg_entry_align_offset(mg_header->len_cmd[idx]);

		if ((offset + pkt_len + align_off) > total_size)
			break;

		mbuf = rte_mbuf_raw_alloc(rx_queue->mb_pool);
		if (!mbuf) {
			LSXINIC_PMD_ERR("MG RX mbuf alloc failed p:%u q:%u",
				rx_queue->port_id, rx_queue->queue_id);
			break;
		}

		mbuf->data_off = RTE_PKTMBUF_HEADROOM;
		data = rte_pktmbuf_mtod(mbuf, char *);
		rte_memcpy(data, (void *)(data_base + offset), pkt_len);
		mbuf->nb_segs = 1;
		mbuf->next = NULL;
		mbuf->pkt_len = pkt_len;
		mbuf->data_len = pkt_len;
		mbuf->port = rx_queue->port_id;
		mbuf->packet_type = RTE_PTYPE_L3_IPV4;

		rx_queue->mcache[rx_queue->mtail] = mbuf;
		rx_queue->mtail = (rx_queue->mtail + 1) & MCACHE_MASK;
		rx_queue->mcnt++;

		offset += pkt_len + align_off;
		LSXINIC_PMD_DBG("EP MGD%d: len=%d next_off=%d\n",
			idx, pkt_len, offset);
	}

	return idx;
}

static uint16_t
lsinic_split_clone_mbufs(struct lsinic_queue *rx_queue,
	struct rte_mbuf *mbuf, uint16_t num)
{
	uint16_t idx, offset;
	char *data_base = rte_pktmbuf_mtod(mbuf, char *);
	struct lsinic_mg_header *mg_header =
			(struct lsinic_mg_header *)data_base;
	struct rte_mbuf *new_mbuf[LSINIC_MERGE_MAX_NUM];
	int ret;
	uint8_t *pcore;

	rx_queue->mcache[rx_queue->mtail] = mbuf;
	rx_queue->mtail = (rx_queue->mtail + 1) & MCACHE_MASK;
	rx_queue->mcnt++;

	mbuf->data_off += sizeof(struct lsinic_mg_header);
	mbuf->data_len = lsinic_mg_entry_len(mg_header->len_cmd[0]);
	mbuf->pkt_len = mbuf->data_len;
	mbuf->nb_segs = 1;
	mbuf->next = NULL;
	mbuf->port = rx_queue->port_id;
	mbuf->packet_type = RTE_PTYPE_L3_IPV4;
	offset = mbuf->pkt_len + mbuf->data_off +
			lsinic_mg_entry_align_offset(mg_header->len_cmd[0]);

	if (num > 1) {
		ret = rte_pktmbuf_alloc_bulk(rx_queue->mb_pool,
			new_mbuf, num - 1);
		if (ret)
			return 1;
		mbuf->refcnt = (uint16_t)(mbuf->refcnt + num - 1);
	} else {
		return num;
	}

	mbuf->ol_flags |= LSINIC_SHARED_MBUF;
	pcore = (uint8_t *)mbuf->dynfield1;
	*pcore = rte_lcore_id();

	for (idx = 0; idx < (num - 1); idx++) {
		new_mbuf[idx]->ol_flags |=
			IND_ATTACHED_MBUF | LSINIC_SHARED_MBUF;
		new_mbuf[idx]->buf_iova = mbuf->buf_iova;
		new_mbuf[idx]->buf_addr = mbuf->buf_addr;
		new_mbuf[idx]->buf_len = mbuf->buf_len;

		new_mbuf[idx]->data_off = offset;
		new_mbuf[idx]->pkt_len =
			lsinic_mg_entry_len(mg_header->len_cmd[idx]);
		new_mbuf[idx]->data_len =
			new_mbuf[idx]->pkt_len;
		new_mbuf[idx]->nb_segs = 1;
		new_mbuf[idx]->next = NULL;
		new_mbuf[idx]->port = rx_queue->port_id;
		new_mbuf[idx]->packet_type = RTE_PTYPE_L3_IPV4;
		pcore = (uint8_t *)new_mbuf[idx]->dynfield1;
		*pcore = rte_lcore_id();
		RTE_ASSERT(ALIGN(new_mbuf[idx]->pkt_len,
			LSINIC_MG_ALIGN_SIZE) ==
			(new_mbuf[idx]->pkt_len +
			lsinic_mg_entry_align_offset(mg_header->len_cmd[idx])));

		rx_queue->mcache[rx_queue->mtail] = new_mbuf[idx];
		rx_queue->mtail = (rx_queue->mtail + 1) & MCACHE_MASK;
		rx_queue->mcnt++;

		offset += new_mbuf[idx]->pkt_len +
			lsinic_mg_entry_align_offset(mg_header->len_cmd[idx]);
	}

	return num;
}

static inline struct lsinic_sw_bd *
lsinic_recv_get_sw_bd(struct lsinic_queue *rxq,
	uint16_t bd_idx)
{
	struct lsinic_adapter *adapter = rxq->adapter;
	struct lsinic_sw_bd *rxe;
	struct rte_qdma_job *dma_job;

	if ((adapter->cap & LSINIC_CAP_XFER_COMPLETE) ||
		(adapter->ep_cap & LSINIC_EP_CAP_RXQ_ORP)) {
		rxe = &rxq->sw_ring[bd_idx];
	} else {
		rxe = rxq->sw_bd[rxq->sw_bd_head];
	}

	if (adapter->cap & LSINIC_CAP_XFER_COMPLETE) {
		if ((*rxe->complete) != LSINIC_XFER_COMPLETE_DONE_FLAG)
			return NULL;
		dma_job = &rxq->dma_jobs[bd_idx];
		dma_job->flags &= ~LSINIC_QDMA_JOB_USING_FLAG;
		rxe->complete = NULL;
	} else if (adapter->ep_cap & LSINIC_EP_CAP_RXQ_ORP) {
		if (!rxe->dma_complete)
			return NULL;
		rxe->dma_complete = 0;
	}

	return rxe;
}

static uint16_t
lsinic_dpaa2_recv_pkts(struct lsinic_queue *rxq,
	uint16_t rx_count)
{
	struct lsinic_adapter *adapter = rxq->adapter;
	struct lsinic_sw_bd *rxe;
	uint16_t bd_idx, nb_rx = 0, fd_idx = 0, mbuf_idx = 0;
	struct lsinic_bd_desc *rxdp = NULL;
	uint32_t count = 0, len, first_idx;
	struct rte_eth_dev *recycle_dev = adapter->split_dev->eth_dev;
	eth_tx_burst_t tx_pkt_burst = NULL;
	struct rte_mbuf *mbuf_array[rx_count];
	uint8_t *rx_complete;

	if (s_use_split_tx_cb) {
		if (adapter->ep_cap & LSINIC_EP_CAP_HW_DIRECT_EGRESS)
			tx_pkt_burst = lsinic_dpaa2_split_tx_lpbk;
		else
			tx_pkt_burst = recycle_dev->tx_pkt_burst;
	}

	first_idx = rxq->next_used_idx & (rxq->nb_desc - 1);
	while (nb_rx < rx_count) {
		bd_idx = rxq->next_used_idx & (rxq->nb_desc - 1);
		rxe = rxq->recv_rxe(rxq, bd_idx);
		if (!rxe)
			break;
		rxdp = LSINIC_EP_BD_DESC(rxq, bd_idx);

		if (rxdp->len_cmd & LSINIC_BD_CMD_MG) {
			count = ((rxdp->len_cmd & LSINIC_BD_MG_NUM_MASK) >>
					LSINIC_BD_MG_NUM_SHIFT) + 1;
		} else {
			count = 1;
		}

		if (tx_pkt_burst) {
			rxq->split_cnt[mbuf_idx] = count;
			mbuf_array[mbuf_idx] = rxe->mbuf;
			fd_idx += count;
			mbuf_idx++;
			if (fd_idx >= MAX_TX_RING_SLOTS) {
				tx_pkt_burst(rxq->recycle_txq,
					mbuf_array, mbuf_idx);
				fd_idx = 0;
				mbuf_idx = 0;
			}
		} else {
			count = lsinic_dpaa2_split_mbuf_to_fd(rxe->mbuf,
					&rxq->recycle_fd[fd_idx], count, &len);
			rxq->bytes += len;
			rxq->bytes_fcs += len +
				LSINIC_ETH_FCS_SIZE * count;
			rxq->bytes_overhead += len +
				LSINIC_ETH_OVERHEAD_SIZE * count;
			rxq->packets += count;
			rxq->new_desc += count;
			fd_idx += count;
			if (fd_idx >= MAX_TX_RING_SLOTS) {
				lsinic_dpaa2_enqueue(rxq->recycle_txq,
					&rxq->recycle_fd[0], fd_idx);
				fd_idx = 0;
			}
		}
		nb_rx++;
		rxq->recv_update(rxq, bd_idx, rxe);
		rxq->next_used_idx++;
	}

	if (rxq->ep2rc_update == EP2RC_INDEX_UPDATE &&
		nb_rx > 0) {
		*rxq->local_free_idx =
			(first_idx + nb_rx) & (rxq->nb_desc - 1);
		*rxq->ep2rc.free_idx = *rxq->local_free_idx;
	} else if (rxq->ep2rc_update == EP2RC_RING_UPDATE &&
		nb_rx > 0) {
		rx_complete = rxq->ep2rc.rx_complete;
		if ((first_idx + nb_rx) < rxq->nb_desc) {
			lsinic_pcie_memset_align(&rx_complete[first_idx],
				RING_BD_HW_COMPLETE,
				nb_rx);
		} else {
			lsinic_pcie_memset_align(&rx_complete[first_idx],
				RING_BD_HW_COMPLETE,
				rxq->nb_desc - first_idx);
			if ((first_idx + nb_rx) != rxq->nb_desc) {
				lsinic_pcie_memset_align(&rx_complete[0],
					RING_BD_HW_COMPLETE,
					first_idx + nb_rx - rxq->nb_desc);
			}
		}
	}

	if (tx_pkt_burst && mbuf_idx) {
		tx_pkt_burst(rxq->recycle_txq, mbuf_array, mbuf_idx);
	} else if (fd_idx > 0) {
		lsinic_dpaa2_enqueue(rxq->recycle_txq,
				&rxq->recycle_fd[0], fd_idx);
	}

	return nb_rx;
}

static uint16_t
lsinic_recv_pkts_to_cache(struct lsinic_queue *rxq)
{
	struct lsinic_adapter *adapter = rxq->adapter;
	struct rte_mbuf *rxm;
	struct lsinic_sw_bd *rxe;
	uint16_t bd_idx, first_idx;
	uint16_t nb_rx = 0;
	uint16_t rx_count;
	struct lsinic_bd_desc *rxdp = NULL;
	int count = 0;
	uint8_t *rx_complete;

	if (!lsinic_queue_running(rxq))
		return 0;

	if ((adapter->cap & LSINIC_CAP_XFER_COMPLETE) ||
		(adapter->ep_cap & LSINIC_EP_CAP_RXQ_ORP)) {
		rx_count = rxq->next_avail_idx - rxq->next_used_idx;
	} else {
		rx_count = rxq->next_dma_idx - rxq->next_used_idx;
	}
	if (!rx_count)
		return 0;

	if (rxq->recycle_txq)
		return lsinic_dpaa2_recv_pkts(rxq, rx_count);

	first_idx = rxq->next_used_idx & (rxq->nb_desc - 1);
	while (nb_rx < rx_count) {
		bd_idx = rxq->next_used_idx & (rxq->nb_desc - 1);
		rxe = rxq->recv_rxe(rxq, bd_idx);
		if (!rxe)
			break;
		rxdp = LSINIC_EP_BD_DESC(rxq, bd_idx);
		nb_rx++;

		rxm = rxe->mbuf;
		RTE_ASSERT(rxm);

		if (rxdp->len_cmd & LSINIC_BD_CMD_MG) {
			count = ((rxdp->len_cmd & LSINIC_BD_MG_NUM_MASK) >>
					LSINIC_BD_MG_NUM_SHIFT) + 1;
			if (rxq->split_type == LSINIC_MBUF_CLONE_SPLIT) {
				count = lsinic_split_clone_mbufs(rxq,
					rxm, count);
			} else {
				count = lsinic_fetch_merge_rx_buffer(rxq,
					rxdp, rxm, count);
			}
		} else {
			rxm->packet_type = RTE_PTYPE_L3_IPV4;
			rxq->mcache[rxq->mtail] = rxm;
			rxq->mtail = (rxq->mtail + 1) & MCACHE_MASK;
			rxq->mcnt++;
			count = 1;
		}

		rxq->recv_update(rxq, bd_idx, rxe);
		rxq->next_used_idx++;

		if (count == 0)
			break;
		if (rxq->mcnt > LSINIC_MERGE_MAX_NUM)
			break;
	}

	if (rxq->ep2rc_update == EP2RC_INDEX_UPDATE &&
		nb_rx > 0) {
		*rxq->local_free_idx =
			(first_idx + nb_rx) & (rxq->nb_desc - 1);
		*rxq->ep2rc.free_idx = *rxq->local_free_idx;
	} else if (rxq->ep2rc_update == EP2RC_RING_UPDATE &&
		nb_rx > 0) {
		rx_complete = rxq->ep2rc.rx_complete;
		if ((first_idx + nb_rx) < rxq->nb_desc) {
			lsinic_pcie_memset_align(&rx_complete[first_idx],
				RING_BD_HW_COMPLETE,
				nb_rx);
		} else {
			lsinic_pcie_memset_align(&rx_complete[first_idx],
				RING_BD_HW_COMPLETE,
				rxq->nb_desc - first_idx);
			if ((first_idx + nb_rx) != rxq->nb_desc) {
				lsinic_pcie_memset_align(&rx_complete[0],
					RING_BD_HW_COMPLETE,
					first_idx + nb_rx - rxq->nb_desc);
			}
		}
	}

	return nb_rx;
}

uint16_t
lsinic_recv_pkts(void *rx_queue, struct rte_mbuf **rx_pkts,
	uint16_t nb_pkts)
{
	struct rte_mbuf *rxm;
	uint16_t nb_rx;
	uint16_t count;
	struct lsinic_queue *rxq = rx_queue;
#ifdef LSXINIC_LATENCY_TEST
	uint64_t current_tick = 0;
	uint64_t tick_load;
	uint8_t *tick_load_8 = (uint8_t *)&tick_load;
	uint8_t *tick_save;
	uint8_t i;
#endif

	lsinic_rxq_loop(rxq);
	if (unlikely(rxq->dma_test.pci_addr ||
		rxq->pair->dma_test.pci_addr))
		return 0;
	lsinic_recv_pkts_to_cache(rxq);
	lsinic_txq_loop(rxq);

	if (rxq->mcnt == 0)
		return 0;

	count = RTE_MIN(nb_pkts, rxq->mcnt);
#ifdef LSXINIC_LATENCY_TEST
	if (count > 0)
		current_tick = rte_get_timer_cycles();
#endif
	for (nb_rx = 0; nb_rx < count; nb_rx++) {
		rxm = rxq->mcache[rxq->mhead];
#ifdef LSXINIC_LATENCY_TEST
		tick_save = rte_pktmbuf_mtod_offset(rxm,
			uint8_t *, rxm->pkt_len - sizeof(uint64_t));
		for (i = 0; i < (uint8_t)sizeof(uint64_t); i++)
			tick_load_8[i] = tick_save[i];
		rxq->cyc_diff_total += (current_tick - tick_load);
		rxq->cyc_diff_curr = (current_tick - tick_load);
		rxm->pkt_len -= sizeof(uint64_t);
		rxm->data_len -= sizeof(uint64_t);
#endif
		rx_pkts[nb_rx] = rxm;
		rxq->mhead = (rxq->mhead + 1) & MCACHE_MASK;
		rxq->mcnt--;
		rxq->bytes += rxm->pkt_len;
		rxq->bytes_fcs += rxm->pkt_len + LSINIC_ETH_FCS_SIZE;
		rxq->bytes_overhead += rxm->pkt_len + LSINIC_ETH_OVERHEAD_SIZE;

#ifdef RTE_LIBRTE_LSINIC_DEBUG_RX
		print_mbuf_all(rxm);
#endif
	}

	rxq->new_desc += nb_rx;
	rxq->packets += nb_rx;

	return nb_rx;
}

/*********************************************************************
 *
 *  Queue management functions
 *
 **********************************************************************/
void
lsinic_dev_tx_queue_release(void *txq)
{
	lsinic_queue_release(txq);
}

int
lsinic_dev_tx_queue_setup(struct rte_eth_dev *dev,
			 uint16_t queue_idx,
			 uint16_t nb_desc,
			 unsigned int socket_id,
			 const struct rte_eth_txconf *tx_conf __rte_unused)
{
	struct lsinic_adapter *adapter = dev->process_private;
	struct lsinic_bdr_reg *bdr_reg =
		LSINIC_REG_OFFSET(adapter->ep_ring_virt_base,
			LSINIC_RING_REG_OFFSET);
	struct lsinic_eth_reg *eth_reg =
		LSINIC_REG_OFFSET(adapter->hw_addr, LSINIC_ETH_REG_OFFSET);
	struct lsinic_queue *txq;
	int qdma_dev_id;
	uint32_t i;

	qdma_dev_id = lsinic_dma_init();
	if (qdma_dev_id < 0)
		return -ENODEV;

	/* Note: ep-tx == rc-rx */

	/* Free memory prior to re-allocation if needed... */
	if (dev->data->tx_queues[queue_idx])
		lsinic_queue_release(dev->data->tx_queues[queue_idx]);

	/* First allocate the tx queue data structure */
	txq = lsinic_queue_alloc(adapter, queue_idx, socket_id,
			nb_desc, LSINIC_QUEUE_TX);
	if (!txq)
		return -ENOMEM;

	txq->dma_id = qdma_dev_id;
	txq->dma_vq = -1;
	txq->port_id = dev->data->port_id;

	/* using RC's rx ring to send EP's packets */
	txq->ep_reg = &bdr_reg->rx_ring[queue_idx];
	txq->rc_bd_desc = NULL;
	txq->rc_reg = txq->ep_reg;
	txq->dev = dev;
	txq->ep_bd_desc = (struct lsinic_bd_desc *)
		(adapter->bd_desc_base + LSINIC_RX_BD_OFFSET +
		queue_idx * LSINIC_RING_SIZE);

	inic_memset(txq->ep_bd_desc, 0,
		txq->nb_desc * sizeof(struct lsinic_bd_desc));
	for (i = 0; i < txq->nb_desc; i++)
		txq->ep_bd_desc[i].bd_status = RING_BD_READY;

	LSXINIC_PMD_DBG("port%d txq%d sw_ring:%p \nep_reg:%p"
		" rc_reg:%p bd_desc:%p dma_jobs:%p",
		txq->port_id, txq->queue_id, txq->sw_ring,
		txq->ep_reg, txq->rc_reg, txq->ep_bd_desc, txq->dma_jobs);

	dev->tx_pkt_burst = lsinic_xmit_pkts;

	lsinic_queue_reset(txq);

	dev->data->tx_queues[queue_idx] = txq;

	if (adapter->tx_ring_bd_count != txq->nb_desc) {
		adapter->tx_ring_bd_count = txq->nb_desc;
		LSINIC_WRITE_REG(&eth_reg->rx_entry_num, txq->nb_desc);
	}
	if (adapter->num_tx_queues <= queue_idx) {
		adapter->num_tx_queues = queue_idx + 1;
		LSINIC_WRITE_REG(&eth_reg->rx_ring_num, adapter->num_tx_queues);
	}

	return 0;
}

void
lsinic_dev_rx_queue_release(void *rxq)
{
	lsinic_queue_release(rxq);
}

static const struct rte_memzone *
lsinic_dev_mempool_continue_mz(struct rte_mempool *mp)
{
	struct rte_mempool_memhdr *hdr;
	struct rte_memzone *mz = NULL;
	struct rte_memzone *last_mz = NULL;

	STAILQ_FOREACH(hdr, &mp->mem_list, next) {
		mz = hdr->opaque;
		if (last_mz && mz != last_mz)
			return NULL;
		last_mz = mz;
	}

	return mz;
}

int
lsinic_dev_rx_queue_setup(struct rte_eth_dev *dev,
	uint16_t queue_idx,
	uint16_t nb_desc,
	unsigned int socket_id,
	const struct rte_eth_rxconf *rx_conf,
	struct rte_mempool *mp)
{
	struct lsinic_adapter *adapter = dev->process_private;
	struct lsinic_bdr_reg *bdr_reg =
		LSINIC_REG_OFFSET(adapter->ep_ring_virt_base,
			LSINIC_RING_REG_OFFSET);
	struct lsinic_eth_reg *eth_reg =
		LSINIC_REG_OFFSET(adapter->hw_addr, LSINIC_ETH_REG_OFFSET);
	struct lsinic_queue *rxq;
	int qdma_dev_id;
	uint32_t i;
	struct lsinic_eth_reg *reg =
		LSINIC_REG_OFFSET(adapter->hw_addr, LSINIC_ETH_REG_OFFSET);
	struct rte_lsx_pciep_device *lsinic_dev;

	qdma_dev_id = lsinic_dma_init();
	if (qdma_dev_id < 0)
		return -ENODEV;

	lsinic_dev = adapter->lsinic_dev;

	/* Note: ep-rx == rc-tx */

	/* Free memory prior to re-allocation if needed... */
	if (dev->data->rx_queues[queue_idx])
		lsinic_queue_release(dev->data->rx_queues[queue_idx]);

	/* First allocate the tx queue data structure */
	rxq = lsinic_queue_alloc(adapter, queue_idx, socket_id,
			nb_desc, LSINIC_QUEUE_RX);
	if (!rxq)
		return -ENOMEM;

	adapter->data_room_size =
		rte_pktmbuf_data_room_size(mp) - RTE_PKTMBUF_HEADROOM;
	LSINIC_WRITE_REG(&reg->max_data_room, adapter->data_room_size);

	rxq->dma_id = qdma_dev_id;
	rxq->dma_vq = -1;
	rxq->mb_pool = mp;
	rxq->port_id = dev->data->port_id;
	rxq->crc_len = 0;
	rxq->drop_en = rx_conf->rx_drop_en;

	/* using RC's tx ring to receive EP's packets */
	rxq->ep_reg = &bdr_reg->tx_ring[queue_idx];
	rxq->rc_bd_desc = NULL;
	rxq->rc_reg = rxq->ep_reg;
	rxq->dev = dev;
	rxq->ep_bd_desc = (struct lsinic_bd_desc *)
		(adapter->bd_desc_base +
		queue_idx * LSINIC_RING_SIZE);

	inic_memset(rxq->ep_bd_desc, 0,
		    rxq->nb_desc * sizeof(struct lsinic_bd_desc));
	for (i = 0; i < rxq->nb_desc; i++)
		rxq->ep_bd_desc[i].bd_status = RING_BD_READY;

	LSXINIC_PMD_DBG("port%d rxq%d sw_ring:%p \nep_reg:%p"
		" rc_reg:%p bd_desc:%p dma_jobs:%p",
		rxq->port_id, rxq->queue_id, rxq->sw_ring,
		rxq->ep_reg, rxq->rc_reg, rxq->ep_bd_desc, rxq->dma_jobs);

	lsinic_queue_reset(rxq);

	dev->data->rx_queues[queue_idx] = rxq;

	if (adapter->rx_ring_bd_count != rxq->nb_desc) {
		adapter->rx_ring_bd_count = rxq->nb_desc;
		LSINIC_WRITE_REG(&eth_reg->tx_entry_num, rxq->nb_desc);
	}
	if (adapter->num_rx_queues <= queue_idx) {
		adapter->num_rx_queues = queue_idx + 1;
		LSINIC_WRITE_REG(&eth_reg->tx_ring_num, adapter->num_rx_queues);
	}

	if (adapter->cap & LSINIC_CAP_XFER_HOST_ACCESS_EP_MEM &&
		!lsinic_dev->virt_addr[LSX_PCIEP_XFER_MEM_BAR_IDX]) {
		const struct rte_memzone *mz;
		int ret;

		mz = lsinic_dev_mempool_continue_mz(mp);
		if (mz) {
			ret = lsx_pciep_set_ib_win_mz(lsinic_dev,
				LSX_PCIEP_XFER_MEM_BAR_IDX, mz,
				0);

			if (ret)
				return ret;
			if (lsx_pciep_hw_sim_get(adapter->pcie_idx) &&
				!lsinic_dev->is_vf)
				lsx_pciep_sim_dev_map_inbound(lsinic_dev);
		}
	}

	return 0;
}

void
lsinic_dev_clear_queues(struct rte_eth_dev *dev)
{
	unsigned int i, j;

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		struct lsinic_queue *txq = dev->data->tx_queues[i];
		struct lsinic_queue *next = txq;

		for (j = 0; j < txq->nb_q; j++) {
			if (!next)
				break;

			lsinic_queue_release_mbufs(txq);
			lsinic_queue_reset(next);
			next = next->sibling;
		}
	}

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		struct lsinic_queue *rxq = dev->data->rx_queues[i];
		struct lsinic_queue *next = rxq;

		for (j = 0; j < rxq->nb_q; j++) {
			if (!next)
				break;

			lsinic_queue_release_mbufs(rxq);
			lsinic_queue_reset(next);
			next = next->sibling;
		}
	}
}

/*********************************************************************
 *
 *  Device RX/TX init functions
 *
 **********************************************************************/
int lsinic_dev_rxq_init(struct lsinic_queue *rxq)
{
	lsinic_queue_init(rxq);

	/* Reset crc_len in case it was changed after queue setup by a
	 * call to configure.
	 */
	rxq->crc_len = 0;

	return 0;
}

/* Initializes Receive Unit.
 */
int
lsinic_dev_rx_init(struct rte_eth_dev *dev)
{
	struct lsinic_queue *rxq;
	uint16_t i;
	int ret;

	/* Setup RX queues */
	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		rxq = dev->data->rx_queues[i];
		ret = lsinic_dev_rxq_init(rxq);
		if (ret)
			return ret;
	}

	return 0;
}

int lsinic_dev_txq_init(struct lsinic_tx_queue *txq)
{
	lsinic_queue_init(txq);

	return 0;
}

/* Initializes Transmit Unit.
 */
void
lsinic_dev_tx_init(struct rte_eth_dev *dev)
{
	struct lsinic_queue *txq;
	uint16_t i;

	/* Setup the Base and Length of the Tx Descriptor Rings */
	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		txq = dev->data->tx_queues[i];
		lsinic_dev_txq_init(txq);
	}
}

void lsinic_dev_rx_tx_bind(struct rte_eth_dev *dev)
{
	struct lsinic_queue *txq;
	struct lsinic_queue *rxq;
	uint16_t i, num;

	num = RTE_MIN(dev->data->nb_tx_queues,
			dev->data->nb_rx_queues);

	/* Link RX and Tx Descriptor Rings */
	for (i = 0; i < num; i++) {
		txq = dev->data->tx_queues[i];
		rxq = dev->data->rx_queues[i];
		if (!txq || !rxq)
			continue;

		rxq->pair = txq;
		txq->pair = rxq;
	}
}

void lsinic_dev_rx_stop(struct rte_eth_dev *dev)
{
	struct lsinic_queue *rxq;
	uint16_t i;

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		rxq = dev->data->rx_queues[i];
		lsinic_queue_stop(rxq);
	}
}

void lsinic_dev_tx_stop(struct rte_eth_dev *dev)
{
	struct lsinic_queue *txq;
	uint16_t i;

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		txq = dev->data->tx_queues[i];
		lsinic_queue_stop(txq);
	}
}

void lsinic_dev_rx_enable_start(struct rte_eth_dev *dev)
{
	struct lsinic_queue *rxq;
	uint16_t i;

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		rxq = dev->data->rx_queues[i];
		lsinic_queue_enable_start(rxq);
	}
}

void lsinic_dev_tx_enable_start(struct rte_eth_dev *dev)
{
	struct lsinic_queue *txq;
	uint16_t i;

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		txq = dev->data->tx_queues[i];
		lsinic_queue_enable_start(txq);
	}
}
