/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2026 NXP
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

#include "lsxinic_common_pmd.h"
#include "lsxinic_common.h"
#include "lsxinic_common_reg.h"
#include "lsxinic_ep_ethdev.h"
#include "lsxinic_ep_rxtx.h"
#include "lsxinic_common_helper.h"
#include "lsxinic_ep_dma.h"

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
static RTE_DEFINE_PER_LCORE(uint8_t,
	lsinic_txq_list_initialized);
static RTE_DEFINE_PER_LCORE(uint8_t,
	lsinic_txq_deqeue_from_rxq);
static RTE_DEFINE_PER_LCORE(uint8_t,
	lsinic_txq_num_in_list);
static RTE_DEFINE_PER_LCORE(struct lsinic_tx_queue_list,
	lsinic_txq_list);
static RTE_DEFINE_PER_LCORE(pthread_t, pthrd_id);

static int s_lsx_tx_busy_log;

static int
lsinic_queue_start(struct lsinic_queue *q);

static inline int
lsinic_tx_bd_available(struct lsinic_queue *txq,
	uint16_t bd_idx);

static void
lsinic_txq_loop(uint16_t dq_sync);

static bool
lsinic_queue_running(struct lsinic_queue *q)
{
	return q->status == LSINIC_QUEUE_RUNNING;
}

static bool
lsinic_queue_msi_masked(struct lsinic_queue *q)
{
	struct lsinic_adapter *adapter = LSINIC_QUEUE_PRIVATE(q);
	struct lsinic_rcs_reg *rcs_reg;

	rcs_reg = LSINIC_REG_OFFSET(adapter->hw_addr, LSINIC_RCS_REG_OFFSET);

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

static void
lsinic_queue_dma_release(struct lsinic_queue *q)
{
	if (q->dma_jobs) {
		rte_free(q->dma_jobs);
		q->dma_jobs = NULL;
	}

	if (q->dma_seg_jobs) {
		rte_free(q->dma_seg_jobs);
		q->dma_seg_jobs = NULL;
	}
}

static int
lsinic_queue_dma_clean(struct lsinic_queue *q)
{
	uint16_t idx_completed[LSINIC_QDMA_DQ_MAX_NB];
	struct lsinic_adapter *adapter = LSINIC_QUEUE_PRIVATE(q);
	int ret, i;

	if (q->pkts_eq == q->pkts_dq ||
		(q->type == LSINIC_QUEUE_TX && adapter->txq_dma_silent) ||
		(q->type == LSINIC_QUEUE_RX && adapter->rxq_dma_silent))
		return 0;

	ret = rte_dma_completed(q->dma_id, q->dma_vq,
		LSINIC_QDMA_DQ_MAX_NB, idx_completed, NULL);
	for (i = 0; i < ret; i++) {
		if (idx_completed[i] < q->nb_desc)
			q->pkts_dq++;
	}

	if (q->pkts_eq != q->pkts_dq) {
		LSXINIC_PMD_WARN("port%d %sq%d %ld pkts in dma",
			q->port_id,
			q->type == LSINIC_QUEUE_TX ? "tx" : "rx",
			q->reg_idx, q->pkts_eq - q->pkts_dq);

		return -EAGAIN;
	}

	return 0;
}

/* (Re)set dynamic lsinic queue fields to defaults */
void
lsinic_queue_reset(struct lsinic_queue *q)
{
	struct lsinic_sw_bd *xe = q->sw_ring;
	struct lsinic_dma_job *dma_jobs = q->dma_jobs;
	uint32_t i;

	q->ep_reg->cir = 0;
	if (q->rc_reg)
		LSINIC_WRITE_REG(&q->rc_reg->cir, 0);
	/* Initialize SW ring entries */
	for (i = 0; i < q->nb_desc; i++) {
		xe[i].mbuf = NULL;
		xe[i].my_idx = i;
		if (q->type == LSINIC_QUEUE_TX &&
			q->rc_mem_bd_type == RC_MEM_SEG_LEN)
			xe[i].dma_complete = 1;
		dma_jobs[i].cnxt = (uint64_t)(&xe[i]);
	}

	q->next_dma_idx = 0;
	q->next_avail_idx = 0;
	q->next_used_idx = 0;
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
}

static inline void
lsinic_qdma_rx_seg_enqueue(struct lsinic_queue *queue)
{
	int ret = -1;
	uint16_t nb_jobs = 0, jobs_idx, i, jobs_avail_idx, j;
	struct rte_dma_sge src[LSINIC_QDMA_EQ_DATA_MAX_NB];
	struct rte_dma_sge dst[LSINIC_QDMA_EQ_DATA_MAX_NB];
	struct lsinic_dma_seg_job *job;
	uint32_t len_total = 0;
	uint64_t flags;
	uint64_t bmt = queue->bypass_iommu ? RTE_DPAAX_QDMA_BMT_FLAG : 0;

	/* Qdma multi-enqueue support, max enqueue 32 entries once.
	 * if there are 32 entries or time out, handle them in batch
	 */

	jobs_avail_idx = queue->jobs_avail_idx;
	nb_jobs = queue->jobs_pending;

	if (!nb_jobs)
		return;

	for (i = 0; i < nb_jobs; i++, jobs_avail_idx++) {
		jobs_idx = jobs_avail_idx & (queue->nb_desc - 1);
		job = &queue->dma_seg_jobs[jobs_idx];
		for (j = 0; j < job->seg_nb; j++) {
			queue->dma_idx[j] = jobs_idx;
			src[j].addr = job->src[j];
			src[j].length = job->len[j];
			dst[j].addr = job->dst[j];
			dst[j].length = job->len[j];
			len_total += job->len[j];
		}
		flags = RTE_DPAAX_QDMA_SG_SUBMIT(queue->dma_idx,
			RTE_DMA_OP_FLAG_SUBMIT);
		ret = rte_dma_copy_sg(queue->dma_id,
			queue->dma_vq, src, dst,
			job->seg_nb, job->seg_nb, flags | bmt);
		if (likely(ret >= 0)) {
			queue->pkts_eq += job->seg_nb;
		} else {
			queue->errors++;
			return;
		}
	}

	queue->jobs_pending -= nb_jobs;
	queue->jobs_avail_idx += nb_jobs;
	queue->bytes_eq += len_total;
}

static inline void
lsinic_qdma_tx_seg_enqueue(struct lsinic_queue *queue)
{
	int ret;
	uint16_t jobs_idx, i, jobs_avail_idx;
	struct rte_dma_sge src[LSINIC_QDMA_EQ_MAX_NB];
	struct rte_dma_sge dst[LSINIC_QDMA_EQ_MAX_NB];
	struct lsinic_dma_job *bd_job = NULL;
	struct lsinic_dma_job *e2r_bd_jobs;
	struct lsinic_dma_seg_job *seg_job;
	uint16_t sg_nb = 0;
	uint32_t txq_dma_bd_start = queue->wdma_bd_start;
	uint32_t total_len = 0;
	uint64_t flags;
	uint64_t bmt = queue->bypass_iommu ? RTE_DPAAX_QDMA_BMT_FLAG : 0;

	jobs_avail_idx = queue->jobs_avail_idx;

	if (!queue->jobs_pending)
		return;

	e2r_bd_jobs = &queue->dma_jobs[LSINIC_E2R_BD_DMA_START];

	if (queue->dma_bd_update & DMA_BD_EP2RC_UPDATE) {
		bd_job = &e2r_bd_jobs[txq_dma_bd_start];
		bd_job->len = queue->wdma_bd_len;
	}

	jobs_idx = jobs_avail_idx & (queue->nb_desc - 1);

	seg_job = &queue->dma_seg_jobs[jobs_idx];

	for (i = 0; i < seg_job->seg_nb; i++) {
		queue->dma_idx[i] = jobs_idx;
		src[i].addr = seg_job->src[i];
		src[i].length = seg_job->len[i];
		dst[i].addr = seg_job->dst[i];
		dst[i].length = seg_job->len[i];
		total_len += seg_job->len[i];
	}
	sg_nb = seg_job->seg_nb;

	if (bd_job) {
		queue->dma_idx[seg_job->seg_nb] = bd_job->idx;
		src[seg_job->seg_nb].addr = bd_job->src;
		src[seg_job->seg_nb].length = bd_job->len;
		dst[seg_job->seg_nb].addr = bd_job->dst;
		dst[seg_job->seg_nb].length = bd_job->len;
		sg_nb++;
	}

	flags = RTE_DPAAX_QDMA_SG_SUBMIT(queue->dma_idx,
			RTE_DMA_OP_FLAG_SUBMIT);
	ret = rte_dma_copy_sg(queue->dma_id, queue->dma_vq,
			src, dst, sg_nb, sg_nb, flags | bmt);
	if (likely(ret >= 0)) {
		queue->jobs_pending--;
		queue->jobs_avail_idx++;
		queue->bytes_eq += total_len;
		queue->pkts_eq += seg_job->seg_nb;
	} else {
		LSXINIC_PMD_ERR("LSINIC QDMA enqueue failed!");
		queue->errors++;
	}

	queue->wdma_bd_start = LSINIC_BD_DMA_START_FLAG;
}

static inline void
lsinic_rxq_dma_eq(void *q, int append)
{
	struct lsinic_queue *queue = q;
	struct lsinic_adapter *adapter = LSINIC_QUEUE_PRIVATE(queue);
	int ret, loop;
	uint16_t nb_jobs = 0, jobs_idx, i, jobs_avail_idx, dq;
	struct rte_dma_sge src[LSINIC_QDMA_EQ_MAX_NB];
	struct rte_dma_sge dst[LSINIC_QDMA_EQ_MAX_NB];
	uint16_t max_jobs_nb;
	struct lsinic_dma_job *job;
	uint32_t len_total = 0;
	uint64_t flags;
	uint64_t bmt = queue->bypass_iommu ? RTE_DPAAX_QDMA_BMT_FLAG : 0;

	/* Qdma multi-enqueue support, max enqueue 32 entries once.
	 * if there are 32 entries or time out, handle them in batch
	 */

	jobs_avail_idx = queue->jobs_avail_idx;
	max_jobs_nb = LSINIC_QDMA_EQ_MAX_NB;

	if (!append) {
		nb_jobs = queue->jobs_pending;
		if (nb_jobs > max_jobs_nb)
			nb_jobs = max_jobs_nb;
	} else {
		if (queue->jobs_pending >= max_jobs_nb)
			nb_jobs = max_jobs_nb;
	}

	if (!nb_jobs)
		return;

	for (i = 0; i < nb_jobs; i++, jobs_avail_idx++) {
		jobs_idx = jobs_avail_idx & (queue->nb_desc - 1);
		job = &queue->dma_jobs[jobs_idx];
		queue->dma_idx[i] = job->idx;
		src[i].addr = queue->dma_jobs[jobs_idx].src;
		src[i].length = job->len;
		dst[i].addr = queue->dma_jobs[jobs_idx].dst;
		dst[i].length = job->len;
		len_total += job->len;
	}

eq_again:
	if (adapter->perf_opt & LSINIC_DMA_OPT_RXQ_SG_DMA) {
		flags = RTE_DPAAX_QDMA_SG_SUBMIT(queue->dma_idx,
			RTE_DMA_OP_FLAG_SUBMIT);
		ret = rte_dma_copy_sg(queue->dma_id,
			queue->dma_vq, src, dst,
			nb_jobs, nb_jobs, flags | bmt);
	} else {
		for (i = 0; i < nb_jobs; i++) {
			flags = RTE_DPAAX_QDMA_COPY_SUBMIT(queue->dma_idx[i], 0);
			ret = rte_dma_copy(queue->dma_id,
				queue->dma_vq, src[i].addr,
				dst[i].addr, src[i].length, flags | bmt);
			if (unlikely(ret < 0))
				break;
		}
		ret = rte_dma_submit(queue->dma_id, queue->dma_vq);
	}
	if (likely(ret >= 0)) {
		queue->jobs_pending -= nb_jobs;
		queue->jobs_avail_idx += nb_jobs;
		queue->bytes_eq += len_total;
		queue->pkts_eq += nb_jobs;
	} else {
		if (!adapter->rxq_dma_silent) {
			loop = 0;
			dq = 0;
			while (!dq) {
				dq = queue->dma_dq(queue);
				loop++;
				if (loop > 1000)
					break;
			}
			if (dq)
				goto eq_again;
		}
		LSXINIC_PMD_ERR("RXQ number of jobs(%d)", nb_jobs);
		LSXINIC_PMD_ERR("RXQ BD: eq(%ld)/dq(%ld)",
			queue->bd_eq, queue->bd_dq);
		LSXINIC_PMD_ERR("RXQ PKT: eq(%ld)/dq(%ld)",
			queue->pkts_eq, queue->pkts_dq);
		queue->errors += nb_jobs;
	}
}

static inline void
lsinic_txq_dma_eq(void *q, int append)
{
	struct lsinic_queue *queue = q;
	struct lsinic_adapter *adapter = LSINIC_QUEUE_PRIVATE(queue);
	int ret, loop;
	uint16_t nb_jobs = 0, jobs_idx, i, jobs_avail_idx;
	struct rte_dma_sge src[LSINIC_QDMA_EQ_MAX_NB];
	struct rte_dma_sge dst[LSINIC_QDMA_EQ_MAX_NB];
	struct lsinic_dma_job *jobs[LSINIC_QDMA_EQ_MAX_NB];
	struct lsinic_dma_job *e2r_bd_jobs;
	uint16_t txq_bd_jobs_num = 0, dq;
	uint16_t bd_jobs_len, max_jobs_nb;
	uint32_t txq_dma_bd_start = queue->wdma_bd_start;
	uint16_t txq_bd_step = queue->wdma_bd_len;
	struct lsinic_bd_desc_128 *ep_bd_desc = NULL;
	uint64_t flags;
	uint64_t bmt = queue->bypass_iommu ? RTE_DPAAX_QDMA_BMT_FLAG : 0;

	if (queue->dma_bd_update & DMA_BD_EP2RC_UPDATE) {
		/* At most 2 TX DMA bd jobs.*/
		max_jobs_nb = LSINIC_QDMA_EQ_MAX_NB - 2;
	} else {
		max_jobs_nb = LSINIC_QDMA_EQ_MAX_NB;
	}

	if (queue->rc_mem_bd_type == RC_MEM_BD_128)
		ep_bd_desc = queue->local_bd_128;

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

	e2r_bd_jobs = &queue->dma_jobs[LSINIC_E2R_BD_DMA_START];

	if ((queue->dma_bd_update & DMA_BD_EP2RC_UPDATE) && nb_jobs) {
		bd_jobs_len = txq_bd_step * nb_jobs;
		jobs[nb_jobs] = &e2r_bd_jobs[txq_dma_bd_start];
		if ((txq_dma_bd_start + nb_jobs) <= queue->nb_desc) {
			txq_bd_jobs_num = 1;
			jobs[nb_jobs]->len = bd_jobs_len;
		} else {
			jobs[nb_jobs]->len = txq_bd_step *
				(queue->nb_desc - txq_dma_bd_start);
			jobs[nb_jobs + 1] = &e2r_bd_jobs[0];
			jobs[nb_jobs + 1]->len =
				bd_jobs_len - jobs[nb_jobs]->len;
			txq_bd_jobs_num = 2;
		}

		if (ep_bd_desc) {
			for (i = 0; i < nb_jobs; i++, jobs_avail_idx++) {
				jobs_idx = jobs_avail_idx &
					(queue->nb_desc - 1);
				jobs[i] = &queue->dma_jobs[jobs_idx];
				ep_bd_desc[jobs_idx].bd_status = RING_BD_HW_COMPLETE;
			}
		} else {
			for (i = 0; i < nb_jobs; i++, jobs_avail_idx++) {
				jobs_idx = jobs_avail_idx & (queue->nb_desc - 1);
				jobs[i] = &queue->dma_jobs[jobs_idx];
			}
		}
	} else if (nb_jobs) {
		for (i = 0; i < nb_jobs; i++, jobs_avail_idx++) {
			jobs_idx = jobs_avail_idx & (queue->nb_desc - 1);
			jobs[i] = &queue->dma_jobs[jobs_idx];
		}
	}

	nb_jobs += txq_bd_jobs_num;

	if (!nb_jobs)
		return;

	for (i = 0; i < nb_jobs; i++) {
		queue->dma_idx[i] = jobs[i]->idx;
		src[i].addr = jobs[i]->src;
		src[i].length = jobs[i]->len;
		dst[i].addr = jobs[i]->dst;
		dst[i].length = jobs[i]->len;
	}

eq_again:
	if (adapter->perf_opt & LSINIC_DMA_OPT_TXQ_SG_DMA) {
		flags = RTE_DPAAX_QDMA_SG_SUBMIT(queue->dma_idx,
			RTE_DMA_OP_FLAG_SUBMIT);
		ret = rte_dma_copy_sg(queue->dma_id, queue->dma_vq,
			src, dst, nb_jobs, nb_jobs, flags | bmt);
	} else {
		for (i = 0; i < nb_jobs; i++) {
			flags = RTE_DPAAX_QDMA_COPY_SUBMIT(queue->dma_idx[i], 0);
			ret = rte_dma_copy(queue->dma_id, queue->dma_vq,
				src[i].addr, dst[i].addr, src[i].length, flags | bmt);
			if (unlikely(ret < 0))
				break;
		}
		ret = rte_dma_submit(queue->dma_id, queue->dma_vq);
	}

	if (likely(ret >= 0)) {
		queue->jobs_pending -= (nb_jobs - txq_bd_jobs_num);
		queue->jobs_avail_idx += (nb_jobs - txq_bd_jobs_num);
		for (i = 0; i < (nb_jobs - txq_bd_jobs_num); i++)
			queue->bytes_eq += jobs[i]->len;
		queue->pkts_eq += (nb_jobs - txq_bd_jobs_num);
		queue->bd_eq += txq_bd_jobs_num;
	} else {
		if (!adapter->txq_dma_silent) {
			loop = 0;
			dq = 0;
			while (!dq) {
				dq = queue->dma_dq(queue);
				loop++;
				if (loop > 10000)
					break;
			}
			if (dq)
				goto eq_again;
		}
		LSXINIC_PMD_ERR("TXQ txbd(%d)/data(%d)",
			txq_bd_jobs_num,
			(nb_jobs - txq_bd_jobs_num));
		LSXINIC_PMD_ERR("TXQ BD: eq(%ld)/dq(%ld)",
			queue->bd_eq, queue->bd_dq);
		LSXINIC_PMD_ERR("TXQ PKT: eq(%ld)/dq(%ld)",
			queue->pkts_eq, queue->pkts_dq);
		queue->errors += (nb_jobs - txq_bd_jobs_num);
	}

	queue->wdma_bd_start = LSINIC_BD_DMA_START_FLAG;
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
	/* Rewrite core ID and thread ID because polling context
	 * may differs from the context to start this txq.
	 */
	txq->core_id = rte_lcore_id();
	txq->pid = pthread_self();
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

	RTE_TAILQ_FOREACH_SAFE(q, &RTE_PER_LCORE(lsinic_txq_list), next, tq) {
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

		if (q->type == LSINIC_QUEUE_TX && !q->pair)
			lsinic_add_txq_to_list(q);
		else
			RTE_PER_LCORE(lsinic_txq_deqeue_from_rxq) = 1;

		q->status = LSINIC_QUEUE_RUNNING;
		q->ep_reg->sr = q->status;
		if (q->rc_reg)
			LSINIC_WRITE_REG(&q->rc_reg->sr, q->status);

		return;
	}

	if (q->status == LSINIC_QUEUE_STOP) {
		if (lsinic_queue_dma_clean(q)) {
			/* Wait to the next loop to clean dma queue */
			rte_delay_ms(500);
			return;
		}

		if (q->type == LSINIC_QUEUE_TX)
			lsinic_remove_txq_from_list(q);
		else
			RTE_PER_LCORE(lsinic_txq_deqeue_from_rxq) = 0;

		q->status = LSINIC_QUEUE_UNAVAILABLE;
		q->ep_reg->sr = q->status;
		if (q->rc_reg)
			LSINIC_WRITE_REG(&q->rc_reg->sr, q->status);

		return;
	}
}

static __rte_always_inline uint16_t
lsinic_queue_next_avail_idx(struct lsinic_queue *q,
	uint16_t fwd)
{
	return (q->next_avail_idx + fwd) & (q->nb_desc - 1);
}

static __rte_always_inline uint16_t
lsinic_queue_next_used_idx(struct lsinic_queue *q,
	uint16_t fwd)
{
	return (q->next_used_idx + fwd) & (q->nb_desc - 1);
}

static uint16_t
lsinic_xmit_seg_pkt(struct lsinic_queue *txq,
	struct rte_mbuf *tx_pkt)
{
	struct lsinic_adapter *adapter = LSINIC_QUEUE_PRIVATE(txq);
	struct lsinic_ep_tx_seg_dst_addr *dst_addr;
	struct lsinic_sw_bd *txe;
	uint16_t bd_idx, seg_size = tx_pkt->tso_segsz, idx = 0;
	uint32_t remain_size = tx_pkt->pkt_len;
	struct lsinic_dma_seg_job *dma_job;
	uint64_t dst, src_base = rte_mbuf_data_iova(tx_pkt), dst_base;
	struct lsinic_rc_rx_seg *local_seg;

	if (unlikely(!lsinic_queue_running(txq))) {
		lsinic_queue_status_update(txq);
		if (!lsinic_queue_running(txq))
			return 0;
	}

	bd_idx = txq->next_avail_idx & (txq->nb_desc - 1);
	dst_addr = &txq->tx_seg_dst_addr[bd_idx];
	local_seg = &txq->local_src_seg[bd_idx];
	txe = &txq->sw_ring[bd_idx];

	if (unlikely(!dst_addr->ready)) {
		txq->ring_full++;
		txq->drop_packet_num++;
		LSXINIC_PMD_DBG("TXQ%d:buf[%d] unavailable",
			txq->queue_id, bd_idx);

		return 0;
	}
	if (unlikely(!txe->dma_complete && !adapter->txq_dma_silent)) {
		txq->ring_full++;
		txq->drop_packet_num++;
		LSXINIC_PMD_DBG("TXQ%d:buf[%d] last dma not complete",
			txq->queue_id, bd_idx);
		return 0;
	}

	dma_job = &txq->dma_seg_jobs[bd_idx];

	txe->dma_complete = 0;
	if (txe->mbuf)
		rte_pktmbuf_free(txe->mbuf);

	txe->mbuf = tx_pkt;

	if (seg_size > tx_pkt->pkt_len || !seg_size)
		seg_size = tx_pkt->pkt_len;

	dst_base = txq->ob_base + dst_addr->addr_base;
	while (remain_size) {
		dma_job->src[idx] = src_base + idx * seg_size;
		if (dst_addr->entry[idx].positive)
			dst = dst_base + dst_addr->entry[idx].offset;
		else
			dst = dst_base - dst_addr->entry[idx].offset;
		dma_job->dst[idx] = dst;
		if (remain_size > seg_size) {
			dma_job->len[idx] = seg_size;
			local_seg->len[idx] = seg_size;
			remain_size -= seg_size;
		} else {
			dma_job->len[idx] = remain_size;
			local_seg->len[idx] = remain_size;
			remain_size = 0;
		}
		idx++;
	}
	dma_job->seg_nb = idx;
	dma_job->cnxt = (uint64_t)txe;

	local_seg->nb = idx;

	txq->packets++;

	txq->bytes += tx_pkt->pkt_len;
	txq->bytes_fcs += tx_pkt->pkt_len +
			LSINIC_ETH_FCS_SIZE * dma_job->seg_nb;
	txq->bytes_overhead += tx_pkt->pkt_len +
		LSINIC_ETH_OVERHEAD_SIZE * dma_job->seg_nb;

	dst_addr->ready = 0;

	txq->jobs_pending++;

	if (txq->wdma_bd_start == LSINIC_BD_DMA_START_FLAG)
		txq->wdma_bd_start = bd_idx;
	lsinic_qdma_tx_seg_enqueue(txq);
	txq->next_avail_idx++;

	return 1;
}

static uint16_t
lsinic_xmit_one_pkt(struct lsinic_queue *txq,
	struct rte_mbuf *tx_pkt, struct rte_mbuf **free_pkt)
{
	struct lsinic_adapter *adapter = LSINIC_QUEUE_PRIVATE(txq);
	const struct lsinic_bd_desc_128 *ep_txd = NULL;
	struct lsinic_ep_tx_dst_addr *dst_addr = NULL;
	struct lsinic_sw_bd *txe;
	uint16_t bd_idx;
	struct lsinic_dma_job *dma_job;
	struct lsinic_bd_desc_128 *ep_local_txd;
	struct lsinic_rc_rx_len *src_len;

	if (unlikely(!lsinic_queue_running(txq))) {
		lsinic_queue_status_update(txq);
		if (!lsinic_queue_running(txq))
			return 0;
	}

	bd_idx = txq->next_avail_idx & (txq->nb_desc - 1);
	if (txq->ep_mem_bd_type == EP_MEM_DST_ADDR_BD)
		dst_addr = &txq->tx_dst_addr[bd_idx];
	else
		ep_txd = &txq->ep_bd_desc[bd_idx];

	/* Make sure there are enough TX descriptors available to
	 * transmit the entire packet.
	 * nb_used better be less than or equal to txq->tx_rs_thresh
	 */

	if (dst_addr) {
		if (!(((uint64_t)dst_addr) & RTE_CACHE_LINE_MASK)) {
			rte_lsinic_prefetch((const uint8_t *)dst_addr +
				RTE_CACHE_LINE_SIZE);
		}
		if (unlikely(!dst_addr->pkt_addr)) {
			txq->ring_full++;
			txq->drop_packet_num++;
			if (!s_lsx_tx_busy_log)
				return 0;
			LSXINIC_PMD_WARN("TXQ%d remote addr[%d] unavailable",
				txq->queue_id, bd_idx);
			if (!txq->rc_tx_dst_addr)
				return 0;

			LSXINIC_PMD_WARN("Address(0x%lx) in RC, pir(%d)",
				txq->rc_tx_dst_addr[bd_idx].pkt_addr,
				txq->ep_reg->pir);
			return 0;
		}

		if (unlikely(tx_pkt->pkt_len >= adapter->max_tx_size)) {
			LSXINIC_PMD_WARN("xmit packet len(%d) > max(%d)",
				tx_pkt->pkt_len, adapter->max_tx_size);
			return 0;
		}

		src_len = &txq->local_src_len[bd_idx];

		dma_job = &txq->dma_jobs[bd_idx];
		txe = &txq->sw_ring[bd_idx];

		if (txe->mbuf) {
			if (free_pkt)
				*free_pkt = txe->mbuf;
			else
				rte_pktmbuf_free(txe->mbuf);
		}
		txe->mbuf = tx_pkt;

		dma_job->src = rte_mbuf_data_iova(tx_pkt);
		dma_job->dst = txq->ob_base + dst_addr->pkt_addr;
		dma_job->len = tx_pkt->pkt_len;
		txq->packets++;

		txq->bytes += tx_pkt->pkt_len;
		txq->bytes_fcs += tx_pkt->pkt_len +
			LSINIC_ETH_FCS_SIZE;
		txq->bytes_overhead += tx_pkt->pkt_len +
			LSINIC_ETH_OVERHEAD_SIZE;

		src_len->total_len = tx_pkt->pkt_len;
		dst_addr->pkt_addr = 0;
		dma_job->cnxt = (uint64_t)txe;

		txq->jobs_pending++;

		if (txq->wdma_bd_start == LSINIC_BD_DMA_START_FLAG)
			txq->wdma_bd_start = bd_idx;
		txq->txq_dma_eq(txq, true);
		txq->next_avail_idx++;

		return 1;
	}

	if (unlikely(!lsinic_tx_bd_available(txq, bd_idx))) {
		txq->ring_full++;
		txq->drop_packet_num++;
		if (!txq->rc_bd_desc || !s_lsx_tx_busy_log)
			return 0;
		LSXINIC_PMD_WARN("Status[%d]: remote(0x%08x)/local(0x%08x)",
			bd_idx, txq->rc_bd_desc[bd_idx].bd_status,
			txq->ep_bd_desc[bd_idx].bd_status);
		LSXINIC_PMD_WARN("DMA BD update: pir(%d)",
			txq->ep_reg->pir);
		return 0;
	}

	src_len = &txq->local_src_len[bd_idx];
	ep_local_txd = &txq->local_bd_128[bd_idx];
	if (ep_txd != ep_local_txd)
		rte_memcpy(ep_local_txd, ep_txd, sizeof(struct lsinic_bd_desc_128));

	dma_job = &txq->dma_jobs[bd_idx];

	txe = &txq->sw_ring[bd_idx];

	if (txe->mbuf) {
		if (free_pkt)
			*free_pkt = txe->mbuf;
		else
			rte_pktmbuf_free(txe->mbuf);
	}
	txe->mbuf = tx_pkt;

	dma_job->src = rte_mbuf_data_iova(tx_pkt);
	dma_job->dst = txq->ob_base + ep_txd->pkt_addr;
	dma_job->len = tx_pkt->pkt_len;
	ep_local_txd->len_cmd = LSINIC_BD_CMD_EOP | tx_pkt->pkt_len;
	txq->packets++;

	txq->bytes += tx_pkt->pkt_len;
	txq->bytes_fcs += tx_pkt->pkt_len + LSINIC_ETH_FCS_SIZE;
	txq->bytes_overhead += tx_pkt->pkt_len + LSINIC_ETH_OVERHEAD_SIZE;

	if (txq->rc_mem_bd_type == RC_MEM_LEN_CMD)
		src_len->total_len = tx_pkt->pkt_len;

	txq->local_bd_128[bd_idx].bd_status = RING_BD_HW_PROCESSING;
	dma_job->cnxt = (uint64_t)txe;

	txq->jobs_pending++;

	if (txq->wdma_bd_start == LSINIC_BD_DMA_START_FLAG)
		txq->wdma_bd_start = bd_idx;
	txq->txq_dma_eq(txq, true);
	txq->next_avail_idx++;

	return 1;
}

static __rte_always_inline struct lsinic_sw_bd *
lsinic_recv_rxe_no_dq(struct lsinic_queue *rxq,
	uint16_t bd_idx)
{
	struct lsinic_sw_bd *rxe = &rxq->sw_ring[bd_idx];
	struct lsinic_sw_bd *next_rxe =
		&rxq->sw_ring[(bd_idx + 1) & (rxq->nb_desc - 1)];

	if (likely(next_rxe->complete))
		rte_lsinic_prefetch(next_rxe->complete);

	if ((*rxe->complete) != LSINIC_XFER_COMPLETE_DONE_FLAG)
		return NULL;
	rxe->complete = NULL;

	return rxe;
}

static __rte_always_inline struct lsinic_sw_bd *
lsinic_recv_rxe(struct lsinic_queue *rxq,
	uint16_t bd_idx)
{
	struct lsinic_sw_bd *rxe = &rxq->sw_ring[bd_idx];

	if (!rxe->dma_complete)
		return NULL;
	rxe->dma_complete = 0;

	return rxe;
}

static __rte_always_inline void
lsinic_recv_dummy_update(struct lsinic_queue *rxq __rte_unused,
	uint16_t bd_idx __rte_unused)
{
}

static __rte_always_inline void
lsinic_recv_rxbd_update(struct lsinic_queue *rxq,
	uint16_t bd_idx)
{
	lsinic_bd_update_used_to_rc(rxq, bd_idx);
}

static int
lsinic_txq_start(struct lsinic_queue *q, uint64_t bd_bus_addr)
{
	uint32_t i;
	uint64_t dma_src_base, dma_dst_base;
	int ret;
	struct lsinic_dma_job *dma_jobs;
	struct lsinic_adapter *adapter = LSINIC_QUEUE_PRIVATE(q);
	struct lsinic_bdr_reg *rc_bdr_reg;
	void *rc_ring_base;

	if (q->ep_reg->isr && adapter->txq_dma_silent) {
		LSXINIC_PMD_ERR("TXQ%d unable to trigger ISR in %s",
			q->queue_id, "dma silent mode");

		return -ENOTSUP;
	}

	if (q->ep_reg->isr) {
		/* Don't support to write RC BD by DMA if ISR is enabled.*/
		q->dma_bd_update &= (~DMA_BD_EP2RC_UPDATE);
	}

	dma_dst_base = q->ob_base + bd_bus_addr;

	rc_ring_base = LSINIC_DEV_RC_RING_VIR(LSINIC_DEV_PCIE_DEV(q->dev));
	rc_bdr_reg = LSINIC_REG_OFFSET(rc_ring_base, LSINIC_RING_REG_OFFSET);

	if (q->ep_mem_bd_type == EP_MEM_BD_128) {
		q->ep_bd_desc = q->ep_bd_shared_addr;
		LSXINIC_PMD_INFO("TXQ%d set by RC with 128 bd",
			q->queue_id);
	} else if (q->ep_mem_bd_type == EP_MEM_DST_ADDR_BD) {
		q->tx_dst_addr = q->ep_bd_shared_addr;
		LSXINIC_PMD_INFO("TXQ%d set by RC with full address",
			q->queue_id);
	} else if (q->ep_mem_bd_type == EP_MEM_DST_ADDR_SEG) {
		q->tx_seg_dst_addr = q->ep_bd_shared_addr;
		LSXINIC_PMD_INFO("TXQ%d set by RC with seg address",
			q->queue_id);
	} else {
		LSXINIC_PMD_ERR("Invalid TXQ%d ep mem bd type(%d)",
			q->queue_id, q->ep_mem_bd_type);

		return -EINVAL;
	}

	if (q->ep_bd_desc)
		q->local_bd_128 = q->ep_bd_shared_addr;
	else
		q->local_bd_128 = rte_zmalloc(NULL, LSINIC_BD_RING_SIZE, RTE_CACHE_LINE_SIZE);

	if (q->rc_mem_bd_type == RC_MEM_BD_128) {
		if (q->rc_bd_desc && q->rc_bd_desc != q->rc_bd_mapped_addr) {
			LSXINIC_PMD_ERR("%s: %p != %p", __func__, q->rc_bd_desc,
				q->rc_bd_mapped_addr);

			return -EINVAL;
		}

		q->rc_bd_desc = q->rc_bd_mapped_addr;

		dma_src_base = rte_mem_virt2iova(q->local_bd_128);
		if (dma_src_base == RTE_BAD_IOVA) {
			LSXINIC_PMD_ERR("No IOMMU map for %p, size=%lx",
				q->local_bd_128, sizeof(struct lsinic_bd_desc_128) * q->nb_desc);

			return -ENOBUFS;
		}
		q->wdma_bd_len = sizeof(struct lsinic_bd_desc_128);
		LSXINIC_PMD_INFO("TXQ%d notify to RC with 128b bd", q->queue_id);
	} else if (q->rc_mem_bd_type == RC_MEM_LEN_CMD) {
		q->tx_len = q->rc_bd_mapped_addr;
		q->local_src_len = rte_zmalloc(NULL,
			LSINIC_LEN_RING_SIZE, RTE_CACHE_LINE_SIZE);
		dma_src_base = rte_mem_virt2iova(q->local_src_len);
		if (dma_src_base == RTE_BAD_IOVA) {
			LSXINIC_PMD_ERR("No IOMMU map for %p, size=%lx",
				q->local_src_len, LSINIC_LEN_RING_SIZE);

			return -ENOBUFS;
		}
		q->wdma_bd_len = sizeof(struct lsinic_rc_rx_len);
		LSXINIC_PMD_INFO("TXQ%d notify to RC with len", q->queue_id);
	} else if (q->rc_mem_bd_type == RC_MEM_SEG_LEN) {
		q->tx_seg = q->rc_bd_mapped_addr;
		q->local_src_seg = rte_malloc(NULL,
			LSINIC_SEG_LEN_RING_SIZE,
			RTE_CACHE_LINE_SIZE);
		dma_src_base = rte_mem_virt2iova(q->local_src_seg);
		if (dma_src_base == RTE_BAD_IOVA) {
			LSXINIC_PMD_ERR("No IOMMU map for %p, size=%lx",
				q->local_src_seg, LSINIC_SEG_LEN_RING_SIZE);

			return -ENOBUFS;
		}
		q->wdma_bd_len = sizeof(struct lsinic_rc_rx_seg);
		LSXINIC_PMD_INFO("TXQ%d notify to RC with seg desc",
			q->queue_id);
	} else {
		LSXINIC_PMD_ERR("Invalid TXQ%d rc mem bd type(%d)",
			q->queue_id, q->rc_mem_bd_type);

		return -EINVAL;
	}

	dma_jobs = &q->dma_jobs[LSINIC_E2R_BD_DMA_START];
	for (i = 0; i < q->nb_desc; i++) {
		dma_jobs[i].src = dma_src_base + i * q->wdma_bd_len;
		dma_jobs[i].dst = dma_dst_base + i * q->wdma_bd_len;
	}
	/* Note: ep-rx == rc-tx */
	q->rc_reg = &rc_bdr_reg->rx_ring[q->queue_id];

	lsinic_queue_reset(q);

	rte_spinlock_lock(&adapter->txq_dma_start_lock);
	if (!adapter->txq_dma_started) {
		ret = rte_dma_start(adapter->txq_dma_id);
		if (ret) {
			LSXINIC_PMD_ERR("dma[%d] start failed(%d)",
				adapter->txq_dma_id, ret);
			rte_spinlock_unlock(&adapter->txq_dma_start_lock);
			return ret;
		}
		adapter->txq_dma_started = 1;
	}
	rte_spinlock_unlock(&adapter->txq_dma_start_lock);

	q->core_id = rte_lcore_id();
	q->pid = pthread_self();

	return 0;
}

static int
lsinic_rxq_start(struct lsinic_queue *q)
{
	uint32_t i;
	struct lsinic_bd_desc_128 *bd_desc;
	int ret;
	struct lsinic_adapter *adapter = LSINIC_QUEUE_PRIVATE(q);
	struct lsinic_bdr_reg *rc_bdr_reg;
	void *rc_ring_base;

	if (q->ep_reg->isr && adapter->rxq_dma_silent) {
		LSXINIC_PMD_ERR("RXQ%d unable to trigger ISR in %s",
			q->queue_id, "dma silent mode");

		return -ENOTSUP;
	}
	q->local_bd_128 = NULL;

	rc_ring_base = LSINIC_DEV_RC_RING_VIR(LSINIC_DEV_PCIE_DEV(q->dev));
	rc_bdr_reg = LSINIC_REG_OFFSET(rc_ring_base, LSINIC_RING_REG_OFFSET);

	if (q->ep_mem_bd_type == EP_MEM_BD_128) {
		q->ep_bd_desc = q->ep_bd_shared_addr;
		bd_desc = q->ep_bd_shared_addr;
		for (i = 0; i < q->nb_desc; i++)
			bd_desc[i].bd_status = RING_BD_READY;
		q->local_bd_128 = q->ep_bd_desc;
		LSXINIC_PMD_INFO("RXQ%d notify by RC with 128b bd",
			q->queue_id);
	} else if (q->ep_mem_bd_type == EP_MEM_SRC_BD_64) {
		q->rx_bd_desc_64 = q->ep_bd_shared_addr;
		LSXINIC_PMD_INFO("RXQ%d notify by RC with 64b bd",
			q->queue_id);
	} else if (q->ep_mem_bd_type == EP_MEM_SRC_SEG_BD) {
		q->rx_src_seg = q->ep_bd_shared_addr;
		LSXINIC_PMD_INFO("RXQ%d notify by RC with SG bd",
			q->queue_id);
	} else {
		LSXINIC_PMD_ERR("Invalid RXQ ep mem bd type(%d)",
			q->ep_mem_bd_type);

		return -EINVAL;
	}

	if (q->rc_mem_bd_type == RC_MEM_BD_128) {
		if (q->rc_bd_desc &&
			q->rc_bd_desc != q->rc_bd_mapped_addr) {
			LSXINIC_PMD_ERR("%s: %p != %p",
				__func__, q->rc_bd_desc, q->rc_bd_mapped_addr);

			return -EINVAL;
		}
		q->rc_bd_desc = q->rc_bd_mapped_addr;
		LSXINIC_PMD_INFO("RXQ%d confirm to RC with 128b bd", q->queue_id);
	} else if (q->rc_mem_bd_type == RC_MEM_BD_CNF) {
		q->rc_rx_complete = q->rc_bd_mapped_addr;
		LSXINIC_PMD_INFO("RXQ%d confirm to RC with bd complete",
			q->queue_id);
	} else if (q->rc_mem_bd_type == RC_MEM_IDX_CNF) {
		q->local_src_free_idx = rte_zmalloc(NULL,
			sizeof(uint32_t), RTE_CACHE_LINE_SIZE);
		q->rc_bd_desc = q->rc_bd_mapped_addr;
		q->rc_bd_desc_64 = q->rc_bd_mapped_addr;
		q->rc_rx_src_seg = q->rc_bd_mapped_addr;
		LSXINIC_PMD_INFO("RXQ%d confirm to RC with idx", q->queue_id);
	} else {
		LSXINIC_PMD_ERR("Invalid RXQ rc mem bd type(%d)",
			q->rc_mem_bd_type);

		return -EINVAL;
	}

	if (adapter->rxq_dma_silent)
		q->recv_rxe = lsinic_recv_rxe_no_dq;
	else
		q->recv_rxe = lsinic_recv_rxe;

	if (q->rc_mem_bd_type == RC_MEM_IDX_CNF)
		q->recv_update = lsinic_recv_dummy_update;
	else if (q->rc_mem_bd_type == RC_MEM_BD_CNF)
		q->recv_update = lsinic_recv_dummy_update;
	else
		q->recv_update = lsinic_recv_rxbd_update;

	q->rc_reg = &rc_bdr_reg->tx_ring[q->queue_id];

	lsinic_queue_reset(q);

	if (q->ep_mem_bd_type == EP_MEM_BD_128 &&
		q->rc_mem_bd_type == RC_MEM_BD_128) {
		rte_memcpy(q->rc_bd_desc, q->ep_bd_desc,
			sizeof(struct lsinic_bd_desc_128) * q->nb_desc);
	} else if (q->rc_mem_bd_type == RC_MEM_BD_CNF) {
		for (i = 0; i < q->nb_desc; i++)
			q->rc_rx_complete[i].bd_complete = RING_BD_READY;
	} else if (q->rc_mem_bd_type == RC_MEM_BD_128) {
		bd_desc = q->rc_bd_desc;
		for (i = 0; i < q->nb_desc; i++) {
			bd_desc[i].pkt_addr = 0;
			bd_desc[i].desc = 0;
			bd_desc[i].bd_status = RING_BD_READY;
		}
	}

	rte_spinlock_lock(&adapter->rxq_dma_start_lock);
	if (!adapter->rxq_dma_started) {
		ret = rte_dma_start(adapter->rxq_dma_id);
		if (ret) {
			LSXINIC_PMD_ERR("dma[%d] start failed(%d)",
				adapter->rxq_dma_id, ret);
			rte_spinlock_unlock(&adapter->rxq_dma_start_lock);
			return ret;
		}
		adapter->rxq_dma_started = 1;
	}
	rte_spinlock_unlock(&adapter->rxq_dma_start_lock);

	q->core_id = rte_lcore_id();
	q->pid = pthread_self();

	return 0;
}

static int
lsinic_queue_start(struct lsinic_queue *q)
{
	struct lsinic_ring_reg *ring_reg = q->ep_reg;
	uint32_t msix_vector;
	uint64_t bd_bus_addr, ob_offset, ob_size;
	struct lsinic_adapter *adapter = LSINIC_QUEUE_PRIVATE(q);
	struct rte_lsx_pciep_device *ep_dev = LSINIC_QUEUE_PCIE_DEV(q);
	uint8_t *rc_ring_base = LSINIC_DEV_RC_RING_VIR(LSINIC_DEV_PCIE_DEV(q->dev));

	LSXINIC_PMD_INFO("port%d %sq%d start, nb_desc:%d",
		q->port_id,
		q->type == LSINIC_QUEUE_TX ? "tx" : "rx",
		q->reg_idx, q->nb_desc);

	if (ep_dev->mmsi_flag != LSINIC_DONT_INT) {
		msix_vector =
			(LSINIC_READ_REG(&ring_reg->icr) >>
			LSINIC_INT_VECTOR_SHIFT);
		q->msix_irq = msix_vector;
		if (!rte_lsx_pciep_hw_sim_get(adapter->pcie_idx)) {
			q->msix_cmd = ep_dev->msix_data[msix_vector];
			q->msix_vaddr = ep_dev->msix_addr[msix_vector];
			if (q->msix_vaddr == 0) {
				LSXINIC_PMD_ERR("q->msix_vaddr == NULL");
				return -EINVAL;
			}
		}
	}

	bd_bus_addr = LSINIC_READ_REG((&q->ep_reg->r_desch));
	bd_bus_addr = bd_bus_addr << 32;
	bd_bus_addr |= LSINIC_READ_REG((&q->ep_reg->r_descl));
	if (bd_bus_addr) {
		if (bd_bus_addr < adapter->rc_ring_bus_base) {
			LSXINIC_PMD_ERR("%s%d %s(0x%lx) < %s(0x%lx)",
				q->type == LSINIC_QUEUE_RX ?
				"RXQ" : "TXQ", q->queue_id,
				"BD PCIe address", bd_bus_addr,
				"BD PCIe base",
				adapter->rc_ring_bus_base);
			return -EINVAL;
		}
		ob_offset = bd_bus_addr - adapter->rc_ring_bus_base;
		ob_size = adapter->rc_ring_size;
		if (ob_offset >= ob_size) {
			LSXINIC_PMD_ERR("%s%d %s(0x%lx) > %s(0x%lx)",
				q->type == LSINIC_QUEUE_RX ?
				"RXQ" : "TXQ", q->queue_id,
				"BD PCIe offset", ob_offset,
				"OB PCIe size", ob_size);
			return -EINVAL;
		}
		q->rc_bd_mapped_addr = rc_ring_base + ob_offset;
	} else {
		LSXINIC_PMD_ERR("%s%d No bd addr set from RC",
			q->type == LSINIC_QUEUE_RX ?
			"RXQ" : "TXQ", q->queue_id);
		return -EINVAL;
	}

	q->ep_mem_bd_type = LSINIC_READ_REG(&q->ep_reg->r_ep_mem_bd_type);
	q->rc_mem_bd_type = LSINIC_READ_REG(&q->ep_reg->r_rc_mem_bd_type);

	if (q->type == LSINIC_QUEUE_RX)
		return lsinic_rxq_start(q);
	else
		return lsinic_txq_start(q, bd_bus_addr);
}

static void
lsinic_queue_stop(struct lsinic_queue *q)
{
	struct lsinic_ring_reg *ring_reg = q->ep_reg;

	q->status = LSINIC_QUEUE_STOP;
	ring_reg->sr = q->status;
	if (q->rc_reg) {
		LSINIC_WRITE_REG(&q->rc_reg->sr, q->status);
		q->rc_reg = NULL;
	}
	q->msix_vaddr = NULL;
}

static int
lsinic_queue_init(struct lsinic_queue *q)
{
	struct lsinic_ring_reg *ring_reg = q->ep_reg;

	ring_reg->barl = q->nb_desc;
	LSINIC_WRITE_REG(&q->rc_reg->barl, q->nb_desc);

	q->status = LSINIC_QUEUE_UNAVAILABLE;
	ring_reg->sr = q->status;
	if (q->rc_reg)
		LSINIC_WRITE_REG(&q->rc_reg->sr, q->status);

	return 0;
}

static void
lsinic_queue_enable_start(struct lsinic_queue *q)
{
	struct lsinic_ring_reg *ring_reg = q->ep_reg;
	uint32_t delay_ms = 0;
	int wait_max_sec = LSINIC_RING_WAIT_DEFAULT_SEC;
	enum lsinic_queue_status status = LSINIC_QUEUE_START;

	if (getenv("LSINIC_RING_WAIT_SEC")) {
		wait_max_sec = atoi("LSINIC_RING_WAIT_SEC");
		if (wait_max_sec < 0)
			wait_max_sec = LSINIC_RING_WAIT_DEFAULT_SEC;
	}
	q->status = LSINIC_QUEUE_START;
	rte_smp_wmb();
	do {
		rte_delay_us_sleep(1000);
		rte_smp_rmb();
		delay_ms++;
		status = q->status;
		if (status == LSINIC_QUEUE_START &&
			!(delay_ms % 1000)) {
			LSXINIC_PMD_WARN("%s%d not running after %d seconds",
				q->type == LSINIC_QUEUE_RX ?
				"RXQ" : "TXQ", q->queue_id, delay_ms / 1000);
			wait_max_sec--;
		}
	} while (status == LSINIC_QUEUE_START && wait_max_sec > 0);

	if (status != LSINIC_QUEUE_RUNNING)	{
		LSXINIC_PMD_WARN("%s%d un-expected status(%d)",
			q->type == LSINIC_QUEUE_RX ?
			"RXQ" : "TXQ", q->queue_id, status);
	}
	ring_reg->sr = q->status;
	if (q->rc_reg)
		LSINIC_WRITE_REG(&q->rc_reg->sr, q->status);
}

static void
lsinic_queue_release_mbufs(struct lsinic_queue *q)
{
	unsigned int i;

	if (q->sw_ring) {
		for (i = 0; i < q->nb_desc; i++) {
			if (q->sw_ring[i].mbuf) {
				rte_pktmbuf_free(q->sw_ring[i].mbuf);
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

	if (q->type == LSINIC_QUEUE_RX &&
		q->local_src_free_idx)
		rte_free(q->local_src_free_idx);
	else if (q->type == LSINIC_QUEUE_TX) {
		if (q->rc_mem_bd_type == RC_MEM_SEG_LEN) {
			if (q->local_src_seg)
				rte_free(q->local_src_seg);
		} else {
			if (q->local_src_len)
				rte_free(q->local_src_len);
		}
	}

	if (q->local_bd_128 &&
		q->local_bd_128 != q->ep_bd_desc)
		rte_free(q->local_bd_128);

	rte_free(q);
}

struct lsinic_queue *
lsinic_queue_alloc(struct rte_eth_dev *dev,
	uint16_t queue_idx, int socket_id, uint32_t nb_desc,
	enum lsinic_queue_type type)
{
	struct lsinic_queue *q;
	struct lsinic_adapter *adapter = LSINIC_DEV_PRIVATE(dev);

	/* Validate number of transmit descriptors.
	 * It must not exceed hardware maximum, and must be multiple
	 * of LSINIC_ALIGN.
	 */
	if (((nb_desc * sizeof(struct lsinic_bd_desc_128)) % LSINIC_ALIGN) ||
	    nb_desc > LSINIC_MAX_RING_DESC || nb_desc < LSINIC_MIN_RING_DESC) {
		LSXINIC_PMD_ERR("lsinic queue cannot support %d descs", nb_desc);
		return NULL;
	}

	/* First allocate the tx queue data structure */
	if (type == LSINIC_QUEUE_RX)
		q = &adapter->rxqs[queue_idx];
	else
		q = &adapter->txqs[queue_idx];

	q->dev = dev;
	q->type = type;

	q->nb_desc = nb_desc;
	q->queue_id = queue_idx;
	q->reg_idx = queue_idx;
	q->dma_vq = -1;

	/* Allocate software ring */
	q->sw_ring = rte_zmalloc_socket("q->sw_ring",
		sizeof(struct lsinic_sw_bd) * nb_desc,
		RTE_CACHE_LINE_SIZE, socket_id);
	if (!q->sw_ring) {
		LSXINIC_PMD_ERR("Failed to create sw_ring");
		goto _err;
	}

	/* Allocate DMA jobs ring */
	q->dma_jobs = rte_zmalloc_socket("q->dma_jobs",
		sizeof(struct lsinic_dma_job) * LSINIC_BD_DMA_MAX_COUNT,
		RTE_CACHE_LINE_SIZE, socket_id);
	if (!q->dma_jobs) {
		LSXINIC_PMD_ERR("Failed to create dma_jobs");
		goto _err;
	}

	q->dma_seg_jobs = rte_zmalloc_socket("q->dma_seg_jobs",
		sizeof(struct lsinic_dma_seg_job) * LSINIC_BD_DMA_MAX_COUNT,
		RTE_CACHE_LINE_SIZE, socket_id);
	if (!q->dma_seg_jobs) {
		LSXINIC_PMD_ERR("Failed to create dma_seg_jobs");
		goto _err;
	}

	return q;

_err:
	lsinic_queue_release(q);
	return NULL;
}

static void
lsinic_queue_trigger_interrupt(struct lsinic_queue *q)
{
	struct lsinic_adapter *adapter;
	struct rte_lsx_pciep_device *ep_dev;

	if (likely(!q->ep_reg->isr))
		return;

	adapter = LSINIC_QUEUE_PRIVATE(q);
	ep_dev = LSINIC_QUEUE_PCIE_DEV(q);

	if (likely(ep_dev->mmsi_flag == LSX_PCIEP_DONT_INT))
		return;

	if (lsinic_queue_msi_masked(q))
		return;

	if (!rte_lsx_pciep_hw_sim_get(adapter->pcie_idx)) {
		/* MSI/MSIx */
		rte_lsx_pciep_start_msix(q->msix_vaddr, q->msix_cmd);
	}
}

/*********************************************************************
 *
 *  TX functions
 *
 **********************************************************************/
static uint16_t
lsinic_tx_len_notify_to_rc(struct lsinic_queue *txq, uint16_t pending)
{
	uint16_t burst1 = 0, burst2 = 0;
	uint16_t bd_idx, bd_idx_first, i;
	struct lsinic_rc_rx_len *remote_len = txq->tx_len;

	bd_idx_first = lsinic_queue_next_used_idx(txq, 0);
	for (i = 0; i < pending; i++) {
		bd_idx = lsinic_queue_next_used_idx(txq, i);
		if (txq->local_bd_128[bd_idx].bd_status != RING_BD_HW_COMPLETE) {
			/* Due to OOO DMA*/
			break;
		}
		txq->local_bd_128[bd_idx].bd_status = RING_BD_READY;
	}
	if ((bd_idx_first + i) > txq->nb_desc) {
		burst1 = txq->nb_desc - bd_idx_first;
		burst2 = i - burst1;
	} else {
		burst1 = i;
		burst2 = 0;
	}
	lsinic_pcie_memcp_align(&remote_len[bd_idx_first],
		&txq->local_src_len[bd_idx_first],
		burst1 * sizeof(struct lsinic_rc_rx_len));
	if (burst2) {
		lsinic_pcie_memcp_align(&remote_len[0],
			&txq->local_src_len[0],
			burst2 * sizeof(struct lsinic_rc_rx_len));
	}

	return i;
}

static uint16_t
lsinic_tx_seg_notify_to_rc(struct lsinic_queue *txq, uint16_t pending)
{
	uint16_t burst1 = 0, burst2 = 0;
	uint16_t bd_idx_first;
	struct lsinic_rc_rx_seg *tx_seg = txq->tx_seg;

	bd_idx_first = lsinic_queue_next_used_idx(txq, 0);
	if ((bd_idx_first + pending) > txq->nb_desc) {
		burst1 = txq->nb_desc - bd_idx_first;
		burst2 = pending - burst1;
	} else {
		burst1 = pending;
		burst2 = 0;
	}

	lsinic_pcie_memcp_align(&tx_seg[bd_idx_first],
		&txq->local_src_seg[bd_idx_first],
		burst1 * sizeof(struct lsinic_rc_rx_seg));
	if (burst2) {
		lsinic_pcie_memcp_align(&tx_seg[0],
			&txq->local_src_seg[0],
			burst2 * sizeof(struct lsinic_rc_rx_seg));
	}

	return pending;
}

static void
lsinic_tx_update_to_rc(struct lsinic_queue *txq)
{
	uint16_t pending, bd_idx, i;

	pending = txq->next_dma_idx - txq->next_used_idx;
	if (txq->rc_mem_bd_type == RC_MEM_SEG_LEN) {
		i = lsinic_tx_seg_notify_to_rc(txq, pending);
	} else if (txq->rc_mem_bd_type == RC_MEM_LEN_CMD) {
		i = lsinic_tx_len_notify_to_rc(txq, pending);
	} else {
		for (i = 0; i < pending; i++) {
			bd_idx = lsinic_queue_next_used_idx(txq, i);
			if (txq->local_bd_128[bd_idx].bd_status != RING_BD_HW_COMPLETE) {
				/* Due to OOO DMA*/
				break;
			}
			lsinic_bd_update_used_to_rc(txq, bd_idx);
			txq->local_bd_128[bd_idx].bd_status = RING_BD_READY;
		}
	}

	txq->next_used_idx += i;

	if (likely(i > 0))
		lsinic_queue_trigger_interrupt(txq);
}

static uint16_t
lsinic_txq_dma_dq(void *q)
{
	struct lsinic_queue *txq = q;
	struct lsinic_adapter *adapter = LSINIC_QUEUE_PRIVATE(txq);
	struct lsinic_dma_job *dma_job;
	struct lsinic_dma_seg_job *seg_job;
	struct lsinic_sw_bd *txe = NULL;
	const struct lsinic_bd_desc_128 *bd;
	uint16_t pkts_dq = 0;
	int i, ret = 0;
	uint16_t idx_completed[LSINIC_QDMA_DQ_MAX_NB], idx;

	ret = rte_dma_completed(adapter->txq_dma_id,
		txq->dma_vq, LSINIC_QDMA_DQ_MAX_NB,
		idx_completed, NULL);
	if (!ret)
		txq->txq_dma_eq(txq, false);

	if (txq->ep_mem_bd_type == EP_MEM_DST_ADDR_SEG)
		goto dq_seg;

	for (i = 0; i < ret; i++) {
		if (idx_completed[i] < LSINIC_BD_ENTRY_COUNT) {
			idx = idx_completed[i];
		} else {
			idx = idx_completed[i] - LSINIC_BD_ENTRY_COUNT;
			txq->bd_dq++;
			continue;
		}
		dma_job = &txq->dma_jobs[idx];
		txq->bytes_dq += dma_job->len;
		pkts_dq++;
		if (likely(txq->dma_bd_update & DMA_BD_EP2RC_UPDATE))
			continue;
		txe = &txq->sw_ring[idx];
		if (txq->ep_bd_desc) {
			bd = &txq->ep_bd_desc[txe->my_idx];
			lsinic_bd_dma_complete_update(txq, txe->my_idx, bd);
		} else {
			lsinic_bd_dma_complete_update(txq, txe->my_idx, NULL);
		}
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
	}
	txq->pkts_dq += pkts_dq;

	return i;

dq_seg:
	for (i = 0; i < ret; i++) {
		if (idx_completed[i] < LSINIC_BD_ENTRY_COUNT) {
			idx = idx_completed[i];
		} else {
			idx = idx_completed[i] - LSINIC_BD_ENTRY_COUNT;
			continue;
		}
		txe = &txq->sw_ring[idx];
		pkts_dq++;
		seg_job = &txq->dma_seg_jobs[idx];
		if (unlikely(!seg_job->seg_nb ||
			seg_job->seg_nb >= RTE_DPAAX_QDMA_JOB_SUBMIT_MAX)) {
			LSXINIC_PMD_ERR("DMA SEG jobs[%d].seg_nb(%d)",
				idx, seg_job->seg_nb);
			rte_panic("Fatal quit\n");
		}
		seg_job->seg_nb--;
		if (!seg_job->seg_nb) {
			txq->bytes_dq += txe->mbuf->pkt_len;
			rte_pktmbuf_free(txe->mbuf);
			txe->mbuf = NULL;
			txe->dma_complete = 1;
		}

		if (likely(txq->dma_bd_update & DMA_BD_EP2RC_UPDATE))
			continue;
		txq->next_dma_idx++;
	}
	txq->pkts_dq += pkts_dq;

	return i;
}

static inline int
lsinic_tx_bd_available(struct lsinic_queue *txq,
	uint16_t bd_idx)
{
	struct lsinic_adapter *adapter = LSINIC_QUEUE_PRIVATE(txq);
	const struct lsinic_bd_desc_128 *ep_txd = &txq->ep_bd_desc[bd_idx];
	int full_count = 0;

	if (!(((uint64_t)ep_txd) & RTE_CACHE_LINE_MASK))
		rte_lsinic_prefetch((const uint8_t *)ep_txd +
			RTE_CACHE_LINE_SIZE);

	while (unlikely(ep_txd->bd_status != RING_BD_READY)) {
		if (!adapter->txq_dma_silent) {
			if (txq->pkts_eq > txq->pkts_dq) {
				txq->dma_dq(txq);
				if (!(txq->dma_bd_update & DMA_BD_EP2RC_UPDATE))
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
lsinic_xmit_pkts_burst(struct lsinic_queue *txq,
	struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	uint16_t tx_num = 0;
	int ret, free_idx = 0;
	const int bulk_free = 1;
	struct rte_mbuf *free_pkts[nb_pkts];
	struct rte_mbuf *free_pkt = NULL;
	struct rte_mbuf **ppkt = NULL;

	if (bulk_free)
		ppkt = &free_pkt;

	if (txq->ep_mem_bd_type == EP_MEM_DST_ADDR_SEG) {
		while (nb_pkts) {
			ret = lsinic_xmit_seg_pkt(txq, tx_pkts[tx_num]);
			if (unlikely(ret != 1)) {
				txq->errors += nb_pkts;
				break;
			}

			tx_num++;
			nb_pkts--;
		}
		goto free_last_pkts;
	}

	while (nb_pkts) {
		ret = lsinic_xmit_one_pkt(txq, tx_pkts[tx_num], ppkt);
		if (ppkt && *ppkt) {
			free_pkts[free_idx] = *ppkt;
			free_idx++;
			*ppkt = NULL;
		}
		if (unlikely(ret != 1)) {
			txq->errors += nb_pkts;
			break;
		}

		tx_num++;
		nb_pkts--;
	}

free_last_pkts:
	if (free_idx > 0)
		rte_pktmbuf_free_bulk(free_pkts, free_idx);

	if (unlikely(!txq->pair)) {
		if (!(txq->dma_bd_update & DMA_BD_EP2RC_UPDATE))
			lsinic_txq_loop(tx_num);
		else
			lsinic_txq_loop(0);
	}

	return tx_num;
}

uint16_t
lsinic_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts,
	uint16_t nb_pkts)
{
	struct lsinic_queue *txq = tx_queue;
	struct lsinic_adapter *adapter = LSINIC_QUEUE_PRIVATE(txq);

	if (unlikely(txq->core_id == RTE_MAX_LCORE && txq->pair)) {
		/* This txq has not been added to list from it's pair.*/
		return 0;
	}

	if (unlikely(!txq->ep_enabled))
		return 0;

	if (unlikely(!lsinic_queue_running(txq))) {
		rte_spinlock_lock(&txq->multi_core_lock);
		lsinic_queue_status_update(txq);
		if (!lsinic_queue_running(txq)) {
			rte_spinlock_unlock(&txq->multi_core_lock);
			return 0;
		}
		rte_spinlock_unlock(&txq->multi_core_lock);
	}

	if (unlikely(!RTE_PER_LCORE(pthrd_id)))
		RTE_PER_LCORE(pthrd_id) = pthread_self();

	if (unlikely(txq->core_id != rte_lcore_id() ||
		!pthread_equal(txq->pid, RTE_PER_LCORE(pthrd_id)))) {
		if (!txq->multi_core_ring) {
			char ring_name[RTE_MEMZONE_NAMESIZE];

			sprintf(ring_name,
				"txq_mpsc_%d_%d_%d_%d_%d",
				adapter->pcie_idx, adapter->pf_idx,
				adapter->is_vf, adapter->vf_idx,
				txq->queue_id);
			rte_spinlock_lock(&txq->multi_core_lock);
			if (txq->multi_core_ring) {
				rte_spinlock_unlock(&txq->multi_core_lock);
				goto eq_start;
			}
			txq->multi_core_ring = rte_ring_create(ring_name,
				txq->nb_desc, rte_socket_id(),
				RING_F_SC_DEQ);
			rte_spinlock_unlock(&txq->multi_core_lock);
			if (txq->multi_core_ring) {
				LSXINIC_PMD_INFO("%s created on core %d.",
					ring_name, rte_lcore_id());
			} else {
				LSXINIC_PMD_ERR("%s created on core %d failed.",
					ring_name, rte_lcore_id());
				return 0;
			}
		}

eq_start:
		return rte_ring_mp_enqueue_burst(txq->multi_core_ring,
				(void * const *)tx_pkts, nb_pkts, NULL);
	}
#ifdef LSXINIC_LATENCY_PROFILING
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

	txq->loop_avail++;

	/* TX loop */
	return lsinic_xmit_pkts_burst(txq, tx_pkts, nb_pkts);
}

/*********************************************************************
 *
 *  RX functions
 *
 **********************************************************************/
static uint16_t
lsinic_rxq_dma_dq(void *q)
{
	struct lsinic_queue *rxq = q;
	struct lsinic_adapter *adapter = LSINIC_QUEUE_PRIVATE(rxq);
	struct lsinic_sw_bd *rxe;
	struct lsinic_bd_desc_128 *rxdp;
	struct lsinic_dma_job *dma_job;
	int i, ret = 0;
	uint16_t idx_completed[LSINIC_QDMA_DQ_MAX_NB], idx;

	if (rxq->pkts_eq == rxq->pkts_dq &&
		rxq->bd_eq == rxq->bd_dq)
		return 0;

	ret = rte_dma_completed(adapter->rxq_dma_id,
		rxq->dma_vq, LSINIC_QDMA_DQ_MAX_NB,
		idx_completed, NULL);
	if (!ret)
		return 0;

	if (rxq->ep_mem_bd_type == EP_MEM_SRC_SEG_BD)
		goto dq_seg;

	for (i = 0; i < ret; i++) {
		if (idx_completed[i] < LSINIC_BD_ENTRY_COUNT) {
			idx = idx_completed[i];
		} else {
			idx = idx_completed[i] - LSINIC_BD_ENTRY_COUNT;
			rxq->bd_dq++;
			continue;
		}
		rxe = &rxq->sw_ring[idx];
		dma_job = &rxq->dma_jobs[idx];
		rxq->bytes_dq += dma_job->len;
		rxq->pkts_dq++;
		if (unlikely(rxe->dma_complete))
			LSXINIC_PMD_WARN("RX BD[%d] DMA complete already??", idx);
		rxe->dma_complete = 1;
		if (rxq->ep_bd_desc) {
			rxdp = &rxq->ep_bd_desc[rxe->my_idx];
			rxdp->bd_status = RING_BD_HW_COMPLETE;
		}
	}

	return ret;

dq_seg:

	for (i = 0; i < ret; i++) {
		if (idx_completed[i] < LSINIC_BD_ENTRY_COUNT) {
			idx = idx_completed[i];
		} else {
			idx = idx_completed[i] - LSINIC_BD_ENTRY_COUNT;
			rxq->bd_dq++;
			continue;
		}
		rxe = &rxq->sw_ring[idx];
		rxq->dma_seg_jobs[idx].seg_nb--;
		if (!rxq->dma_seg_jobs[idx].seg_nb) {
			rxq->bytes_dq += rxe->mbuf->pkt_len;
			rxe->dma_complete = 1;
		}
		rxq->pkts_dq++;
	}

	return ret;
}

static __rte_always_inline void
lsinic_recv_mbuf_dma_set(void *job,
	struct rte_mbuf *mbuf, uint32_t pkt_len, uint32_t port_id,
	int complete_check)
{
	struct lsinic_sw_bd *rxe;
	struct lsinic_dma_job *dma_job = job;

	dma_job->dst = rte_mbuf_data_iova_default(mbuf);
	mbuf->nb_segs = 1;
	mbuf->next = NULL;
	mbuf->pkt_len = pkt_len;
	mbuf->data_len = pkt_len;
	mbuf->port = port_id;
	rxe = (struct lsinic_sw_bd *)dma_job->cnxt;
	mbuf->data_off = RTE_PKTMBUF_HEADROOM + rxe->align_dma_offset;
	rxe->mbuf = mbuf;
	if (complete_check) {
		rxe->complete = rte_pktmbuf_mtod_offset(mbuf,
			char *, pkt_len);
		(*rxe->complete) = LSINIC_XFER_COMPLETE_INIT_FLAG;
		dma_job->len++;
	} else {
		rxe->dma_complete = 0;
	}
}

static uint16_t
lsinic_recv_seg_bd(struct lsinic_queue *rxq)
{
	struct lsinic_adapter *adapter = LSINIC_QUEUE_PRIVATE(rxq);
	struct lsinic_seg_desc *rxdp, *rc_rxdp;
	struct lsinic_dma_seg_job *dma_seg_job;
	struct rte_mbuf *rxm;
	struct lsinic_sw_bd *rxe;
	uint64_t addr_base = rxq->ob_base;

	uint32_t offset = 0, align_len;
	uint16_t bd_idx, idx, next_bd_idx;
	uint8_t *prefetch_addr;

	rxq->loop_total++;
	if (unlikely(lsinic_queue_next_avail_idx(rxq, 1) ==
		lsinic_queue_next_used_idx(rxq, 0)))
		return 0;

	bd_idx = lsinic_queue_next_avail_idx(rxq, 0);

	next_bd_idx = (bd_idx + 1) & (rxq->nb_desc - 1);
	prefetch_addr = (void *)&rxq->rx_src_seg[next_bd_idx];

extract_again:
	rxdp = &rxq->rx_src_seg[bd_idx];
	if (!rxdp->nb) {
		if (!rxq->rc_bd_check)
			goto quit_recv;
		if (rxq->rc_bd_check_pp < LSINIC_RC_BD_CHECK_PP_MAX) {
			rxq->rc_bd_check_pp++;
			goto quit_recv;
		}
		rxq->rc_bd_check_pp = 0;
		rc_rxdp = &rxq->rc_rx_src_seg[bd_idx];
		if (rc_rxdp->nb) {
			rxq->align_err++;
			rte_memcpy(rxdp, rc_rxdp, sizeof(struct lsinic_seg_desc));
			goto extract_again;
		}
quit_recv:
		rxq->rxq_dma_eq(rxq, false);
		return 0;
	}

	rxq->rc_bd_check_pp = 0;

	for (idx = 0; idx < LSINIC_SEG_DESC_CACHE_LINE_NB; idx++)
		rte_prefetch0(prefetch_addr + idx * RTE_CACHE_LINE_SIZE);

	rxm = rte_pktmbuf_alloc(rxq->mb_pool);
	if (unlikely(!rxm)) {
		rxq->rxq_dma_eq(rxq, false);
		return 0;
	}

	rxm->data_off = RTE_PKTMBUF_HEADROOM;

	rxe = &rxq->sw_ring[bd_idx];
	rxe->mbuf = rxm;
	dma_seg_job = &rxq->dma_seg_jobs[bd_idx];

	addr_base += rxdp->base_addr;
	for (idx = 0; idx < rxdp->nb; idx++) {
		if (rxdp->entry[idx].positive) {
			dma_seg_job->src[idx] = addr_base +
				rxdp->entry[idx].offset;
		} else {
			dma_seg_job->src[idx] = addr_base -
				rxdp->entry[idx].offset;
		}
		dma_seg_job->len[idx] = rxdp->entry[idx].len;
		dma_seg_job->dst[idx] = rte_pktmbuf_iova_offset(rxm, offset);
		offset += dma_seg_job->len[idx];
	}
	dma_seg_job->seg_nb = rxdp->nb;
	dma_seg_job->cnxt = (uint64_t)rxe;

	rxm->pkt_len = offset;
	rxm->data_len = offset;

	align_len = offset;
	while (align_len % rxdp->nb)
		align_len++;
	rxm->tso_segsz = align_len / rxdp->nb;

	if (adapter->rxq_dma_silent) {
		rxe->complete = rte_pktmbuf_mtod_offset(rxm,
			char *, offset);
		(*rxe->complete) = LSINIC_XFER_COMPLETE_INIT_FLAG;
		dma_seg_job->len[rxdp->nb - 1]++;
	} else {
		rxe->dma_complete = 0;
	}

	rxq->next_avail_idx++;

	rxq->loop_avail++;

	rxq->jobs_pending++;
	lsinic_qdma_rx_seg_enqueue(rxq);

	return rxdp->nb;
}

static inline int
lsinic_recv_bd_64_extract(struct lsinic_queue *rxq, uint16_t bd_idx,
	uint64_t *pdma, uint16_t *psize)
{
	union lsinic_bd_desc_64 *rxdp_64, *rc_bd_desc_64;

	rxdp_64 = &rxq->rx_bd_desc_64[bd_idx];

extract_again:
	if (unlikely(!rxdp_64->len_cmd)) {
		if (!rxq->rc_bd_check)
			goto quit_recv;
		if (rxq->rc_bd_check_pp < LSINIC_RC_BD_CHECK_PP_MAX) {
			rxq->rc_bd_check_pp++;
			goto quit_recv;
		}
		rxq->rc_bd_check_pp = 0;
		rc_bd_desc_64 = &rxq->rc_bd_desc_64[bd_idx];
		if (rc_bd_desc_64->len_cmd) {
			rxq->align_err++;
			LSXINIC_PMD_DBG("RX BD[%d] RC(0x%lx) != EP(err count=%ld)",
				bd_idx, rc_bd_desc_64->desc, rxq->align_err);
			rxdp_64->desc = rc_bd_desc_64->desc;
			goto extract_again;
		}
quit_recv:
		rxq->rxq_dma_eq(rxq, false);
		return false;
	}
	rxq->rc_bd_check_pp = 0;

	*pdma = rxdp_64->pkt_addr;
	*psize = rxdp_64->len_cmd;
	rxdp_64->desc = 0;

	return true;
}

static inline int
lsinic_recv_bd_extract(struct lsinic_queue *rxq, uint16_t bd_idx,
	uint64_t *pdma, uint16_t *psize)
{
	struct lsinic_bd_desc_128 *rxdp, *rc_bd_desc;

	rxdp = &rxq->ep_bd_desc[bd_idx];

	if (!(((uint64_t)rxdp) & RTE_CACHE_LINE_MASK)) {
		rte_lsinic_prefetch((const uint8_t *)rxdp +
			RTE_CACHE_LINE_SIZE);
	}

extract_again:
	if (rxdp->bd_status != RING_BD_AVAILABLE) {
		if (!rxq->rc_bd_check)
			goto quit_recv;
		if (rxq->rc_bd_check_pp < LSINIC_RC_BD_CHECK_PP_MAX) {
			rxq->rc_bd_check_pp++;
			goto quit_recv;
		}
		rxq->rc_bd_check_pp = 0;
		rc_bd_desc = &rxq->rc_bd_desc[bd_idx];
		if (rc_bd_desc->bd_status == RING_BD_AVAILABLE) {
			rxq->align_err++;
			LSXINIC_PMD_DBG("RX BD[%d] RC stat(0x%08x) != EP(0x%08x)(err count=%ld)",
				bd_idx, rc_bd_desc->bd_status, rxdp->bd_status, rxq->align_err);
			rte_memcpy(rxdp, rc_bd_desc, sizeof(struct lsinic_bd_desc_128));
			goto extract_again;
		}
quit_recv:
		rxq->rxq_dma_eq(rxq, false);
		return false;
	}
	rxq->rc_bd_check_pp = 0;
	rxdp->bd_status = RING_BD_HW_PROCESSING;

	*pdma = rxdp->pkt_addr;
	*psize = rxdp->len_cmd & LSINIC_BD_LEN_MASK;

	return true;
}

static uint16_t
lsinic_recv_bd_bulk_alloc_buf(struct lsinic_queue *rxq)
{
	struct lsinic_adapter *adapter = LSINIC_QUEUE_PRIVATE(rxq);
	struct lsinic_dma_job *dma_job[DEFAULT_TX_RS_THRESH];
	struct lsinic_sw_bd *rxe = NULL;
	struct rte_mbuf *rxm[DEFAULT_TX_RS_THRESH];

	uint32_t pkt_len[DEFAULT_TX_RS_THRESH];
	uint16_t bd_idx, i, size, bd_num = 0;
	uint64_t dma;
	int ret;

	do {
		if (unlikely(lsinic_queue_next_avail_idx(rxq, 1) ==
			lsinic_queue_next_used_idx(rxq, 0)))
			break;
		bd_idx = lsinic_queue_next_avail_idx(rxq, 0);
		if (rxq->ep_mem_bd_type == EP_MEM_SRC_BD_64) {
			if (!lsinic_recv_bd_64_extract(rxq, bd_idx, &dma, &size))
				break;
		} else {
			if (!lsinic_recv_bd_extract(rxq, bd_idx, &dma, &size))
				break;
		}
		if (unlikely(size > adapter->data_room_size)) {
			rxq->errors++;
			rte_panic("port%d rxq%d BD%d size:%d > %d\n",
				rxq->port_id, rxq->queue_id, bd_idx, size,
				adapter->data_room_size);
			/** Don't handle this error.*/
		}

		dma_job[bd_num] = &rxq->dma_jobs[bd_idx];
		rxe = &rxq->sw_ring[bd_idx];
		dma_job[bd_num]->cnxt = (uint64_t)rxe;
		dma_job[bd_num]->src = dma + rxq->ob_base;
		/* qdma read memory must be aligned 64 */
		rxe->align_dma_offset =
			LSINIC_ALIGN_DMA_CALC_OFFSET(dma_job[bd_num]->src);
		dma_job[bd_num]->src -= rxe->align_dma_offset;
#ifdef LSINIC_CHECK_DMA_ALIGNED
		if (!rte_is_aligned((void *)dma_job[bd_num]->src,
			RTE_CACHE_LINE_SIZE)) {
			LSXINIC_PMD_DBG("BD%d src:0x%lx %s",
				bd_num, dma_job->src, "not aligned with cache line");
		}
#endif
		pkt_len[bd_num] = size - rxq->crc_len;
		dma_job[bd_num]->len = pkt_len[bd_num] + rxe->align_dma_offset;

		bd_num++;
		rxq->next_avail_idx++;

		if (bd_num >= DEFAULT_TX_RS_THRESH)
			break;
	} while (1);

	rxq->loop_total++;

	if (unlikely(!bd_num))
		return 0;

	ret = rte_pktmbuf_alloc_bulk(rxq->mb_pool, rxm, bd_num);
	if (ret) {
		/** Roll back.*/
		rxq->next_avail_idx -= bd_num;
		adapter->eth_data->rx_mbuf_alloc_failed += bd_num;
		goto quit;
	}

	for (i = 0; i < bd_num; i++) {
		rxq->rx_dma_mbuf_set(dma_job[i], rxm[i], pkt_len[i],
			rxq->port_id, adapter->rxq_dma_silent);
		rxq->jobs_pending++;
		rxq->rxq_dma_eq(rxq, true);
	}
	rxq->rxq_dma_eq(rxq, false);

quit:
	if (bd_num > 0)
		rxq->loop_avail++;

	return bd_num;
}

static uint16_t
lsinic_recv_bd(struct lsinic_queue *rxq)
{
	struct lsinic_adapter *adapter = LSINIC_QUEUE_PRIVATE(rxq);
	struct lsinic_bd_desc_128 *rxdp;
	struct lsinic_dma_job *dma_job;
	struct lsinic_sw_bd *rxe = NULL;
	struct rte_mbuf *rxm;

	uint32_t pkt_len;
	uint16_t bd_idx;
	uint32_t size;
	uint32_t len_cmd;
	uint16_t bd_num = 0;

	do {
		if (unlikely(lsinic_queue_next_avail_idx(rxq, 1) ==
			lsinic_queue_next_used_idx(rxq, 0)))
			break;
		bd_idx = lsinic_queue_next_avail_idx(rxq, 0);
		rxdp = &rxq->ep_bd_desc[bd_idx];

		if (!(((uint64_t)rxdp) & RTE_CACHE_LINE_MASK)) {
			rte_lsinic_prefetch((const uint8_t *)rxdp +
				RTE_CACHE_LINE_SIZE);
		}

		if (rxdp->bd_status != RING_BD_AVAILABLE) {
			rxq->rxq_dma_eq(rxq, false);
			break;
		}
		rxdp->bd_status = RING_BD_HW_PROCESSING;

		len_cmd = rxdp->len_cmd;
		size = len_cmd & LSINIC_BD_LEN_MASK;
		if (unlikely(size > adapter->data_room_size)) {
			LSXINIC_PMD_ERR("port%d rxq%d BD%d len_cmd:0x%08x",
				rxq->port_id, rxq->queue_id, bd_idx, len_cmd);
			rxq->errors++;
			rte_panic("line %d\tassert \"%s\" failed\n",
				__LINE__, "size err");

			break;
		}

		dma_job = &rxq->dma_jobs[bd_idx];

		rxe = &rxq->sw_ring[bd_idx];

		dma_job->cnxt = (uint64_t)rxe;

		LSXINIC_PMD_DBG("port%d rxq%d bd_idx=%d pkt_len=%d",
			rxq->port_id, rxq->queue_id,
			bd_idx, size);

		rxm = rte_mbuf_raw_alloc(rxq->mb_pool);
		if (unlikely(!rxm)) {
			adapter->eth_data->rx_mbuf_alloc_failed++;

			LSXINIC_PMD_DBG("Port%d RXQ%d mbuf alloc failed",
				rxq->port_id, rxq->queue_id);
			break;
		}

		/* rxm is ret_mbuf passed to upper layer */
		rxe->mbuf = rxm;

		dma_job->dst = rte_mbuf_data_iova_default(rxm);
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

		rxm->nb_segs = 1;
		rxm->next = NULL;
		rxm->pkt_len = pkt_len;
		rxm->data_len = pkt_len;
		rxm->port = rxq->port_id;
		rxm->data_off = RTE_PKTMBUF_HEADROOM +
			rxe->align_dma_offset;

		if (adapter->rxq_dma_silent) {
			rxe->complete = rte_pktmbuf_mtod_offset(rxm, char *, dma_job->len);
			(*rxe->complete) = LSINIC_XFER_COMPLETE_INIT_FLAG;
			dma_job->len++;
		} else {
			rxe->dma_complete = 0;
		}

		rxq->next_avail_idx++;
		rxq->jobs_pending++;
		rxq->rxq_dma_eq(rxq, true);
		bd_num++;

		if (bd_num >= DEFAULT_TX_RS_THRESH)
			break;
	} while (1);

	if (unlikely(!bd_num))
		return 0;

	rxq->rxq_dma_eq(rxq, false);

	rxq->loop_avail++;

	return bd_num;
}

static void
lsinic_txq_loop(uint16_t dq_sync)
{
	struct lsinic_queue *q, *tq;
	struct lsinic_adapter *adapter;
	struct rte_mbuf *tx_pkts[DEFAULT_TX_RS_THRESH];
	uint16_t ret, i, xmit_ret, dq, dq_total = 0;

	if (unlikely(!RTE_PER_LCORE(pthrd_id)))
		RTE_PER_LCORE(pthrd_id) = pthread_self();

	/* Check if txq already added to list */
	RTE_TAILQ_FOREACH_SAFE(q, &RTE_PER_LCORE(lsinic_txq_list), next, tq) {
		adapter = LSINIC_QUEUE_PRIVATE(q);
		if (unlikely(!lsinic_queue_running(q))) {
			lsinic_queue_status_update(q);
			if (!lsinic_queue_running(q))
				continue;
		}

		if (unlikely(q->core_id != rte_lcore_id())) {
			TAILQ_REMOVE(&RTE_PER_LCORE(lsinic_txq_list),
				q, next);
			continue;
		}

		if (q->multi_core_ring) {
			ret = rte_ring_sc_dequeue_burst(q->multi_core_ring,
				(void **)tx_pkts, DEFAULT_TX_RS_THRESH, NULL);
			if (ret) {
				xmit_ret = lsinic_xmit_pkts(q, tx_pkts, ret);
				for (i = xmit_ret; i < ret; i++)
					rte_pktmbuf_free(tx_pkts[i]);
			}
		}

		if (!adapter->txq_dma_silent) {
			if (unlikely(dq_sync)) {
				while (dq_total != dq_sync) {
					q->txq_dma_eq(q, false);
					dq = q->dma_dq(q);
					if (dq > 0)
						dq_total += dq;
				}
			} else {
				dq_total = q->dma_dq(q);
			}
			if (!(q->dma_bd_update & DMA_BD_EP2RC_UPDATE)) {
				if (dq_total > 0)
					lsinic_tx_update_to_rc(q);
			}
		} else if (q->ep_mem_bd_type != EP_MEM_DST_ADDR_SEG) {
			if (likely(q->packets_old == q->packets))
				q->txq_dma_eq(q, false);
			q->packets_old = q->packets;
		}

		q->loop_total++;
	}
}

static int
lsinic_rxq_loop(struct lsinic_queue *rxq)
{
	struct lsinic_adapter *adapter = LSINIC_QUEUE_PRIVATE(rxq);
	const int bulk_alloc = 1;
	uint16_t rc_recvd = 0;

	if (unlikely(!lsinic_queue_running(rxq))) {
		lsinic_queue_status_update(rxq);
		if (rxq->pair)
			lsinic_add_txq_to_list(rxq->pair);
		if (!lsinic_queue_running(rxq))
			return -EAGAIN;
	}

	if (unlikely(!rxq->ep_enabled))
		return 0;

	if (rxq->ep_mem_bd_type == EP_MEM_SRC_SEG_BD) {
		rc_recvd = lsinic_recv_seg_bd(rxq);
	} else if (bulk_alloc) {
		rc_recvd = lsinic_recv_bd_bulk_alloc_buf(rxq);
	} else {
		if (rxq->ep_mem_bd_type != EP_MEM_BD_128) {
			LSXINIC_PMD_ERR("RX by SHORT BD TBD");
			return -EINVAL;
		}
		rc_recvd = lsinic_recv_bd(rxq);
	}

	if (!adapter->rxq_dma_silent)
		rxq->dma_dq(rxq);

	return rc_recvd;
}

static const uint8_t
s_hw_complete_16b[16] __rte_cache_aligned = {
	RING_BD_HW_COMPLETE, RING_BD_HW_COMPLETE,
	RING_BD_HW_COMPLETE, RING_BD_HW_COMPLETE,
	RING_BD_HW_COMPLETE, RING_BD_HW_COMPLETE,
	RING_BD_HW_COMPLETE, RING_BD_HW_COMPLETE,

	RING_BD_HW_COMPLETE, RING_BD_HW_COMPLETE,
	RING_BD_HW_COMPLETE, RING_BD_HW_COMPLETE,
	RING_BD_HW_COMPLETE, RING_BD_HW_COMPLETE,
	RING_BD_HW_COMPLETE, RING_BD_HW_COMPLETE
};

static inline void
lsinic_recv_cnf_burst_update(struct lsinic_queue *rxq,
	uint16_t nb_rx, uint16_t first_idx)
{
	uint8_t *start;

	if (unlikely(!nb_rx))
		return;

	if (rxq->rc_mem_bd_type == RC_MEM_IDX_CNF) {
		rxq->local_src_free_idx->idx_complete =
			(first_idx + nb_rx) & (rxq->nb_desc - 1);
		rxq->rc_reg->cir = rxq->local_src_free_idx->idx_complete;
	} else if (rxq->rc_mem_bd_type == RC_MEM_BD_CNF) {
		start = &rxq->rc_rx_complete[first_idx].bd_complete;
		if ((first_idx + nb_rx) < rxq->nb_desc) {
			lsinic_pcie_memset_align(start,
				s_hw_complete_16b, nb_rx);
		} else {
			lsinic_pcie_memset_align(start,
				s_hw_complete_16b,
				rxq->nb_desc - first_idx);
			if ((first_idx + nb_rx) != rxq->nb_desc) {
				start = &rxq->rc_rx_complete[0].bd_complete;
				lsinic_pcie_memset_align(start,
					s_hw_complete_16b,
					first_idx + nb_rx - rxq->nb_desc);
			}
		}
	} else {
		/* Implemented by recv_update callback*/
	}
}

static void
lsinic_recv_pkts_to_cache_seg(struct lsinic_queue *rxq)
{
	struct rte_mbuf *rxm;
	struct lsinic_sw_bd *rxe;
	uint16_t bd_idx, first_idx;
	uint16_t nb_rx = 0;
	uint16_t rx_count;
	struct lsinic_seg_desc *rxdp = NULL;

	rx_count = rxq->next_avail_idx - rxq->next_used_idx;
	if (!rx_count)
		return;

	first_idx = lsinic_queue_next_used_idx(rxq, 0);
	while (nb_rx < rx_count) {
		bd_idx = lsinic_queue_next_used_idx(rxq, 0);
		rxdp = &rxq->rx_src_seg[bd_idx];
		rxe = rxq->recv_rxe(rxq, bd_idx);
		if (!rxe)
			break;
		nb_rx++;

		rxm = rxe->mbuf;
		RTE_ASSERT(rxm);

		/** Merge multiple segments from RC to single continue buffer,
		 * so the nb_segs should be 1.
		 */
		rxm->nb_segs = 1;
		rxm->packet_type = RTE_PTYPE_L3_IPV4;
		rxq->mcache[rxq->mtail] = rxm;
		rxq->mtail = (rxq->mtail + 1) & MCACHE_MASK;
		rxq->mcnt++;
		rxdp->nb = 0;

		rxq->next_used_idx++;

		if (rxq->mcnt > LSINIC_MAX_BURST_NUM)
			break;
	}

	lsinic_recv_cnf_burst_update(rxq, nb_rx, first_idx);
}

static void
lsinic_recv_pkts_to_cache(struct lsinic_queue *rxq)
{
	struct rte_mbuf *rxm;
	struct lsinic_sw_bd *rxe;
	uint16_t bd_idx, first_idx;
	uint16_t nb_rx = 0;
	uint16_t rx_count;

	rx_count = rxq->next_avail_idx - rxq->next_used_idx;
	if (!rx_count)
		return;

	first_idx = lsinic_queue_next_used_idx(rxq, 0);
	while (nb_rx < rx_count) {
		bd_idx = lsinic_queue_next_used_idx(rxq, 0);
		rxe = rxq->recv_rxe(rxq, bd_idx);
		if (!rxe)
			break;
		nb_rx++;

		rxm = rxe->mbuf;
		RTE_ASSERT(rxm);
		rxm->packet_type = RTE_PTYPE_L3_IPV4;
		rxq->mcache[rxq->mtail] = rxm;
		rxq->mtail = (rxq->mtail + 1) & MCACHE_MASK;
		rxq->mcnt++;

		rxq->recv_update(rxq, bd_idx);
		rxq->next_used_idx++;

		if (rxq->mcnt > LSINIC_MAX_BURST_NUM)
			break;
	}

	lsinic_recv_cnf_burst_update(rxq, nb_rx, first_idx);
}

uint16_t
lsinic_recv_pkts(void *rx_queue, struct rte_mbuf **rx_pkts,
	uint16_t nb_pkts)
{
	int ret;
	struct rte_mbuf *rxm;
	uint16_t nb_rx;
	uint16_t count;
	struct lsinic_queue *rxq = rx_queue;
#ifdef LSXINIC_LATENCY_PROFILING
	uint64_t current_tick = 0;
	uint64_t tick_load;
	uint8_t *tick_load_8 = (uint8_t *)&tick_load;
	uint8_t *tick_save;
	uint8_t i;
	double cyc_per_us = (struct lsinic_adapter *)LSINIC_QUEUE_PRIVATE(rxq)->cycs_per_us;
	double curr_latency;
#endif
	uint64_t pkt_old = rxq->packets;

	if (unlikely(!rxq->ep_enabled))
		return 0;

	lsinic_txq_loop(0);
	ret = lsinic_rxq_loop(rxq);
	if (unlikely(ret < 0)) {
		/**This RXQ not started yet.*/
		return 0;
	}
	if (rxq->ep_mem_bd_type == EP_MEM_SRC_SEG_BD)
		lsinic_recv_pkts_to_cache_seg(rxq);
	else
		lsinic_recv_pkts_to_cache(rxq);

	if (rxq->mcnt == 0)
		return 0;

	count = RTE_MIN(nb_pkts, rxq->mcnt);
#ifdef LSXINIC_LATENCY_PROFILING
	if (count > 0)
		current_tick = rte_get_timer_cycles();
#endif
	for (nb_rx = 0; nb_rx < count; nb_rx++) {
		rxm = rxq->mcache[rxq->mhead];
#ifdef LSXINIC_LATENCY_PROFILING
		tick_save = rte_pktmbuf_mtod_offset(rxm,
			uint8_t *, rxm->pkt_len - sizeof(uint64_t));
		for (i = 0; i < (uint8_t)sizeof(uint64_t); i++)
			tick_load_8[i] = tick_save[i];
		rxq->cyc_diff_total += (current_tick - tick_load);
		curr_latency = (current_tick - tick_load) / cyc_per_us;
		if (rxq->latency_min > curr_latency)
			rxq->latency_min = curr_latency;
		rxq->avg_latency =
			rxq->cyc_diff_total /
			(rxq->packets + nb_rx + 1) / cyc_per_us;
		if (curr_latency >= 2 * rxq->avg_latency &&
			curr_latency < 4 * rxq->avg_latency) {
			rxq->avg_x2_total++;
		} else if (curr_latency >= 4 * rxq->avg_latency &&
			curr_latency < 10 * rxq->avg_latency) {
			rxq->avg_x2_total++;
			rxq->avg_x4_total++;
		} else if (curr_latency >= 10 * rxq->avg_latency &&
			curr_latency < 20 * rxq->avg_latency) {
			rxq->avg_x2_total++;
			rxq->avg_x4_total++;
			rxq->avg_x10_total++;
		} else if (curr_latency >= 20 * rxq->avg_latency &&
			curr_latency < 40 * rxq->avg_latency) {
			rxq->avg_x2_total++;
			rxq->avg_x4_total++;
			rxq->avg_x10_total++;
			rxq->avg_x20_total++;
		} else if (curr_latency >= 40 * rxq->avg_latency &&
			curr_latency < 100 * rxq->avg_latency) {
			rxq->avg_x2_total++;
			rxq->avg_x4_total++;
			rxq->avg_x10_total++;
			rxq->avg_x20_total++;
			rxq->avg_x40_total++;
		} else if (curr_latency >= 100 * rxq->avg_latency) {
			rxq->avg_x2_total++;
			rxq->avg_x4_total++;
			rxq->avg_x10_total++;
			rxq->avg_x20_total++;
			rxq->avg_x40_total++;
			rxq->avg_x100_total++;
		}
		rxm->pkt_len -= sizeof(uint64_t);
		rxm->data_len -= sizeof(uint64_t);
#endif
		rx_pkts[nb_rx] = rxm;
		rxq->mhead = (rxq->mhead + 1) & MCACHE_MASK;
		rxq->mcnt--;
		rxq->bytes += rxm->pkt_len;
		rxq->bytes_fcs += rxm->pkt_len +
			LSINIC_ETH_FCS_SIZE * rxm->nb_segs;
		rxq->bytes_overhead += rxm->pkt_len +
			LSINIC_ETH_OVERHEAD_SIZE * rxm->nb_segs;

#ifdef RTE_LIBRTE_LSINIC_DEBUG_RX
		lsinic_mbuf_print_all(rxm);
#endif
	}

	rxq->packets += nb_rx;
	if (rxq->packets > pkt_old)
		lsinic_queue_trigger_interrupt(rxq);

	return nb_rx;
}

/*********************************************************************
 *
 *  Queue management functions
 *
 **********************************************************************/
void
lsinic_dev_tx_queue_release(struct rte_eth_dev *dev,
	uint16_t qid)
{
	lsinic_queue_release(dev->data->tx_queues[qid]);
}

int
lsinic_dev_tx_queue_setup(struct rte_eth_dev *dev,
	uint16_t queue_idx, uint16_t nb_desc, uint32_t socket_id,
	const struct rte_eth_txconf *tx_conf __rte_unused)
{
	struct lsinic_adapter *adapter = LSINIC_DEV_PRIVATE(dev);
	struct lsinic_bdr_reg *bdr_reg;
	struct lsinic_eth_reg *eth_reg;
	struct lsinic_queue *txq;
	uint16_t max_qpairs;
	uint64_t base_offset;
	uint8_t *txq_base;
	uint64_t q_offset = queue_idx * LSINIC_RING_SIZE;

	bdr_reg = LSINIC_REG_OFFSET(adapter->ep_ring_virt_base, LSINIC_RING_REG_OFFSET);
	eth_reg = LSINIC_REG_OFFSET(adapter->hw_addr, LSINIC_ETH_REG_OFFSET);
	max_qpairs = LSINIC_READ_REG(&eth_reg->max_qpairs);
	if (queue_idx >= max_qpairs) {
		LSXINIC_PMD_ERR("config txq index(%d) >= max qpair(%d)",
			queue_idx, max_qpairs);
		return -EINVAL;
	}
	base_offset = LSINIC_EP2RC_RING_OFFSET(max_qpairs);
	txq_base = adapter->bd_desc_base + base_offset;
	/* Note: ep-tx == rc-rx */

	/* Free memory prior to re-allocation if needed... */
	if (dev->data->tx_queues[queue_idx])
		lsinic_queue_release(dev->data->tx_queues[queue_idx]);

	/* First allocate the tx queue data structure */
	txq = lsinic_queue_alloc(dev, queue_idx, socket_id,
			nb_desc, LSINIC_QUEUE_TX);
	if (!txq)
		return -ENOMEM;

	txq->txq_dma_eq = lsinic_txq_dma_eq;
	txq->dma_dq = lsinic_txq_dma_dq;
	txq->dma_id = adapter->txq_dma_id;
	txq->dma_vq = -1;
	txq->port_id = dev->data->port_id;

	/* using RC's rx ring to send EP's packets */
	txq->ep_reg = &bdr_reg->rx_ring[queue_idx];
	txq->rc_bd_desc = NULL;
	txq->rc_reg = txq->ep_reg;
	txq->dev = dev;
	txq->ep_bd_shared_addr = txq_base + q_offset;

	txq->core_id = RTE_MAX_LCORE;
	txq->pid = 0;
	rte_spinlock_init(&txq->multi_core_lock);

	lsinic_byte_memset(txq->ep_bd_shared_addr,
		0, LSINIC_RING_SIZE);

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

	txq->wdma_bd_start = LSINIC_BD_DMA_START_FLAG;
	txq->dma_idx = rte_malloc(NULL,
		sizeof(uint16_t) * nb_desc,
		RTE_DPAAX_QDMA_SG_IDX_ADDR_ALIGN);
	if (!txq->dma_idx)
		return -ENOMEM;

	LSINIC_WRITE_REG(&txq->ep_reg->ready, LSINIC_INIT_FLAG);

	return 0;
}

void
lsinic_dev_rx_queue_release(struct rte_eth_dev *dev,
	uint16_t qid)
{
	lsinic_queue_release(dev->data->rx_queues[qid]);
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
	uint16_t queue_idx, uint16_t nb_desc, uint32_t socket_id,
	const struct rte_eth_rxconf *rx_conf, struct rte_mempool *mp)
{
	struct lsinic_adapter *adapter = LSINIC_DEV_PRIVATE(dev);
	struct lsinic_bdr_reg *bdr_reg;
	struct lsinic_eth_reg *eth_reg;
	struct lsinic_queue *rxq;
	uint16_t max_qpairs;
	struct rte_lsx_pciep_device *ep_dev;
	uint64_t base_offset;
	uint8_t *rxq_base;
	uint64_t q_offset = queue_idx * LSINIC_RING_SIZE;
	char *env = getenv("LSINIC_EP_RXQ_RC_BD_CHECK");

	bdr_reg = LSINIC_REG_OFFSET(adapter->ep_ring_virt_base, LSINIC_RING_REG_OFFSET);
	eth_reg = LSINIC_REG_OFFSET(adapter->hw_addr, LSINIC_ETH_REG_OFFSET);
	max_qpairs = LSINIC_READ_REG(&eth_reg->max_qpairs);
	if (queue_idx >= max_qpairs) {
		LSXINIC_PMD_ERR("config rxq index(%d) >= max qpair(%d)",
			queue_idx, max_qpairs);
		return -EINVAL;
	}
	base_offset = LSINIC_RC2EP_RING_OFFSET(max_qpairs);
	rxq_base = adapter->bd_desc_base + base_offset;
	ep_dev = LSINIC_DEV_PCIE_DEV(dev);

	/* Note: ep-rx == rc-tx */

	/* Free memory prior to re-allocation if needed... */
	if (dev->data->rx_queues[queue_idx])
		lsinic_queue_release(dev->data->rx_queues[queue_idx]);

	/* First allocate the tx queue data structure */
	rxq = lsinic_queue_alloc(dev, queue_idx, socket_id,
			nb_desc, LSINIC_QUEUE_RX);
	if (!rxq)
		return -ENOMEM;
	rxq->rc_bd_check = true;
	if (env)
		rxq->rc_bd_check = atoi(env);

	adapter->data_room_size = rte_pktmbuf_data_room_size(mp) - RTE_PKTMBUF_HEADROOM;
	adapter->max_tx_size = adapter->data_room_size;
	LSINIC_WRITE_REG(&eth_reg->max_data_room, adapter->data_room_size);

	rxq->rx_dma_mbuf_set = lsinic_recv_mbuf_dma_set;
	rxq->rxq_dma_eq = lsinic_rxq_dma_eq;
	rxq->dma_dq = lsinic_rxq_dma_dq;
	rxq->dma_id = adapter->rxq_dma_id;
	rxq->dma_vq = -1;
	rxq->mb_pool = mp;
	rxq->port_id = dev->data->port_id;
	rxq->crc_len = 0;
	rxq->drop_en = rx_conf->rx_drop_en;
	rxq->core_id = RTE_MAX_LCORE;
	rxq->pid = 0;
	rte_spinlock_init(&rxq->multi_core_lock);

	/* using RC's tx ring to receive EP's packets */
	rxq->ep_reg = &bdr_reg->tx_ring[queue_idx];
	rxq->rc_bd_desc = NULL;
	rxq->rc_reg = rxq->ep_reg;
	rxq->dev = dev;
	rxq->ep_bd_shared_addr = rxq_base + q_offset;

	lsinic_byte_memset(rxq->ep_bd_shared_addr, 0,
		LSINIC_RING_SIZE);

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

	if (adapter->ep_mem_dbg &&
		!ep_dev->virt_addr[LSX_PCIEP_EP_MEM_POOL_BAR_IDX]) {
		const struct rte_memzone *mz;
		int ret, bar;
		uint64_t mask;

		mz = lsinic_dev_mempool_continue_mz(mp);
		if (!mz)
			return -ENOMEM;

		mask = rte_lsx_pciep_bus_win_mask(ep_dev);
		if (mask && (mask & mz->len)) {
			LSXINIC_PMD_ERR("!Align Len(0x%lx)-mask(0x%lx)",
				mz->len, mask);
			return -EINVAL;
		}

		bar = LSX_PCIEP_EP_MEM_POOL_BAR_IDX;
		ep_dev->virt_addr[bar] = mz->addr;
		ep_dev->iov_addr[bar] = mz->iova;
		ep_dev->phy_addr[bar] = rte_mem_virt2phy(mz->addr);

		ret = rte_lsx_pciep_set_ib_win(ep_dev, bar, mz->len);
		if (ret)
			return ret;
		if (rte_lsx_pciep_hw_sim_get(adapter->pcie_idx) && !ep_dev->is_vf) {
			ret = rte_lsx_pciep_sim_dev_map_inbound(ep_dev);
			if (ret)
				return ret;
		}
	}

	rxq->wdma_bd_start = LSINIC_BD_DMA_START_FLAG;
	rxq->dma_idx = rte_malloc(NULL,
		sizeof(uint16_t) * nb_desc,
		RTE_DPAAX_QDMA_SG_IDX_ADDR_ALIGN);
	if (!rxq->dma_idx)
		return -ENOMEM;

#ifdef LSXINIC_LATENCY_PROFILING
	rxq->latency_min = 1000 * 1000;
#endif
	LSINIC_WRITE_REG(&rxq->ep_reg->ready, LSINIC_INIT_FLAG);

	return 0;
}

void
lsinic_dev_clear_queues(struct rte_eth_dev *dev)
{
	uint32_t i;
	struct lsinic_queue *txq, *rxq;

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		txq = dev->data->tx_queues[i];

		if (!txq || txq->status == LSINIC_QUEUE_RUNNING)
			continue;

		lsinic_queue_release_mbufs(txq);
		lsinic_queue_reset(txq);
		if (txq->multi_core_ring) {
			rte_ring_free(txq->multi_core_ring);
			txq->multi_core_ring = NULL;
		}
	}

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		rxq = dev->data->rx_queues[i];

		if (!rxq || rxq->status == LSINIC_QUEUE_RUNNING)
			continue;

		lsinic_queue_release_mbufs(rxq);
		lsinic_queue_reset(rxq);
		if (rxq->multi_core_ring) {
			rte_ring_free(rxq->multi_core_ring);
			rxq->multi_core_ring = NULL;
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
		if (rxq->status != LSINIC_QUEUE_RUNNING) {
			ret = lsinic_dev_rxq_init(rxq);
			if (ret)
				return ret;
		}
		rxq->ep_enabled = 1;
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
		if (txq->status != LSINIC_QUEUE_RUNNING)
			lsinic_dev_txq_init(txq);
		txq->ep_enabled = 1;
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

uint16_t
lsinic_dev_rx_stop(struct rte_eth_dev *dev, int force)
{
	struct lsinic_queue *rxq;
	uint16_t i, stop_count = 0;

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		rxq = dev->data->rx_queues[i];
		if (!rxq) {
			stop_count++;
			continue;
		}
		rxq->ep_enabled = 0;
		if (force || rxq->status != LSINIC_QUEUE_RUNNING) {
			lsinic_queue_stop(rxq);
			stop_count++;
		}
	}

	return stop_count;
}

uint16_t
lsinic_dev_tx_stop(struct rte_eth_dev *dev, int force)
{
	struct lsinic_queue *txq;
	uint16_t i, stop_count = 0;

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		txq = dev->data->tx_queues[i];
		if (!txq) {
			stop_count++;
			continue;
		}
		txq->ep_enabled = 0;
		if (force || txq->status != LSINIC_QUEUE_RUNNING) {
			lsinic_queue_stop(txq);
			stop_count++;
		}
	}

	return stop_count;
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
