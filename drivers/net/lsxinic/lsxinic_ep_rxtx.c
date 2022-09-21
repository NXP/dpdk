/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2023 NXP
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
#include <portal/dpaa2_hw_pvt.h>

#include "lsxinic_ep_tool.h"
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
RTE_DEFINE_PER_LCORE(uint8_t, lsinic_txq_list_initialized);
RTE_DEFINE_PER_LCORE(uint8_t, lsinic_txq_deqeue_from_rxq);
RTE_DEFINE_PER_LCORE(uint8_t, lsinic_txq_num_in_list);
RTE_DEFINE_PER_LCORE(struct lsinic_tx_queue_list, lsinic_txq_list);

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
lsinic_lbd_dma_start_update(struct lsinic_queue *queue,
	uint16_t used_idx)
{
	queue->local_src_bd_desc[used_idx].bd_status &=
		~((uint32_t)RING_BD_STATUS_MASK);
	queue->local_src_bd_desc[used_idx].bd_status |=
		RING_BD_HW_PROCESSING;
}

static void
lsinic_queue_dma_release(struct lsinic_queue *q)
{
	if (q->dma_jobs) {
		rte_free(q->dma_jobs);
		q->dma_jobs = NULL;
	}
}

static int
lsinic_queue_dma_create(struct lsinic_queue *q)
{
	uint32_t i;
	int pcie_id = q->adapter->pcie_idx;
	int pf_id = q->adapter->pf_idx;
	int is_vf = q->adapter->is_vf;
	int vf_id = q->adapter->vf_idx;
	uint16_t *pvq;
	int ret, dma_id;

	if (q->dma_vq >= 0)
		return 0;

	q->wdma_bd_start = -1;

	if (q->type == LSINIC_QUEUE_RX) {
		dma_id = q->adapter->rxq_dma_id;
		pvq = &q->adapter->rxq_dma_vchan_used;
		if (q->adapter->rbp_enable) {
			q->qdma_config.direction = RTE_DMA_DIR_DEV_TO_MEM;
			q->qdma_config.src_port.port_type = RTE_DMA_PORT_PCIE;
			q->qdma_config.src_port.pcie.coreid = pcie_id;
			q->qdma_config.src_port.pcie.pfid = pf_id;
			if (is_vf) {
				q->qdma_config.src_port.pcie.vfen = 1;
				q->qdma_config.src_port.pcie.vfid = vf_id;
			} else {
				q->qdma_config.src_port.pcie.vfen = 0;
			}
			q->qdma_config.dst_port.port_type = RTE_DMA_PORT_NONE;
		} else {
			q->qdma_config.direction = RTE_DMA_DIR_MEM_TO_MEM;
			q->qdma_config.src_port.port_type = RTE_DMA_PORT_NONE;
			q->qdma_config.dst_port.port_type = RTE_DMA_PORT_NONE;
		}
	} else {
		dma_id = q->adapter->txq_dma_id;
		pvq = &q->adapter->txq_dma_vchan_used;
		if (q->adapter->rbp_enable) {
			q->qdma_config.direction = RTE_DMA_DIR_MEM_TO_DEV;
			q->qdma_config.src_port.port_type = RTE_DMA_PORT_NONE;
			q->qdma_config.dst_port.port_type = RTE_DMA_PORT_PCIE;
			q->qdma_config.dst_port.pcie.coreid = pcie_id;
			q->qdma_config.dst_port.pcie.pfid = pf_id;
			if (is_vf) {
				q->qdma_config.dst_port.pcie.vfen = 1;
				q->qdma_config.dst_port.pcie.vfid = vf_id;
			} else {
				q->qdma_config.dst_port.pcie.vfen = 0;
			}
		} else {
			q->qdma_config.direction = RTE_DMA_DIR_MEM_TO_MEM;
			q->qdma_config.src_port.port_type = RTE_DMA_PORT_NONE;
			q->qdma_config.dst_port.port_type = RTE_DMA_PORT_NONE;
		}
	}

	q->qdma_config.nb_desc = LSINIC_BD_DMA_MAX_COUNT;

	for (i = 0; i < LSINIC_BD_DMA_MAX_COUNT; i++)
		q->dma_jobs[i].idx = i;

	ret = rte_dma_vchan_setup(dma_id, *pvq, &q->qdma_config);
	if (ret)
		return ret;
	q->dma_vq = *pvq;
	(*pvq)++;
	q->dma_id = dma_id;

	q->dma_bd_update = 0;
	if (q->type == LSINIC_QUEUE_TX) {
		if (q->adapter->ep_cap & LSINIC_EP_CAP_TXQ_DMA_NO_RSP)
			q->dma_bd_update |= DMA_BD_EP2RC_UPDATE;
	}

	return 0;
}

static int
lsinic_queue_dma_clean(struct lsinic_queue *q)
{
	uint16_t idx_completed[LSINIC_QDMA_DQ_MAX_NB];
	int ret;

	if (q->pkts_eq == q->pkts_dq ||
		(q->type == LSINIC_QUEUE_TX &&
		q->dma_bd_update & DMA_BD_EP2RC_UPDATE) ||
		(q->type == LSINIC_QUEUE_RX &&
		q->adapter->cap & LSINIC_CAP_XFER_COMPLETE))
		return 0;

	ret = rte_dma_completed(q->dma_id, q->dma_vq,
		LSINIC_QDMA_DQ_MAX_NB, idx_completed, NULL);

	q->pkts_dq += ret;

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
	LSINIC_WRITE_REG(&q->rc_reg->cir, 0);
	/* Initialize SW ring entries */
	for (i = 0; i < q->nb_desc; i++) {
		xe[i].mbuf = NULL;
		xe[i].my_idx = i;
		dma_jobs[i].cnxt = (uint64_t)(&xe[i]);
	}

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
}

static inline void
lsinic_qdma_rx_multiple_enqueue(struct lsinic_queue *queue,
	bool append)
{
	int ret;
	uint16_t nb_jobs = 0, jobs_idx, i, jobs_avail_idx;
	struct rte_dma_sge src[LSINIC_QDMA_EQ_DATA_MAX_NB];
	struct rte_dma_sge dst[LSINIC_QDMA_EQ_DATA_MAX_NB];
	uint16_t max_jobs_nb;
	uint32_t ep_cap = queue->adapter->ep_cap, idx_len;
	struct lsinic_dma_job *job;
	uint32_t len_total = 0;

	/* Qdma multi-enqueue support, max enqueue 32 entries once.
	 * if there are 32 entries or time out, handle them in batch
	 */

	jobs_avail_idx = queue->jobs_avail_idx;

	max_jobs_nb = LSINIC_QDMA_EQ_DATA_MAX_NB;

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
		idx_len = RTE_DPAA2_QDMA_IDX_LEN(job->idx,
			job->len);
		src[i].addr = queue->dma_jobs[jobs_idx].src;
		src[i].length = idx_len;
		dst[i].addr = queue->dma_jobs[jobs_idx].dst;
		dst[i].length = idx_len;
		len_total += job->len;
	}

	if (ep_cap & LSINIC_EP_CAP_RXQ_SG_DMA) {
		ret = rte_dma_copy_sg(queue->dma_id,
			queue->dma_vq, src, dst,
			nb_jobs, nb_jobs, RTE_DMA_OP_FLAG_SUBMIT);
	} else {
		for (i = 0; i < nb_jobs; i++) {
			ret = rte_dma_copy(queue->dma_id,
				queue->dma_vq, src[i].addr,
				dst[i].addr, src[i].length, 0);
			if (unlikely(ret))
				break;
		}
		ret = rte_dma_submit(queue->dma_id, queue->dma_vq);
	}
	if (likely(!ret)) {
		queue->jobs_pending -= nb_jobs;
		queue->jobs_avail_idx += nb_jobs;
		queue->bytes_eq += len_total;
		queue->pkts_eq += nb_jobs;
	} else {
		queue->errors++;
	}
}

static inline void
lsinic_qdma_tx_multiple_enqueue(struct lsinic_queue *queue,
	bool append)
{
	int ret;
	uint16_t nb_jobs = 0, jobs_idx, i, jobs_avail_idx;
	struct rte_dma_sge src[LSINIC_QDMA_EQ_MAX_NB];
	struct rte_dma_sge dst[LSINIC_QDMA_EQ_MAX_NB];
	struct lsinic_dma_job *jobs[LSINIC_QDMA_EQ_MAX_NB];
	struct lsinic_dma_job *e2r_bd_jobs;
	uint16_t txq_bd_jobs_num = 0;
	uint16_t bd_jobs_len, max_jobs_nb;
	int txq_dma_bd_start = queue->wdma_bd_start;
	uint16_t txq_bd_step = queue->bd_dma_step;
	struct lsinic_bd_desc *ep_bd_desc = NULL;
	uint32_t ep_cap = queue->adapter->ep_cap;

	if (queue->dma_bd_update & DMA_BD_EP2RC_UPDATE) {
		/* At most 2 TX DMA bd jobs.*/
		max_jobs_nb = LSINIC_QDMA_EQ_MAX_NB - 2;
	} else {
		max_jobs_nb = LSINIC_QDMA_EQ_MAX_NB;
	}

	if (queue->rc_mem_bd_type == RC_MEM_LONG_BD)
		ep_bd_desc = queue->local_src_bd_desc;

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

	if ((queue->dma_bd_update & DMA_BD_EP2RC_UPDATE) &&
		nb_jobs) {
		bd_jobs_len = txq_bd_step * nb_jobs;
		jobs[nb_jobs] = &e2r_bd_jobs[txq_dma_bd_start];
		if ((txq_dma_bd_start + nb_jobs) <= (int)queue->nb_desc) {
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
				ep_bd_desc[jobs_idx].bd_status &=
					~((uint32_t)RING_BD_STATUS_MASK);
				ep_bd_desc[jobs_idx].bd_status |=
					RING_BD_HW_COMPLETE;
			}
		} else {
			for (i = 0; i < nb_jobs; i++, jobs_avail_idx++) {
				jobs_idx = jobs_avail_idx &
					(queue->nb_desc - 1);
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
		src[i].addr = jobs[i]->src;
		src[i].length = RTE_DPAA2_QDMA_IDX_LEN(jobs[i]->idx,
			jobs[i]->len);
		dst[i].addr = jobs[i]->dst;
		dst[i].length = RTE_DPAA2_QDMA_IDX_LEN(jobs[i]->idx,
			jobs[i]->len);
	}

	if (ep_cap & LSINIC_EP_CAP_TXQ_SG_DMA) {
		ret = rte_dma_copy_sg(queue->dma_id, queue->dma_vq,
			src, dst,
			nb_jobs, nb_jobs, RTE_DMA_OP_FLAG_SUBMIT);
	} else {
		for (i = 0; i < nb_jobs; i++) {
			ret = rte_dma_copy(queue->dma_id, queue->dma_vq,
				src[i].addr, dst[i].addr, src[i].length, 0);
			if (unlikely(ret))
				break;
		}
		ret = rte_dma_submit(queue->dma_id, queue->dma_vq);
	}

	if (likely(!ret)) {
		queue->jobs_pending -= (nb_jobs - txq_bd_jobs_num);
		queue->jobs_avail_idx += (nb_jobs - txq_bd_jobs_num);
		for (i = 0; i < (nb_jobs - txq_bd_jobs_num); i++)
			queue->bytes_eq += jobs[i]->len;
		queue->pkts_eq += (nb_jobs - txq_bd_jobs_num);
		if (txq_bd_jobs_num) {
			queue->wdma_bd_start = -1;
			queue->wdma_bd_nb = 0;
		}
	} else {
		LSXINIC_PMD_ERR("LSINIC QDMA enqueue failed!");
		queue->errors++;
	}
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
lsinic_xmit_one_pkt(struct lsinic_queue *txq,
	struct rte_mbuf *tx_pkt, struct rte_mbuf **free_pkt)
{
	const struct lsinic_bd_desc *ep_txd = NULL;
	struct lsinic_ep_tx_dst_addr *dst_addr = NULL;
	struct lsinic_sw_bd *txe;
	uint16_t bd_idx;
	struct lsinic_dma_job *dma_job;
	struct lsinic_bd_desc *ep_local_txd;
	struct lsinic_rc_rx_len_idx *local_idx;

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
			LSXINIC_PMD_DBG("%s:TXQ%d:buf[%d] unavailable",
				txq->adapter->lsinic_dev->name,
				txq->queue_id, bd_idx);

			return 0;
		}
		local_idx = &txq->local_src_len_idx[bd_idx];

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

		local_idx->total_len = tx_pkt->pkt_len;
		local_idx->idx = 0;

		dst_addr->pkt_addr = 0;
		dma_job->cnxt = (uint64_t)txe;

		txq->jobs_pending++;

		if (txq->wdma_bd_start < 0)
			txq->wdma_bd_start = bd_idx;
		txq->wdma_bd_nb++;
		lsinic_qdma_tx_multiple_enqueue(txq, true);
		txq->next_avail_idx++;

		return 1;
	}

	if (unlikely(!lsinic_tx_bd_available(txq, bd_idx))) {
		txq->ring_full++;
		txq->drop_packet_num++;
		LSXINIC_PMD_DBG("%s:TXQ%d:bd[%d]:0x%08x unavailable",
			txq->adapter->lsinic_dev->name,
			txq->queue_id, bd_idx, ep_txd->bd_status);

		return 0;
	}

	local_idx = &txq->local_src_len_idx[bd_idx];
	ep_local_txd = &txq->local_src_bd_desc[bd_idx];
	if (ep_txd != ep_local_txd)
		memcpy(ep_local_txd, ep_txd, sizeof(struct lsinic_bd_desc));

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

	if (txq->rc_mem_bd_type == RC_MEM_LEN_CMD) {
		local_idx->total_len = tx_pkt->pkt_len;
		local_idx->idx = lsinic_bd_ctx_idx(ep_txd->bd_status);
	}

	lsinic_lbd_dma_start_update(txq, bd_idx);
	dma_job->cnxt = (uint64_t)txe;

	txq->jobs_pending++;

	if (txq->wdma_bd_start < 0)
		txq->wdma_bd_start = bd_idx;
	txq->wdma_bd_nb++;
	lsinic_qdma_tx_multiple_enqueue(txq, true);
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
lsinic_queue_start(struct lsinic_queue *q)
{
	struct lsinic_ring_reg *ring_reg = q->ep_reg;
	uint32_t msix_vector, i, cap;
	uint64_t bd_bus_addr, ob_offset;
	uint64_t dma_src_base = 0, dma_dst_base, step = 0;
	int ret;
	uint32_t queue_idx = q->queue_id;
	struct lsinic_adapter *adapter = q->adapter;
	struct rte_lsx_pciep_device *lsinic_dev = adapter->lsinic_dev;
	struct lsinic_bdr_reg *rc_bdr_reg =
		LSINIC_REG_OFFSET(adapter->rc_ring_virt_base,
			LSINIC_RING_REG_OFFSET);
	struct lsinic_dma_job *e2r_bd_dma_jobs;
	struct lsinic_eth_reg *reg =
		LSINIC_REG_OFFSET(adapter->hw_addr, LSINIC_ETH_REG_OFFSET);
	uint32_t ep_mem_bd_type, rc_mem_bd_type;
	struct lsinic_bd_desc *tmp_bd_desc;

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
		if (!rte_lsx_pciep_hw_sim_get(adapter->pcie_idx)) {
			q->msix_cmd = lsinic_dev->msix_data[msix_vector];
			q->msix_vaddr = lsinic_dev->msix_addr[msix_vector];
			if (q->msix_vaddr == 0) {
				LSXINIC_PMD_ERR("q->msix_vaddr == NULL");
				return -EINVAL;
			}
		}
	}

	bd_bus_addr = LSINIC_READ_REG_64B((uint64_t *)(&q->ep_reg->r_descl));
	if (bd_bus_addr) {
		ob_offset = bd_bus_addr - lsinic_dev->ob_map_bus_base;
		q->rc_bd_mapped_addr = lsinic_dev->ob_virt_base + ob_offset;
	} else {
		rte_panic("No bd addr set from RC");
	}

	ep_mem_bd_type = LSINIC_READ_REG(&q->ep_reg->r_ep_mem_bd_type);
	rc_mem_bd_type = LSINIC_READ_REG(&q->ep_reg->r_rc_mem_bd_type);

	if (ep_mem_bd_type == EP_MEM_LONG_BD &&
		rc_mem_bd_type == RC_MEM_LONG_BD) {
		/** Slow path*/
		rte_spinlock_lock(&adapter->cap_lock);
		cap = q->adapter->cap;
		if (q->type == LSINIC_QUEUE_RX)
			LSINIC_CAP_XFER_RC_XMIT_CNF_TYPE_SET(cap,
				RC_XMIT_BD_CNF);
		else
			LSINIC_CAP_XFER_EP_XMIT_BD_TYPE_SET(cap,
				EP_XMIT_LBD_TYPE);
		q->adapter->cap = cap;
		LSINIC_WRITE_REG(&reg->cap, adapter->cap);
		rte_spinlock_unlock(&adapter->cap_lock);
	}
	q->ep_mem_bd_type = ep_mem_bd_type;
	q->rc_mem_bd_type = rc_mem_bd_type;

	if (q->type == LSINIC_QUEUE_RX) {
		if (q->ep_mem_bd_type == EP_MEM_LONG_BD) {
			q->ep_bd_desc = q->ep_bd_shared_addr;
			tmp_bd_desc = q->ep_bd_shared_addr;
			for (i = 0; i < q->nb_desc; i++)
				tmp_bd_desc[i].bd_status = RING_BD_READY;
			LSXINIC_PMD_INFO("RXQ%d notify by RC with long bd",
				q->queue_id);
		} else if (q->ep_mem_bd_type == EP_MEM_SRC_ADDRL_BD) {
			q->rx_src_addrl = q->ep_bd_shared_addr;
			LSXINIC_PMD_INFO("RXQ%d notify by RC with low addr",
				q->queue_id);
		} else if (q->ep_mem_bd_type == EP_MEM_SRC_ADDRX_BD) {
			q->rx_src_addrx = q->ep_bd_shared_addr;
			LSXINIC_PMD_INFO("RXQ%d notify by RC with index addr",
				q->queue_id);
		} else {
			rte_panic("Invalid RXQ ep mem bd type(%d)",
				q->ep_mem_bd_type);
		}

		q->local_src_bd_desc = rte_malloc(NULL,
				LSINIC_BD_RING_SIZE,
				RTE_CACHE_LINE_SIZE);

		if (q->rc_mem_bd_type == RC_MEM_LONG_BD) {
			q->rc_bd_desc = q->rc_bd_mapped_addr;
			LSXINIC_PMD_INFO("RXQ%d confirm to RC with long bd",
				q->queue_id);
		} else if (q->rc_mem_bd_type == RC_MEM_BD_CNF) {
			q->rx_complete = q->rc_bd_mapped_addr;
			LSXINIC_PMD_INFO("RXQ%d confirm to RC with bd complete",
				q->queue_id);
		} else if (q->rc_mem_bd_type == RC_MEM_IDX_CNF) {
			q->free_idx = q->rc_bd_mapped_addr;
			q->local_src_free_idx = rte_malloc(NULL,
				sizeof(uint32_t), RTE_CACHE_LINE_SIZE);
			LSXINIC_PMD_INFO("RXQ%d confirm to RC with idx",
				q->queue_id);
		} else {
			rte_panic("Invalid RXQ rc mem bd type(%d)",
				q->rc_mem_bd_type);
		}
	} else {
		if (q->ep_mem_bd_type == EP_MEM_LONG_BD) {
			q->ep_bd_desc = q->ep_bd_shared_addr;
			LSXINIC_PMD_INFO("TXQ%d notify by RC with long bd",
				q->queue_id);
		} else if (q->ep_mem_bd_type == EP_MEM_DST_ADDR_BD) {
			q->tx_dst_addr = q->ep_bd_shared_addr;
			LSXINIC_PMD_INFO("TXQ%d notify by RC with full address",
				q->queue_id);
		} else {
			rte_panic("Invalid TXQ ep mem bd type(%d)",
				q->ep_mem_bd_type);
		}

		if (q->ep_bd_desc) {
			q->local_src_bd_desc = q->ep_bd_shared_addr;
		} else {
			q->local_src_bd_desc = rte_malloc(NULL,
				LSINIC_BD_RING_SIZE,
				RTE_CACHE_LINE_SIZE);
		}

		if (q->rc_mem_bd_type == RC_MEM_LONG_BD) {
			q->rc_bd_desc = q->rc_bd_mapped_addr;
			dma_src_base =
				DPAA2_VADDR_TO_IOVA(q->local_src_bd_desc);
			step = sizeof(struct lsinic_bd_desc);
			LSXINIC_PMD_INFO("TXQ%d notify to RC with long bd",
				q->queue_id);
		} else if (q->rc_mem_bd_type == RC_MEM_LEN_CMD) {
			q->tx_len_idx = q->rc_bd_mapped_addr;
			q->local_src_len_idx = rte_malloc(NULL,
				LSINIC_LEN_IDX_RING_SIZE,
				RTE_CACHE_LINE_SIZE);
			dma_src_base =
				DPAA2_VADDR_TO_IOVA(q->local_src_len_idx);
			step = sizeof(struct lsinic_rc_rx_len_idx);
			LSXINIC_PMD_INFO("TXQ%d notify to RC with len/cmd",
				q->queue_id);
		} else {
			rte_panic("Invalid TXQ rc mem bd type(%d)",
				q->rc_mem_bd_type);
		}
	}

	e2r_bd_dma_jobs = &q->dma_jobs[LSINIC_E2R_BD_DMA_START];
	if (dma_src_base) {
		dma_dst_base = q->ob_base + bd_bus_addr;
		q->bd_dma_step = step;
		for (i = 0; i < q->nb_desc; i++) {
			e2r_bd_dma_jobs[i].src = dma_src_base + i * step;
			e2r_bd_dma_jobs[i].dst = dma_dst_base + i * step;
		}
	}

	if (q->type == LSINIC_QUEUE_RX) {
		if (adapter->cap & LSINIC_CAP_XFER_COMPLETE)
			q->recv_rxe = lsinic_recv_rxe_no_dq;
		else
			q->recv_rxe = lsinic_recv_rxe;

		if (q->rc_mem_bd_type == RC_MEM_IDX_CNF)
			q->recv_update = lsinic_recv_dummy_update;
		else if (q->rc_mem_bd_type == RC_MEM_BD_CNF)
			q->recv_update = lsinic_recv_dummy_update;
		else
			q->recv_update = lsinic_recv_rxbd_update;
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

	if (!q->rc_bd_mapped_addr) {
		LSXINIC_PMD_ERR("q->rc_bd_mapped_addr == NULL");
		return -ENOMEM;
	}

	lsinic_queue_reset(q);

	if (q->type == LSINIC_QUEUE_RX) {
		rte_memcpy(q->rc_bd_mapped_addr,
			q->ep_bd_shared_addr,
			LSINIC_RING_SIZE);
		if (q->rc_mem_bd_type == RC_MEM_BD_CNF) {
			for (i = 0; i < q->nb_desc; i++)
				q->rx_complete[i].bd_complete = RING_BD_READY;
		}
	}

	rte_spinlock_lock(&adapter->rxq_dma_start_lock);
	if (q->type == LSINIC_QUEUE_RX &&
		!adapter->rxq_dma_started) {
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

	rte_spinlock_lock(&adapter->txq_dma_start_lock);
	if (q->type == LSINIC_QUEUE_TX &&
		!adapter->txq_dma_started) {
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

	return 0;
}

static void
lsinic_queue_stop(struct lsinic_queue *q)
{
	struct lsinic_ring_reg *ring_reg = q->ep_reg;

	q->status = LSINIC_QUEUE_STOP;
	ring_reg->sr = q->status;
	LSINIC_WRITE_REG(&q->rc_reg->sr, q->status);
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
		if (q->local_src_len_idx)
			rte_free(q->local_src_len_idx);
	}

	if (q->local_src_bd_desc &&
		q->local_src_bd_desc != q->ep_bd_desc)
		rte_free(q->local_src_bd_desc);

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

	if (adapter->rbp_enable)
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

	/* Allocate DMA jobs ring */
	q->dma_jobs = rte_zmalloc_socket("q->dma_jobs",
		sizeof(struct lsinic_dma_job) * LSINIC_BD_DMA_MAX_COUNT,
		RTE_CACHE_LINE_SIZE, socket_id);
	if (!q->dma_jobs) {
		LSXINIC_PMD_ERR("Failed to create dma_jobs");
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
	if (!q->new_desc_thresh) {
		q->new_desc = 0;
		return;
	}
	if (lsinic_queue_msi_masked(q))
		return;

	if (!q->new_desc)
		return;

	if (!rte_lsx_pciep_hw_sim_get(q->adapter->pcie_idx)) {
		if (q->new_desc_thresh && (q->new_desc >= q->new_desc_thresh ||
			(lsinic_timeout(q)))) {
			/* MSI */
			rte_lsx_pciep_start_msix(q->msix_vaddr, q->msix_cmd);
			q->new_desc = 0;
		}
	}
}

/*********************************************************************
 *
 *  TX functions
 *
 **********************************************************************/
static void
lsinic_tx_notify_burst_to_rc(struct lsinic_queue *txq)
{
	uint16_t pending, burst1 = 0, burst2 = 0;
	uint16_t bd_idx, bd_idx_first, i;
	struct lsinic_bd_desc *local_bd;
	struct lsinic_rc_rx_len_idx *tx_len_idx = txq->tx_len_idx;

	pending = txq->next_dma_idx - txq->next_used_idx;
	bd_idx_first = lsinic_queue_next_used_idx(txq, 0);
	for (i = 0; i < pending; i++) {
		bd_idx = lsinic_queue_next_used_idx(txq, i);
		local_bd = &txq->local_src_bd_desc[bd_idx];
		if ((local_bd->bd_status & RING_BD_STATUS_MASK)
			!= RING_BD_HW_COMPLETE) {
			/* Due to OOO DMA*/
			break;
		}
		lsinic_ep_notify_to_rc(txq, bd_idx, 0);
	}
	if ((bd_idx_first + i) > txq->nb_desc) {
		burst1 = txq->nb_desc - bd_idx_first;
		burst2 = i - burst1;
	} else {
		burst1 = i;
		burst2 = 0;
	}
	lsinic_pcie_memcp_align((uint8_t *)&tx_len_idx[bd_idx_first],
		(uint8_t *)&txq->local_src_len_idx[bd_idx_first],
		burst1 * sizeof(struct lsinic_rc_rx_len_idx));
	if (burst2) {
		lsinic_pcie_memcp_align((uint8_t *)&tx_len_idx[0],
			(uint8_t *)&txq->local_src_len_idx[0],
			burst2 * sizeof(struct lsinic_rc_rx_len_idx));
	}
	txq->next_used_idx += i;
	txq->new_desc += i;
	lsinic_queue_trigger_interrupt(txq);
}

static void
lsinic_tx_update_to_rc(struct lsinic_queue *txq)
{
	uint16_t pending, bd_idx, i;
	struct lsinic_bd_desc *local_bd;

	if (txq->rc_mem_bd_type == RC_MEM_LEN_CMD) {
		lsinic_tx_notify_burst_to_rc(txq);

		return;
	}

	pending = txq->next_dma_idx - txq->next_used_idx;
	for (i = 0; i < pending; i++) {
		bd_idx = lsinic_queue_next_used_idx(txq, 0);
		local_bd = &txq->local_src_bd_desc[bd_idx];
		if ((local_bd->bd_status & RING_BD_STATUS_MASK)
			!= RING_BD_HW_COMPLETE) {
			/* Due to OOO DMA*/
			break;
		}
		if (txq->rc_mem_bd_type == RC_MEM_LEN_CMD)
			lsinic_ep_notify_to_rc(txq, bd_idx, 1);
		else
			lsinic_bd_update_used_to_rc(txq, bd_idx);
	}

	txq->next_used_idx += i;
	txq->new_desc += i;

	lsinic_queue_trigger_interrupt(txq);
}

static uint16_t
lsinic_tx_dma_dequeue(struct lsinic_queue *txq)
{
	struct lsinic_dma_job *dma_job;
	struct lsinic_sw_bd *txe = NULL;
	const struct lsinic_bd_desc *bd;
	uint16_t pkts_dq = 0;
	int i, ret = 0;
	uint16_t idx_completed[LSINIC_QDMA_DQ_MAX_NB], idx;

	ret = rte_dma_completed(txq->adapter->txq_dma_id,
		txq->dma_vq, LSINIC_QDMA_DQ_MAX_NB,
		idx_completed, NULL);
	if (!ret)
		lsinic_qdma_tx_multiple_enqueue(txq, false);

	for (i = 0; i < ret; i++) {
		if (idx_completed[i] < LSINIC_BD_ENTRY_COUNT) {
			idx = idx_completed[i];
		} else {
			/** Never goes to this branch.*/
			idx = idx_completed[i] - LSINIC_BD_ENTRY_COUNT;
			continue;
		}
		dma_job = &txq->dma_jobs[idx];
		txq->bytes_dq += dma_job->len;
		txe = &txq->sw_ring[idx];
		pkts_dq++;
		bd = &txq->ep_bd_desc[txe->my_idx];
		lsinic_bd_dma_complete_update(txq, txe->my_idx, bd);
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
}

static inline int lsinic_tx_bd_available(struct lsinic_queue *txq,
	uint16_t bd_idx)
{
	const struct lsinic_bd_desc *ep_txd = &txq->ep_bd_desc[bd_idx];
	int full_count = 0;

	if (!(((uint64_t)ep_txd) & RTE_CACHE_LINE_MASK))
		rte_lsinic_prefetch((const uint8_t *)ep_txd +
			RTE_CACHE_LINE_SIZE);

	while (unlikely((ep_txd->bd_status & RING_BD_STATUS_MASK) !=
					RING_BD_READY)) {
		if (!(txq->dma_bd_update & DMA_BD_EP2RC_UPDATE)) {
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

	txq->core_id = rte_lcore_id();

	if (bulk_free)
		ppkt = &free_pkt;

	UNUSED(mg_enable);
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

	if (free_idx > 0)
		rte_pktmbuf_free_bulk(free_pkts, free_idx);

	if (!txq->new_desc)
		txq->new_tsc = rte_rdtsc();

	if (unlikely(!txq->pair ||
		(txq->pair && txq->pair->core_id != txq->core_id))) {
		txq->core_id = rte_lcore_id();
		if (!(txq->dma_bd_update & DMA_BD_EP2RC_UPDATE)) {
			uint16_t dq_total = 0, dq;

			while (dq_total != tx_num) {
				lsinic_qdma_tx_multiple_enqueue(txq, false);
				dq = lsinic_tx_dma_dequeue(txq);
				if (dq > 0)
					dq_total += dq;
			}
			lsinic_tx_update_to_rc(txq);
		} else {
			lsinic_qdma_tx_multiple_enqueue(txq, false);
			txq->packets_old = txq->packets;
		}
	}

	return tx_num;
}

uint16_t
lsinic_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts,
	uint16_t nb_pkts)
{
	struct lsinic_queue *txq;

	txq = tx_queue;
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

	if (unlikely(!lsinic_queue_running(txq))) {
		lsinic_queue_status_update(txq);
		if (!lsinic_queue_running(txq))
			return 0;
	}

	txq->loop_avail++;

	/* TX loop */
	return lsinic_xmit_pkts_burst(txq, tx_pkts, nb_pkts, 0);
}

/*********************************************************************
 *
 *  RX functions
 *
 **********************************************************************/
static uint16_t
lsinic_rx_dma_dequeue(struct lsinic_queue *rxq)
{
	struct lsinic_sw_bd *rxe;
	struct lsinic_bd_desc *rxdp;
	struct lsinic_dma_job *dma_job;
	int i, ret = 0;
	uint16_t idx_completed[LSINIC_QDMA_DQ_MAX_NB], idx;

	if (rxq->pkts_eq == rxq->pkts_dq)
		return 0;

	ret = rte_dma_completed(rxq->adapter->rxq_dma_id,
		rxq->dma_vq, LSINIC_QDMA_DQ_MAX_NB,
		idx_completed, NULL);
	if (likely(ret > 0))
		rxq->pkts_dq += ret;
	else
		return 0;

	for (i = 0; i < ret; i++) {
		if (idx_completed[i] < LSINIC_BD_ENTRY_COUNT) {
			idx = idx_completed[i];
		} else {
			/** Never goes to this branch.*/
			idx = idx_completed[i] - LSINIC_BD_ENTRY_COUNT;
			continue;
		}
		dma_job = &rxq->dma_jobs[idx];
		rxe = &rxq->sw_ring[idx];
		rxq->bytes_dq += dma_job->len;
		rxe->dma_complete = 1;
		rxdp = &rxq->ep_bd_desc[rxe->my_idx];
		lsinic_bd_dma_complete_update(rxq, rxe->my_idx, rxdp);

		rte_lsinic_prefetch(rte_pktmbuf_mtod(rxe->mbuf, void *));
	}

	return ret;
}

static __rte_always_inline void
lsinic_recv_mbuf_dma_set(struct lsinic_dma_job *dma_job,
	struct rte_mbuf *mbuf, uint32_t pkt_len, uint32_t port_id)
{
	struct lsinic_sw_bd *rxe;

	dma_job->dst = rte_mbuf_data_iova_default(mbuf);
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
	struct lsinic_bd_desc *rxdp = &q->local_src_bd_desc[bd_idx];

	rxdp->bd_status &= ~((uint32_t)RING_BD_STATUS_MASK);
	rxdp->bd_status |= bd_status;
}

static uint16_t
lsinic_recv_idx_bulk_alloc_buf(struct lsinic_queue *rxq)
{
	struct lsinic_ep_rx_src_addrx *rxdp;
	struct lsinic_dma_job *dma_job[DEFAULT_TX_RS_THRESH];
	struct rte_mbuf *rxm[DEFAULT_TX_RS_THRESH];
	struct lsinic_sw_bd *rxe;

	uint32_t pkt_len[DEFAULT_TX_RS_THRESH];
	uint16_t bd_idx;
	uint16_t bd_num = 0, idx, size;
	const uint64_t addr_base =
		rxq->ob_base + rxq->adapter->rc_dma_base;
	const uint32_t rc_dma_elt_size =
		rxq->adapter->rc_dma_elt_size;

	do {
		if (unlikely(lsinic_queue_next_avail_idx(rxq, 1) ==
			lsinic_queue_next_used_idx(rxq, 0)))
			break;
		bd_idx = lsinic_queue_next_avail_idx(rxq, 0);
		rxdp = &rxq->rx_src_addrx[bd_idx];

		if (!(((uint64_t)rxdp) & RTE_CACHE_LINE_MASK)) {
			rte_lsinic_prefetch((uint8_t *)rxdp +
				RTE_CACHE_LINE_SIZE);
		}

		if (!rxdp->idx_cmd_len) {
			lsinic_qdma_rx_multiple_enqueue(rxq, false);
			break;
		}

		size = rxdp->len;
		if (unlikely(size > rxq->adapter->data_room_size)) {
			LSXINIC_PMD_ERR("port%d rxq%d BD%d size:0x%08x",
				rxq->port_id, rxq->queue_id, bd_idx, size);
			rxq->errors++;
			rte_panic("line %d\tassert \"%s\" failed\n",
				__LINE__, "size err");
			/* to do skip this bd */
			/* TODO
			 * dma_job for this entry should also be skipped
			 */

			break;
		}
		rxe = &rxq->sw_ring[bd_idx];
		dma_job[bd_num] = &rxq->dma_jobs[bd_idx];
		dma_job[bd_num]->cnxt = (uint64_t)rxe;

		dma_job[bd_num]->src = addr_base +
			rxdp->pkt_idx * rc_dma_elt_size;

		pkt_len[bd_num] = size;
		dma_job[bd_num]->len = pkt_len[bd_num];

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
		for (idx = 0; idx < bd_num; idx++) {
			lsinic_recv_mbuf_dma_set(dma_job[idx],
				rxm[idx], pkt_len[idx], rxq->port_id);
			rxe = (struct lsinic_sw_bd *)dma_job[idx]->cnxt;
			rxe->complete =
				rte_pktmbuf_mtod_offset(rxm[idx],
					char *, pkt_len[idx]);
			(*rxe->complete) =
				LSINIC_XFER_COMPLETE_INIT_FLAG;
			dma_job[idx]->len++;
		}
		for (idx = 0; idx < bd_num; idx++) {
			rxq->jobs_pending++;
			lsinic_qdma_rx_multiple_enqueue(rxq, true);
		}

		if (rxq->new_desc == 0)
			rxq->new_tsc = rte_rdtsc();
	} else {
		rxq->next_avail_idx -= bd_num;
	}

	if (bd_num > 0)
		rxq->loop_avail++;

	return bd_num;
}

static uint16_t
lsinic_recv_addrl_bulk_alloc_buf(struct lsinic_queue *rx_queue)
{
	struct lsinic_queue *rxq;
	struct lsinic_ep_rx_src_addrl *rxdp;
	struct lsinic_dma_job *dma_job[DEFAULT_TX_RS_THRESH];
	struct rte_mbuf *rxm[DEFAULT_TX_RS_THRESH];
	struct lsinic_sw_bd *rxe;

	uint32_t pkt_len[DEFAULT_TX_RS_THRESH];
	uint16_t bd_idx;
	uint32_t size;
	uint32_t len_cmd;
	uint16_t bd_num = 0, idx;
	uint64_t addr_base;

	rxq = rx_queue;
	addr_base = rxq->ob_base + rx_queue->adapter->rc_dma_base;

	do {
		if (unlikely(lsinic_queue_next_avail_idx(rxq, 1) ==
			lsinic_queue_next_used_idx(rxq, 0)))
			break;
		bd_idx = lsinic_queue_next_avail_idx(rxq, 0);
		rxdp = &rxq->rx_src_addrl[bd_idx];

		if (!(((uint64_t)rxdp) & RTE_CACHE_LINE_MASK)) {
			rte_lsinic_prefetch((uint8_t *)rxdp +
				RTE_CACHE_LINE_SIZE);
		}

		if (!rxdp->addr_cmd_len) {
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
		rxe = &rxq->sw_ring[bd_idx];
		dma_job[bd_num] = &rxq->dma_jobs[bd_idx];
		dma_job[bd_num]->cnxt = (uint64_t)rxe;

		dma_job[bd_num]->src = addr_base + rxdp->pkt_addr_low;

		pkt_len[bd_num] = size;
		dma_job[bd_num]->len = pkt_len[bd_num];

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
		for (idx = 0; idx < bd_num; idx++) {
			lsinic_recv_mbuf_dma_set(dma_job[idx],
				rxm[idx], pkt_len[idx], rxq->port_id);
			rxe = (struct lsinic_sw_bd *)dma_job[idx]->cnxt;
			rxe->complete =
				rte_pktmbuf_mtod_offset(rxm[idx],
					char *, pkt_len[idx]);
			(*rxe->complete) =
				LSINIC_XFER_COMPLETE_INIT_FLAG;
			dma_job[idx]->len++;
		}
		for (idx = 0; idx < bd_num; idx++) {
			rxq->jobs_pending++;
			lsinic_qdma_rx_multiple_enqueue(rxq, true);
		}

		if (rxq->new_desc == 0)
			rxq->new_tsc = rte_rdtsc();
	} else {
		rxq->next_avail_idx -= bd_num;
	}

	if (bd_num > 0)
		rxq->loop_avail++;

	return bd_num;
}

static uint16_t
lsinic_recv_bd_bulk_alloc_buf(struct lsinic_queue *rx_queue)
{
	struct lsinic_queue *rxq;
	struct lsinic_bd_desc *rxdp;
	struct lsinic_dma_job *dma_job[DEFAULT_TX_RS_THRESH];
	struct lsinic_sw_bd *rxe = NULL;
	struct rte_mbuf *rxm[DEFAULT_TX_RS_THRESH];

	uint32_t pkt_len[DEFAULT_TX_RS_THRESH];
	uint16_t bd_idx, first_bd_idx;
	uint32_t size;
	uint32_t len_cmd;
	uint16_t bd_num = 0, idx;

	rxq = rx_queue;
	first_bd_idx = lsinic_queue_next_avail_idx(rxq, 0);

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

		if ((rxdp->bd_status & RING_BD_STATUS_MASK) !=
			RING_BD_AVAILABLE) {
			lsinic_qdma_rx_multiple_enqueue(rxq, false);
			break;
		}
		rxdp->bd_status &= ~((uint32_t)RING_BD_STATUS_MASK);
		rxdp->bd_status |= RING_BD_HW_PROCESSING;

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

		rxe = &rxq->sw_ring[bd_idx];

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
					char *, pkt_len[idx]);
				(*rxe->complete) =
					LSINIC_XFER_COMPLETE_INIT_FLAG;
				dma_job[idx]->len++;
			}
		} else {
			for (idx = 0; idx < bd_num; idx++) {
				lsinic_recv_mbuf_dma_set(dma_job[idx],
					rxm[idx], pkt_len[idx], rxq->port_id);
				rxe = (struct lsinic_sw_bd *)dma_job[idx]->cnxt;
				rxe->dma_complete = 0;
			}
		}
		for (idx = 0; idx < bd_num; idx++) {
			rxq->jobs_pending++;
			lsinic_qdma_rx_multiple_enqueue(rxq, true);
		}

		if (rxq->new_desc == 0)
			rxq->new_tsc = rte_rdtsc();
	} else {
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
	struct lsinic_dma_job *dma_job;
	struct lsinic_sw_bd *rxe = NULL;
	struct rte_mbuf *rxm;

	uint32_t pkt_len;
	uint16_t bd_idx;
	uint32_t size;
	uint32_t len_cmd;
	uint16_t bd_num = 0;

	rxq = rx_queue;

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

		if ((rxdp->bd_status & RING_BD_STATUS_MASK) !=
			RING_BD_AVAILABLE) {
			lsinic_qdma_rx_multiple_enqueue(rxq, false);
			break;
		}
		rxdp->bd_status &= ~((uint32_t)RING_BD_STATUS_MASK);
		rxdp->bd_status |= RING_BD_HW_PROCESSING;

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

		rxe = &rxq->sw_ring[bd_idx];

		if (rxq->adapter->cap & LSINIC_CAP_XFER_COMPLETE) {
			lsinic_local_bd_status_update(rxq, bd_idx,
				RING_BD_ADDR_CHECK | RING_BD_HW_COMPLETE);
		} else {
			lsinic_local_bd_status_update(rxq, bd_idx,
				RING_BD_HW_PROCESSING);
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

		if (rx_queue->adapter->cap &
			LSINIC_CAP_XFER_COMPLETE) {
			rxe->complete =
				rte_pktmbuf_mtod_offset(rxm,
					char *, dma_job->len);
			(*rxe->complete) =
				LSINIC_XFER_COMPLETE_INIT_FLAG;
			dma_job->len++;
		} else {
			rxe->dma_complete = 0;
		}

		rxq->next_avail_idx++;
		rxq->jobs_pending++;
		lsinic_qdma_rx_multiple_enqueue(rxq, true);
		bd_num++;

		if (bd_num >= DEFAULT_TX_RS_THRESH)
			break;
	} while (1);

	if (unlikely(!bd_num))
		return 0;

	if (rxq->new_desc == 0)
		rxq->new_tsc = rte_rdtsc();

	rxq->loop_avail++;

	return bd_num;
}

static void
lsinic_txq_loop(void)
{
	struct lsinic_queue *q, *tq;

	/* Check if txq already added to list */
	RTE_TAILQ_FOREACH_SAFE(q, &RTE_PER_LCORE(lsinic_txq_list), next, tq) {
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

		if (!(q->dma_bd_update & DMA_BD_EP2RC_UPDATE)) {
			lsinic_tx_dma_dequeue(q);
			lsinic_tx_update_to_rc(q);
		} else {
			if (likely(q->packets_old == q->packets))
				lsinic_qdma_tx_multiple_enqueue(q, false);
			q->packets_old = q->packets;
		}

		q->loop_total++;
	}
}

static int
lsinic_rxq_loop(struct lsinic_queue *rxq)
{
	const int bulk_alloc = 1;
	uint16_t rc_recvd = 0;

	if (unlikely(!lsinic_queue_running(rxq))) {
		lsinic_queue_status_update(rxq);
		if (!lsinic_queue_running(rxq))
			return -EAGAIN;
		if (rxq->pair)
			lsinic_add_txq_to_list(rxq->pair);
	}

	if (bulk_alloc) {
		if (rxq->ep_mem_bd_type == EP_MEM_SRC_ADDRX_BD)
			rc_recvd = lsinic_recv_idx_bulk_alloc_buf(rxq);
		else if (rxq->ep_mem_bd_type == EP_MEM_SRC_ADDRL_BD)
			rc_recvd = lsinic_recv_addrl_bulk_alloc_buf(rxq);
		else
			rc_recvd = lsinic_recv_bd_bulk_alloc_buf(rxq);
	} else {
		if (rxq->ep_mem_bd_type != EP_MEM_LONG_BD) {
			LSXINIC_PMD_ERR("RX by SHORT BD TBD");
			return -EINVAL;
		}
		rc_recvd = lsinic_recv_bd(rxq);
	}
	if (!(rxq->adapter->cap & LSINIC_CAP_XFER_COMPLETE)) {
		lsinic_rx_dma_dequeue(rxq);
		lsinic_queue_trigger_interrupt(rxq);
	}

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
		rxq->free_idx->idx_complete =
			rxq->local_src_free_idx->idx_complete;
	} else if (rxq->rc_mem_bd_type == RC_MEM_BD_CNF) {
		start = &rxq->rx_complete[first_idx].bd_complete;
		if ((first_idx + nb_rx) < rxq->nb_desc) {
			lsinic_pcie_memset_align(start,
				s_hw_complete_16b, nb_rx);
		} else {
			lsinic_pcie_memset_align(start,
				s_hw_complete_16b,
				rxq->nb_desc - first_idx);
			if ((first_idx + nb_rx) != rxq->nb_desc) {
				start = &rxq->rx_complete[0].bd_complete;
				lsinic_pcie_memset_align(start,
					s_hw_complete_16b,
					first_idx + nb_rx - rxq->nb_desc);
			}
		}
	} else {
		/* Implemented by recv_update callback*/
	}
}

static uint16_t
lsinic_recv_pkts_to_cache_idx(struct lsinic_queue *rxq)
{
	struct rte_mbuf *rxm;
	struct lsinic_sw_bd *rxe;
	uint16_t bd_idx, first_idx;
	uint16_t nb_rx = 0;
	uint16_t rx_count;
	struct lsinic_ep_rx_src_addrx *rxdp = NULL;

	rx_count = rxq->next_avail_idx - rxq->next_used_idx;
	if (!rx_count)
		return 0;

	first_idx = lsinic_queue_next_used_idx(rxq, 0);
	while (nb_rx < rx_count) {
		bd_idx = lsinic_queue_next_used_idx(rxq, 0);
		rxdp = &rxq->rx_src_addrx[bd_idx];
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

		rxdp->idx_cmd_len = 0;

		rxq->next_used_idx++;

		if (rxq->mcnt > LSINIC_MAX_BURST_NUM)
			break;
	}

	lsinic_recv_cnf_burst_update(rxq, nb_rx, first_idx);

	return nb_rx;
}

static uint16_t
lsinic_recv_pkts_to_cache_addrl(struct lsinic_queue *rxq)
{
	struct rte_mbuf *rxm;
	struct lsinic_sw_bd *rxe;
	uint16_t bd_idx, first_idx;
	uint16_t nb_rx = 0;
	uint16_t rx_count;
	struct lsinic_ep_rx_src_addrl *rxdp = NULL;

	rx_count = rxq->next_avail_idx - rxq->next_used_idx;
	if (!rx_count)
		return 0;

	first_idx = lsinic_queue_next_used_idx(rxq, 0);
	while (nb_rx < rx_count) {
		bd_idx = lsinic_queue_next_used_idx(rxq, 0);
		rxe = rxq->recv_rxe(rxq, bd_idx);
		if (!rxe)
			break;
		rxdp = &rxq->rx_src_addrl[bd_idx];
		nb_rx++;

		rxm = rxe->mbuf;
		RTE_ASSERT(rxm);

		rxm->packet_type = RTE_PTYPE_L3_IPV4;
		rxq->mcache[rxq->mtail] = rxm;
		rxq->mtail = (rxq->mtail + 1) & MCACHE_MASK;
		rxq->mcnt++;
		rxdp->addr_cmd_len = 0;

		rxq->next_used_idx++;

		if (rxq->mcnt > LSINIC_MAX_BURST_NUM)
			break;
	}

	lsinic_recv_cnf_burst_update(rxq, nb_rx, first_idx);

	return nb_rx;
}

static uint16_t
lsinic_recv_pkts_to_cache(struct lsinic_queue *rxq)
{
	struct rte_mbuf *rxm;
	struct lsinic_sw_bd *rxe;
	uint16_t bd_idx, first_idx;
	uint16_t nb_rx = 0;
	uint16_t rx_count;

	rx_count = rxq->next_avail_idx - rxq->next_used_idx;
	if (!rx_count)
		return 0;

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

	return nb_rx;
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
	double cyc_per_us = rxq->adapter->cycs_per_us;
	double curr_latency;
#endif

	lsinic_txq_loop();
	ret = lsinic_rxq_loop(rxq);
	if (unlikely(ret < 0)) {
		/**This RXQ not started yet.*/
		return 0;
	}
	if (rxq->ep_mem_bd_type == EP_MEM_SRC_ADDRX_BD)
		lsinic_recv_pkts_to_cache_idx(rxq);
	else if (rxq->ep_mem_bd_type == EP_MEM_SRC_ADDRL_BD)
		lsinic_recv_pkts_to_cache_addrl(rxq);
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
		rxq->avg_latency =
			rxq->cyc_diff_total /
			(rxq->packets + nb_rx + 1) / cyc_per_us;
		curr_latency = (current_tick - tick_load) / cyc_per_us;
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
		rxq->bytes_fcs += rxm->pkt_len + LSINIC_ETH_FCS_SIZE;
		rxq->bytes_overhead += rxm->pkt_len + LSINIC_ETH_OVERHEAD_SIZE;

#ifdef RTE_LIBRTE_LSINIC_DEBUG_RX
		lsinic_mbuf_print_all(rxm);
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
lsinic_dev_tx_queue_release(struct rte_eth_dev *dev,
	uint16_t qid)
{
	lsinic_queue_release(dev->data->tx_queues[qid]);
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
	int ret;

	/* Note: ep-tx == rc-rx */

	/* Free memory prior to re-allocation if needed... */
	if (dev->data->tx_queues[queue_idx])
		lsinic_queue_release(dev->data->tx_queues[queue_idx]);

	/* First allocate the tx queue data structure */
	txq = lsinic_queue_alloc(adapter, queue_idx, socket_id,
			nb_desc, LSINIC_QUEUE_TX);
	if (!txq)
		return -ENOMEM;

	txq->dma_id = adapter->txq_dma_id;
	txq->dma_vq = -1;
	txq->port_id = dev->data->port_id;

	/* using RC's rx ring to send EP's packets */
	txq->ep_reg = &bdr_reg->rx_ring[queue_idx];
	txq->rc_bd_desc = NULL;
	txq->rc_reg = txq->ep_reg;
	txq->dev = dev;
	txq->ep_bd_shared_addr =
		(adapter->bd_desc_base + LSINIC_RX_BD_OFFSET +
		queue_idx * LSINIC_RING_SIZE);

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

	ret = lsinic_queue_dma_create(txq);
	if (ret) {
		LSXINIC_PMD_ERR("dma create for port%d txq%d failed",
			txq->port_id,
			txq->queue_id);

		return ret;
	}

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
	int ret;
	struct lsinic_eth_reg *reg =
		LSINIC_REG_OFFSET(adapter->hw_addr, LSINIC_ETH_REG_OFFSET);
	struct rte_lsx_pciep_device *lsinic_dev;

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

	rxq->dma_id = adapter->rxq_dma_id;
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
	rxq->ep_bd_shared_addr = (adapter->bd_desc_base +
		queue_idx * LSINIC_RING_SIZE);

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

	if (adapter->cap & LSINIC_CAP_XFER_HOST_ACCESS_EP_MEM &&
		!lsinic_dev->virt_addr[LSX_PCIEP_XFER_MEM_BAR_IDX]) {
		const struct rte_memzone *mz;
		int ret;

		mz = lsinic_dev_mempool_continue_mz(mp);
		if (!mz)
			return -ENOMEM;

		ret = rte_lsx_pciep_set_ib_win_mz(lsinic_dev,
			LSX_PCIEP_XFER_MEM_BAR_IDX, mz, 0);
		if (ret)
			return ret;
		if (rte_lsx_pciep_hw_sim_get(adapter->pcie_idx) &&
			!lsinic_dev->is_vf) {
			ret = rte_lsx_pciep_sim_dev_map_inbound(lsinic_dev);
			if (ret)
				return ret;
		}
	}

	ret = lsinic_queue_dma_create(rxq);
	if (ret) {
		LSXINIC_PMD_ERR("dma create for port%d rxq%d failed",
			rxq->port_id,
			rxq->queue_id);

		return ret;
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
