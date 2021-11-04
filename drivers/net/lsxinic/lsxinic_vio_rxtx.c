// SPDX-License-Identifier: BSD-3-Clause
/* Copyright 2020-2021 NXP  */

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

#include "lsxinic_common.h"
#include "lsxinic_common_pmd.h"
#include "lsxinic_vio_common.h"
#include "lsxinic_vio_net.h"
#include "lsxinic_vio_rxtx.h"
#include "lsxinic_ep_dma.h"
#include <dpaa2_hw_pvt.h>
#include <rte_pmd_dpaa2_qdma.h>

#include <fsl_qbman_portal.h>
#include <portal/dpaa2_hw_dpio.h>
#include <dpaa2_hw_mempool.h>
#include <dpaa2_ethdev.h>

#define DEFAULT_TX_RS_THRESH 32

/* TX queues list */
TAILQ_HEAD(lsxvio_tx_queue_list, lsxvio_queue);

/* per thread TX queue list */
RTE_DEFINE_PER_LCORE(uint8_t, lsxvio_txq_list_initialized);
RTE_DEFINE_PER_LCORE(uint8_t, lsxvio_txq_deqeue_from_rxq);
RTE_DEFINE_PER_LCORE(uint8_t, lsxvio_txq_num_in_list);
RTE_DEFINE_PER_LCORE(struct lsxvio_tx_queue_list, lsxvio_txq_list);

static void lsxvio_tx_loop(void);

static void
lsxvio_queue_dma_release(struct lsxvio_queue *q)
{
	uint32_t i;

	if (q->qdma_pool) {
		for (i = 0; i < q->nb_desc; i++) {
			rte_mempool_put(q->qdma_pool,
				q->dma_jobs[i].usr_elem);
			rte_mempool_put(q->qdma_pool,
				q->e2r_bd_dma_jobs[i].usr_elem);
			rte_mempool_put(q->qdma_pool,
				q->r2e_bd_dma_jobs[i].usr_elem);
		}
		rte_mempool_free(q->qdma_pool);
		q->qdma_pool = NULL;
	}

	if (q->dma_vq >= 0)
		rte_rawdev_queue_release(q->dma_id, q->dma_vq);
}

static void
lsxvio_queue_release_mbufs(struct lsxvio_queue *q)
{
	uint32_t i;

	if (q->sw_ring) {
		for (i = 0; i < q->nb_desc; i++) {
			if (q->sw_ring[i].mbuf) {
				rte_pktmbuf_free_seg(q->sw_ring[i].mbuf);
				q->sw_ring[i].mbuf = NULL;
			}
		}
	}
}

static int
lsxvio_queue_dma_create(struct lsxvio_queue *q)
{
	uint32_t lcore_id = rte_lcore_id(), i, sg_enable = 0;
	uint32_t vq_flags = RTE_QDMA_VQ_EXCLUSIVE_PQ;
	int pcie_id = q->adapter->lsx_dev->pcie_id;
	enum PEX_TYPE pex_type = lsx_pciep_type_get(pcie_id);
	char *penv;

	penv = getenv("LSINIC_QDMA_SG_ENABLE");
	if (penv)
		sg_enable = atoi(penv);

	if (q->adapter->rbp_enable && sg_enable) {
		if (pex_type != PEX_LX2160_REV2 &&
			pex_type != PEX_LS208X) {
			LSXINIC_PMD_WARN("RBP does not support qDMA SG");
			sg_enable = 0;
		}
	}

	if (sg_enable)
		vq_flags |= RTE_QDMA_VQ_FD_LONG_FORMAT |
					RTE_QDMA_VQ_FD_SG_FORMAT;

	if (pex_type == PEX_LS208X ||
		lsx_pciep_hw_sim_get(pcie_id))
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

	if (q->adapter->rbp_enable) {
		q->rbp.enable = 1;
		if (vq_flags & RTE_QDMA_VQ_FD_LONG_FORMAT)
			q->rbp.use_ultrashort = 0;
		else
			q->rbp.use_ultrashort = 1;

		if (q->type == LSXVIO_QUEUE_RX) {
			q->rbp.srbp = 1;
			q->rbp.sportid = pcie_id;
			q->rbp.spfid = q->adapter->pf_idx;
			if (q->adapter->is_vf) {
				q->rbp.svfid = q->adapter->vf_idx;
				q->rbp.svfa = 1;
			} else {
				q->rbp.svfa = 0;
			}
			q->rbp.drbp = 0;
		} else {
			q->rbp.drbp = 1;
			q->rbp.dportid = pcie_id;
			q->rbp.dpfid = q->adapter->pf_idx;
			if (q->adapter->is_vf) {
				q->rbp.dvfid = q->adapter->vf_idx;
				q->rbp.dvfa = 1;
			} else {
				q->rbp.dvfa = 0;
			}
			q->rbp.srbp = 0;
		}
		q->qdma_config.flags = vq_flags;
		q->qdma_config.rbp = &q->rbp;
		q->dma_vq = rte_qdma_queue_setup(q->dma_id, -1,
			&q->qdma_config);
	} else {
		q->qdma_config.flags = vq_flags;
		q->qdma_config.rbp = NULL;
		q->dma_vq = rte_qdma_queue_setup(q->dma_id, -1,
			&q->qdma_config);
	}
	LSXINIC_PMD_DBG("qid=%d, lcore_id=%d dma_vq=%d rbp=%d",
		q->queue_id, lcore_id, q->dma_vq, q->rbp.enable);
	if (q->dma_vq < 0)
		LSXINIC_PMD_ERR("Failed to create DMA");

	if (vq_flags & RTE_QDMA_VQ_NO_RESPONSE && q->dma_vq >= 0) {
		char qdma_pool_name[32];

		sprintf(qdma_pool_name, "pool_%d:%d:%d:%d_%d_%d",
				q->adapter->pcie_idx,
				q->adapter->pf_idx,
				q->adapter->is_vf,
				q->adapter->is_vf ? q->adapter->vf_idx : 0,
				q->type, q->queue_id);
		q->qdma_pool = rte_mempool_create(qdma_pool_name,
			3 * q->nb_desc, 4096, q->nb_desc / 4, 0,
			NULL, NULL, NULL, NULL, SOCKET_ID_ANY, 0);
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
				rte_rawdev_queue_release(q->dma_id,
					q->dma_vq);
				q->dma_vq = -1;

				return -1;
			}
		}
	}

	return q->dma_vq;
}

static uint16_t
lsxvio_queue_dma_clean(struct lsxvio_queue *q)
{
	struct rte_qdma_job *jobs[LSXVIO_QDMA_DQ_MAX_NB];
	int ret = 0;
	struct rte_qdma_enqdeq context;

	context.vq_id = q->dma_vq;
	context.job = jobs;

	if (q->pkts_eq == q->pkts_dq)
		return 0;

	ret = rte_qdma_dequeue_buffers(q->dma_id, NULL,
			LSXVIO_QDMA_DQ_MAX_NB, &context);

	q->pkts_dq += ret;

	return (uint16_t)(q->pkts_eq - q->pkts_dq);
}

static void
lsxvio_queue_free_swring(struct lsxvio_queue *q)
{
	if (!q)
		return;

	if (q->sw_ring)
		rte_free(q->sw_ring);
	if (q->dma_jobs)
		rte_free(q->dma_jobs);
	if (q->e2r_bd_dma_jobs)
		rte_free(q->e2r_bd_dma_jobs);
	if (q->r2e_bd_dma_jobs)
		rte_free(q->r2e_bd_dma_jobs);
}

void
lsxvio_queue_release(struct lsxvio_queue *q)
{
	if (!q)
		return;

	lsxvio_queue_release_mbufs(q);
	lsxvio_queue_free_swring(q);
	lsxvio_queue_dma_release(q);
	rte_free(q);
}

static struct lsxvio_queue *
lsxvio_queue_alloc(struct lsxvio_adapter *adapter,
	uint16_t queue_idx,
	int socket_id, uint32_t nb_desc)
{
	struct lsxvio_queue *q;

	q = rte_zmalloc_socket("ethdev queue", sizeof(struct lsxvio_queue),
			RTE_CACHE_LINE_SIZE, socket_id);
	if (!q) {
		LSXINIC_PMD_ERR("Failed to allocate memory for queue\n");
		return NULL;
	}
	memset(q, 0, sizeof(struct lsxvio_queue));

	adapter->vqs[queue_idx] = q;
	q->adapter = adapter;

	if (adapter->rbp_enable)
		q->ob_base = 0;
	else
		q->ob_base = adapter->ob_base;

	q->ob_virt_base = adapter->ob_virt_base;
	q->nb_desc = nb_desc;
	q->new_desc_thresh = DEFAULT_TX_RS_THRESH;
	q->queue_id = queue_idx;
	q->dma_vq = -1;

	/* Allocate software ring */
	q->sw_ring = rte_zmalloc_socket("q->sw_ring",
			sizeof(struct lsxvio_queue_entry) * nb_desc,
			RTE_CACHE_LINE_SIZE, socket_id);
	if (!q->sw_ring) {
		LSXINIC_PMD_ERR("Failed to create sw_ring");
		goto _err;
	}

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
		LSXINIC_PMD_ERR("Failed to create EP 2 RC BD DMA jobs");
		goto _err;
	}

	q->r2e_bd_dma_jobs = rte_zmalloc_socket(NULL,
			sizeof(struct rte_qdma_job) * nb_desc,
			RTE_CACHE_LINE_SIZE, socket_id);
	if (!q->r2e_bd_dma_jobs) {
		LSXINIC_PMD_ERR("Failed to create RC 2 EP BD DMA jobs");
		goto _err;
	}

	adapter->num_queues += 1;

	return q;

_err:
	lsxvio_queue_release(q);
	return NULL;
}

void
lsxvio_queue_reset(struct lsxvio_queue *q)
{
	struct lsxvio_queue_entry *xe = q->sw_ring;
	struct rte_qdma_job *dma_jobs = q->dma_jobs;
	uint32_t i;

	/* Initialize SW ring entries */
	for (i = 0; i < q->nb_desc; i++) {
		xe[i].mbuf = NULL;
		xe[i].idx = i;
		xe[i].bd_idx = i;
		xe[i].flag = 0;
		dma_jobs[i].cnxt = (uint64_t)(&xe[i]);
		dma_jobs[i].flags = RTE_QDMA_JOB_SRC_PHY |
				   RTE_QDMA_JOB_DEST_PHY;
		dma_jobs[i].vq_id = q->dma_vq;
	}

	q->next_dma_idx = 0;
	q->last_avail_idx = 0;
	q->last_used_idx = 0;
	q->new_desc = 0;
	q->errors = 0;
	q->drop_packet_num = 0;
	q->ring_full = 0;
	q->loop_total = 0;
	q->loop_avail = 0;

	q->jobs_pending = 0;
	q->mhead = 0;
	q->mtail = 0;
	q->mcnt = 0;
}

static int lsxvio_add_txq_to_list(struct lsxvio_queue *txq)
{
	struct lsxvio_queue *queue = NULL;

	if (!RTE_PER_LCORE(lsxvio_txq_list_initialized)) {
		TAILQ_INIT(&RTE_PER_LCORE(lsxvio_txq_list));
		RTE_PER_LCORE(lsxvio_txq_list_initialized) = 1;
		RTE_PER_LCORE(lsxvio_txq_num_in_list) = 0;
	}

	/* Check if txq already added to list */
	TAILQ_FOREACH(queue, &RTE_PER_LCORE(lsxvio_txq_list), next) {
		if (queue == txq)
			return 0;
	}

	TAILQ_INSERT_TAIL(&RTE_PER_LCORE(lsxvio_txq_list), txq, next);
	RTE_PER_LCORE(lsxvio_txq_num_in_list)++;

	LSXINIC_PMD_DBG("Add port%d txq%d to list NUM%d",
		txq->port_id, txq->queue_id,
		RTE_PER_LCORE(lsxvio_txq_num_in_list));

	return 0;
}

static int
lsxvio_remove_txq_from_list(struct lsxvio_queue *txq)
{
	struct lsxvio_queue *q, *tq;

	TAILQ_FOREACH_SAFE(q, &RTE_PER_LCORE(lsxvio_txq_list), next, tq) {
		if (q == txq) {
			TAILQ_REMOVE(&RTE_PER_LCORE(lsxvio_txq_list),
				q, next);
			RTE_PER_LCORE(lsxvio_txq_num_in_list)--;
			LSXINIC_PMD_DBG("Remove port%d txq%d from list NUM%d",
				txq->port_id, txq->queue_id,
				RTE_PER_LCORE(lsxvio_txq_num_in_list));
			break;
		}
	}

	return 0;
}

static void
lsxvio_queue_stop(struct lsxvio_queue *q)
{
	q->status = LSXVIO_QUEUE_STOP;
}

static void
lsxvio_queue_start(struct lsxvio_queue *q)
{
	q->new_time_thresh = 1 * rte_get_timer_hz() / 1000000; /* ns->s */
	q->new_desc_thresh = DEFAULT_TX_RS_THRESH;

	if (lsxvio_queue_dma_create(q) < 0)
		return;

	lsxvio_queue_reset(q);
}

static void lsxvio_queue_update(struct lsxvio_queue *q)
{
	if (q->status == LSXVIO_QUEUE_UNAVAILABLE)
		return;

	if (q->status == LSXVIO_QUEUE_RUNNING)
		return;

	if (q->status == LSXVIO_QUEUE_START) {
		lsxvio_queue_start(q);

		if (q->type == LSXVIO_QUEUE_TX)
			lsxvio_add_txq_to_list(q);

		q->status = LSXVIO_QUEUE_RUNNING;
	}
	if (q->status == LSXVIO_QUEUE_STOP) {
		if (q->type == LSXVIO_QUEUE_TX)
			lsxvio_remove_txq_from_list(q);

		if (lsxvio_queue_dma_clean(q) != 0)
			return;
	}
}

static int
lsxvio_queue_init(struct lsxvio_queue *q)
{
	/* Currently the queeu has been inited in lsxvio_queue_alloc. */
	q->status = LSXVIO_QUEUE_UNAVAILABLE;

	return 0;
}

int
lsxvio_dev_tx_queue_setup(struct rte_eth_dev *dev,
	uint16_t tx_queue_id,
	uint16_t nb_desc,
	unsigned int socket_id,
	const struct rte_eth_txconf *tx_conf __rte_unused)
{
	struct lsxvio_adapter *adapter = dev->data->dev_private;
	uint16_t queue_idx = tx_queue_id * VIRTIO_QNUM + VIRTIO_RXQ;
	struct lsxvio_queue *txq;

	/* Free memory prior to re-allocation if needed... */
	if (dev->data->tx_queues[queue_idx])
		lsxvio_queue_release(dev->data->tx_queues[queue_idx]);

	/* First allocate the tx queue data structure */
	txq = lsxvio_queue_alloc(adapter, queue_idx, socket_id, nb_desc);
	if (!txq)
		return -ENOMEM;

	txq->dma_id = adapter->qdma_dev_id;
	txq->port_id = dev->data->port_id;

	/* using RC's rx ring to send EP's packets */
	txq->dev = dev;
	txq->type = LSXVIO_QUEUE_TX;
	LSXINIC_PMD_DBG("port%d txq%d dma_id=%d, desc:%p, "
		"sw_ring=%p, dma_jobs:%p",
		txq->port_id, txq->queue_id, txq->dma_id,
		txq->sw_ring, txq->desc, txq->dma_jobs);

	dev->data->tx_queues[tx_queue_id] = txq;

	return 0;
}

void
lsxvio_dev_tx_queue_release(void *txq)
{
	lsxvio_queue_release(txq);
}

void
lsxvio_dev_rx_queue_release(void *rxq)
{
	lsxvio_queue_release(rxq);
}

int
lsxvio_dev_rx_queue_setup(struct rte_eth_dev *dev,
	uint16_t rx_queue_id,
	uint16_t nb_desc,
	unsigned int socket_id,
	const struct rte_eth_rxconf *rx_conf,
	struct rte_mempool *mp)
{
	struct lsxvio_adapter *adapter = dev->data->dev_private;
	uint16_t queue_idx = rx_queue_id * VIRTIO_QNUM + VIRTIO_TXQ;
	struct lsxvio_queue *rxq;

	/* Free memory prior to re-allocation if needed... */
	if (dev->data->rx_queues[queue_idx] != NULL)
		lsxvio_queue_release(dev->data->rx_queues[queue_idx]);

	/* First allocate the tx queue data structure */
	rxq = lsxvio_queue_alloc(adapter, queue_idx, socket_id, nb_desc);
	if (!rxq)
		return -ENOMEM;

	rxq->dma_id = adapter->qdma_dev_id;
	rxq->mb_pool = mp;
	rxq->port_id = dev->data->port_id;
	rxq->crc_len = 0;
	rxq->drop_en = rx_conf->rx_drop_en;

	/* using RC's rx ring to send EP's packets */
	rxq->desc = NULL;
	rxq->dev = dev;
	rxq->type = LSXVIO_QUEUE_RX;
	LSXINIC_PMD_DBG("port%d rxq%d dma_id=%d, sw_ring:%p "
		"desc:%p dma_jobs:%p",
		rxq->port_id, rxq->queue_id, rxq->dma_id,
		rxq->sw_ring, rxq->desc, rxq->dma_jobs);

	dev->data->rx_queues[rx_queue_id] = rxq;

	return 0;
}

/* Initializes Receive Unit. */
int
lsxvio_dev_rx_init(struct rte_eth_dev *dev)
{
	struct lsxvio_queue *rxq;
	uint16_t i;
	int ret;

	/* Setup RX queues */
	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		rxq = dev->data->rx_queues[i];
		ret = lsxvio_queue_init(rxq);
		if (ret)
			return ret;
	}

	return 0;
}

/* Initializes Transmit Unit. */
void
lsxvio_dev_tx_init(struct rte_eth_dev *dev)
{
	struct lsxvio_queue *txq;
	uint16_t i;

	/* Setup the Base and Length of the Tx Descriptor Rings */
	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		txq = dev->data->tx_queues[i];
		lsxvio_queue_init(txq);
	}
}

void lsxvio_dev_rx_tx_bind(struct rte_eth_dev *dev)
{
	struct lsxvio_queue *txq;
	struct lsxvio_queue *rxq;
	uint16_t i, num;

	num = RTE_MIN(dev->data->nb_tx_queues,
		     dev->data->nb_rx_queues);

	/* Setup the Base and Length of the Tx Descriptor Rings */
	for (i = 0; i < num; i++) {
		txq = dev->data->tx_queues[i];
		rxq = dev->data->rx_queues[i];
		if (!txq || !rxq)
			continue;

		rxq->pair = txq;
		txq->pair = rxq;
	}
}

void lsxvio_dev_rx_stop(struct rte_eth_dev *dev)
{
	struct lsxvio_queue *rxq;
	uint16_t i;

	/* Setup the Base and Length of the Tx Descriptor Rings */
	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		rxq = dev->data->rx_queues[i];
		lsxvio_queue_stop(rxq);
	}
}

void lsxvio_dev_tx_stop(struct rte_eth_dev *dev)
{
	struct lsxvio_queue *txq;
	uint16_t i;

	/* Setup the Base and Length of the Tx Descriptor Rings */
	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		txq = dev->data->tx_queues[i];
		lsxvio_queue_stop(txq);
	}
}

void
lsxvio_dev_clear_queues(struct rte_eth_dev *dev)
{
	uint32_t i, j;

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		struct lsxvio_queue *txq = dev->data->tx_queues[i];
		struct lsxvio_queue *next = txq;

		for (j = 0; j < txq->nb_q; j++) {
			if (next == NULL)
				break;

			lsxvio_queue_release_mbufs(txq);
			lsxvio_queue_reset(next);
			next = next->sibling;
		}
	}

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		struct lsxvio_queue *rxq = dev->data->rx_queues[i];
		struct lsxvio_queue *next = rxq;

		for (j = 0; j < rxq->nb_q; j++) {
			if (!next)
				break;

			lsxvio_queue_release_mbufs(rxq);
			lsxvio_queue_reset(next);
			next = next->sibling;
		}
	}
}

static __rte_always_inline void
update_shadow_used_ring_split(struct lsxvio_queue *vq,
	uint16_t desc_idx, uint32_t len)
{
	uint16_t i = vq->shadow_used_idx++;

	vq->shadow_used_split[i].id  = desc_idx;
	vq->shadow_used_split[i].len = len;
}

static __rte_always_inline void
do_flush_shadow_used_ring_split(struct lsxvio_queue *vq,
	uint16_t to, uint16_t from, uint16_t size)
{
	uint16_t i;

	for (i = 0; i < size; i++) {
		vq->used->ring[to + i].id = vq->shadow_used_split[from + i].id;
		vq->used->ring[to + i].len =
			vq->shadow_used_split[from + i].len +
			vq->adapter->vtnet_hdr_size;
	}
}

static __rte_always_inline void
flush_shadow_used_ring_split(struct lsxvio_queue *vq)
{
	uint16_t used_idx = vq->last_used_idx & (vq->nb_desc - 1);
	uint16_t shadow_used_idx = vq->shadow_used_idx;

	if (used_idx + shadow_used_idx <= vq->nb_desc) {
		do_flush_shadow_used_ring_split(vq, used_idx, 0,
			shadow_used_idx);
	} else {
		uint16_t size;

		/* update used ring interval [used_idx, vq->size] */
		size = vq->nb_desc - used_idx;
		do_flush_shadow_used_ring_split(vq, used_idx, 0, size);

		 /* update the left half used ring interval [0, left_size] */
		do_flush_shadow_used_ring_split(vq, 0, size,
			shadow_used_idx - size);
	}

	vq->last_used_idx += shadow_used_idx;
	vq->used->idx += shadow_used_idx;
	vq->shadow_used_idx = 0;
}

static inline void
lsxvio_qdma_multiple_enqueue(struct lsxvio_queue *queue,
	struct rte_qdma_job **jobs, uint16_t nb_jobs)
{
	int ret = 0;
	struct rte_qdma_enqdeq e_context;

	/* Qdma multi-enqueue support, max enqueue 32 entries once.
	 * if there are 32 entries or time out, handle them in batch
	 */
	e_context.vq_id = queue->dma_vq;
	e_context.job = jobs;
	ret = rte_qdma_enqueue_buffers(queue->dma_id, NULL, nb_jobs,
			&e_context);
	if (likely(ret > 0)) {
		queue->jobs_pending -= ret;
		queue->pkts_eq += ret;
	} else {
		LSXINIC_PMD_ERR("LSX RX QDMA enqueue failed!"
			"ret=%d, nb_jobs=%d, dma_id=%d\n",
			ret, nb_jobs, queue->dma_id);
		queue->errors++;
	}
}

/*********************************************************************
 *
 *  RX functions
 *
 **********************************************************************/
static uint16_t
lsxvio_rx_dma_dequeue(struct lsxvio_queue *rxq)
{
	struct rte_qdma_job *jobs[LSXVIO_QDMA_DQ_MAX_NB];
	struct rte_qdma_job *dma_job;
	struct lsxvio_queue_entry *rxe = NULL;
	int i, idx, ret = 0;

	struct rte_qdma_enqdeq context;

	if (rxq->pkts_eq == rxq->pkts_dq)
		return 0;

	context.vq_id = rxq->dma_vq;
	context.job = jobs;
	ret = rte_qdma_dequeue_buffers(rxq->dma_id, NULL,
			LSXVIO_QDMA_DQ_MAX_NB,
			&context);

	LSXINIC_PMD_DBG("enter %s nb_in_dma=%ld, dequeue ret=%d",
		__func__, rxq->pkts_eq - rxq->pkts_dq, ret);
	for (i = 0; i < ret; i++) {
		dma_job = jobs[i];
		if (!dma_job)
			continue;
		dma_job->flags &= ~LSINIC_QDMA_JOB_USING_FLAG;
		rxe = (struct lsxvio_queue_entry *)dma_job->cnxt;
		if (unlikely(dma_job->status != 0)) {
			LSXINIC_PMD_ERR("rxe%d dma error %x, cpu:%d",
				rxe->idx,
				dma_job->status, rte_lcore_id());
		}
		if (rxe) {
			if (rxe->flag) {
				idx = rxe->idx & (rxq->nb_desc - 1);
				update_shadow_used_ring_split(rxq, idx, 0);
			}

			/* This should record the completed jobs,
			 * so it need to be updated after got
			 * qdma response.
			 */
			rxq->mcache[rxq->mtail] = rxe->mbuf;
			rxq->mtail = (rxq->mtail + 1) & MCACHE_MASK;
			rxq->mcnt++;
			rte_prefetch0(rte_pktmbuf_mtod(rxe->mbuf, void *));
		}
	}
	rxq->pkts_dq += ret;

	LSXINIC_PMD_DBG("exit %s nb_in_dma=%ld dequeue ret=%d\n",
			__func__, rxq->pkts_eq - rxq->pkts_dq, ret);

	return i;
}

static void
lsxvio_recv_one_pkt(struct lsxvio_queue *rxq,
	uint16_t desc_idx, uint16_t head)
{
	struct rte_qdma_job *dma_job = &rxq->dma_jobs[desc_idx];
	struct lsxvio_queue_entry *rxe = &rxq->sw_ring[desc_idx];
	struct vring_desc *desc = &rxq->desc[desc_idx];
	struct rte_mbuf *rxm;
	uint32_t pkt_len;
	uint32_t total_bytes = 0, total_packets = 0;
	uint32_t len;

	if (unlikely(dma_job->flags & LSINIC_QDMA_JOB_USING_FLAG)) {
		/*Workaround, need further investigation for this situation.*/
		LSXINIC_PMD_DBG("RXQ%d: dma_jobs[%d] is in DMA",
			rxq->queue_id, desc_idx);

		return;
	}
	LSXINIC_PMD_DBG("desc info: addr=%lx len=%d flags=%x, next=%x",
		desc->addr, desc->len, desc->flags, desc->next);
	len = desc->len;
	len -= rxq->adapter->vtnet_hdr_size;
	if (len > LSXVIO_MAX_DATA_PER_TXD) {
		LSXINIC_PMD_ERR("port%d rxq%d BD%d error len:0x%08x, cpu:%d",
			rxq->port_id, rxq->queue_id, desc_idx, len,
			rte_lcore_id());
		rxq->errors++;
		return;
	}
	pkt_len = len - rxq->crc_len;

	rxm = rte_mbuf_raw_alloc(rxq->mb_pool);
	if (!rxm) {
		LSXINIC_PMD_DBG("RX mbuf alloc failed"
			" port_id=%u queue_id=%u",
			(unsigned int)rxq->port_id,
			(unsigned int)rxq->queue_id);
		rte_eth_devices[rxq->port_id].data->rx_mbuf_alloc_failed++;
		return;
	}

	/* rxm is ret_mbuf passed to upper layer */
	rxe->mbuf = rxm;
	rxe->len = len;
	rxe->flag = head;

	dma_job->cnxt = (uint64_t)rxe;
	dma_job->dest =
		rte_cpu_to_le_64(rte_mbuf_data_iova_default(rxm));
	dma_job->src =
		desc->addr + rxq->ob_base +
		rxq->adapter->vtnet_hdr_size;
	rxe->align_dma_offset = (dma_job->src) & LSXVIO_DMA_ALIGN_MASK;
	dma_job->src -= rxe->align_dma_offset;
	dma_job->len = pkt_len + rxe->align_dma_offset;

	LSXINIC_PMD_DBG("dma info: src=%lx dest=%lx len=%d, "
		"rxq_id=%d type=%d, drbp=%d, srbp=%d dma_id=%d",
		dma_job->src, dma_job->dest, dma_job->len,
		rxq->queue_id, rxq->type, rxq->rbp.drbp,
		rxq->rbp.srbp, rxq->dma_id);
	rxm->nb_segs = 1;
	rxm->next = NULL;
	rxm->pkt_len = pkt_len;
	rxm->data_len = pkt_len;
	rxm->port = rxq->port_id;
	rxm->data_off = RTE_PKTMBUF_HEADROOM + rxe->align_dma_offset;

	dma_job->flags |= LSINIC_QDMA_JOB_USING_FLAG;

	rxq->jobs_pending++;
	if (rxq->new_desc == 0)
		rxq->new_tsc = rte_rdtsc();
	/*rxq->nb_in_dma++;*/
	total_bytes += len + rxe->align_dma_offset;
	total_packets++;
}

static void
lsxvio_recv_bd(struct lsxvio_queue *vq)
{
	struct rte_qdma_job *jobs[LSXVIO_QDMA_EQ_MAX_NB];
	uint16_t free_entries, i, j, avail_idx, desc_idx, head, bd_num = 0;

	if (vq->shadow_avail)
		free_entries = vq->shadow_avail->idx - vq->last_avail_idx;
	else
		free_entries = vq->avail->idx - vq->last_avail_idx;

	if (free_entries == 0)
		return;

	for (i = 0; i < free_entries; i++) {
		avail_idx = (vq->last_avail_idx + i) & (vq->nb_desc - 1);
		desc_idx = vq->avail->ring[avail_idx];
		head = 1;
		LSXINIC_PMD_DBG("avail_idx=%d, desc_idx=%d free_entries=%d",
			avail_idx, desc_idx, free_entries);
		/** Currently no indirect support. */
		j = 0;
		do {
			lsxvio_recv_one_pkt(vq, desc_idx, head);
			jobs[j] = &vq->dma_jobs[desc_idx];
			head = 0;
			bd_num++;
			j++;
			if (!(vq->desc[desc_idx].flags & VRING_DESC_F_NEXT))
				break;
			desc_idx = vq->desc[desc_idx].next;
		} while (1);

		lsxvio_qdma_multiple_enqueue(vq, jobs, j);

		if (bd_num >= DEFAULT_TX_RS_THRESH) {
			i++;
			break;
		}
	}

	vq->last_avail_idx += i;
}

static bool
lsxvio_queue_running(struct lsxvio_queue *q)
{
	return q->status == LSXVIO_QUEUE_RUNNING;
}

static uint16_t
lsxvio_recv_pkts_to_cache(struct lsxvio_queue *rxq)
{
	/* Seems no need now.*/
	return rxq->queue_id;
}

static bool
lsxvio_timeout(struct lsxvio_queue *q)
{
	uint64_t timer_period;

	timer_period = rte_rdtsc() - q->new_tsc;
	if (timer_period >= q->new_time_thresh)
		return true;
	else
		return false;
}

static void
lsxvio_queue_trigger_interrupt(struct lsxvio_queue *q)
{
	if (!q->new_desc_thresh) {
		q->new_desc = 0;
		return;
	}
	if (!q->new_desc)
		return;

	if (!lsx_pciep_hw_sim_get(q->adapter->pcie_idx)) {
		if (q->new_desc_thresh &&
			(q->new_desc >= q->new_desc_thresh ||
			(lsxvio_timeout(q)))) {
			/* MSI */
			lsx_pciep_msix_cmd_send(q->msix_vaddr, q->msix_cmd);
			q->new_desc = 0;
		}
	}
}

uint16_t
lsxvio_recv_pkts(void *rx_queue, struct rte_mbuf **rx_pkts,
	uint16_t nb_pkts)
{
	uint16_t nb_rx = 0;
	uint16_t count = 0;
	struct rte_mbuf *rxm;
	struct lsxvio_queue *rxq = rx_queue;
#ifdef RTE_LIBRTE_LSINIC_DEBUG_RX
	uint16_t i;
	char *cpu_virt;
#endif

	if (!lsxvio_queue_running(rxq)) {
		/* From now the queue can work. */
		lsxvio_queue_update(rxq);
		if (!lsxvio_queue_running(rxq))
			return 0;
	}

	lsxvio_recv_bd(rxq);
	lsxvio_recv_pkts_to_cache(rxq);

	lsxvio_rx_dma_dequeue(rxq);

	lsxvio_tx_loop();

	if (rxq->mcnt < 1)
		return 0;

	count = RTE_MIN(nb_pkts, rxq->mcnt);

	for (nb_rx = 0; nb_rx < count; nb_rx++) {
		rxm = rxq->mcache[rxq->mhead];
#ifdef RTE_LIBRTE_LSINIC_DEBUG_RX
		cpu_virt = rte_pktmbuf_mtod_offset(rxm, char *, 0);
		LSXINIC_PMD_DBG("recv buf, pf=%d, qid=%d, len=%d",
			rxq->adapter->pf_idx, rxq->queue_id, rxm->pkt_len);
		for (i = 0; i < rxm->pkt_len; i += 4) {
			LSXINIC_PMD_DBG("%x ",
				rte_be_to_cpu_32(*(uint32_t *)(cpu_virt + i)));
		}
		LSXINIC_PMD_DBG("\n");
#endif
		rxm->packet_type = RTE_PTYPE_L3_IPV4;
		rx_pkts[nb_rx] = rxm;
		rxq->mhead = (rxq->mhead + 1) & MCACHE_MASK;
		rxq->mcnt--;
		rxq->bytes += rxm->pkt_len;
		rxq->bytes_fcs +=
			rxm->pkt_len + LSINIC_ETH_FCS_SIZE;
		rxq->bytes_overhead +=
			rxm->pkt_len + LSINIC_ETH_OVERHEAD_SIZE;
	}

	if (rxq->shadow_used_idx)
		flush_shadow_used_ring_split(rxq);

	rxq->new_desc += nb_rx;
	rxq->packets += nb_rx;

	lsxvio_queue_trigger_interrupt(rxq);

	return nb_rx;
}

static uint16_t
lsxvio_tx_dma_dequeue(struct lsxvio_queue *txq)
{
	struct rte_qdma_job *jobs[LSXVIO_QDMA_DQ_MAX_NB];
	struct rte_qdma_job *dma_job;
	struct lsxvio_queue_entry *txe = NULL;
	uint16_t idx;
	int i, ret = 0;
	struct rte_qdma_enqdeq context;

	if (txq->pkts_eq == txq->pkts_dq)
		return 0;

	context.vq_id = txq->dma_vq;
	context.job = jobs;
	ret = rte_qdma_dequeue_buffers(txq->dma_id, NULL,
			LSXVIO_QDMA_DQ_MAX_NB,
			&context);
	for (i = 0; i < ret; i++) {
		dma_job = jobs[i];
		if (!dma_job)
			continue;
		txe = (struct lsxvio_queue_entry *)dma_job->cnxt;
		if (dma_job->status != 0) {
			LSXINIC_PMD_ERR("QDMA fd returned err: %d",
				dma_job->status);
		}
		if (txe) {
			idx = txe->idx & (txq->nb_desc - 1);
			/* This should record the completed jobs,
			 * so it need to be updated after got
			 * qdma response.
			 */
			update_shadow_used_ring_split(txq, idx, txe->len);
			LSXINIC_PMD_DBG("port%d txq%d "
				"next_dma_idx=%d "
				"last_used_idx=%d "
				"idx=%d "
				"txe->idx=%d "
				"txe->len=%d "
				"shadow_used_idx=%d\n",
				txq->port_id, txq->queue_id,
				txq->next_dma_idx,
				txq->last_used_idx,
				idx, txe->idx, txe->len,
				txq->shadow_used_idx);
			rte_pktmbuf_free(txe->mbuf);
			txe->mbuf = NULL;
			txq->next_dma_idx++;
		}
	}
	txq->pkts_dq += ret;

	return i;
}

static void
lsxvio_xmit_one_pkt(struct lsxvio_queue *vq, uint16_t desc_idx,
	struct rte_mbuf *rxm, uint16_t head)
{
	struct rte_qdma_job *dma_job = &vq->dma_jobs[desc_idx];
	struct lsxvio_queue_entry *txe = &vq->sw_ring[desc_idx];
	struct vring_desc *desc = &vq->desc[desc_idx];

	/* rxm is ret_mbuf passed to upper layer */
	txe->mbuf = rxm;
	txe->flag = head;
	txe->len = rxm->pkt_len;

	dma_job->cnxt = (uint64_t)txe;
	dma_job->src = rte_mbuf_data_iova(rxm) - vq->adapter->vtnet_hdr_size;
	dma_job->dest = desc->addr + vq->ob_base;
	dma_job->len = rxm->pkt_len + vq->adapter->vtnet_hdr_size;
	if (vq->new_desc == 0)
		vq->new_tsc = rte_rdtsc();

	vq->jobs_pending++;
	LSXINIC_PMD_DBG("xmit src=%lx, dest=%lx, len=%d, pending=%d",
		dma_job->src, dma_job->dest, dma_job->len, vq->jobs_pending);
}

static void lsxvio_tx_loop(void)
{
	struct lsxvio_queue *q, *tq;

	TAILQ_FOREACH_SAFE(q, &RTE_PER_LCORE(lsxvio_txq_list), next, tq) {
		if (!lsxvio_queue_running(q)) {
			/* From now the queue can work. */
			lsxvio_queue_update(q);
			if (!lsxvio_queue_running(q))
				return;
		}

		if (q->pkts_eq > q->pkts_dq) {
			lsxvio_tx_dma_dequeue(q);
			if (q->shadow_used_idx) {
				q->new_desc += q->shadow_used_idx;
				flush_shadow_used_ring_split(q);
				lsxvio_queue_trigger_interrupt(q);
			}
		}

		q->loop_total++;
	}
}

static uint16_t
lsxvio_xmit_pkts_burst(struct lsxvio_queue *vq,
	struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	uint16_t tx_num = 0, free_entries, i, j, avail_idx, desc_idx, head;
	struct rte_qdma_job *jobs[LSXVIO_QDMA_EQ_MAX_NB];

	free_entries = vq->avail->idx - vq->last_avail_idx;
	if (free_entries == 0)
		return 0;

	for (i = 0; (i < free_entries) && nb_pkts; i++) {
		avail_idx = (vq->last_avail_idx + i) & (vq->nb_desc - 1);
		desc_idx = vq->avail->ring[avail_idx];
		head = 1;

		/** Currently no indirect support. */
		j = 0;
		while (1) {
			memset((char *)tx_pkts[tx_num]->buf_addr +
				tx_pkts[tx_num]->data_off -
				vq->adapter->vtnet_hdr_size,
				0, vq->adapter->vtnet_hdr_size);
			lsxvio_xmit_one_pkt(vq, desc_idx,
				tx_pkts[tx_num], head);
			vq->bytes += tx_pkts[tx_num]->pkt_len;
			vq->bytes_fcs +=
				tx_pkts[tx_num]->pkt_len +
				LSINIC_ETH_FCS_SIZE;
			vq->bytes_overhead +=
				tx_pkts[tx_num]->pkt_len +
				LSINIC_ETH_OVERHEAD_SIZE;
			jobs[j] = &vq->dma_jobs[desc_idx];
			j++;
			tx_num++;
			nb_pkts--;
			vq->packets++;
			if ((vq->desc[desc_idx].flags & VRING_DESC_F_NEXT) == 0)
				break;
			desc_idx = vq->desc[desc_idx].next;
			head = 0;
		}

		lsxvio_qdma_multiple_enqueue(vq, jobs, j);
	}

	vq->last_avail_idx += i;

	return tx_num;
}

uint16_t
lsxvio_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts,
	uint16_t nb_pkts)
{
	struct lsxvio_queue *txq;

	txq = tx_queue;

	if (!lsxvio_queue_running(txq)) {
		/* From now the queue can work. */
		lsxvio_queue_update(txq);
		if (!lsxvio_queue_running(txq))
			return 0;
	}

	txq->loop_avail++;

	/* TX loop */
	return lsxvio_xmit_pkts_burst(txq, tx_pkts, nb_pkts);
}
