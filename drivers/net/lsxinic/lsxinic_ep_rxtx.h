/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2021 NXP
 */

#ifndef _LSXINIC_EP_RXTX_H_
#define _LSXINIC_EP_RXTX_H_

#include <rte_pmd_dpaa2_qdma.h>
#include "lsxinic_common_reg.h"
#include "lsxinic_common.h"

#define RTE_PMD_USE_PREFETCH
#undef LSINIC_CHECK_DMA_ALIGNED
#define LSINIC_PACKED_RING_CHECK

/**
 * If a packet size is smaller than 256 bytes
 * it will take less time to copy the packet to a new mbuf
 * than to update BD to point a new mbuf. On the contrary,
 * for large packets the time of updating BD is less than copying
 */
#define LSINIC_COPY_PKTS_MAX_SIZE 256

#define LSINIC_INTERRUPT_THRESHOLD 32
#define LSINIC_INTERRUPT_INTERVAL 100 /* 100ms */

#ifdef RTE_PMD_USE_PREFETCH
#define rte_lsinic_prefetch(p)   rte_prefetch0(p)
#else
#define rte_lsinic_prefetch(p)   do {} while (0)
#endif

#ifdef RTE_ARCH_ARM64
#define lsinic_invalidate(p) \
	{ asm volatile("dc civac, %0" : : "r"(p) : "memory"); }
#else
#define lsinic_invalidate(p)
#endif

#define LSINIC_RING_FULL_THRESH_COUNT 1

#undef LSXINIC_LATENCY_TEST

/**
 * Structure associated with each descriptor of the TX ring of a TX queue.
 */
struct lsinic_sw_bd {
	struct rte_mbuf *mbuf; /**< mbuf associated with TX desc, if any. */
	struct lsinic_bd_desc bd;
	uint32_t align_dma_offset;
	struct lsinic_mg_header mg_header;
	union {
		char *complete;
		uint8_t dma_complete;
	};
};

enum lsinix_split_type {
	LSINIC_CPU_SPLIT,
	LSINIC_HW_SPLIT,
	LSINIC_MBUF_CLONE_SPLIT
};

enum lsinic_pci_dma_test_status {
	LSINIC_PCI_DMA_TEST_UNINIT,
	LSINIC_PCI_DMA_TEST_INIT,
	LSINIC_PCI_DMA_TEST_START,
	LSINIC_PCI_DMA_TEST_STOP
};

struct lsinic_pci_dma_test {
	uint64_t pci_addr;
	enum lsinic_pci_dma_test_status status;
	uint16_t pkt_len;
	struct rte_qdma_queue_config qdma_cfg;
	int dma_vq;
	uint16_t latency_burst;
	struct rte_mbuf **mbufs;
	struct rte_ring *jobs_ring;
};

/**
 * Structure associated with each RX queue.
 */
#define MCACHE_NUM (LSINIC_MERGE_MAX_NUM * 4)
#define MCACHE_MASK (MCACHE_NUM - 1)

#define SP_RING_MAX_NUM (1024)

enum ep2rc_update_type {
	EP2RC_BD_UPDATE,
	EP2RC_RING_UPDATE,
	EP2RC_BD_DMA_UPDATE,
	EP2RC_RING_DMA_UPDATE,
	EP2RC_INDEX_UPDATE,
	EP2RC_INVALID_UPDATE
};

union ep_ep2rc_ring {
#ifdef LSINIC_BD_CTX_IDX_USED
	struct ep2rc_notify *tx_notify;
#endif
	uint8_t *rx_complete;
	uint32_t *free_idx;
	void *union_ring;
};

typedef struct lsinic_sw_bd *
(*lsinic_recv_rxe_t)(struct lsinic_queue *rxq,
	uint16_t bd_idx);

typedef void
(*lsinic_recv_update_t)(struct lsinic_queue *rxq,
	uint16_t bd_idx, void *rxe);

struct lsinic_queue {
	struct lsinic_adapter *adapter;
	struct lsinic_queue *pair;
	enum LSINIC_QEUE_TYPE type;
	enum LSINIC_QEUE_STATUS status;
	/* flag */
	uint32_t flag;
	uint64_t cyc_diff_total;
	uint64_t cyc_diff_curr;

	struct rte_mempool  *mb_pool; /**< mbuf pool to populate RX ring. */

	/* queue register */
	struct lsinic_ring_reg *ep_reg; /* ring reg point to EP memory */
	struct lsinic_ring_reg *rc_reg; /* ring reg point to RC memory */

	struct lsinic_bd_desc *ep_bd_desc; /* bd desc point to EP mem */
	struct lsinic_bd_desc *rc_bd_desc; /* bd desc point to RC mem */
	union ep_ep2rc_ring ep2rc; /* ep2rc ring point to RC mem */
	enum ep2rc_update_type ep2rc_update;
	union {
#ifdef LSINIC_BD_CTX_IDX_USED
		struct ep2rc_notify *local_notify;
#endif
		uint32_t *local_free_idx;
	};
	struct lsinic_sw_bd *sw_ring;
	struct lsinic_sw_bd **sw_bd_pool;
	int sw_bd_pool_cnt;
	int sw_bd_pool_size;

	lsinic_recv_rxe_t recv_rxe;
	lsinic_recv_update_t recv_update;

	struct lsinic_dpni_mg_dsc *mg_dsc;
	uint16_t mg_dsc_head;
	uint16_t mg_dsc_tail;

	/* DMA */
	struct rte_qdma_job *dma_jobs;

	struct rte_qdma_job *e2r_bd_dma_jobs;
	struct rte_qdma_job *r2e_bd_dma_jobs;
	uint16_t bd_dma_step;
	int wdma_bd_start;
	int wdma_bd_nb;

	uint16_t rdma_idx;

	uint32_t core_id;
	int32_t dma_id;
	int32_t dma_vq;
	uint64_t ob_base;
	uint8_t *ob_virt_base;

	struct lsinic_pci_dma_test dma_test;

	/* MSI-X */
	uint32_t msix_irq;
	uint32_t msix_cmd;
	uint64_t msix_vaddr;
	uint64_t new_tsc;
	uint64_t new_time_thresh;
	uint16_t new_desc;
	uint32_t new_desc_thresh;

	/* BD index */
	uint16_t head;
	uint16_t next_dma_idx;    /**< number of TX descriptors. */
	uint16_t next_avail_idx;
	uint16_t next_used_idx;

	/* queue setting */
	uint32_t nb_desc;
	uint32_t nb_avail;

	/* Multi-en/dequeue for qdma */
	uint32_t jobs_pending;
	uint16_t jobs_avail_idx;

	uint32_t queue_id; /**< RX queue index. */
	uint32_t reg_idx;  /**< RX queue register index. */
	uint32_t port_id;  /**< Device port identifier. */
	uint32_t crc_len;  /**< 0 if CRC stripped, 4 otherwise. */
	uint32_t drop_en;  /**< If not 0, set SRRCTL.Drop_En. */

	/* qDMA configure */
	struct rte_qdma_rbp rbp;
	struct rte_qdma_queue_config qdma_config;

	uint64_t packets_old;
	/* statistics */
	uint64_t packets;
	uint64_t bytes;
	uint64_t bytes_fcs;
	uint64_t bytes_overhead;
	uint64_t bytes_overhead_old;
	uint64_t errors;
	uint64_t drop_packet_num;
	uint64_t ring_full;
	uint64_t loop_total;
	uint64_t loop_avail;

	/* point to the working queue */
	struct lsinic_queue *working;
	/* point to the next queue belonged to the same core */
	struct lsinic_queue *sibling;
	uint32_t nb_q;

	struct rte_eth_dev *dev;

	uint16_t mhead;
	uint16_t mtail;
	uint32_t mcnt;
	struct rte_mbuf *mcache[MCACHE_NUM];

	uint16_t sw_bd_head;
	uint16_t sw_bd_tail;
	int sw_bd_cnt;
	struct lsinic_sw_bd *sw_bd[MCACHE_NUM];

	enum lsinix_split_type split_type;
	void *recycle_txq;
	void *recycle_rxq;
	struct qbman_fd *recycle_fd;
	uint16_t split_cnt[MCACHE_NUM];

	int64_t recycle_pending;

	struct rte_mempool *qdma_pool;

	uint64_t bytes_dq;
	uint64_t bytes_eq;
	uint64_t pkts_dq;
	uint64_t pkts_eq;

	/* Pointer to Next instance used by q list */
	TAILQ_ENTRY(lsinic_queue) next;
};

struct lsinic_dpni_mg_dsc {
	struct rte_mbuf *attach_mbuf;
	struct lsinic_mg_header mg_header;
};

#define LSINIC_ALIGN_DMA_CALC_OFFSET(addr)   ((addr) & (64 - 1))

#define  lsinic_rx_queue lsinic_queue
#define  lsinic_tx_queue lsinic_queue

#ifndef LSINIC_QDMA_EQ_MAX_NB
#define LSINIC_QDMA_EQ_MAX_NB (RTE_QDMA_SG_ENTRY_NB_MAX / 2)
#endif

#ifndef LSINIC_QDMA_DQ_MAX_NB
#define LSINIC_QDMA_DQ_MAX_NB RTE_QDMA_SG_ENTRY_NB_MAX
#endif

#define LSINIC_SHARED_MBUF    (1ULL << 63)
/* Flagged in dma job*/
#define LSINIC_QDMA_JOB_USING_FLAG (1ULL << 31)

static inline void
lsinic_sw_bd_reset(struct lsinic_queue *q)
{
	q->sw_bd_pool_cnt = 0;
}

static inline void
lsinic_sw_bd_push(struct lsinic_queue *q,
	void **elems, int elem_count)
{
	RTE_ASSERT((q->sw_bd_pool_cnt + elem_count) <=
				q->sw_bd_pool_size);
	memcpy(&q->sw_bd_pool[q->sw_bd_pool_cnt],
		&elems[0], elem_count * sizeof(void *));
	q->sw_bd_pool_cnt += elem_count;
}

static inline void
lsinic_sw_bd_push_array(struct lsinic_queue *q,
	struct lsinic_sw_bd *elems, int elem_count)
{
	int i;

	RTE_ASSERT((q->sw_bd_pool_cnt + elem_count) <=
				q->sw_bd_pool_size);
	for (i = 0; i < elem_count; i++)
		q->sw_bd_pool[q->sw_bd_pool_cnt + i] = (void *)&elems[i];
	q->sw_bd_pool_cnt += elem_count;
}

static inline void
lsinic_sw_bd_pop(struct lsinic_queue *q,
	void **elems, int elem_count)
{
	RTE_ASSERT((q->sw_bd_pool_cnt - elem_count) >= 0);
	memcpy(&elems[0],
		&q->sw_bd_pool[q->sw_bd_pool_cnt - elem_count],
		elem_count * sizeof(void *));
	q->sw_bd_pool_cnt -= elem_count;
}

static inline uint32_t
lsinic_get_pending(uint32_t tail, uint32_t head, uint32_t count)
{
	if (head != tail)
		return (head > tail) ?
			head - tail : (head + count - tail);
	return 0;
}

static __rte_always_inline void
lsinic_bd_update_used_to_rc(struct lsinic_queue *queue,
	uint16_t used_idx)
{
#ifdef LSINIC_BD_CTX_IDX_USED
	mem_cp128b_atomic((uint8_t *)&queue->rc_bd_desc[used_idx],
		(const uint8_t *)&queue->ep_bd_desc[used_idx]);
#else
	/* Update sw_ctx and desc only. total 16B size.
	 * Don't update pkt_addr, otherwise mem barrier is required.
	 */
	if (queue->ep_bd_desc[used_idx].bd_status & RING_BD_ADDR_CHECK) {
		queue->rc_bd_desc[used_idx].pkt_addr =
			queue->ep_bd_desc[used_idx].pkt_addr;
		rte_wmb();
	}
	mem_cp128b_atomic((uint8_t *)&queue->rc_bd_desc[used_idx].sw_ctx,
		(const uint8_t *)&queue->ep_bd_desc[used_idx].sw_ctx);
	if (queue->ep_bd_desc[used_idx].bd_status & RING_BD_ADDR_CHECK) {
		queue->ep_bd_desc[used_idx].len_cmd =
			queue->rc_bd_desc[used_idx].len_cmd;
		rte_rmb();
	}
#endif
}

#ifdef LSINIC_BD_CTX_IDX_USED
static __rte_always_inline void
lsinic_ep_notify_to_rc(struct lsinic_queue *queue,
	uint16_t used_idx, int remote)
{
	struct ep2rc_notify *tx_notify = &queue->ep2rc.tx_notify[used_idx];
	struct ep2rc_notify *local_notify = &queue->local_notify[used_idx];
	struct lsinic_bd_desc *ep_bd_desc = &queue->ep_bd_desc[used_idx];
	uint32_t *local_32 = (uint32_t *)local_notify;
	uint32_t *remote_32 = (uint32_t *)tx_notify;
	uint16_t cnt;

	local_notify->total_len = ep_bd_desc->len_cmd & LSINIC_BD_LEN_MASK;
	if (ep_bd_desc->len_cmd & LSINIC_BD_CMD_MG) {
		cnt = ((ep_bd_desc->len_cmd & LSINIC_BD_MG_NUM_MASK) >>
			LSINIC_BD_MG_NUM_SHIFT) + 1;
	} else {
		cnt = 1;
	}
	EP2RC_TX_IDX_CNT_SET(local_notify->cnt_idx,
		lsinic_bd_ctx_idx(ep_bd_desc->bd_status),
		cnt);
	if (remote)
		*remote_32 = *local_32;
}
#endif

static __rte_always_inline void
lsinic_bd_read_rc_bd_desc(struct lsinic_queue *queue,
	uint16_t used_idx,
	struct lsinic_bd_desc *bd_desc)
{
	rte_memcpy(bd_desc, &queue->rc_bd_desc[used_idx],
			sizeof(struct lsinic_bd_desc));
}

static __rte_always_inline void
lsinic_bd_dma_complete_update(struct lsinic_queue *queue,
	uint16_t used_idx, struct lsinic_bd_desc *bd)
{
	rte_memcpy(&queue->ep_bd_desc[used_idx], bd,
		sizeof(struct lsinic_bd_desc));
#ifdef LSINIC_BD_CTX_IDX_USED
	queue->ep_bd_desc[used_idx].bd_status &=
		~((uint32_t)RING_BD_STATUS_MASK);
	queue->ep_bd_desc[used_idx].bd_status |=
		RING_BD_ADDR_CHECK;
	queue->ep_bd_desc[used_idx].bd_status |=
		RING_BD_HW_COMPLETE;
#else
	queue->ep_bd_desc[used_idx].bd_status =
		RING_BD_HW_COMPLETE | RING_BD_ADDR_CHECK;
#endif
}

void lsinic_rx_queue_release_mbufs(struct lsinic_rx_queue *rxq);
void lsinic_rx_queue_release(struct lsinic_rx_queue *rxq);
void lsinic_reset_rx_queue(struct lsinic_rx_queue *rxq);
void lsinic_tx_queue_release(struct lsinic_tx_queue *txq);
void lsinic_reset_tx_queue(struct lsinic_tx_queue *txq);

int lsinic_dev_rxq_init(struct lsinic_rx_queue *rxq);
int lsinic_dev_txq_init(struct lsinic_tx_queue *txq);
int lsinic_dev_rx_mq_init(struct lsinic_rx_queue *rxq);
int lsinic_dev_tx_mq_init(struct lsinic_tx_queue *txq);
void lsinic_dev_rx_tx_bind(struct rte_eth_dev *dev);
void lsinic_dev_rx_stop(struct rte_eth_dev *dev);
void lsinic_dev_tx_stop(struct rte_eth_dev *dev);
void lsinic_dev_rx_enable_start(struct rte_eth_dev *dev);
void lsinic_dev_tx_enable_start(struct rte_eth_dev *dev);
int lsinic_dev_tx_queue_setup(struct rte_eth_dev *dev,
	uint16_t queue_idx,
	uint16_t nb_desc,
	unsigned int socket_id,
	const struct rte_eth_txconf *tx_conf);

int lsinic_dev_rx_queue_setup(struct rte_eth_dev *dev,
	uint16_t queue_idx,
	uint16_t nb_desc,
	unsigned int socket_id,
	const struct rte_eth_rxconf *rx_conf,
	struct rte_mempool *mp);

void lsinic_queue_reset(struct lsinic_queue *q);

void lsinic_queue_release(struct lsinic_queue *q);

struct lsinic_queue *
lsinic_queue_alloc(struct lsinic_adapter *adapter,
	uint16_t queue_idx,
	int socket_id, uint32_t nb_desc,
	enum LSINIC_QEUE_TYPE type);

#endif
