/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2022 NXP
 */

#ifndef _LSXINIC_EP_RXTX_H_
#define _LSXINIC_EP_RXTX_H_

#include "lsxinic_ep_dma.h"
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

/**
 * Structure associated with each descriptor of the TX ring of a TX queue.
 */
struct lsinic_sw_bd {
	struct rte_mbuf *mbuf; /**< mbuf associated with TX desc, if any. */
	uint16_t my_idx; /* const after initalization*/
	uint16_t align_dma_offset;
	union {
		char *complete;
		uint8_t dma_complete;
	};
};

/**
 * Structure associated with each RX queue.
 */
#define MCACHE_NUM (LSINIC_MAX_BURST_NUM * 4)
#define MCACHE_MASK (MCACHE_NUM - 1)

#define SP_RING_MAX_NUM (1024)

enum queue_dma_bd_update {
	DMA_BD_EP2RC_UPDATE = (1 << 0),
	DMA_BD_RC2EP_UPDATE = (1 << 1)
};

#define LSINIC_DATA_DMA_START 0
#define LSINIC_E2R_BD_DMA_START \
	(LSINIC_DATA_DMA_START + LSINIC_BD_ENTRY_COUNT)
#define LSINIC_BD_DMA_MAX_COUNT \
	(LSINIC_E2R_BD_DMA_START + LSINIC_BD_ENTRY_COUNT)

struct lsinic_queue {
	struct lsinic_adapter *adapter;
	struct lsinic_queue *pair;
	enum LSINIC_QEUE_TYPE type;
	enum LSINIC_QEUE_STATUS status;
	/* flag */
	uint32_t flag;
#ifdef LSXINIC_LATENCY_PROFILING
	uint64_t cyc_diff_total;
	double avg_latency;
	uint64_t avg_x2_total;
	uint64_t avg_x4_total;
	uint64_t avg_x10_total;
	uint64_t avg_x20_total;
	uint64_t avg_x40_total;
	uint64_t avg_x100_total;
#endif
	struct rte_mempool  *mb_pool; /**< mbuf pool to populate RX ring. */

	/* queue register */
	struct lsinic_ring_reg *ep_reg; /* ring reg point to EP memory */
	struct lsinic_ring_reg *rc_reg; /* ring reg point to RC memory */

	/* point to EP mem */
	enum EP_MEM_BD_TYPE ep_mem_bd_type;
	struct lsinic_bd_desc *local_src_bd_desc;
	void *ep_bd_shared_addr;
	struct lsinic_bd_desc *ep_bd_desc;
	/* For TX ring*/
	struct lsinic_ep_tx_dst_addr *tx_dst_addr;

	/* For RX ring*/
	struct lsinic_ep_rx_src_addrl *rx_src_addrl;
	struct lsinic_ep_rx_src_addrx *rx_src_addrx;

	/* point to RC mem */
	enum RC_MEM_BD_TYPE rc_mem_bd_type;
	void *rc_bd_mapped_addr;

	struct lsinic_bd_desc *rc_bd_desc;
	/* For TX ring*/
	struct lsinic_rc_rx_len_idx *tx_len_idx;

	/* For RX ring*/
	struct lsinic_rc_tx_bd_cnf *rx_complete;
	struct lsinic_rc_tx_idx_cnf *free_idx;

	uint32_t dma_bd_update;
	union {
		/* For TX ring*/
		struct lsinic_rc_rx_len_idx *local_src_len_idx;
		/* For RX ring*/
		struct lsinic_rc_tx_idx_cnf *local_src_free_idx;
	};
	struct lsinic_sw_bd *sw_ring;

	struct lsinic_sw_bd *(*recv_rxe)(struct lsinic_queue *rxq,
		uint16_t bd_idx);
	void (*recv_update)(struct lsinic_queue *rxq,
		uint16_t bd_idx);

	/* DMA */
	struct lsinic_dma_job *dma_jobs;
	uint16_t bd_dma_step;
	int wdma_bd_start;
	int wdma_bd_nb;

	uint32_t core_id;
	int16_t dma_id;
	int32_t dma_vq;
	uint64_t ob_base;
	uint8_t *ob_virt_base;

	/* MSI-X */
	uint32_t msix_irq;
	uint32_t msix_cmd;
	void *msix_vaddr;
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
	struct rte_dma_vchan_conf qdma_config;

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

	uint64_t bytes_dq;
	uint64_t bytes_eq;
	uint64_t pkts_dq;
	uint64_t pkts_eq;

	/* Pointer to Next instance used by q list */
	TAILQ_ENTRY(lsinic_queue) next;
};

#define LSINIC_ALIGN_DMA_CALC_OFFSET(addr)   ((addr) & (64 - 1))

#define  lsinic_rx_queue lsinic_queue
#define  lsinic_tx_queue lsinic_queue

#define LSINIC_SHARED_MBUF    (1ULL << 63)

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
	mem_cp128b_atomic((uint8_t *)&queue->rc_bd_desc[used_idx],
		(const uint8_t *)&queue->local_src_bd_desc[used_idx]);
}

static __rte_always_inline void
lsinic_ep_notify_to_rc(struct lsinic_queue *queue,
	uint16_t used_idx, int remote)
{
	struct lsinic_bd_desc *ep_bd_desc =
		&queue->local_src_bd_desc[used_idx];
	struct lsinic_rc_rx_len_idx *tx_len_idx =
		&queue->tx_len_idx[used_idx];
	struct lsinic_rc_rx_len_idx *local_len_idx =
		&queue->local_src_len_idx[used_idx];
	uint32_t *local_32 = (uint32_t *)local_len_idx;
	uint32_t *remote_32 = (uint32_t *)tx_len_idx;

	local_len_idx->total_len = ep_bd_desc->len_cmd & LSINIC_BD_LEN_MASK;
	local_len_idx->idx = lsinic_bd_ctx_idx(ep_bd_desc->bd_status);

	if (remote)
		*remote_32 = *local_32;
}

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
	uint16_t used_idx, const struct lsinic_bd_desc *bd)
{
	rte_memcpy(&queue->local_src_bd_desc[used_idx], bd,
		sizeof(struct lsinic_bd_desc));
	queue->local_src_bd_desc[used_idx].bd_status &=
		~((uint32_t)RING_BD_STATUS_MASK);
	queue->local_src_bd_desc[used_idx].bd_status |=
		RING_BD_ADDR_CHECK;
	queue->local_src_bd_desc[used_idx].bd_status |=
		RING_BD_HW_COMPLETE;
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
