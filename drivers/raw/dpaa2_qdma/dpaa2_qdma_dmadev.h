/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018-2023 NXP
 */

#ifndef _DPAA2_QDMA_DMADEV_H_
#define _DPAA2_QDMA_DMADEV_H_

#include <rte_pmd_dpaa2_qdma.h>
#include "dpaa2_qdma_common.h"

#define DPAA2_QDMA_MAX_DESC		4096
#define DPAA2_QDMA_MIN_DESC		1
#define DPAA2_QDMA_MAX_VHANS		64

#define DPAA2_QDMA_VQ_FD_SHORT_FORMAT		(1ULL << 0)
#define DPAA2_QDMA_VQ_FD_SG_FORMAT		(1ULL << 1)
#define DPAA2_QDMA_VQ_NO_RESPONSE		(1ULL << 2)

struct dpaa2_qdma_rbp {
	uint32_t use_ultrashort:1;
	uint32_t enable:1;
	/**
	 * dportid:
	 * 0000 PCI-Express 1
	 * 0001 PCI-Express 2
	 * 0010 PCI-Express 3
	 * 0011 PCI-Express 4
	 * 0100 PCI-Express 5
	 * 0101 PCI-Express 6
	 */
	uint32_t dportid:4;
	uint32_t dpfid:2;
	uint32_t dvfid:6;
	uint32_t dvfa:1;
	/*using route by port for destination */
	uint32_t drbp:1;
	/**
	 * sportid:
	 * 0000 PCI-Express 1
	 * 0001 PCI-Express 2
	 * 0010 PCI-Express 3
	 * 0011 PCI-Express 4
	 * 0100 PCI-Express 5
	 * 0101 PCI-Express 6
	 */
	uint32_t sportid:4;
	uint32_t spfid:2;
	uint32_t svfid:6;
	uint32_t svfa:1;
	/* using route by port for source */
	uint32_t srbp:1;
	uint32_t rsv:2;
};

struct qdma_cntx_fle_sdd {
	struct qbman_fle fle[DPAA2_QDMA_MAX_FLE];
	struct qdma_sdd sdd[DPAA2_QDMA_MAX_SDD];
} __rte_packed;

struct qdma_cntx_sg {
	struct qdma_cntx_fle_sdd fle_sdd;
	struct qdma_sg_entry sg_src_entry[RTE_DPAA2_QDMA_JOB_SUBMIT_MAX];
	struct qdma_sg_entry sg_dst_entry[RTE_DPAA2_QDMA_JOB_SUBMIT_MAX];
	uint16_t cntx_idx[RTE_DPAA2_QDMA_JOB_SUBMIT_MAX];
	uint16_t job_nb;
	uint16_t rsv[3];
} __rte_packed;

struct qdma_cntx_long {
	struct qdma_cntx_fle_sdd fle_sdd;
	uint16_t cntx_idx;
	uint16_t rsv[3];
} __rte_packed;

#define DPAA2_QDMA_IDXADDR_FROM_SG_FLAG(flag) \
	((void *)((flag) - ((flag) & RTE_DPAA2_QDMA_SG_IDX_ADDR_MASK)))

#define DPAA2_QDMA_IDX_FROM_FLAG(flag) \
	((flag) >> RTE_DPAA2_QDMA_COPY_IDX_OFFSET)

/** Represents a QDMA device. */
struct qdma_device {
	/** VQ's of this device */
	struct qdma_virt_queue *vqs;
	/** Total number of VQ's */
	uint16_t num_vqs;
	uint8_t is_silent;
};

/** Represents a DPDMAI raw device */
struct dpaa2_dpdmai_dev {
	/** Pointer to Next device instance */
	TAILQ_ENTRY(dpaa2_qdma_device) next;
	/** HW ID for DPDMAI object */
	uint32_t dpdmai_id;
	/** Tocken of this device */
	uint16_t token;
	/** Number of queue in this DPDMAI device */
	uint8_t num_queues;
	/** RX queues */
	struct dpaa2_queue rx_queue[DPAA2_DPDMAI_MAX_QUEUES];
	/** TX queues */
	struct dpaa2_queue tx_queue[DPAA2_DPDMAI_MAX_QUEUES];
	struct qdma_device *qdma_dev;
};

#define QDMA_CNTX_IDX_RING_EXTRA_SPACE 64
#define QDMA_CNTX_IDX_RING_MAX_FREE \
	(DPAA2_QDMA_MAX_DESC - QDMA_CNTX_IDX_RING_EXTRA_SPACE)
struct qdma_cntx_idx_ring {
	uint16_t cntx_idx_ring[DPAA2_QDMA_MAX_DESC];
	uint16_t start;
	uint16_t tail;
	uint16_t free_space;
	uint16_t nb_in_ring;
};

#define DPAA2_QDMA_DESC_DEBUG_FLAG (1 << 0)

/** Represents a QDMA virtual queue */
struct qdma_virt_queue {
	/** Associated hw queue */
	struct dpaa2_dpdmai_dev *dpdmai_dev;
	/** FLE pool for the queue */
	struct rte_mempool *fle_pool;
	uint64_t fle_iova2va_offset;
	void **fle_elem;
	/** Route by port */
	struct dpaa2_qdma_rbp rbp;
	/** States if this vq is in use or not */
	uint8_t fle_pre_populate;
	/** Number of descriptor for the virtual DMA channel */
	uint16_t nb_desc;
	/* Total number of enqueues on this VQ */
	uint64_t num_enqueues;
	/* Total number of dequeues from this VQ */
	uint64_t num_dequeues;

	uint16_t vq_id;
	uint32_t flags;
	struct qbman_fd fd[DPAA2_QDMA_MAX_DESC];
	uint16_t fd_idx;
	struct qdma_cntx_idx_ring *ring_cntx_idx;

	/**Used for silent enabled*/
	struct qdma_cntx_sg *cntx_sg[DPAA2_QDMA_MAX_DESC];
	struct qdma_cntx_long *cntx_long[DPAA2_QDMA_MAX_DESC];
	uint16_t slient_idx;

	int num_valid_jobs;

	struct rte_dma_stats stats;
};

#endif /* _DPAA2_QDMA_DMADEV_H_ */
