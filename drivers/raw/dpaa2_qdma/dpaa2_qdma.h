/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018-2023 NXP
 */

#ifndef __DPAA2_QDMA_H__
#define __DPAA2_QDMA_H__

#include <rte_pmd_dpaa2_qdma.h>
#include "dpaa2_qdma_common.h"

#define FLE_SG_JOB_GET_NB(val) \
	((uint32_t)(val >> 32))

#define FLE_SG_JOB_GET_SIZE(val) \
	((uint32_t)(val & 0xffffffff))

#define FLE_SG_JOB_SET_NB(val, nb) \
	(val |= ((uint64_t)nb) << 32)

#define FLE_SG_JOB_SET_SIZE(val, size) \
	(val |= size)

struct qdma_fle_elem {
	union {
		uint64_t sg_job_nb_len;
		struct rte_qdma_job *single_job;
	};
	struct qbman_fle fle[DPAA2_QDMA_MAX_FLE];
	struct qdma_sdd sdd[DPAA2_QDMA_MAX_SDD];
} __attribute__((__packed__));

#define DPAA2_QDMA_MAX_SG_NB RTE_QDMA_SG_ENTRY_NB_MAX

struct qdma_fle_sg_elem {
	struct qdma_fle_elem fle_elem;
	struct qdma_sg_entry sg_src_entry[DPAA2_QDMA_MAX_SG_NB];
	struct qdma_sg_entry sg_dst_entry[DPAA2_QDMA_MAX_SG_NB];
	struct rte_qdma_job *sg_jobs[DPAA2_QDMA_MAX_SG_NB];
} __attribute__((__packed__));

/** FLE pool cache size */
#define QDMA_FLE_CACHE_SIZE(_num) (_num/(RTE_MAX_LCORE * 2))

/** Maximum possible H/W Queues on each core */
#define MAX_HW_QUEUE_PER_CORE		64

#define QDMA_PCIE_BASE_ADDRESS_MASK (0xfff8000000000)
/**
 * Represents a QDMA device.
 * A single QDMA device exists which is combination of multiple DPDMAI rawdev's.
 */
struct qdma_device {
	/** total number of hw queues. */
	uint16_t num_hw_queues;

	/** VQ's of this device */
	struct qdma_virt_queue *vqs;
	/** Maximum number of VQ's */
	uint16_t max_vqs;
	/** Device state - started or stopped */
	uint8_t state;
	/** A lock to QDMA device whenever required */
	rte_spinlock_t lock;
};

/** Represents a QDMA H/W queue */
struct qdma_hw_queue {
	/** Pointer to Next instance */
	TAILQ_ENTRY(qdma_hw_queue) next;
	/** DPDMAI device to communicate with HW */
	struct dpaa2_dpdmai_dev *dpdmai_dev;
	/** queue ID to communicate with HW */
	uint16_t queue_id;
	/** Associated lcore id */
	uint32_t lcore_id;
	/** Number of users of this hw queue */
	uint32_t num_users;
};

/** Represents a QDMA virtual queue */
struct qdma_virt_queue {
	/** Associated hw queue */
	struct qdma_hw_queue *hw_queue;
	/** FLE pool for the queue */
	struct rte_mempool *fle_pool;
	/** For simple fd */
	void **simple_job_pool;
	uint64_t fle_iova2va_offset;
	/** Route by port */
	struct rte_qdma_rbp rbp;
	/** Associated lcore id */
	uint32_t lcore_id;
	uint32_t queue_size;
	/** States if this vq is in use or not */
	uint8_t in_use;
	uint8_t fle_pre_populate;
	/* Total number of enqueues on this VQ */
	uint64_t num_enqueues;
	/* Total number of dequeues from this VQ */
	uint64_t num_dequeues;

	/* Total size in DMA by this VQ */
	uint64_t bytes_in_dma;

	uint16_t vq_id;
	uint32_t flags;

	void **fle_elems;

	int (*set_fd)(struct qdma_virt_queue *qdma_vq,
		struct qbman_fd *fd,
		struct rte_qdma_job **job,
		uint16_t nb_jobs, uint16_t *nb_set);

	uint32_t (*get_job)(struct qdma_virt_queue *qdma_vq,
		const struct qbman_fd *fd,
		struct rte_qdma_job **job,
		uint16_t *nb_jobs, uint16_t *vq_id);

	int (*dequeue_job)(struct qdma_virt_queue *qdma_vq,
		uint16_t *vq_id, struct rte_qdma_job **job,
		uint16_t nb_jobs);

	int (*enqueue_job)(struct qdma_virt_queue *qdma_vq,
		struct rte_qdma_job **job,
		uint16_t nb_jobs);
};

/** Represents a QDMA per core hw queues allocation in virtual mode */
struct qdma_per_core_info {
	/** list for allocated hw queues */
	struct qdma_hw_queue *hw_queues[MAX_HW_QUEUE_PER_CORE];
	/* Number of hw queues allocated for this core */
	uint16_t num_hw_queues;
};

/** Represents a DPDMAI raw device */
struct dpaa2_dpdmai_dev {
	/** Pointer to Next device instance */
	TAILQ_ENTRY(dpaa2_qdma_device) next;
	/** handle to DPDMAI object */
	struct fsl_mc_io dpdmai;
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

#endif /* __DPAA2_QDMA_H__ */
