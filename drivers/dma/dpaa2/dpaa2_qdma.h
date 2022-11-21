/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018-2022 NXP
 */

#ifndef _DPAA2_QDMA_H_
#define _DPAA2_QDMA_H_

#define DPAA2_QDMA_MAX_DESC		4096
#define DPAA2_QDMA_MIN_DESC		1
#define DPAA2_QDMA_MAX_VHANS		64

#define DPAA2_QDMA_VQ_FD_SHORT_FORMAT		(1ULL << 0)
#define DPAA2_QDMA_VQ_FD_SG_FORMAT		(1ULL << 1)
#define DPAA2_QDMA_VQ_NO_RESPONSE		(1ULL << 2)

#define DPAA2_DPDMAI_MAX_QUEUES	16

#define QDMA_JOB_HW_CNTX_IDX (RTE_DPAA2_QDMA_JOB_USR_CNTX_IDX + 1)

/** FLE pool cache size */
#define QDMA_FLE_CACHE_SIZE(_num) (_num/(RTE_MAX_LCORE * 2))

/** Notification by FQD_CTX[fqid] */
#define QDMA_SER_CTX (1 << 8)
#define DPAA2_RBP_MEM_RW            0x0
/**
 * Source descriptor command read transaction type for RBP=0:
 * coherent copy of cacheable memory
 */
#define DPAA2_COHERENT_NO_ALLOCATE_CACHE	0xb
#define DPAA2_LX2_COHERENT_NO_ALLOCATE_CACHE	0x7
/**
 * Destination descriptor command write transaction type for RBP=0:
 * coherent copy of cacheable memory
 */
#define DPAA2_COHERENT_ALLOCATE_CACHE		0x6
#define DPAA2_LX2_COHERENT_ALLOCATE_CACHE	0xb

/** Maximum possible H/W Queues on each core */
#define MAX_HW_QUEUE_PER_CORE		64

#define QDMA_RBP_UPPER_ADDRESS_MASK (0xfff0000000000)

/** Source/Destination Descriptor */
struct qdma_sdd {
	uint32_t rsv;
	/** Stride configuration */
	uint32_t stride;
	/** Route-by-port command */
	union {
		uint32_t rbpcmd;
		struct rbpcmd_st {
			uint32_t vfid:6;
			uint32_t rsv4:2;
			uint32_t pfid:1;
			uint32_t rsv3:7;
			uint32_t attr:3;
			uint32_t rsv2:1;
			uint32_t at:2;
			uint32_t vfa:1;
			uint32_t ca:1;
			uint32_t tc:3;
			uint32_t rsv1:5;
		} rbpcmd_simple;
	};
	union {
		uint32_t cmd;
		struct rcmd_simple {
			uint32_t portid:4;
			uint32_t rsv1:14;
			uint32_t rbp:1;
			uint32_t ssen:1;
			uint32_t rthrotl:4;
			uint32_t sqos:3;
			uint32_t ns:1;
			uint32_t rdtype:4;
		} read_cmd;
		struct wcmd_simple {
			uint32_t portid:4;
			uint32_t rsv3:10;
			uint32_t rsv2:2;
			uint32_t lwc:2;
			uint32_t rbp:1;
			uint32_t dsen:1;
			uint32_t rsv1:4;
			uint32_t dqos:3;
			uint32_t ns:1;
			uint32_t wrttype:4;
		} write_cmd;
	};
} __rte_packed;

#define QDMA_SG_FMT_SDB	0x0 /* single data buffer */
#define QDMA_SG_FMT_FDS	0x1 /* frame data section */
#define QDMA_SG_FMT_SGTE	0x2 /* SGT extension */
#define QDMA_SG_SL_SHORT	0x1 /* short length */
#define QDMA_SG_SL_LONG	0x0 /* long length */
#define QDMA_SG_F	0x1 /* last sg entry */
#define QDMA_SG_BMT_ENABLE 0x1
#define QDMA_SG_BMT_DISABLE 0x0

struct qdma_sg_entry {
	uint32_t addr_lo;		/* address 0:31 */
	uint32_t addr_hi:17;	/* address 32:48 */
	uint32_t rsv:15;
	union {
		uint32_t data_len_sl0;	/* SL=0, the long format */
		struct {
			uint32_t len:17;	/* SL=1, the short format */
			uint32_t reserve:3;
			uint32_t sf:1;
			uint32_t sr:1;
			uint32_t size:10;	/* buff size */
		} data_len_sl1;
	} data_len;					/* AVAIL_LENGTH */
	union {
		uint32_t ctrl_fields;
		struct {
			uint32_t bpid:14;
			uint32_t ivp:1;
			uint32_t bmt:1;
			uint32_t offset:12;
			uint32_t fmt:2;
			uint32_t sl:1;
			uint32_t f:1;
		} ctrl;
	};
} __rte_packed;

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

enum {
	DPAA2_QDMA_SDD_FLE,
	DPAA2_QDMA_SRC_FLE,
	DPAA2_QDMA_DST_FLE,
	DPAA2_QDMA_MAX_FLE
};

enum {
	DPAA2_QDMA_SRC_SDD,
	DPAA2_QDMA_DST_SDD,
	DPAA2_QDMA_MAX_SDD
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

	int num_valid_jobs;

	struct rte_dma_stats stats;
};

/** Represents a QDMA device. */
struct qdma_device {
	/** VQ's of this device */
	struct qdma_virt_queue *vqs;
	/** Total number of VQ's */
	uint16_t num_vqs;
	/** Device state - started or stopped */
	uint8_t state;
	uint8_t is_silent;
};

#endif /* _DPAA2_QDMA_H_ */
