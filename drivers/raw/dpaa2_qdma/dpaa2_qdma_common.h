/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018-2023 NXP
 */

#ifndef __DPAA2_QDMA_COMMON_H__
#define __DPAA2_QDMA_COMMON_H__

#define DPAA2_DPDMAI_MAX_QUEUES	8

#define DPAA2_QDMA_FD_FLUSH_FORMAT 0x0
#define DPAA2_QDMA_FD_LONG_FORMAT 0x1
#define DPAA2_QDMA_FD_SHORT_FORMAT 0x3

#define DPAA2_QDMA_BMT_ENABLE 0x1
#define DPAA2_QDMA_BMT_DISABLE 0x0

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
#define QDMA_SG_BMT_ENABLE DPAA2_QDMA_BMT_ENABLE
#define QDMA_SG_BMT_DISABLE DPAA2_QDMA_BMT_DISABLE

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

enum dpaa2_qdma_fd_type {
	DPAA2_QDMA_FD_SHORT = 1,
	DPAA2_QDMA_FD_LONG = 2,
	DPAA2_QDMA_FD_SG = 3
};

#define DPAA2_QDMA_FD_ATT_TYPE_OFFSET 13
#define DPAA2_QDMA_FD_ATT_TYPE(att) \
	(att >> DPAA2_QDMA_FD_ATT_TYPE_OFFSET)
#define DPAA2_QDMA_FD_ATT_CNTX(att) \
	(att & ((1 << DPAA2_QDMA_FD_ATT_TYPE_OFFSET) - 1))

static inline void
dpaa2_qdma_fd_set_addr(struct qbman_fd *fd,
	uint64_t addr)
{
	fd->simple_ddr.saddr_lo = lower_32_bits(addr);
	fd->simple_ddr.saddr_hi = upper_32_bits(addr);
}

static inline void
dpaa2_qdma_fd_save_att(struct qbman_fd *fd,
	uint16_t job_idx, enum dpaa2_qdma_fd_type type)
{
	fd->simple_ddr.rsv1_att = job_idx |
		(type << DPAA2_QDMA_FD_ATT_TYPE_OFFSET);
}

static inline uint16_t
dpaa2_qdma_fd_get_att(const struct qbman_fd *fd)
{
	return fd->simple_ddr.rsv1_att;
}

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

int
dpaa2_qdma_dmadev_probe(struct rte_dpaa2_driver *dpaa2_drv,
	struct rte_dpaa2_device *dpaa2_dev);
int
dpaa2_qdma_dmadev_remove(struct rte_dpaa2_device *dpaa2_dev);

#endif /* __DPAA2_QDMA_COMMON_H__ */
