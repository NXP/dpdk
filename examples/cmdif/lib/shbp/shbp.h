/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 * Copyright 2015 Freescale Semiconductor Inc.
 * Copyright 2018-2019 NXP
 */

#ifndef __SHBP_H__
#define __SHBP_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <cmdif.h>

#ifndef MODULU_POWER_OF_TWO
#define MODULU_POWER_OF_TWO(NUM, MOD) \
	((uint32_t)(NUM) & ((uint32_t)(MOD) - 1))
#endif

/** Total bytes including the reserved bytes */
#define SHBP_TOTAL_BYTES \
	(sizeof(struct shbp) > 64 ? sizeof(struct shbp) : 64)

/** Number of BDs, must be power of 2 */
#define SHBP_SIZE(BP)		(0x1U << (BP)->max_num)

#define SHBP_ALLOC_IS_FULL(BP)	\
	(((BP)->alloc.enq - (BP)->alloc.deq) == SHBP_SIZE(BP))

#define SHBP_ALLOC_IS_EMPTY(BP)	\
	(((BP)->alloc.enq - (BP)->alloc.deq) == 0)

#define SHBP_FREE_IS_FULL(BP) \
	(((BP)->free.enq - (BP)->free.deq) == SHBP_SIZE(BP))

#define SHBP_FREE_IS_EMPTY(BP)	(((BP)->free.enq - (BP)->free.deq) == 0)

/** Number of bytes */
#define SHBP_SIZE_BYTES(BP)	(SHBP_SIZE(BP) << 3)

/** Always modulu power of 2 */
#define SHBP_BD_IND(SHBP, NUM)	(MODULU_POWER_OF_TWO(NUM, SHBP_SIZE((SHBP))))

/** Offset of the BD in BYTES - mod 2^x */
#define SHBP_BD_OFF(SHBP, NUM)	(SHBP_BD_IND(SHBP, NUM) << 3)

/** Member offset in bytes */
#define SHBP_MEM_OFF(SHBP, PTR) (uint32_t)((uint8_t *)(PTR) - (uint8_t *)(SHBP))

/**
 * Structure representing one ring
 */
struct shbp_q {
	/** Base address of the pool */
	uint64_t base;
	/** Number of released buffers */
	uint32_t enq;
	/** Number of acquired buffers */
	uint32_t deq;
};

/**
 * Structure representing shared buffer pool.
 * Must reside in non cacheable memory.
 */
struct shbp {
	/** Allocations queue */
	struct shbp_q alloc;
	/** Free queue */
	struct shbp_q free;
	/** Master of the allocation, must be 1 byte */
	uint8_t alloc_master;
	/** Max number of BDs in the pool is 2^max_buf, must be 1 byte */
	/* See also SHBP_TOTAL_BYTES */
	uint8_t max_num;
};

#ifdef __cplusplus
}
#endif

#endif /* _SHBP_H__ */
