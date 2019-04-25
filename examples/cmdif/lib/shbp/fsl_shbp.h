/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 * Copyright 2015 Freescale Semiconductor Inc.
 * Copyright 2018-2019 NXP
 */

#ifndef __FSL_SHBP_H__
#define __FSL_SHBP_H__

/**
 * @file
 *
 * Shared Buffer Pool (b/w GPP and AIOP) API's for GPP.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/** GPP is the allocation master */
#define SHBP_GPP_MASTER		0x1

/**
 * This is an internal DPAA2 SHBP structure, not required
 * to be known to the user.
 */
struct shbp;

/**
 * Calculator for 'mem_ptr' size for shbp_create(). num_bufs must
 * be 2^x and higher than 8.
 *
 * @param num_bufs
 *   Number of buffers which will be added into the
 *   SHBP pool. num_bufs must be 2^x and higher than 8.
 *
 * @returns
 *   - The 'mem_ptr' size required by shbp_create()
 *   - <0 in case of error
 */
uint64_t shbp_mem_ptr_size(uint32_t num_bufs);

/**
 * Get buffer from shared pool
 *
 * @param bp
 *   Buffer pool handle
 *
 * @returns
 *   - Address on Success
 *   - NULL for error
 */
void *shbp_acquire(struct shbp *bp);

/**
 * Return or add buffer into the shared pool
 *
 * @param bp
 *   Buffer pool handle
 * @param buf
 *   Pointer to buffer
 *
 * @returns
 *   - 0: Success.
 *   - <0: Error code.
 */
int shbp_release(struct shbp *bp, void *buf);

/**
 * Create shared pool from a given buffer
 *
 * The shared pool is created as empty, use shbp_release() to fill it
 *
 * @param mem_ptr
 *   Pointer to memory to be used for shared management;
 *   it should be aligned to cache line
 * @param size
 *   Size of mem_ptr
 * @param flags
 *   Flags to be used for pool creation, 0 means AIOP is the allocation master.
 *   See #SHBP_GPP_MASTER.
 * @param bp
 *   Pointer to shared pool handle. This is an out parameter.
 *
 * @returns
 *   - 0: Success.
 *   - <0: Error code.
 */
int shbp_create(void *mem_ptr,
		uint32_t size,
		uint32_t flags,
		struct shbp **bp);

/**
 * Move free buffers into allocation queue
 *
 * @param bp
 *   Buffer pool handle
 *
 * @returns
 *   - 0: number of the buffers added to the allocation queue.
 *   - <0: Error code.
 */
int shbp_refill(struct shbp *bp);


/**
 * Returns the pointers from pool that need to be freed upon pool destruction
 *
 * Pointer to struct shbp will not be returned by shbp_destroy() but it
 * must be freed by user
 *
 * @param bp
 *   Buffer pool handle
 * @param ptr
 *   Pointer to be freed for pool destruction
 *
 * @returns
 *   - 0: if there are no buffers to be freed.
 *   - <0: Error code until there are buffers inside shared pool
 *         that need to be freed.
 */
int shbp_destroy(struct shbp *bp, void **ptr);

#ifdef __cplusplus
}
#endif

#endif
