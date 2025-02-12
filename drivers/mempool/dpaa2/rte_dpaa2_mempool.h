/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018 NXP
 */

#ifndef __RTE_DPAA2_MEMPOOL_H__
#define __RTE_DPAA2_MEMPOOL_H__

/**
 * @file
 *
 * NXP specific mempool related functions.
 *
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_compat.h>
#include <rte_mempool.h>

struct dpaa2_dpbp_cfg {
	uint32_t depletion_entry;
	uint32_t depletion_exit;
	uint32_t surplus_entry;
	uint32_t surplus_exit;
	uint64_t message_iova;
	uint64_t message_ctx;
	uint32_t options;
};

/**
 * Get BPID corresponding to the packet pool
 *
 * @param mp
 *   memory pool
 *
 * @return
 *   BPID of the buffer pool
 */
uint16_t
rte_dpaa2_mbuf_pool_bpid(struct rte_mempool *mp);

/**
 * Get MBUF from the corresponding 'buf_addr'
 *
 * @param mp
 *   memory pool
 * @param buf_addr
 *   The 'buf_addr' of the mbuf. This is the start buffer address
 *   of the packet buffer (mbuf).
 *
 * @return
 *   - MBUF pointer for success
 *   - NULL in case of error
 */
struct rte_mbuf *
rte_dpaa2_mbuf_from_buf_addr(struct rte_mempool *mp, void *buf_addr);

/**
 * Initialize the rte_dpaa2_bpid_info
 * In generial, it is called in the secondary process and
 * mp has been created in the primary process.
 *
 * @param mp
 *   memory pool
 *
 * @return
 *  - 0 on success.
 *  - (<0) on failure.
 */
__rte_internal
int rte_dpaa2_bpid_info_init(struct rte_mempool *mp);

int rte_dpaa2_dpbp_set_notifications(struct rte_mempool *mp, struct dpaa2_dpbp_cfg *dpbp_cfg);

#ifdef __cplusplus
}
#endif

#endif /* __RTE_DPAA2_MEMPOOL_H__ */
