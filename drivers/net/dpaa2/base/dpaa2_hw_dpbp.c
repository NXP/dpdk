/*-
 *   BSD LICENSE
 *
 *   Copyright (c) 2016 Freescale Semiconductor, Inc. All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Freescale Semiconductor, Inc nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/vfs.h>
#include <libgen.h>
#include <rte_mbuf.h>

#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_string_fns.h>
#include <rte_cycles.h>
#include <rte_kvargs.h>
#include <rte_dev.h>
#include <rte_ethdev.h>

/* DPAA2 Global constants */
#include <dpaa2_hw_pvt.h>

#include "dpaa2_logs.h"
/* DPAA2 Base interface files */
#include <dpaa2_hw_dpbp.h>
#include <dpaa2_hw_dpni.h>
#include <dpaa2_hw_dpio.h>

static struct dpbp_node *g_dpbp_list;
static struct dpbp_node *avail_dpbp;

struct dpaa2_bp_info bpid_info[MAX_BPID];

struct dpaa2_bp_list *h_bp_list;

int
dpaa2_create_dpbp_device(
		int dpbp_id)
{
	struct dpbp_node *dpbp_node;
	int ret;

	/* Allocate DPAA2 dpbp handle */
	dpbp_node = (struct dpbp_node *)malloc(sizeof(struct dpbp_node));
	if (!dpbp_node) {
		PMD_DRV_LOG(ERR, "Memory allocation failed for DPBP Device");
		return -1;
	}

	/* Open the dpbp object */
	dpbp_node->dpbp.regs = mcp_ptr_list[MC_PORTAL_INDEX];
	ret = dpbp_open(&dpbp_node->dpbp,
		CMD_PRI_LOW, dpbp_id, &dpbp_node->token);
	if (ret) {
		PMD_DRV_LOG(ERR, "Resource alloc failure with err code: %d",
			    ret);
		free(dpbp_node);
		return -1;
	}

	/* Clean the device first */
	ret = dpbp_reset(&dpbp_node->dpbp, CMD_PRI_LOW, dpbp_node->token);
	if (ret) {
		PMD_DRV_LOG(ERR, "Failure cleaning dpbp device with"
			"error code %d\n", ret);
		return -1;
	}

	dpbp_node->dpbp_id = dpbp_id;
	/* Add the dpbp handle into the global list */
	dpbp_node->next = g_dpbp_list;
	g_dpbp_list = dpbp_node;
	avail_dpbp = g_dpbp_list;

	PMD_DRV_LOG(INFO, "Buffer resource initialized");

	return 0;
}

int hw_mbuf_create_pool(struct rte_mempool *mp)
{
	struct dpaa2_bp_list *bp_list;
	struct dpbp_attr dpbp_attr;
	uint32_t bpid;
	int ret;

	if (!avail_dpbp) {
		PMD_DRV_LOG(ERR, "DPAA2 resources not available");
		return -1;
	}

	ret = dpbp_enable(&avail_dpbp->dpbp, CMD_PRI_LOW, avail_dpbp->token);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Resource enable failure with"
			"err code: %d\n", ret);
		return -1;
	}

	ret = dpbp_get_attributes(&avail_dpbp->dpbp, CMD_PRI_LOW,
				  avail_dpbp->token, &dpbp_attr);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Resource read failure with"
			"err code: %d\n", ret);
		ret = dpbp_disable(&avail_dpbp->dpbp, CMD_PRI_LOW,
				   avail_dpbp->token);
		return -1;
	}

	/* Allocate the bp_list which will be added into global_bp_list */
	bp_list = (struct dpaa2_bp_list *)malloc(sizeof(struct dpaa2_bp_list));
	if (!bp_list) {
		PMD_DRV_LOG(ERR, "No heap memory available");
		return -1;
	}

	/* Set parameters of buffer pool list */
	bp_list->buf_pool.num_bufs = mp->size;
	bp_list->buf_pool.size = mp->elt_size
			- sizeof(struct rte_mbuf) - rte_pktmbuf_priv_size(mp);
	bp_list->buf_pool.bpid = dpbp_attr.bpid;
	bp_list->buf_pool.h_bpool_mem = NULL;
	bp_list->buf_pool.mp = mp;
	bp_list->buf_pool.dpbp_node = avail_dpbp;
	bp_list->next = h_bp_list;

	bpid = dpbp_attr.bpid;

	/* Increment the available DPBP */
	avail_dpbp = avail_dpbp->next;

	bpid_info[bpid].meta_data_size = sizeof(struct rte_mbuf)
				+ rte_pktmbuf_priv_size(mp);
	bpid_info[bpid].bp_list = bp_list;
	bpid_info[bpid].bpid = bpid;

	mp->pool_data = (void *)&bpid_info[bpid];

	PMD_DRV_LOG(DEBUG, "BP List created for bpid =%d", dpbp_attr.bpid);

	h_bp_list = bp_list;
	/* Identification for our offloaded pool_data structure
	 */
	mp->flags |= MEMPOOL_F_HW_PKT_POOL;
	return 0;
}

void hw_mbuf_free_pool(struct rte_mempool *mp __rte_unused)
{
	/* TODO:
	 * 1. Release bp_list memory allocation
	 * 2. opposite of dpbp_enable()
	 * <More>
	 */
	struct dpaa2_bp_list *bp;

	/* Iterate over h_bp_list linked list and release each element */
	while (h_bp_list) {
		bp = h_bp_list;
		h_bp_list = bp->next;

		/* TODO: Should be changed to rte_free */
		free(bp);
	}

	return;
}

static
void dpaa2_mbuf_release(struct rte_mempool *pool __rte_unused,
			    void * const *obj_table,
			    uint32_t bpid,
			    uint32_t meta_data_size,
			    int count)
{
	struct qbman_release_desc releasedesc;
	struct qbman_swp *swp;
	int ret;
	int i, n;
	uint64_t bufs[DPAA2_MBUF_MAX_ACQ_REL];

	swp = thread_io_info.dpio_dev->sw_portal;

	/* Create a release descriptor required for releasing
	 * buffers into BMAN */
	qbman_release_desc_clear(&releasedesc);
	qbman_release_desc_set_bpid(&releasedesc, bpid);

	n = count % DPAA2_MBUF_MAX_ACQ_REL;

	/* convert mbuf to buffers  for the remainder*/
	for (i = 0; i < n ; i++) {
#ifdef RTE_LIBRTE_DPAA2_USE_PHYS_IOVA
		bufs[i] = (uint64_t)rte_mempool_virt2phy(pool, obj_table[i])
				+ meta_data_size;
#else
		bufs[i] = (uint64_t)obj_table[i] + meta_data_size;
#endif
	}
	/* feed them to bman*/
	do {
		ret = qbman_swp_release(swp, &releasedesc, bufs, n);
	} while (ret == -EBUSY);

	/* if there are more buffers to free */
	while (n < count) {
		/* convert mbuf to buffers */
		for (i = 0; i < DPAA2_MBUF_MAX_ACQ_REL; i++) {
#ifdef RTE_LIBRTE_DPAA2_USE_PHYS_IOVA
			bufs[i] = (uint64_t)
				rte_mempool_virt2phy(pool, obj_table[n + i])
					+ meta_data_size;
#else
			bufs[i] = (uint64_t)obj_table[n + i] + meta_data_size;
#endif
		}

		do {
			ret = qbman_swp_release(swp, &releasedesc, bufs,
						DPAA2_MBUF_MAX_ACQ_REL);
			} while (ret == -EBUSY);
		n += DPAA2_MBUF_MAX_ACQ_REL;
	}
}

int hw_mbuf_alloc_bulk(struct rte_mempool *pool,
		       void **obj_table, unsigned count)
{
#ifdef RTE_LIBRTE_DPAA2_DEBUG_DRIVER
	static int alloc;
#endif
	struct qbman_swp *swp;
	uint32_t mbuf_size;
	uint16_t bpid;
	uint64_t bufs[7];
	int i, ret;
	unsigned n = 0;
	struct dpaa2_bp_info *bp_info;

	bp_info = mempool_to_bpinfo(pool);

	if (!(bp_info->bp_list)) {
		printf("\nDPAA2 buffer pool not configured\n");
		return -2;
	}

	bpid = bp_info->bpid;

	if (!thread_io_info.dpio_dev) {
		ret = dpaa2_affine_qbman_swp();
		if (ret != 0) {
			PMD_DRV_LOG(ERR, "Failed to allocate IO portal");
			return -1;
		}
	}
	swp = thread_io_info.dpio_dev->sw_portal;

	mbuf_size = sizeof(struct rte_mbuf) + rte_pktmbuf_priv_size(pool);

	while (n < count) {
		/* Acquire is all-or-nothing, so we drain in 7s,
		 * then the remainder.
		 */
		if ((count - n) > DPAA2_MBUF_MAX_ACQ_REL) {
			ret = qbman_swp_acquire(swp, bpid, bufs,
						DPAA2_MBUF_MAX_ACQ_REL);
		} else {
			ret = qbman_swp_acquire(swp, bpid, bufs,
						count - n);
		}
		/* In case of less than requested number of buffers available
		 * in pool, qbman_swp_acquire returns 0
		 */
		if (ret <= 0) {
			PMD_DRV_LOG(ERR, "Buffer acquire failed with"
				    "err code: %d", ret);
			/* The API expect the exact number of requested buffers */
			/* Releasing all buffers allocated */
			dpaa2_mbuf_release(pool, obj_table, bpid,
					   bp_info->meta_data_size, n);
			return -1;
		}
		/* assigning mbuf from the acquired objects */
		for (i = 0; (i < ret) && bufs[i]; i++) {
			/* TODO-errata - objerved that bufs may be null
			i.e. first buffer is valid, remaining 6 buffers may be null */
			DPAA2_MODIFY_IOVA_TO_VADDR(bufs[i], uint64_t);
			obj_table[n] = (struct rte_mbuf *)(bufs[i] - mbuf_size);
			rte_mbuf_refcnt_set((struct rte_mbuf *)obj_table[n], 0);
			PMD_DRV_LOG(DEBUG, "Acquired %p address %p from BMAN",
				    (void *)bufs[i], (void *)obj_table[n]);
			n++;
		}
	}

#ifdef RTE_LIBRTE_DPAA2_DEBUG_DRIVER
	alloc += n;
	PMD_DRV_LOG(DEBUG, "Total = %d , req = %d done = %d",
		    alloc, count, n);
#endif
	return 0;
}

int hw_mbuf_free_bulk(struct rte_mempool *pool, void * const *obj_table,
		      unsigned n)
{
	struct dpaa2_bp_info *bp_info;

	bp_info = mempool_to_bpinfo(pool);
	if (!(bp_info->bp_list)) {
		PMD_DRV_LOG(ERR, "DPAA2 buffer pool not configured");
		return -1;
	}
	dpaa2_mbuf_release(pool, obj_table, bp_info->bpid,
			   bp_info->meta_data_size, n);

	return 0;
}

unsigned hw_mbuf_get_count(const struct rte_mempool *mp __rte_unused)
{
	/* TODO: incomplete */
	return 0;
}

int hw_mbuf_supported(const struct rte_mempool *mp __rte_unused)
{
	if (!avail_dpbp) {
		PMD_DRV_LOG(WARNING, "DPAA2 mempool resources not available\n");
		return -1;
	}
	return 0;
}

struct rte_mempool_ops dpaa2_mpool_ops = {
	.name = "dpaa2",
	.alloc = hw_mbuf_create_pool,
	.free = hw_mbuf_free_pool,
	.enqueue = hw_mbuf_free_bulk,
	.dequeue = hw_mbuf_alloc_bulk,
	.get_count = hw_mbuf_get_count,
	.supported = hw_mbuf_supported,
};

MEMPOOL_REGISTER_OPS(dpaa2_mpool_ops);
