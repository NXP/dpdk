/*-
 *   BSD LICENSE
 *
 *   Copyright (c) 2014 Freescale Semiconductor, Inc. All rights reserved.
 *   All rights reserved.
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
 *     * Neither the name of Freescale Semiconductor nor the names of its
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

#include "rte_pci.h"
#include "rte_memzone.h"

#include "rte_eth_dpaa2_pvt.h"
#include "fsl_qbman_portal.h"
#include <fsl_dpbp.h>

#include <rte_log.h>
#include "dpaa2_logs.h"

static struct dpbp_node *g_dpbp_list;
static struct dpbp_node *avail_dpbp;

struct bp_info bpid_info[MAX_BPID];

struct dpaa2_bp_list *h_bp_list;

static inline void dpaa2_mbuf_release(uint64_t buf, uint32_t bpid);

int
dpaa2_create_dpbp_device(
		int dpbp_id)
{
	struct dpbp_node *dpbp_node;
	int ret;

	/* Allocate DPAA2 dpbp handle */
	dpbp_node = (struct dpbp_node *)malloc(sizeof(struct dpbp_node));
	if (!dpbp_node) {
		PMD_DRV_LOG(ERR, "Memory allocation failed for DPBP Device\n");
		return -1;
	}

	/* Open the dpbp object */
	dpbp_node->dpbp.regs = mcp_ptr_list[MC_PORTAL_INDEX];
	ret = dpbp_open(&dpbp_node->dpbp, CMD_PRI_LOW, dpbp_id, &dpbp_node->token);
	if (ret) {
		PMD_DRV_LOG(ERR, "Resource allocation failure with err code: %d",
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

	PMD_DRV_LOG(INFO, "Buffer resource initialized\n");

	return 0;
}

int hw_mbuf_create_pool(struct rte_mempool *mp)
{
	struct dpaa2_bp_list *bp_list;
	struct dpbp_attr dpbp_attr;
	int ret;
	int mbuf_alignsize, mdata_alignsize;

	if (!avail_dpbp) {
		PMD_DRV_LOG(ERR, "DPAA2 resources not available\n");
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
		PMD_DRV_LOG(ERR, "No heap memory available\n");
		return -1;
	}

	/*
	* +-------+---------+-----------+-------------+----------+---------\
	* | SW-An | HW-An |/| rte_mbuf  | priv_size |/| HEADROOM | Data... /
	* |       |       |\|           |           |\|          |         \
	* +-------+-------|-+-----------+-----------|-+----------+---------/
	*                 \  \                      \  \
	*                Pad |                     Pad |
	*                  mbuf_alignsize             mdata_alignsize
	*/

	/* Aligning the rte_mbuf from Annotation area */
	/* TODO: Needs revisit. This assumes 256KB alignment of Annotation
	 * area. Converting to 64 raises issue in port initialization
	 */
	mbuf_alignsize = DPAA2_ALIGN_ROUNDUP(DPAA2_HW_BUF_RESERVE,
				DPAA2_PACKET_LAYOUT_ALIGN);

	/* Aligning the meta-data size until data start */
	mdata_alignsize = DPAA2_ALIGN_ROUNDUP((mbuf_alignsize
				+ sizeof(struct rte_mbuf)
				+ rte_pktmbuf_priv_size(mp)
				+ RTE_PKTMBUF_HEADROOM),
				DPAA2_PACKET_LAYOUT_ALIGN);

	/* Set parameters of buffer pool list */
	bp_list->buf_pool.num_bufs = mp->size;
	bp_list->buf_pool.size = mp->elt_size - mdata_alignsize;
	bp_list->buf_pool.bpid = dpbp_attr.bpid;
	bp_list->buf_pool.h_bpool_mem = NULL;
	bp_list->buf_pool.mp = mp;
	bp_list->buf_pool.dpbp_node = avail_dpbp;
	bp_list->next = h_bp_list;

	/* Increment the available DPBP */
	avail_dpbp = avail_dpbp->next;

	/* meta_data_size is area from start of buffer until start of
	*  rte_mbuf
	*/
	bpid_info[dpbp_attr.bpid].meta_data_size = mbuf_alignsize;
	bpid_info[dpbp_attr.bpid].bp_list = bp_list;
	bpid_info[dpbp_attr.bpid].bpid = dpbp_attr.bpid;

	mp->hw_pool_priv = (void *)&bpid_info[dpbp_attr.bpid];

	PMD_DRV_LOG(INFO, "BP List created for bpid =%d\n", dpbp_attr.bpid);

	h_bp_list = bp_list;
	return 0;
}

int hw_mbuf_alloc_bulk(struct rte_mempool *pool,
			 void **obj_table, unsigned count)
{
#ifdef RTE_LIBRTE_DPAA2_DEBUG_DRIVER
	static int alloc;
#endif
	struct qbman_swp *swp;
	uint16_t bpid;
	uint64_t bufs[64];
	int ret;
	unsigned i, n = 0;
	struct rte_mbuf **mt = (struct rte_mbuf **)obj_table;
	struct bp_info *bp_info;

	PMD_DRV_LOG(DEBUG, "%s/n", __func__);
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

	/* if number of buffers requested is less than 7 */
	if (count < DPAA2_MBUF_MAX_ACQ_REL) {
		ret = qbman_swp_acquire(swp, bpid, &bufs[n], count);
		if (ret <= 0) {
			PMD_DRV_LOG(ERR, "Failed to allocate buffers %d", ret);
			return -1;
		}
		n = ret;
		goto set_buf;
	}

	while (n < count) {
		ret = 0;
		/* Acquire is all-or-nothing, so we drain in 7s,
		 * then the remainder.
		 */
		if ((count - n) > DPAA2_MBUF_MAX_ACQ_REL) {
			ret = qbman_swp_acquire(swp, bpid, &bufs[n],
						DPAA2_MBUF_MAX_ACQ_REL);
			if (ret == DPAA2_MBUF_MAX_ACQ_REL) {
				n += ret;
			}
		} else {
			ret = qbman_swp_acquire(swp, bpid, &bufs[n], count - n);
			if (ret > 0) {
				PMD_DRV_LOG(DEBUG, "Drained buffer: %x",
					bufs[n]);
				n += ret;
			}
		}
		if (ret < 0) {
			PMD_DRV_LOG(WARNING, "Buffer aquire failed with"
				"err code: %d", ret);
			break;
		}
	}

	/* This function either returns expected buffers or error */
	if (count != n) {
		i = 0;
		/* Releasing all buffers allocated */
		while (i < n) {
			dpaa2_mbuf_release(bufs[i], bpid);
			i++;
		}
		return -1;
	}

	if (ret < 0 || n == 0) {
		PMD_DRV_LOG(ERR, "Failed to allocate buffers %d", ret);
		return -1;
	}

set_buf:
	for (i = 0; i < n; i++ ) {
		/* Cannot handle a situation where bufs[i] is NULL */
		RTE_MBUF_ASSERT(bufs[i]);

		DPAA2_MODIFY_IOVA_TO_VADDR(bufs[i], uint64_t);
		mt[i] = (struct rte_mbuf *)(bufs[i] + bp_info->meta_data_size);
		PMD_DRV_LOG(DEBUG, "Acquired %p address %p from BMAN\n",
			(void *)bufs[i], (void *)mt[i]);
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
	unsigned i;
	struct rte_mbuf *m;
	uint64_t buf;
	struct qbman_release_desc releasedesc;
	struct qbman_swp *swp;
	int ret;
	struct bp_info *bp_info;

	PMD_DRV_LOG(DEBUG, "%s/n", __func__);

	bp_info = mempool_to_bpinfo(pool);
	if (!(bp_info->bp_list)) {
		PMD_DRV_LOG(INFO, "DPAA2 buffer pool not configured\n");
		return -1;
	}

	if (!thread_io_info.dpio_dev) {
		ret = dpaa2_affine_qbman_swp();
		if (ret != 0) {
			PMD_DRV_LOG(ERR, "Failed to allocate IO portal");
			return ret;
		}
	}
	swp = thread_io_info.dpio_dev->sw_portal;

	/* Create a release descriptor required for releasing
	 * buffers into BMAN */
	qbman_release_desc_clear(&releasedesc);
	qbman_release_desc_set_bpid(&releasedesc, bp_info->bpid);

	/*todo - optimize it*/
	for (i = 0; i < n; i++) {
		m = (struct rte_mbuf *)(obj_table[i]);
		buf = (uint64_t)DPAA2_BUF_FROM_INLINE_MBUF(m,
					bp_info->meta_data_size);
		DPAA2_MODIFY_VADDR_TO_IOVA(buf, uint64_t);
		do {
			/* Release buffer into the BMAN */
			ret = qbman_swp_release(swp, &releasedesc, &buf, 1);
		} while (ret == -EBUSY);
		PMD_TX_FREE_LOG(DEBUG, "Released %p address to BMAN\n", buf);
	}

	return 0;
}

static inline void dpaa2_mbuf_release(uint64_t buf, uint32_t bpid)
{
	struct qbman_release_desc releasedesc;
	struct qbman_swp *swp;
	int ret;

	if (!thread_io_info.dpio_dev) {
		ret = dpaa2_affine_qbman_swp();
		if (ret != 0) {
			PMD_DRV_LOG(ERR, "Failed to allocate IO portal");
			return;
		}
	}
	swp = thread_io_info.dpio_dev->sw_portal;

	/* Create a release descriptor required for releasing
	 * buffers into BMAN */
	qbman_release_desc_clear(&releasedesc);
	qbman_release_desc_set_bpid(&releasedesc, bpid);

	DPAA2_MODIFY_VADDR_TO_IOVA(buf, uint64_t);
	do {
		/* Release buffer into the BMAN */
		ret = qbman_swp_release(swp, &releasedesc, &buf, 1);
	} while (ret == -EBUSY);
	PMD_TX_FREE_LOG(DEBUG, "Released %p address to BMAN\n", buf);
}

/* hw generated buffer layout:
 *
 *[SW_PTA][HW_ANNOT][cache_ALIGN]   [struct rte_mbuf][priv_size][HEADROOM][DATA]
 */
int hw_mbuf_init(
		struct rte_mempool *mp,
		void *_m)
{
	struct rte_mbuf *m;
	uint32_t mbuf_size, buf_len, priv_size;
	struct bp_info *bp_info;

	bp_info = mempool_to_bpinfo(mp);

	if (!bp_info->bp_list) {
		PMD_DRV_LOG(WARNING, "DPAA2 buffer pool not configured\n");
		return -1;
	}
	/*todo - assuming that h_bp_list will be at top node*/

	priv_size = rte_pktmbuf_priv_size(mp);
	mbuf_size = sizeof(struct rte_mbuf) + priv_size;

	RTE_MBUF_ASSERT(RTE_ALIGN(priv_size, RTE_MBUF_PRIV_ALIGN) == priv_size);
	RTE_MBUF_ASSERT(mp->elt_size >= mbuf_size);

	memset(_m, 0, mp->elt_size);

	buf_len = rte_pktmbuf_data_room_size(mp)
			- bp_info->meta_data_size;

	RTE_MBUF_ASSERT(buf_len <= UINT16_MAX);

	m = (struct rte_mbuf *)
		((unsigned char *)_m + bp_info->meta_data_size);

	/* start of buffer is after mbuf structure and priv data */
	m->priv_size = priv_size;
	m->buf_addr = (char *)_m + mbuf_size + bp_info->meta_data_size;
	m->buf_physaddr = rte_mempool_virt2phy(mp, _m)
		+ bp_info->meta_data_size + mbuf_size;
	m->buf_len = (uint16_t)buf_len;

	/* keep some headroom between start of buffer and data */
	m->data_off = RTE_MIN(RTE_PKTMBUF_HEADROOM, (uint16_t)m->buf_len);

	/* init some constant fields */
	m->pool = mp;
	m->nb_segs = 1;
	m->port = 0xff;

	PMD_DRV_LOG(DEBUG2,"buf =%p, meta = %d, bpid = %d"
		"mbuf =%p, buf_addr =%p, data_off = %d, buf_len=%d, elt_sz=%d ",
		_m,  bp_info->meta_data_size,
		bp_info->bpid, m, m->buf_addr, m->data_off,
		m->buf_len, mp->elt_size);

	/* Release the mempool buffer to BMAN */
	dpaa2_mbuf_release((uint64_t)_m, bp_info->bpid);
	return 0;
}

