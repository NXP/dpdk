/*-
 *   BSD LICENSE
 *
 *   Copyright (c) 2016 Freescale Semiconductor, Inc. All rights reserved.
 *   Copyright (c) 2016 NXP. All rights reserved.
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

#ifndef _DPAA2_HW_DPBP_H_
#define _DPAA2_HW_DPBP_H_

#define DPAA2_MAX_BUF_POOLS	8

struct buf_pool_cfg {
	void *addr; /*!< The address from where DPAA2 will carve out the
		     * buffers. 'addr' should be 'NULL' if user wants
		     * to create buffers from the memory which user
		     * asked DPAA2 to reserve during 'nadk init'
		     */
	phys_addr_t    phys_addr;  /*!< corresponding physical address
				    * of the memory provided in addr
				    */
	uint32_t num; /*!< number of buffers */
	uint32_t size; /*!< size of each buffer. 'size' should include
			* any headroom to be reserved and alignment
			*/
	uint16_t align; /*!< Buffer alignment (in bytes) */
	uint16_t bpid; /*!< The buffer pool id. This will be filled
			*in by DPAA2 for each buffer pool
			*/
};

struct buf_pool {
	uint32_t size;
	uint32_t num_bufs;
	uint16_t bpid;
	uint8_t *h_bpool_mem;
	struct rte_mempool *mp;
	struct dpaa2_dpbp_dev *dpbp_node;
};

/*!
 * Buffer pool list configuration structure. User need to give DPAA2 the
 * valid number of 'num_buf_pools'.
 */
struct dpaa2_bp_list_cfg {
	struct buf_pool_cfg buf_pool; /* Configuration of each buffer pool*/
};

struct dpaa2_bp_list {
	struct dpaa2_bp_list *next;
	struct rte_mempool *mp;
	struct buf_pool buf_pool;
};

struct dpaa2_bp_info {
	uint32_t meta_data_size;
	uint32_t bpid;
	struct dpaa2_bp_list *bp_list;
};

#define mempool_to_bpinfo(mp) ((struct dpaa2_bp_info *)(mp)->pool_data)
#define mempool_to_bpid(mp) ((mempool_to_bpinfo(mp))->bpid)

extern struct dpaa2_bp_info rte_dpaa2_bpid_info[MAX_BPID];

int rte_dpaa2_mbuf_alloc_bulk(struct rte_mempool *pool,
		       void **obj_table, unsigned int count);

#endif /* _DPAA2_HW_DPBP_H_ */
