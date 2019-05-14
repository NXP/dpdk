/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2016 Intel Corporation.
 * Copyright(c) 2016 6WIND S.A.
 * Copyright(c) 2018 Solarflare Communications Inc.
 * Copyright 2019 NXP
 */

#include <rte_mempool.h>

ssize_t
rte_mempool_op_calc_mem_size_default(const struct rte_mempool *mp,
				     uint32_t obj_num, uint32_t pg_shift,
				     size_t *min_chunk_size, size_t *align)
{
	size_t total_elt_sz;
	size_t obj_per_page, pg_num, pg_sz;
	size_t mem_size;

#ifdef RTE_LIBRTE_DPAA_ERRATA_LS1043_A010022
	/* Reserve more memory as we need to align buffers to 4K boundary.
	 * This change does not change the number of objects allocated.
	 */
	if (mp->flags & MEMPOOL_F_1043_MBUF)
		obj_num += LS1043_MAX_MEMZONES;
#endif

	total_elt_sz = mp->header_size + mp->elt_size + mp->trailer_size;
	if (total_elt_sz == 0) {
		mem_size = 0;
	} else if (pg_shift == 0) {
		mem_size = total_elt_sz * obj_num;
	} else {
		pg_sz = (size_t)1 << pg_shift;
		obj_per_page = pg_sz / total_elt_sz;
		if (obj_per_page == 0) {
			/*
			 * Note that if object size is bigger than page size,
			 * then it is assumed that pages are grouped in subsets
			 * of physically continuous pages big enough to store
			 * at least one object.
			 */
			mem_size =
				RTE_ALIGN_CEIL(total_elt_sz, pg_sz) * obj_num;
		} else {
			pg_num = (obj_num + obj_per_page - 1) / obj_per_page;
			mem_size = pg_num << pg_shift;
		}
	}

	*min_chunk_size = RTE_MAX((size_t)1 << pg_shift, total_elt_sz);

	*align = RTE_MAX((size_t)RTE_CACHE_LINE_SIZE, (size_t)1 << pg_shift);

	return mem_size;
}

int
rte_mempool_op_populate_default(struct rte_mempool *mp, unsigned int max_objs,
		void *vaddr, rte_iova_t iova, size_t len,
		rte_mempool_populate_obj_cb_t *obj_cb, void *obj_cb_arg)
{
	size_t total_elt_sz;
	size_t off;
	unsigned int i;
	void *obj;
#ifdef RTE_LIBRTE_DPAA_ERRATA_LS1043_A010022
	int idx = 0, change = LS1043_OFFSET_CHANGE_IDX;
#endif

	total_elt_sz = mp->header_size + mp->elt_size + mp->trailer_size;

	for (off = 0, i = 0; off + total_elt_sz <= len && i < max_objs; i++) {
#ifdef RTE_LIBRTE_DPAA_ERRATA_LS1043_A010022
	/* Due to A010022 hardware errata on LS1043, buf size is kept 4K
	 * (including metadata). This size is completely divisible by our L1
	 * cache size (32K) which leads to cache collisions of buffer metadata
	 * (mbuf) and performance drop. To minimize these cache collisions,
	 * offset of buffer is changed after an interval of 8 and value is
	 * reversed after 64 buffer.
	 */
		if (mp->flags & MEMPOOL_F_1043_MBUF) {
			if (off == 0)
				off = ((uintptr_t)vaddr % total_elt_sz) ?
					total_elt_sz - ((uintptr_t)vaddr %
					total_elt_sz) : 0;

			if (idx == LS1043_OFFSET_CHANGE_IDX) {
				change = -change;
				idx = 0;
			}
			if (idx % LS1043_MAX_BUF_IN_CACHE == 0)
				off += change;
			idx++;
		}
#endif
		off += mp->header_size;
		obj = (char *)vaddr + off;
		obj_cb(mp, obj_cb_arg, obj,
		       (iova == RTE_BAD_IOVA) ? RTE_BAD_IOVA : (iova + off));
		rte_mempool_ops_enqueue_bulk(mp, &obj, 1);
		off += mp->elt_size + mp->trailer_size;
	}

	return i;
}
