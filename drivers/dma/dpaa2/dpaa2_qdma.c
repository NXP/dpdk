/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018-2022 NXP
 */

#include <string.h>

#include <rte_eal.h>
#include <rte_fslmc.h>
#include <rte_atomic.h>
#include <rte_lcore.h>
#include <rte_dmadev.h>
#include <rte_dmadev_pmd.h>
#include <rte_malloc.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_prefetch.h>
#include <rte_kvargs.h>

#include <mc/fsl_dpdmai.h>
#include <portal/dpaa2_hw_pvt.h>
#include <portal/dpaa2_hw_dpio.h>

#include "rte_pmd_dpaa2_qdma.h"
#include "dpaa2_qdma.h"
#include "dpaa2_qdma_logs.h"

#define DPAA2_QDMA_NO_PREFETCH "no_prefetch"

/* Dynamic log type identifier */
int dpaa2_qdma_logtype;

static uint32_t dpaa2_coherent_no_alloc_cache;
static uint32_t dpaa2_coherent_alloc_cache;

static inline int
qdma_cntx_idx_ring_eq(struct qdma_cntx_idx_ring *ring,
	const uint16_t *elem, uint16_t nb,
	uint16_t *free_space)
{
	if (unlikely(nb > ring->free_space))
		return 0;

	if ((ring->tail + nb) < DPAA2_QDMA_MAX_DESC) {
		rte_memcpy(&ring->cntx_idx_ring[ring->tail],
			elem, nb * sizeof(uint16_t));
		ring->tail += nb;
	} else {
		rte_memcpy(&ring->cntx_idx_ring[ring->tail],
			elem,
			(DPAA2_QDMA_MAX_DESC - ring->tail) *
			sizeof(uint16_t));
		rte_memcpy(&ring->cntx_idx_ring[0],
			&elem[DPAA2_QDMA_MAX_DESC - ring->tail],
			(nb - DPAA2_QDMA_MAX_DESC + ring->tail) *
			sizeof(uint16_t));
		ring->tail = (ring->tail + nb) & (DPAA2_QDMA_MAX_DESC - 1);
	}
	ring->free_space -= nb;
	ring->nb_in_ring += nb;

	if (free_space)
		*free_space = ring->free_space;

	return nb;
}

static inline int
qdma_cntx_idx_ring_dq(struct qdma_cntx_idx_ring *ring,
	uint16_t *elem, uint16_t max)
{
	int ret = ring->nb_in_ring > max ? max : ring->nb_in_ring;

	if (!ret)
		return 0;

	if ((ring->start + ret) < DPAA2_QDMA_MAX_DESC) {
		rte_memcpy(elem,
			&ring->cntx_idx_ring[ring->start],
			ret * sizeof(uint16_t));
		ring->start += ret;
	} else {
		rte_memcpy(elem,
			&ring->cntx_idx_ring[ring->start],
			(DPAA2_QDMA_MAX_DESC - ring->start) *
			sizeof(uint16_t));
		rte_memcpy(&elem[DPAA2_QDMA_MAX_DESC - ring->start],
			&ring->cntx_idx_ring[0],
			(ret - DPAA2_QDMA_MAX_DESC + ring->start) *
			sizeof(uint16_t));
		ring->start = (ring->start + ret) & (DPAA2_QDMA_MAX_DESC - 1);
	}
	ring->free_space += ret;
	ring->nb_in_ring -= ret;

	return ret;
}

static int
dpaa2_qdma_multi_eq(struct qdma_virt_queue *qdma_vq)
{
	struct dpaa2_dpdmai_dev *dpdmai_dev = qdma_vq->dpdmai_dev;
	uint16_t txq_id = dpdmai_dev->tx_queue[qdma_vq->vq_id].fqid;
	struct qbman_eq_desc eqdesc;
	struct qbman_swp *swp;
	uint32_t num_to_send = 0;
	uint16_t num_tx = 0;
	uint32_t enqueue_loop, loop;
	int ret;
	struct qbman_fd *fd = qdma_vq->fd;
	uint16_t nb_fds = qdma_vq->fd_idx, idx, dst_idx;

	if (unlikely(!DPAA2_PER_LCORE_DPIO)) {
		ret = dpaa2_affine_qbman_swp();
		if (ret) {
			DPAA2_QDMA_ERR("Failed to allocate IO portal, tid: %d",
				rte_gettid());
			return -EIO;
		}
	}
	swp = DPAA2_PER_LCORE_PORTAL;

	/* Prepare enqueue descriptor */
	qbman_eq_desc_clear(&eqdesc);
	qbman_eq_desc_set_fq(&eqdesc, txq_id);
	qbman_eq_desc_set_no_orp(&eqdesc, 0);
	qbman_eq_desc_set_response(&eqdesc, 0, 0);

	while (nb_fds > 0) {
		num_to_send = (nb_fds > dpaa2_eqcr_size) ?
			dpaa2_eqcr_size : nb_fds;

		/* Enqueue the packet to the QBMAN */
		enqueue_loop = 0;
		loop = num_to_send;

		while (enqueue_loop < loop) {
			ret = qbman_swp_enqueue_multiple(swp,
				&eqdesc,
				&fd[num_tx + enqueue_loop],
				NULL,
				loop - enqueue_loop);
			if (likely(ret >= 0))
				enqueue_loop += ret;
		}
		num_tx += num_to_send;
		nb_fds -= loop;
	}

	qdma_vq->num_enqueues += num_tx;
	if (unlikely(num_tx != qdma_vq->fd_idx)) {
		dst_idx = 0;
		for (idx = num_tx; idx < qdma_vq->fd_idx; idx++) {
			rte_memcpy(&qdma_vq->fd[dst_idx],
				&qdma_vq->fd[idx],
				sizeof(struct qbman_fd));
			dst_idx++;
		}
	}
	qdma_vq->fd_idx -= num_tx;

	return num_tx;
}

static void
fle_sdd_pre_populate(struct qdma_cntx_fle_sdd *fle_sdd,
	struct dpaa2_qdma_rbp *rbp, uint64_t src, uint64_t dest,
	uint32_t fmt)
{
	struct qbman_fle *fle = fle_sdd->fle;
	struct qdma_sdd *sdd = fle_sdd->sdd;
	uint64_t sdd_iova = DPAA2_VADDR_TO_IOVA(sdd);

	/* first frame list to source descriptor */
	DPAA2_SET_FLE_ADDR(&fle[DPAA2_QDMA_SDD_FLE], sdd_iova);
	DPAA2_SET_FLE_LEN(&fle[DPAA2_QDMA_SDD_FLE],
		DPAA2_QDMA_MAX_SDD * (sizeof(struct qdma_sdd)));

	/* source and destination descriptor */
	if (rbp && rbp->enable) {
		/* source */
		sdd[DPAA2_QDMA_SRC_SDD].read_cmd.portid =
			rbp->sportid;
		sdd[DPAA2_QDMA_SRC_SDD].rbpcmd_simple.pfid =
			rbp->spfid;
		sdd[DPAA2_QDMA_SRC_SDD].rbpcmd_simple.vfid =
			rbp->svfid;
		sdd[DPAA2_QDMA_SRC_SDD].rbpcmd_simple.vfa =
			rbp->svfa;

		if (rbp->srbp) {
			sdd[DPAA2_QDMA_SRC_SDD].read_cmd.rbp =
				rbp->srbp;
			sdd[DPAA2_QDMA_SRC_SDD].read_cmd.rdtype =
				DPAA2_RBP_MEM_RW;
		} else {
			sdd[DPAA2_QDMA_SRC_SDD].read_cmd.rdtype =
				dpaa2_coherent_no_alloc_cache;
		}
		/* destination */
		sdd[DPAA2_QDMA_DST_SDD].write_cmd.portid =
			rbp->dportid;
		sdd[DPAA2_QDMA_DST_SDD].rbpcmd_simple.pfid =
			rbp->dpfid;
		sdd[DPAA2_QDMA_DST_SDD].rbpcmd_simple.vfid =
			rbp->dvfid;
		sdd[DPAA2_QDMA_DST_SDD].rbpcmd_simple.vfa =
			rbp->dvfa;

		if (rbp->drbp) {
			sdd[DPAA2_QDMA_DST_SDD].write_cmd.rbp =
				rbp->drbp;
			sdd[DPAA2_QDMA_DST_SDD].write_cmd.wrttype =
				DPAA2_RBP_MEM_RW;
		} else {
			sdd[DPAA2_QDMA_DST_SDD].write_cmd.wrttype =
				dpaa2_coherent_alloc_cache;
		}
	} else {
		sdd[DPAA2_QDMA_SRC_SDD].read_cmd.rdtype =
			dpaa2_coherent_no_alloc_cache;
		sdd[DPAA2_QDMA_DST_SDD].write_cmd.wrttype =
			dpaa2_coherent_alloc_cache;
	}
	/* source frame list to source buffer */
	DPAA2_SET_FLE_ADDR(&fle[DPAA2_QDMA_SRC_FLE], src);
#ifdef RTE_LIBRTE_DPAA2_USE_PHYS_IOVA
	DPAA2_SET_FLE_BMT(&fle[DPAA2_QDMA_SRC_FLE]);
#endif
	fle[DPAA2_QDMA_SRC_FLE].word4.fmt = fmt;

	/* destination frame list to destination buffer */
	DPAA2_SET_FLE_ADDR(&fle[DPAA2_QDMA_DST_FLE], dest);
#ifdef RTE_LIBRTE_DPAA2_USE_PHYS_IOVA
	DPAA2_SET_FLE_BMT(&fle[DPAA2_QDMA_DST_FLE]);
#endif
	fle[DPAA2_QDMA_DST_FLE].word4.fmt = fmt;

	/* Final bit: 1, for last frame list */
	DPAA2_SET_FLE_FIN(&fle[DPAA2_QDMA_DST_FLE]);
}

static void
sg_entry_pre_populate(struct qdma_cntx_sg *sg_cntx)
{
	uint16_t i;
	struct qdma_sg_entry *src_sge = sg_cntx->sg_src_entry;
	struct qdma_sg_entry *dst_sge = sg_cntx->sg_dst_entry;

	for (i = 0; i < RTE_DPAA2_QDMA_JOB_SUBMIT_MAX; i++) {
		/* source SG */
		src_sge[i].ctrl.sl = QDMA_SG_SL_LONG;
		src_sge[i].ctrl.fmt = QDMA_SG_FMT_SDB;
#ifdef RTE_LIBRTE_DPAA2_USE_PHYS_IOVA
		src_sge[i].ctrl.bmt = QDMA_SG_BMT_ENABLE;
#else
		src_sge[i].ctrl.bmt = QDMA_SG_BMT_DISABLE;
#endif
		/* destination SG */
		dst_sge[i].ctrl.sl = QDMA_SG_SL_LONG;
		dst_sge[i].ctrl.fmt = QDMA_SG_FMT_SDB;
#ifdef RTE_LIBRTE_DPAA2_USE_PHYS_IOVA
		dst_sge[i].ctrl.bmt = QDMA_SG_BMT_ENABLE;
#else
		dst_sge[i].ctrl.bmt = QDMA_SG_BMT_DISABLE;
#endif
	}
}

static void
fle_sdd_sg_pre_populate(struct qdma_cntx_sg *sg_cntx,
	struct qdma_virt_queue *qdma_vq)
{
	struct qdma_sg_entry *src_sge = sg_cntx->sg_src_entry;
	struct qdma_sg_entry *dst_sge = sg_cntx->sg_dst_entry;
	rte_iova_t src_sge_iova, dst_sge_iova;
	struct dpaa2_qdma_rbp *rbp = &qdma_vq->rbp;

	memset(sg_cntx, 0, sizeof(struct qdma_cntx_sg));

	src_sge_iova = DPAA2_VADDR_TO_IOVA(src_sge);
	dst_sge_iova = DPAA2_VADDR_TO_IOVA(dst_sge);

	sg_entry_pre_populate(sg_cntx);
	fle_sdd_pre_populate(&sg_cntx->fle_sdd,
		rbp, src_sge_iova, dst_sge_iova,
		QBMAN_FLE_WORD4_FMT_SGE);
}

static inline uint32_t
sg_entry_post_populate(const struct rte_dma_sge *src,
	const struct rte_dma_sge *dst, struct qdma_cntx_sg *sg_cntx,
	uint16_t nb_sge)
{
	uint16_t i = 0, idx;
	uint32_t total_len = 0, len;
	struct qdma_sg_entry *src_sge = sg_cntx->sg_src_entry;
	struct qdma_sg_entry *dst_sge = sg_cntx->sg_dst_entry;

	for (i = 0; i < (nb_sge - 1); i++) {
		if (unlikely(src[i].length != dst[i].length))
			return -ENOTSUP;
		len = RTE_DPAA2_QDMA_LEN_FROM_LENGTH(src[i].length);
		idx = RTE_DPAA2_QDMA_IDX_FROM_LENGTH(src[i].length);
		src_sge->addr_lo = (uint32_t)src[i].addr;
		src_sge->addr_hi = (src[i].addr >> 32);
		src_sge->data_len.data_len_sl0 = len;

		dst_sge->addr_lo = (uint32_t)dst[i].addr;
		dst_sge->addr_hi = (dst[i].addr >> 32);
		dst_sge->data_len.data_len_sl0 = len;
		total_len += len;
		sg_cntx->cntx_idx[i] = idx;

		src_sge->ctrl.f = 0;
		dst_sge->ctrl.f = 0;
		src_sge++;
		dst_sge++;
	}

	if (unlikely(src[i].length != dst[i].length))
		return -ENOTSUP;

	len = RTE_DPAA2_QDMA_LEN_FROM_LENGTH(src[i].length);
	idx = RTE_DPAA2_QDMA_IDX_FROM_LENGTH(src[i].length);

	src_sge->addr_lo = (uint32_t)src[i].addr;
	src_sge->addr_hi = (src[i].addr >> 32);
	src_sge->data_len.data_len_sl0 = len;

	dst_sge->addr_lo = (uint32_t)dst[i].addr;
	dst_sge->addr_hi = (dst[i].addr >> 32);
	dst_sge->data_len.data_len_sl0 = len;

	total_len += len;
	sg_cntx->cntx_idx[i] = idx;
	sg_cntx->job_nb = nb_sge;

	src_sge->ctrl.f = QDMA_SG_F;
	dst_sge->ctrl.f = QDMA_SG_F;

	return total_len;
}

static inline void
sg_fle_post_populate(struct qbman_fle fle[],
	size_t len)
{
	DPAA2_SET_FLE_LEN(&fle[DPAA2_QDMA_SRC_FLE], len);
	DPAA2_SET_FLE_LEN(&fle[DPAA2_QDMA_DST_FLE], len);
}

static inline uint32_t
sg_entry_populate(const struct rte_dma_sge *src,
	const struct rte_dma_sge *dst, struct qdma_cntx_sg *sg_cntx,
	uint16_t nb_sge)
{
	uint16_t i, idx;
	uint32_t total_len = 0, len;
	struct qdma_sg_entry *src_sge = sg_cntx->sg_src_entry;
	struct qdma_sg_entry *dst_sge = sg_cntx->sg_dst_entry;

	for (i = 0; i < nb_sge; i++) {
		if (unlikely(src[i].length != dst[i].length))
			return -ENOTSUP;
		len = RTE_DPAA2_QDMA_LEN_FROM_LENGTH(src[i].length);
		idx = RTE_DPAA2_QDMA_IDX_FROM_LENGTH(src[i].length);

		src_sge->addr_lo = (uint32_t)src[i].addr;
		src_sge->addr_hi = (src[i].addr >> 32);
		src_sge->data_len.data_len_sl0 = len;
		src_sge->ctrl.sl = QDMA_SG_SL_LONG;
		src_sge->ctrl.fmt = QDMA_SG_FMT_SDB;
#ifdef RTE_LIBRTE_DPAA2_USE_PHYS_IOVA
		src_sge->ctrl.bmt = QDMA_SG_BMT_ENABLE;
#else
		src_sge->ctrl.bmt = QDMA_SG_BMT_DISABLE;
#endif
		dst_sge->addr_lo = (uint32_t)dst[i].addr;
		dst_sge->addr_hi = (dst[i].addr >> 32);
		dst_sge->data_len.data_len_sl0 = len;
		dst_sge->ctrl.sl = QDMA_SG_SL_LONG;
		dst_sge->ctrl.fmt = QDMA_SG_FMT_SDB;
#ifdef RTE_LIBRTE_DPAA2_USE_PHYS_IOVA
		dst_sge->ctrl.bmt = QDMA_SG_BMT_ENABLE;
#else
		dst_sge->ctrl.bmt = QDMA_SG_BMT_DISABLE;
#endif
		total_len += len;
		sg_cntx->cntx_idx[i] = idx;

		if (i == (nb_sge - 1)) {
			src_sge->ctrl.f = QDMA_SG_F;
			dst_sge->ctrl.f = QDMA_SG_F;
		} else {
			src_sge->ctrl.f = 0;
			dst_sge->ctrl.f = 0;
		}
		src_sge++;
		dst_sge++;
	}

	sg_cntx->job_nb = nb_sge;

	return total_len;
}

static inline void
fle_populate(struct qbman_fle fle[],
	struct qdma_sdd sdd[], uint64_t sdd_iova,
	struct dpaa2_qdma_rbp *rbp,
	uint64_t src_iova, uint64_t dst_iova, size_t len,
	uint32_t fmt)
{
	/* first frame list to source descriptor */
	DPAA2_SET_FLE_ADDR(&fle[DPAA2_QDMA_SDD_FLE], sdd_iova);
	DPAA2_SET_FLE_LEN(&fle[DPAA2_QDMA_SDD_FLE],
		(DPAA2_QDMA_MAX_SDD * (sizeof(struct qdma_sdd))));

	/* source and destination descriptor */
	if (rbp && rbp->enable) {
		/* source */
		sdd[DPAA2_QDMA_SRC_SDD].read_cmd.portid =
			rbp->sportid;
		sdd[DPAA2_QDMA_SRC_SDD].rbpcmd_simple.pfid =
			rbp->spfid;
		sdd[DPAA2_QDMA_SRC_SDD].rbpcmd_simple.vfid =
			rbp->svfid;
		sdd[DPAA2_QDMA_SRC_SDD].rbpcmd_simple.vfa =
			rbp->svfa;

		if (rbp->srbp) {
			sdd[DPAA2_QDMA_SRC_SDD].read_cmd.rbp =
				rbp->srbp;
			sdd[DPAA2_QDMA_SRC_SDD].read_cmd.rdtype =
				DPAA2_RBP_MEM_RW;
		} else {
			sdd[DPAA2_QDMA_SRC_SDD].read_cmd.rdtype =
				dpaa2_coherent_no_alloc_cache;
		}
		/* destination */
		sdd[DPAA2_QDMA_DST_SDD].write_cmd.portid =
			rbp->dportid;
		sdd[DPAA2_QDMA_DST_SDD].rbpcmd_simple.pfid =
			rbp->dpfid;
		sdd[DPAA2_QDMA_DST_SDD].rbpcmd_simple.vfid =
			rbp->dvfid;
		sdd[DPAA2_QDMA_DST_SDD].rbpcmd_simple.vfa =
			rbp->dvfa;

		if (rbp->drbp) {
			sdd[DPAA2_QDMA_DST_SDD].write_cmd.rbp =
				rbp->drbp;
			sdd[DPAA2_QDMA_DST_SDD].write_cmd.wrttype =
				DPAA2_RBP_MEM_RW;
		} else {
			sdd[DPAA2_QDMA_DST_SDD].write_cmd.wrttype =
				dpaa2_coherent_alloc_cache;
		}

	} else {
		sdd[DPAA2_QDMA_SRC_SDD].read_cmd.rdtype =
			dpaa2_coherent_no_alloc_cache;
		sdd[DPAA2_QDMA_DST_SDD].write_cmd.wrttype =
			dpaa2_coherent_alloc_cache;
	}
	/* source frame list to source buffer */
	DPAA2_SET_FLE_ADDR(&fle[DPAA2_QDMA_SRC_FLE], src_iova);
#ifdef RTE_LIBRTE_DPAA2_USE_PHYS_IOVA
	DPAA2_SET_FLE_BMT(&fle[DPAA2_QDMA_SRC_FLE]);
#endif
	fle[DPAA2_QDMA_SRC_FLE].word4.fmt = fmt;
	DPAA2_SET_FLE_LEN(&fle[DPAA2_QDMA_SRC_FLE], len);

	/* destination frame list to destination buffer */
	DPAA2_SET_FLE_ADDR(&fle[DPAA2_QDMA_DST_FLE], dst_iova);
#ifdef RTE_LIBRTE_DPAA2_USE_PHYS_IOVA
	DPAA2_SET_FLE_BMT(&fle[DPAA2_QDMA_DST_FLE]);
#endif
	fle[DPAA2_QDMA_DST_FLE].word4.fmt = fmt;
	DPAA2_SET_FLE_LEN(&fle[DPAA2_QDMA_DST_FLE], len);

	/* Final bit: 1, for last frame list */
	DPAA2_SET_FLE_FIN(&fle[DPAA2_QDMA_DST_FLE]);
}

static inline void
fle_post_populate(struct qbman_fle fle[],
	uint64_t src, uint64_t dest, size_t len)
{
	DPAA2_SET_FLE_ADDR(&fle[DPAA2_QDMA_SRC_FLE], src);
	DPAA2_SET_FLE_LEN(&fle[DPAA2_QDMA_SRC_FLE], len);

	DPAA2_SET_FLE_ADDR(&fle[DPAA2_QDMA_DST_FLE], dest);
	DPAA2_SET_FLE_LEN(&fle[DPAA2_QDMA_DST_FLE], len);
}

static inline int
dpaa2_qdma_submit(void *dev_private, uint16_t vchan)
{
	struct dpaa2_dpdmai_dev *dpdmai_dev = dev_private;
	struct qdma_device *qdma_dev = dpdmai_dev->qdma_dev;
	struct qdma_virt_queue *qdma_vq = &qdma_dev->vqs[vchan];
	uint16_t expected = qdma_vq->fd_idx;
	int ret;

	ret = dpaa2_qdma_multi_eq(qdma_vq);
	if (likely(ret == expected))
		return 0;

	return -EBUSY;
}

static inline void
dpaa2_qdma_fle_dump(const struct qbman_fle *fle)
{
	DPAA2_QDMA_INFO("addr:0x%08x-0x%08x, len:%d, frc:0x%08x, bpid:%d",
		fle->addr_hi, fle->addr_lo, fle->length, fle->frc,
		fle->word4.bpid);
	DPAA2_QDMA_INFO("ivp:%d, bmt:%d, off:%d, fmt:%d, sl:%d, f:%d",
		fle->word4.ivp, fle->word4.bmt, fle->word4.offset,
		fle->word4.fmt, fle->word4.sl, fle->word4.f);
}

static inline void
dpaa2_qdma_sdd_dump(const struct qdma_sdd *sdd)
{
	DPAA2_QDMA_INFO("stride:%d, rbpcmd:0x%08x, cmd:0x%08x",
		sdd->stride, sdd->rbpcmd, sdd->cmd);
}

static inline void
dpaa2_qdma_sge_dump(const struct qdma_sg_entry *sge)
{
	DPAA2_QDMA_INFO("addr 0x%08x-0x%08x, len:0x%08x, ctl:0x%08x",
		sge->addr_hi, sge->addr_lo, sge->data_len.data_len_sl0,
		sge->ctrl_fields);
}

static void
dpaa2_qdma_long_fmt_dump(const struct qbman_fle *fle)
{
	int i;
	const struct qdma_cntx_fle_sdd *fle_sdd;
	const struct qdma_sdd *sdd;
	const struct qdma_cntx_sg *cntx_sg = NULL;
	const struct qdma_cntx_long *cntx_long = NULL;

	fle_sdd = container_of(fle, const struct qdma_cntx_fle_sdd, fle[0]);
	sdd = fle_sdd->sdd;

	for (i = 0; i < DPAA2_QDMA_MAX_FLE; i++) {
		DPAA2_QDMA_INFO("fle[%d] info:", i);
		dpaa2_qdma_fle_dump(&fle[i]);
	}

	if (fle[DPAA2_QDMA_SRC_FLE].word4.fmt !=
		fle[DPAA2_QDMA_DST_FLE].word4.fmt) {
		DPAA2_QDMA_ERR("fle[%d].fmt(%d) != fle[%d].fmt(%d)",
			DPAA2_QDMA_SRC_FLE,
			fle[DPAA2_QDMA_SRC_FLE].word4.fmt,
			DPAA2_QDMA_DST_FLE,
			fle[DPAA2_QDMA_DST_FLE].word4.fmt);

		return;
	} else if (fle[DPAA2_QDMA_SRC_FLE].word4.fmt ==
		QBMAN_FLE_WORD4_FMT_SGE) {
		cntx_sg = container_of(fle_sdd, const struct qdma_cntx_sg,
			fle_sdd);
	} else if (fle[DPAA2_QDMA_SRC_FLE].word4.fmt ==
		QBMAN_FLE_WORD4_FMT_SBF) {
		cntx_long = container_of(fle_sdd, const struct qdma_cntx_long,
			fle_sdd);
	} else {
		DPAA2_QDMA_ERR("Unsupported fle format:%d",
			fle[DPAA2_QDMA_SRC_FLE].word4.fmt);
		return;
	}

	for (i = 0; i < DPAA2_QDMA_MAX_SDD; i++) {
		DPAA2_QDMA_INFO("sdd[%d] info:", i);
		dpaa2_qdma_sdd_dump(&sdd[i]);
	}

	if (cntx_long) {
		DPAA2_QDMA_INFO("long format/Single buffer cntx idx:%d",
			cntx_long->cntx_idx);
	}

	if (cntx_sg) {
		DPAA2_QDMA_INFO("long format/SG format, job number:%d",
			cntx_sg->job_nb);
		if (!cntx_sg->job_nb ||
			cntx_sg->job_nb > RTE_DPAA2_QDMA_JOB_SUBMIT_MAX) {
			DPAA2_QDMA_ERR("Invalid SG job number:%d",
				cntx_sg->job_nb);
			return;
		}
		for (i = 0; i < cntx_sg->job_nb; i++) {
			DPAA2_QDMA_INFO("sg[%d] src info:", i);
			dpaa2_qdma_sge_dump(&cntx_sg->sg_src_entry[i]);
			DPAA2_QDMA_INFO("sg[%d] dst info:", i);
			dpaa2_qdma_sge_dump(&cntx_sg->sg_dst_entry[i]);
			DPAA2_QDMA_INFO("cntx_idx[%d]:%d", i,
				cntx_sg->cntx_idx[i]);
		}
	}
}

static int
dpaa2_qdma_copy_sg(void *dev_private,
	uint16_t vchan,
	const struct rte_dma_sge *src,
	const struct rte_dma_sge *dst,
	uint16_t nb_src, uint16_t nb_dst,
	uint64_t flags)
{
	struct dpaa2_dpdmai_dev *dpdmai_dev = dev_private;
	struct qdma_device *qdma_dev = dpdmai_dev->qdma_dev;
	struct qdma_virt_queue *qdma_vq = &qdma_dev->vqs[vchan];
	int ret = 0, expected;
	uint32_t cntx_idx, len;
	struct qbman_fd *fd = &qdma_vq->fd[qdma_vq->fd_idx];
	struct qdma_cntx_sg *cntx_sg;
	rte_iova_t cntx_iova, fle_iova, sdd_iova;
	rte_iova_t src_sge_iova, dst_sge_iova;
	struct qbman_fle *fle;
	struct qdma_sdd *sdd;

	if (unlikely(nb_src != nb_dst))
		return -ENOTSUP;

	memset(fd, 0, sizeof(struct qbman_fd));

	if (qdma_dev->is_silent) {
		cntx_idx = RTE_DPAA2_QDMA_IDX_FROM_LENGTH(src[0].length);
		cntx_sg = qdma_vq->cntx_sg[cntx_idx];
	} else {
		ret = rte_mempool_get(qdma_vq->fle_pool,
			(void **)&cntx_sg);
		if (ret)
			return ret;
		DPAA2_SET_FD_FRC(fd, QDMA_SER_CTX);
	}

#ifdef RTE_LIBRTE_DPAA2_USE_PHYS_IOVA
	cntx_iova = rte_mempool_virt2iova(cntx_sg);
#else
	cntx_iova = DPAA2_VADDR_TO_IOVA(cntx_sg);
#endif

	fle = cntx_sg->fle_sdd.fle;
	fle_iova = cntx_iova +
		offsetof(struct qdma_cntx_sg, fle_sdd) +
		offsetof(struct qdma_cntx_fle_sdd, fle);

	DPAA2_SET_FD_ADDR(fd, fle_iova);
	DPAA2_SET_FD_COMPOUND_FMT(fd);
	DPAA2_SET_FD_FLC(fd, (uint64_t)cntx_sg);

	if (qdma_vq->fle_pre_populate) {
		if (unlikely(!fle[DPAA2_QDMA_SRC_FLE].length))
			fle_sdd_sg_pre_populate(cntx_sg, qdma_vq);

		len = sg_entry_post_populate(src, dst,
			cntx_sg, nb_src);
		sg_fle_post_populate(fle, len);
	} else {
		sdd = cntx_sg->fle_sdd.sdd;
		sdd_iova = cntx_iova +
			offsetof(struct qdma_cntx_sg, fle_sdd) +
			offsetof(struct qdma_cntx_fle_sdd, sdd);
		src_sge_iova = cntx_iova +
			offsetof(struct qdma_cntx_sg, sg_src_entry);
		dst_sge_iova = cntx_iova +
			offsetof(struct qdma_cntx_sg, sg_dst_entry);
		len = sg_entry_populate(src, dst,
			cntx_sg, nb_src);

		fle_populate(fle, sdd, sdd_iova,
			&qdma_vq->rbp, src_sge_iova, dst_sge_iova, len,
			QBMAN_FLE_WORD4_FMT_SGE);
	}

	if (unlikely(qdma_vq->flags & DPAA2_QDMA_DESC_DEBUG_FLAG))
		dpaa2_qdma_long_fmt_dump(cntx_sg->fle_sdd.fle);

	qdma_vq->fd_idx++;

	if (flags & RTE_DMA_OP_FLAG_SUBMIT) {
		expected = qdma_vq->fd_idx;
		ret = dpaa2_qdma_multi_eq(qdma_vq);
		if (likely(ret == expected))
			return 0;
	} else {
		return 0;
	}

	return ret;
}

static int
dpaa2_qdma_copy(void *dev_private, uint16_t vchan,
	rte_iova_t src, rte_iova_t dst,
	uint32_t length, uint64_t flags)
{
	struct dpaa2_dpdmai_dev *dpdmai_dev = dev_private;
	struct qdma_device *qdma_dev = dpdmai_dev->qdma_dev;
	struct qdma_virt_queue *qdma_vq = &qdma_dev->vqs[vchan];
	int ret = 0, expected;
	uint16_t cntx_idx;
	uint32_t len;
	struct qbman_fd *fd = &qdma_vq->fd[qdma_vq->fd_idx];
	struct qdma_cntx_long *cntx_long;
	rte_iova_t cntx_iova, fle_iova, sdd_iova;
	struct qbman_fle *fle;
	struct qdma_sdd *sdd;

	memset(fd, 0, sizeof(struct qbman_fd));

	cntx_idx = RTE_DPAA2_QDMA_IDX_FROM_LENGTH(length);
	len = RTE_DPAA2_QDMA_LEN_FROM_LENGTH(length);

	if (qdma_dev->is_silent) {
		cntx_long = qdma_vq->cntx_long[cntx_idx];
	} else {
		ret = rte_mempool_get(qdma_vq->fle_pool,
			(void **)&cntx_long);
		if (ret)
			return ret;
		DPAA2_SET_FD_FRC(fd, QDMA_SER_CTX);
		cntx_long->cntx_idx = cntx_idx;
	}

#ifdef RTE_LIBRTE_DPAA2_USE_PHYS_IOVA
	cntx_iova = rte_mempool_virt2iova(cntx_long);
#else
	cntx_iova = DPAA2_VADDR_TO_IOVA(cntx_long);
#endif

	fle = cntx_long->fle_sdd.fle;
	fle_iova = cntx_iova +
		offsetof(struct qdma_cntx_long, fle_sdd) +
		offsetof(struct qdma_cntx_fle_sdd, fle);

	DPAA2_SET_FD_ADDR(fd, fle_iova);
	DPAA2_SET_FD_COMPOUND_FMT(fd);
	DPAA2_SET_FD_FLC(fd, (uint64_t)cntx_long);

	if (qdma_vq->fle_pre_populate) {
		if (unlikely(!fle[DPAA2_QDMA_SRC_FLE].length)) {
			fle_sdd_pre_populate(&cntx_long->fle_sdd,
				&qdma_vq->rbp,
				0, 0, QBMAN_FLE_WORD4_FMT_SBF);
		}

		fle_post_populate(fle, src, dst, len);
	} else {
		sdd = cntx_long->fle_sdd.sdd;
		sdd_iova = cntx_iova +
			offsetof(struct qdma_cntx_long, fle_sdd) +
			offsetof(struct qdma_cntx_fle_sdd, sdd);
		fle_populate(fle, sdd, sdd_iova, &qdma_vq->rbp,
			src, dst, len,
			QBMAN_FLE_WORD4_FMT_SBF);
	}

	if (unlikely(qdma_vq->flags & DPAA2_QDMA_DESC_DEBUG_FLAG))
		dpaa2_qdma_long_fmt_dump(cntx_long->fle_sdd.fle);

	qdma_vq->fd_idx++;

	if (flags & RTE_DMA_OP_FLAG_SUBMIT) {
		expected = qdma_vq->fd_idx;
		ret = dpaa2_qdma_multi_eq(qdma_vq);
		if (likely(ret == expected))
			return 0;
	} else {
		return 0;
	}

	return ret;
}

static uint16_t
dpaa2_qdma_dequeue(void *dev_private,
	uint16_t vchan, const uint16_t nb_cpls,
	uint16_t *cntx_idx, bool *has_error)
{
	struct dpaa2_dpdmai_dev *dpdmai_dev = dev_private;
	struct qdma_device *qdma_dev = dpdmai_dev->qdma_dev;
	struct qdma_virt_queue *qdma_vq = &qdma_dev->vqs[vchan];

	struct dpaa2_queue *rxq;
	struct qbman_result *dq_storage, *dq_storage1 = NULL;
	struct qbman_pull_desc pulldesc;
	struct qbman_swp *swp;
	struct queue_storage_info_t *q_storage;
	uint32_t fqid;
	uint8_t status, pending;
	uint8_t num_rx = 0;
	const struct qbman_fd *fd;
	int ret, pull_size;
	struct qbman_fle *fle;
	struct qdma_cntx_fle_sdd *fle_sdd;
	struct qdma_cntx_sg *cntx_sg;
	struct qdma_cntx_long *cntx_long;
	uint16_t free_space = 0, fle_elem_nb = 0;

	if (unlikely(qdma_dev->is_silent))
		return 0;

	if (unlikely(!DPAA2_PER_LCORE_DPIO)) {
		ret = dpaa2_affine_qbman_swp();
		if (ret) {
			DPAA2_QDMA_ERR("Allocate portal err, tid(%d)",
				rte_gettid());
			if (has_error)
				*has_error = true;
			return 0;
		}
	}
	swp = DPAA2_PER_LCORE_PORTAL;

	pull_size = (nb_cpls > dpaa2_dqrr_size) ?
		dpaa2_dqrr_size : nb_cpls;
	rxq = &(dpdmai_dev->rx_queue[qdma_vq->vq_id]);
	fqid = rxq->fqid;
	q_storage = rxq->q_storage;

	if (unlikely(!q_storage->active_dqs)) {
		q_storage->toggle = 0;
		dq_storage = q_storage->dq_storage[q_storage->toggle];
		q_storage->last_num_pkts = pull_size;
		qbman_pull_desc_clear(&pulldesc);
		qbman_pull_desc_set_numframes(&pulldesc,
			q_storage->last_num_pkts);
		qbman_pull_desc_set_fq(&pulldesc, fqid);
		qbman_pull_desc_set_storage(&pulldesc, dq_storage,
			(size_t)(DPAA2_VADDR_TO_IOVA(dq_storage)), 1);
		if (check_swp_active_dqs(DPAA2_PER_LCORE_DPIO->index)) {
			while (!qbman_check_command_complete(
			       get_swp_active_dqs(
			       DPAA2_PER_LCORE_DPIO->index)))
				;
			clear_swp_active_dqs(DPAA2_PER_LCORE_DPIO->index);
		}
		while (1) {
			if (qbman_swp_pull(swp, &pulldesc)) {
				DPAA2_QDMA_DP_WARN("QBMAN busy");
					/* Portal was busy, try again */
				continue;
			}
			break;
		}
		q_storage->active_dqs = dq_storage;
		q_storage->active_dpio_id = DPAA2_PER_LCORE_DPIO->index;
		set_swp_active_dqs(DPAA2_PER_LCORE_DPIO->index,
			dq_storage);
	}

	dq_storage = q_storage->active_dqs;
	rte_prefetch0((void *)(size_t)(dq_storage));
	rte_prefetch0((void *)(size_t)(dq_storage + 1));

	/* Prepare next pull descriptor. This will give space for the
	 * prefething done on DQRR entries
	 */
	q_storage->toggle ^= 1;
	dq_storage1 = q_storage->dq_storage[q_storage->toggle];
	qbman_pull_desc_clear(&pulldesc);
	qbman_pull_desc_set_numframes(&pulldesc, pull_size);
	qbman_pull_desc_set_fq(&pulldesc, fqid);
	qbman_pull_desc_set_storage(&pulldesc, dq_storage1,
		(size_t)(DPAA2_VADDR_TO_IOVA(dq_storage1)), 1);

	/* Check if the previous issued command is completed.
	 * Also seems like the SWP is shared between the Ethernet Driver
	 * and the SEC driver.
	 */
	while (!qbman_check_command_complete(dq_storage))
		;
	if (dq_storage == get_swp_active_dqs(q_storage->active_dpio_id))
		clear_swp_active_dqs(q_storage->active_dpio_id);

	pending = 1;

	do {
		/* Loop until the dq_storage is updated with
		 * new token by QBMAN
		 */
		while (!qbman_check_new_result(dq_storage))
			;
		rte_prefetch0((void *)((size_t)(dq_storage + 2)));
		/* Check whether Last Pull command is Expired and
		 * setting Condition for Loop termination
		 */
		if (qbman_result_DQ_is_pull_complete(dq_storage)) {
			pending = 0;
			/* Check for valid frame. */
			status = qbman_result_DQ_flags(dq_storage);
			if (unlikely((status & QBMAN_DQ_STAT_VALIDFRAME) == 0))
				continue;
		}
		fd = qbman_result_DQ_fd(dq_storage);
		fle_sdd = (void *)DPAA2_GET_FD_FLC(fd);
		fle = fle_sdd->fle;
		qdma_vq->fle_elem[fle_elem_nb] = fle_sdd;
		fle_elem_nb++;
		if (fle[DPAA2_QDMA_SRC_FLE].word4.fmt ==
			QBMAN_FLE_WORD4_FMT_SGE) {
			cntx_sg = container_of(fle_sdd,
				struct qdma_cntx_sg, fle_sdd);
			ret = qdma_cntx_idx_ring_eq(qdma_vq->ring_cntx_idx,
				cntx_sg->cntx_idx,
				cntx_sg->job_nb, &free_space);
		} else {
			cntx_long = container_of(fle_sdd,
				struct qdma_cntx_long, fle_sdd);
			ret = qdma_cntx_idx_ring_eq(qdma_vq->ring_cntx_idx,
				&cntx_long->cntx_idx,
				1, &free_space);
		}
		if (!ret || free_space < RTE_DPAA2_QDMA_JOB_SUBMIT_MAX)
			pending = 0;

		dq_storage++;
	} while (pending);

	if (check_swp_active_dqs(DPAA2_PER_LCORE_DPIO->index)) {
		while (!qbman_check_command_complete(
		       get_swp_active_dqs(DPAA2_PER_LCORE_DPIO->index)))
			;
		clear_swp_active_dqs(DPAA2_PER_LCORE_DPIO->index);
	}
	/* issue a volatile dequeue command for next pull */
	while (1) {
		if (qbman_swp_pull(swp, &pulldesc)) {
			DPAA2_QDMA_DP_WARN("QBMAN is busy (2)");
			continue;
		}
		break;
	}

	q_storage->active_dqs = dq_storage1;
	q_storage->active_dpio_id = DPAA2_PER_LCORE_DPIO->index;
	set_swp_active_dqs(DPAA2_PER_LCORE_DPIO->index, dq_storage1);

	rte_mempool_put_bulk(qdma_vq->fle_pool,
		qdma_vq->fle_elem, fle_elem_nb);

	num_rx = qdma_cntx_idx_ring_dq(qdma_vq->ring_cntx_idx,
		cntx_idx, nb_cpls);

	if (has_error)
		*has_error = false;

	return num_rx;
}

static int
dpaa2_qdma_info_get(const struct rte_dma_dev *dev,
	struct rte_dma_info *dev_info,
	uint32_t info_sz __rte_unused)
{
	struct dpaa2_dpdmai_dev *dpdmai_dev = dev->data->dev_private;

	dev_info->dev_capa = RTE_DMA_CAPA_MEM_TO_MEM |
			     RTE_DMA_CAPA_MEM_TO_DEV |
			     RTE_DMA_CAPA_DEV_TO_DEV |
			     RTE_DMA_CAPA_DEV_TO_MEM |
			     RTE_DMA_CAPA_SILENT |
			     RTE_DMA_CAPA_OPS_COPY;
	dev_info->max_vchans = dpdmai_dev->num_queues;
	dev_info->max_desc = DPAA2_QDMA_MAX_DESC;
	dev_info->min_desc = DPAA2_QDMA_MIN_DESC;

	return 0;
}

static int
dpaa2_qdma_configure(struct rte_dma_dev *dev,
	const struct rte_dma_conf *dev_conf,
	uint32_t conf_sz)
{
	char name[32]; /* RTE_MEMZONE_NAMESIZE = 32 */
	struct dpaa2_dpdmai_dev *dpdmai_dev = dev->data->dev_private;
	struct qdma_device *qdma_dev = dpdmai_dev->qdma_dev;
	uint16_t i;

	DPAA2_QDMA_FUNC_TRACE();

	RTE_SET_USED(conf_sz);

	/* In case QDMA device is not in stopped state, return -EBUSY */
	if (qdma_dev->state == 1) {
		DPAA2_QDMA_ERR("%s Not stopped, configure failed.",
			dev->data->dev_name);
		return -EBUSY;
	}

	/* Allocate Virtual Queues */
	sprintf(name, "qdma_%d_vq", dev->data->dev_id);
	qdma_dev->vqs = rte_malloc(name,
		(sizeof(struct qdma_virt_queue) * dev_conf->nb_vchans),
		RTE_CACHE_LINE_SIZE);
	if (!qdma_dev->vqs) {
		DPAA2_QDMA_ERR("%s: VQs(%d) alloc failed.",
			dev->data->dev_name, dev_conf->nb_vchans);
		return -ENOMEM;
	}
	for (i = 0; i < dev_conf->nb_vchans; i++)
		qdma_dev->vqs[i].vq_id = i;

	qdma_dev->num_vqs = dev_conf->nb_vchans;
	qdma_dev->is_silent = dev_conf->enable_silent;

	return 0;
}

static int
dpaa2_qdma_vchan_rbp_set(struct qdma_virt_queue *vq,
	const struct rte_dma_vchan_conf *conf)
{
	if (conf->direction == RTE_DMA_DIR_MEM_TO_DEV ||
		conf->direction == RTE_DMA_DIR_DEV_TO_DEV) {
		if (conf->dst_port.port_type != RTE_DMA_PORT_PCIE)
			return -EINVAL;
		vq->rbp.enable = 1;
		vq->rbp.dportid = conf->dst_port.pcie.coreid;
		vq->rbp.dpfid = conf->dst_port.pcie.pfid;
		if (conf->dst_port.pcie.vfen) {
			vq->rbp.dvfa = 1;
			vq->rbp.dvfid = conf->dst_port.pcie.vfid;
		}
		vq->rbp.drbp = 1;
	}
	if (conf->direction == RTE_DMA_DIR_DEV_TO_MEM ||
		conf->direction == RTE_DMA_DIR_DEV_TO_DEV) {
		if (conf->src_port.port_type != RTE_DMA_PORT_PCIE)
			return -EINVAL;
		vq->rbp.enable = 1;
		vq->rbp.sportid = conf->src_port.pcie.coreid;
		vq->rbp.spfid = conf->src_port.pcie.pfid;
		if (conf->src_port.pcie.vfen) {
			vq->rbp.svfa = 1;
			vq->rbp.dvfid = conf->src_port.pcie.vfid;
		}
		vq->rbp.srbp = 1;
	}

	return 0;
}

static int
dpaa2_qdma_vchan_setup(struct rte_dma_dev *dev, uint16_t vchan,
	const struct rte_dma_vchan_conf *conf,
	uint32_t conf_sz)
{
	struct dpaa2_dpdmai_dev *dpdmai_dev = dev->data->dev_private;
	struct qdma_device *qdma_dev = dpdmai_dev->qdma_dev;
	uint32_t pool_size;
	char pool_name[64];
	int ret;
	char *env = NULL;

	DPAA2_QDMA_FUNC_TRACE();

	RTE_SET_USED(conf_sz);

	ret = dpaa2_qdma_vchan_rbp_set(&qdma_dev->vqs[vchan], conf);
	if (ret)
		return ret;

	/**Default enable FLE PRE POPULATE*/
	env = getenv("DPAA2_QDMA_FLE_PRE_POPULATE");
	if (env)
		qdma_dev->vqs[vchan].fle_pre_populate = atoi(env);
	else
		qdma_dev->vqs[vchan].fle_pre_populate = 1;

	env = getenv("DPAA2_QDMA_DESC_DEBUG");
	if (env && atoi(env))
		qdma_dev->vqs[vchan].flags |= DPAA2_QDMA_DESC_DEBUG_FLAG;
	else
		qdma_dev->vqs[vchan].flags &= (~DPAA2_QDMA_DESC_DEBUG_FLAG);

	snprintf(pool_name, sizeof(pool_name),
		"qdma_fle_pool_dev%d_qid%d", dpdmai_dev->dpdmai_id, vchan);
	pool_size = RTE_MAX(sizeof(struct qdma_cntx_sg),
		sizeof(struct qdma_cntx_long));

	qdma_dev->vqs[vchan].fle_pool = rte_mempool_create(pool_name,
		DPAA2_QDMA_MAX_DESC * 2, pool_size,
		512, 0,	NULL, NULL, NULL, NULL,
		SOCKET_ID_ANY, 0);
	if (!qdma_dev->vqs[vchan].fle_pool) {
		DPAA2_QDMA_ERR("%s create failed", pool_name);
		return -ENOMEM;
	}

	if (qdma_dev->is_silent) {
		ret = rte_mempool_get_bulk(qdma_dev->vqs[vchan].fle_pool,
			(void **)qdma_dev->vqs[vchan].cntx_sg,
			DPAA2_QDMA_MAX_DESC);
		if (ret) {
			DPAA2_QDMA_ERR("sg cntx get from %s for silent mode",
				pool_name);
			return ret;
		}
		ret = rte_mempool_get_bulk(qdma_dev->vqs[vchan].fle_pool,
			(void **)qdma_dev->vqs[vchan].cntx_long,
			DPAA2_QDMA_MAX_DESC);
		if (ret) {
			DPAA2_QDMA_ERR("long cntx get from %s for silent mode",
				pool_name);
			return ret;
		}
	} else {
		qdma_dev->vqs[vchan].ring_cntx_idx = rte_malloc(NULL,
			sizeof(struct qdma_cntx_idx_ring),
			RTE_CACHE_LINE_SIZE);
		if (!qdma_dev->vqs[vchan].ring_cntx_idx) {
			DPAA2_QDMA_ERR("DQ response ring alloc failed.");

			return -ENOMEM;
		}
		qdma_dev->vqs[vchan].ring_cntx_idx->start = 0;
		qdma_dev->vqs[vchan].ring_cntx_idx->tail = 0;
		qdma_dev->vqs[vchan].ring_cntx_idx->free_space =
			QDMA_CNTX_IDX_RING_MAX_FREE;
		qdma_dev->vqs[vchan].ring_cntx_idx->nb_in_ring = 0;

		qdma_dev->vqs[vchan].fle_elem = rte_malloc(NULL,
			sizeof(void *) * DPAA2_QDMA_MAX_DESC,
			RTE_CACHE_LINE_SIZE);
	}

	qdma_dev->vqs[vchan].dpdmai_dev = dpdmai_dev;
	qdma_dev->vqs[vchan].nb_desc = conf->nb_desc;

	return 0;
}

static int
dpaa2_qdma_start(struct rte_dma_dev *dev)
{
	struct dpaa2_dpdmai_dev *dpdmai_dev = dev->data->dev_private;
	struct qdma_device *qdma_dev = dpdmai_dev->qdma_dev;

	DPAA2_QDMA_FUNC_TRACE();

	qdma_dev->state = 1;

	return 0;
}

static int
dpaa2_qdma_stop(struct rte_dma_dev *dev)
{
	struct dpaa2_dpdmai_dev *dpdmai_dev = dev->data->dev_private;
	struct qdma_device *qdma_dev = dpdmai_dev->qdma_dev;

	DPAA2_QDMA_FUNC_TRACE();

	qdma_dev->state = 0;

	return 0;
}

static int
dpaa2_qdma_reset(struct rte_dma_dev *dev)
{
	struct dpaa2_dpdmai_dev *dpdmai_dev = dev->data->dev_private;
	struct qdma_device *qdma_dev = dpdmai_dev->qdma_dev;
	int i;

	DPAA2_QDMA_FUNC_TRACE();

	/* In case QDMA device is not in stopped state, return -EBUSY */
	if (qdma_dev->state == 1) {
		DPAA2_QDMA_ERR("%s Not stopped, reset failed.",
			dev->data->dev_name);
		return -EBUSY;
	}

	/* In case there are pending jobs on any VQ, return -EBUSY */
	for (i = 0; i < qdma_dev->num_vqs; i++) {
		if ((qdma_dev->vqs[i].num_enqueues !=
		    qdma_dev->vqs[i].num_dequeues) &&
		    !qdma_dev->is_silent) {
			DPAA2_QDMA_ERR("VQ(%d) pending: eq(%ld) != dq(%ld)",
				i, qdma_dev->vqs[i].num_enqueues,
				qdma_dev->vqs[i].num_dequeues);
			return -EBUSY;
		}
	}

	if (qdma_dev->vqs)
		rte_free(qdma_dev->vqs);
	qdma_dev->vqs = NULL;

	/* Reset QDMA device structure */
	qdma_dev->num_vqs = 0;

	return 0;
}

static int
dpaa2_qdma_close(__rte_unused struct rte_dma_dev *dev)
{
	DPAA2_QDMA_FUNC_TRACE();

	dpaa2_qdma_reset(dev);

	return 0;
}

static int
dpaa2_qdma_stats_get(const struct rte_dma_dev *dmadev, uint16_t vchan,
		    struct rte_dma_stats *rte_stats, uint32_t size)
{
	struct dpaa2_dpdmai_dev *dpdmai_dev = dmadev->data->dev_private;
	struct qdma_device *qdma_dev = dpdmai_dev->qdma_dev;
	struct qdma_virt_queue *qdma_vq = &qdma_dev->vqs[vchan];
	struct rte_dma_stats *stats = &qdma_vq->stats;

	RTE_SET_USED(size);

	/* TODO - directly use stats */
	stats->submitted = qdma_vq->num_enqueues;
	stats->completed = qdma_vq->num_dequeues;
	*rte_stats = *stats;

	return 0;
}

static int
dpaa2_qdma_stats_reset(struct rte_dma_dev *dmadev, uint16_t vchan)
{
	struct dpaa2_dpdmai_dev *dpdmai_dev = dmadev->data->dev_private;
	struct qdma_device *qdma_dev = dpdmai_dev->qdma_dev;
	struct qdma_virt_queue *qdma_vq = &qdma_dev->vqs[vchan];

	qdma_vq->num_enqueues = 0;
	qdma_vq->num_dequeues = 0;

	return 0;
}

static uint16_t
dpaa2_qdma_burst_capacity(const void *dev_private, uint16_t vchan)
{
	const struct dpaa2_dpdmai_dev *dpdmai_dev = dev_private;
	struct qdma_device *qdma_dev = dpdmai_dev->qdma_dev;
	struct qdma_virt_queue *qdma_vq = &qdma_dev->vqs[vchan];

	return qdma_vq->nb_desc - qdma_vq->num_valid_jobs;
}

static struct rte_dma_dev_ops dpaa2_qdma_ops = {
	.dev_info_get     = dpaa2_qdma_info_get,
	.dev_configure    = dpaa2_qdma_configure,
	.dev_start        = dpaa2_qdma_start,
	.dev_stop         = dpaa2_qdma_stop,
	.dev_close        = dpaa2_qdma_close,
	.vchan_setup      = dpaa2_qdma_vchan_setup,
	.stats_get        = dpaa2_qdma_stats_get,
	.stats_reset      = dpaa2_qdma_stats_reset,
};

static int
dpaa2_dpdmai_dev_uninit(struct rte_dma_dev *dev)
{
	struct dpaa2_dpdmai_dev *dpdmai_dev = dev->data->dev_private;
	struct dpaa2_queue *rxq;
	int ret, i;

	DPAA2_QDMA_FUNC_TRACE();

	ret = dpdmai_disable(&dpdmai_dev->dpdmai, CMD_PRI_LOW,
			dpdmai_dev->token);
	if (ret) {
		DPAA2_QDMA_ERR("dpdmai(%d) disable failed",
			dpdmai_dev->dpdmai_id);
	}

	/* Set up the DQRR storage for Rx */
	for (i = 0; i < dpdmai_dev->num_queues; i++) {
		rxq = &dpdmai_dev->rx_queue[i];
		if (rxq->q_storage) {
			dpaa2_free_dq_storage(rxq->q_storage);
			rte_free(rxq->q_storage);
		}
	}

	/* Close the device at underlying layer*/
	ret = dpdmai_close(&dpdmai_dev->dpdmai, CMD_PRI_LOW, dpdmai_dev->token);
	if (ret) {
		DPAA2_QDMA_ERR("dpdmai(%d) close failed",
			dpdmai_dev->dpdmai_id);
	}

	return ret;
}

static int
dpaa2_dpdmai_dev_init(struct rte_dma_dev *dev, int dpdmai_id)
{
	struct dpaa2_dpdmai_dev *dpdmai_dev = dev->data->dev_private;
	struct dpdmai_rx_queue_cfg rx_queue_cfg;
	struct dpdmai_attr attr;
	struct dpdmai_rx_queue_attr rx_attr;
	struct dpdmai_tx_queue_attr tx_attr;
	struct dpaa2_queue *rxq;
	int ret, i;

	DPAA2_QDMA_FUNC_TRACE();

	/* Open DPDMAI device */
	dpdmai_dev->dpdmai_id = dpdmai_id;
	dpdmai_dev->dpdmai.regs = dpaa2_get_mcp_ptr(MC_PORTAL_INDEX);
	dpdmai_dev->qdma_dev = rte_malloc(NULL,
		sizeof(struct qdma_device), RTE_CACHE_LINE_SIZE);
	ret = dpdmai_open(&dpdmai_dev->dpdmai, CMD_PRI_LOW,
			dpdmai_dev->dpdmai_id, &dpdmai_dev->token);
	if (ret) {
		DPAA2_QDMA_ERR("%s: dma(%d) open failed(%d)",
			__func__, dpdmai_dev->dpdmai_id, ret);
		return ret;
	}

	/* Get DPDMAI attributes */
	ret = dpdmai_get_attributes(&dpdmai_dev->dpdmai, CMD_PRI_LOW,
			dpdmai_dev->token, &attr);
	if (ret) {
		DPAA2_QDMA_ERR("%s: dma(%d) get attributes failed(%d)",
			__func__, dpdmai_dev->dpdmai_id, ret);
		goto init_err;
	}
	dpdmai_dev->num_queues = attr.num_of_queues;

	/* Set up Rx Queues */
	for (i = 0; i < dpdmai_dev->num_queues; i++) {
		memset(&rx_queue_cfg, 0, sizeof(struct dpdmai_rx_queue_cfg));
		ret = dpdmai_set_rx_queue(&dpdmai_dev->dpdmai,
				CMD_PRI_LOW,
				dpdmai_dev->token,
				i, 0, &rx_queue_cfg);
		if (ret) {
			DPAA2_QDMA_ERR("%s Q%d set failed(%d)",
				dev->data->dev_name, i, ret);
			goto init_err;
		}

		/* Allocate DQ storage for the DPDMAI Rx queues */
		rxq = &dpdmai_dev->rx_queue[i];
		rxq->q_storage = rte_malloc("dq_storage",
			sizeof(struct queue_storage_info_t),
			RTE_CACHE_LINE_SIZE);
		if (!rxq->q_storage) {
			DPAA2_QDMA_ERR("%s DQ info(Q%d) alloc failed",
				dev->data->dev_name, i);
			ret = -ENOMEM;
			goto init_err;
		}

		memset(rxq->q_storage, 0, sizeof(struct queue_storage_info_t));
		ret = dpaa2_alloc_dq_storage(rxq->q_storage);
		if (ret) {
			DPAA2_QDMA_ERR("%s DQ storage(Q%d) alloc failed(%d)",
				dev->data->dev_name, i, ret);
			goto init_err;
		}
	}

	/* Get Rx and Tx queues FQID's */
	for (i = 0; i < dpdmai_dev->num_queues; i++) {
		ret = dpdmai_get_rx_queue(&dpdmai_dev->dpdmai, CMD_PRI_LOW,
				dpdmai_dev->token, i, 0, &rx_attr);
		if (ret) {
			DPAA2_QDMA_ERR("Get DPDMAI%d-RXQ%d failed(%d)",
				dpdmai_dev->dpdmai_id, i, ret);
			goto init_err;
		}
		dpdmai_dev->rx_queue[i].fqid = rx_attr.fqid;

		ret = dpdmai_get_tx_queue(&dpdmai_dev->dpdmai, CMD_PRI_LOW,
				dpdmai_dev->token, i, 0, &tx_attr);
		if (ret) {
			DPAA2_QDMA_ERR("Get DPDMAI%d-TXQ%d failed(%d)",
				dpdmai_dev->dpdmai_id, i, ret);
			goto init_err;
		}
		dpdmai_dev->tx_queue[i].fqid = tx_attr.fqid;
	}

	/* Enable the device */
	ret = dpdmai_enable(&dpdmai_dev->dpdmai, CMD_PRI_LOW,
			    dpdmai_dev->token);
	if (ret) {
		DPAA2_QDMA_ERR("Enabling device failed with err: %d", ret);
		goto init_err;
	}

	if (!dpaa2_coherent_no_alloc_cache) {
		if (dpaa2_svr_family == SVR_LX2160A) {
			dpaa2_coherent_no_alloc_cache =
				DPAA2_LX2_COHERENT_NO_ALLOCATE_CACHE;
			dpaa2_coherent_alloc_cache =
				DPAA2_LX2_COHERENT_ALLOCATE_CACHE;
		} else {
			dpaa2_coherent_no_alloc_cache =
				DPAA2_COHERENT_NO_ALLOCATE_CACHE;
			dpaa2_coherent_alloc_cache =
				DPAA2_COHERENT_ALLOCATE_CACHE;
		}
	}

	DPAA2_QDMA_DEBUG("Initialized dpdmai object successfully");

	/* Reset the QDMA device */
	ret = dpaa2_qdma_reset(dev);
	if (ret) {
		DPAA2_QDMA_ERR("Resetting QDMA failed");
		goto init_err;
	}

	return 0;
init_err:
	dpaa2_dpdmai_dev_uninit(dev);
	return ret;
}

static int
dpaa2_qdma_probe(struct rte_dpaa2_driver *dpaa2_drv,
	struct rte_dpaa2_device *dpaa2_dev)
{
	struct rte_dma_dev *dmadev;
	int ret;

	DPAA2_QDMA_FUNC_TRACE();

	RTE_SET_USED(dpaa2_drv);

	dmadev = rte_dma_pmd_allocate(dpaa2_dev->device.name,
		rte_socket_id(),
		sizeof(struct dpaa2_dpdmai_dev));
	if (!dmadev) {
		DPAA2_QDMA_ERR("Unable to allocate dmadevice");
		return -EINVAL;
	}

	dpaa2_dev->dmadev = dmadev;
	dmadev->dev_ops = &dpaa2_qdma_ops;
	dmadev->device = &dpaa2_dev->device;
	dmadev->fp_obj->dev_private = dmadev->data->dev_private;
	dmadev->fp_obj->copy = dpaa2_qdma_copy;
	dmadev->fp_obj->copy_sg = dpaa2_qdma_copy_sg;
	dmadev->fp_obj->submit = dpaa2_qdma_submit;
	dmadev->fp_obj->completed = dpaa2_qdma_dequeue;
	dmadev->fp_obj->burst_capacity = dpaa2_qdma_burst_capacity;

	/* Invoke PMD device initialization function */
	ret = dpaa2_dpdmai_dev_init(dmadev, dpaa2_dev->object_id);
	if (ret) {
		rte_dma_pmd_release(dpaa2_dev->device.name);
		return ret;
	}

	dmadev->state = RTE_DMA_DEV_READY;
	return 0;
}

static int
dpaa2_qdma_remove(struct rte_dpaa2_device *dpaa2_dev)
{
	struct rte_dma_dev *dmadev = dpaa2_dev->dmadev;
	int ret;

	DPAA2_QDMA_FUNC_TRACE();

	dpaa2_dpdmai_dev_uninit(dmadev);

	ret = rte_dma_pmd_release(dpaa2_dev->device.name);
	if (ret)
		DPAA2_QDMA_ERR("Device cleanup failed");

	return 0;
}

static struct rte_dpaa2_driver rte_dpaa2_qdma_pmd;

static struct rte_dpaa2_driver rte_dpaa2_qdma_pmd = {
	.drv_flags = RTE_DPAA2_DRV_IOVA_AS_VA,
	.drv_type = DPAA2_QDMA,
	.probe = dpaa2_qdma_probe,
	.remove = dpaa2_qdma_remove,
};

RTE_PMD_REGISTER_DPAA2(dpaa2_qdma, rte_dpaa2_qdma_pmd);
RTE_PMD_REGISTER_PARAM_STRING(dpaa2_qdma,
	"no_prefetch=<int> ");
RTE_LOG_REGISTER_DEFAULT(dpaa_qdma2_logtype, INFO);
