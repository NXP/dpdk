/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018-2022 NXP
 */

#include <string.h>

#include <rte_eal.h>
#include <rte_fslmc.h>
#include <rte_atomic.h>
#include <rte_lcore.h>
#include <rte_rawdev.h>
#include <rte_rawdev_pmd.h>
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

uint32_t dpaa2_coherent_no_alloc_cache;
uint32_t dpaa2_coherent_alloc_cache;

/* QDMA device */
static struct qdma_device q_dev;

/* QDMA H/W queues list */
TAILQ_HEAD(qdma_hw_queue_list, qdma_hw_queue);
static struct qdma_hw_queue_list qdma_queue_list
	= TAILQ_HEAD_INITIALIZER(qdma_queue_list);

/* QDMA per core data */
static struct qdma_per_core_info qdma_core_info[RTE_MAX_LCORE];

static inline int
qdma_populate_fd_pci(phys_addr_t src, phys_addr_t dest,
			uint32_t len, struct qbman_fd *fd,
			struct rte_qdma_rbp *rbp, int ser)
{
	fd->simple_pci.saddr_lo = lower_32_bits((uint64_t) (src));
	fd->simple_pci.saddr_hi = upper_32_bits((uint64_t) (src));

	fd->simple_pci.len_sl = len;

	fd->simple_pci.bmt = 1;
	fd->simple_pci.fmt = 3;
	fd->simple_pci.sl = 1;
	fd->simple_pci.ser = ser;

	fd->simple_pci.sportid = rbp->sportid;	/*pcie 3 */

	fd->simple_pci.svfid = rbp->svfid;
	fd->simple_pci.spfid = rbp->spfid;
	fd->simple_pci.svfa = rbp->svfa;
	fd->simple_pci.dvfid = rbp->dvfid;
	fd->simple_pci.dpfid = rbp->dpfid;
	fd->simple_pci.dvfa = rbp->dvfa;

	fd->simple_pci.srbp = rbp->srbp;
	if (rbp->srbp)
		fd->simple_pci.rdttype = 0;
	else
		fd->simple_pci.rdttype = dpaa2_coherent_alloc_cache;

	/*dest is pcie memory */
	fd->simple_pci.dportid = rbp->dportid;	/*pcie 3 */
	fd->simple_pci.drbp = rbp->drbp;
	if (rbp->drbp)
		fd->simple_pci.wrttype = 0;
	else
		fd->simple_pci.wrttype = dpaa2_coherent_no_alloc_cache;

	fd->simple_pci.daddr_lo = lower_32_bits((uint64_t) (dest));
	fd->simple_pci.daddr_hi = upper_32_bits((uint64_t) (dest));

	return 0;
}

static inline int
qdma_populate_fd_ddr(phys_addr_t src, phys_addr_t dest,
			uint32_t len, struct qbman_fd *fd, int ser)
{
	fd->simple_ddr.saddr_lo = lower_32_bits((uint64_t) (src));
	fd->simple_ddr.saddr_hi = upper_32_bits((uint64_t) (src));

	fd->simple_ddr.len = len;

	fd->simple_ddr.bmt = 1;
	fd->simple_ddr.fmt = 3;
	fd->simple_ddr.sl = 1;
	fd->simple_ddr.ser = ser;
	/**
	 * src If RBP=0 {NS,RDTTYPE[3:0]}: 0_1011
	 * Coherent copy of cacheable memory,
	* lookup in downstream cache, no allocate
	 * on miss
	 */
	fd->simple_ddr.rns = 0;
	fd->simple_ddr.rdttype = dpaa2_coherent_alloc_cache;
	/**
	 * dest If RBP=0 {NS,WRTTYPE[3:0]}: 0_0111
	 * Coherent write of cacheable memory,
	 * lookup in downstream cache, no allocate on miss
	 */
	fd->simple_ddr.wns = 0;
	fd->simple_ddr.wrttype = dpaa2_coherent_no_alloc_cache;

	fd->simple_ddr.daddr_lo = lower_32_bits((uint64_t) (dest));
	fd->simple_ddr.daddr_hi = upper_32_bits((uint64_t) (dest));

	return 0;
}

static inline void
post_populate_sg_fle(struct qbman_fle fle[],
	size_t len)
{
	DPAA2_SET_FLE_LEN(&fle[DPAA2_QDMA_SRC_FLE], len);
	DPAA2_SET_FLE_LEN(&fle[DPAA2_QDMA_DST_FLE], len);
}

static inline void
post_populate_fle(struct qbman_fle fle[],
	uint64_t src, uint64_t dest, size_t len)
{
#ifdef RTE_LIBRTE_DPAA2_USE_PHYS_IOVA
	DPAA2_SET_FLE_ADDR(&fle[DPAA2_QDMA_SRC_FLE], src);
#else
	DPAA2_SET_FLE_ADDR(&fle[DPAA2_QDMA_SRC_FLE],
		DPAA2_VADDR_TO_IOVA(src));
#endif
	DPAA2_SET_FLE_LEN(&fle[DPAA2_QDMA_SRC_FLE], len);

#ifdef RTE_LIBRTE_DPAA2_USE_PHYS_IOVA
	DPAA2_SET_FLE_ADDR(&fle[DPAA2_QDMA_DST_FLE], dest);
#else
	DPAA2_SET_FLE_ADDR(&fle[DPAA2_QDMA_DST_FLE],
		DPAA2_VADDR_TO_IOVA(dest));
#endif
	DPAA2_SET_FLE_LEN(&fle[DPAA2_QDMA_DST_FLE], len);
}


static inline void
populate_fle(struct qbman_fle fle[],
	struct qdma_sdd sdd[], uint64_t sdd_iova,
	struct rte_qdma_rbp *rbp,
	uint64_t src, uint64_t dest, size_t len,
	uint32_t flags, uint32_t fmt)
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
	if (flags & RTE_QDMA_JOB_SRC_PHY) {
		DPAA2_SET_FLE_ADDR(&fle[DPAA2_QDMA_SRC_FLE], src);
#ifdef RTE_LIBRTE_DPAA2_USE_PHYS_IOVA
		DPAA2_SET_FLE_BMT(&fle[DPAA2_QDMA_SRC_FLE]);
#endif
	} else {
		DPAA2_SET_FLE_ADDR(&fle[DPAA2_QDMA_SRC_FLE],
			DPAA2_VADDR_TO_IOVA(src));
	}
	fle[DPAA2_QDMA_SRC_FLE].word4.fmt = fmt;
	DPAA2_SET_FLE_LEN(&fle[DPAA2_QDMA_SRC_FLE], len);

	/* destination frame list to destination buffer */
	if (flags & RTE_QDMA_JOB_DEST_PHY) {
		DPAA2_SET_FLE_ADDR(&fle[DPAA2_QDMA_DST_FLE], dest);
#ifdef RTE_LIBRTE_DPAA2_USE_PHYS_IOVA
		DPAA2_SET_FLE_BMT(&fle[DPAA2_QDMA_DST_FLE]);
#endif
	} else {
		DPAA2_SET_FLE_ADDR(&fle[DPAA2_QDMA_DST_FLE],
			DPAA2_VADDR_TO_IOVA(dest));
	}
	fle[DPAA2_QDMA_DST_FLE].word4.fmt = fmt;
	DPAA2_SET_FLE_LEN(&fle[DPAA2_QDMA_DST_FLE], len);

	/* Final bit: 1, for last frame list */
	DPAA2_SET_FLE_FIN(&fle[DPAA2_QDMA_DST_FLE]);
}

static inline int
dpdmai_dev_set_fd_us(struct qdma_virt_queue *qdma_vq,
	struct qbman_fd *fd, struct rte_qdma_job **job,
	uint16_t nb_jobs)
{
	struct rte_qdma_rbp *rbp = &qdma_vq->rbp;
	struct rte_qdma_job **ppjob;
	size_t iova;
	int ret = 0, loop, total_len = 0, ser;

	if (qdma_vq->flags & RTE_QDMA_VQ_NO_RESPONSE &&
		!(qdma_vq->flags & RTE_QDMA_VQ_NO_RSP_DRAIN))
		ser = 0;
	else
		ser = 1;

	/* TO DO: EP PCIe2PCIe.*/
	RTE_ASSERT(!(rbp->srbp && rbp->drbp));

	for (loop = 0; loop < nb_jobs; loop++) {
		if (rbp->drbp)
			iova = (size_t)job[loop]->src;
		else if (rbp->srbp)
			iova = (size_t)job[loop]->dest;
		else if (job[loop]->src & QDMA_PCIE_BASE_ADDRESS_MASK)
			iova = (size_t)job[loop]->dest;
		else
			iova = (size_t)job[loop]->src;

		/* Set the metadata */
		job[loop]->vq_id = qdma_vq->vq_id;
		ppjob = (struct rte_qdma_job **)DPAA2_IOVA_TO_VADDR(iova) - 1;
		*ppjob = job[loop];
		total_len += job[loop]->len;

		if ((rbp->drbp == 1) || (rbp->srbp == 1))
			ret = qdma_populate_fd_pci((phys_addr_t)job[loop]->src,
							(phys_addr_t)job[loop]->dest,
							job[loop]->len, &fd[loop], rbp, ser);
		else
			ret = qdma_populate_fd_ddr((phys_addr_t)job[loop]->src,
							(phys_addr_t)job[loop]->dest,
							job[loop]->len, &fd[loop], ser);
	}

	return ret < 0 ? ret : total_len;
}

static inline uint32_t
post_populate_sg_entry(struct rte_qdma_job **jobs,
	struct qdma_sg_entry *src_sge, struct qdma_sg_entry *dst_sge,
	uint16_t nb_jobs)
{
	uint16_t i = 0;
	uint32_t total_len = 0;
	uint64_t iova;

	for (i = 0; i < (nb_jobs - 1); i++) {
		/* source SG */
		if (likely(jobs[i]->flags & RTE_QDMA_JOB_SRC_PHY)) {
			src_sge->addr_lo = (uint32_t)jobs[i]->src;
			src_sge->addr_hi = (jobs[i]->src >> 32);
		} else {
			iova = DPAA2_VADDR_TO_IOVA(jobs[i]->src);
			src_sge->addr_lo = (uint32_t)iova;
			src_sge->addr_hi = iova >> 32;
		}
		src_sge->data_len.data_len_sl0 = jobs[i]->len;

		if (likely(jobs[i]->flags & RTE_QDMA_JOB_DEST_PHY)) {
			dst_sge->addr_lo = (uint32_t)jobs[i]->dest;
			dst_sge->addr_hi = (jobs[i]->dest >> 32);
		} else {
			iova = DPAA2_VADDR_TO_IOVA(jobs[i]->dest);
			dst_sge->addr_lo = (uint32_t)iova;
			dst_sge->addr_hi = iova >> 32;
		}
		dst_sge->data_len.data_len_sl0 = jobs[i]->len;
		total_len += jobs[i]->len;

		src_sge->ctrl.f = 0;
		dst_sge->ctrl.f = 0;
		src_sge++;
		dst_sge++;
	}

	if (likely(jobs[i]->flags & RTE_QDMA_JOB_SRC_PHY)) {
		src_sge->addr_lo = (uint32_t)jobs[i]->src;
		src_sge->addr_hi = (jobs[i]->src >> 32);
	} else {
		iova = DPAA2_VADDR_TO_IOVA(jobs[i]->src);
		src_sge->addr_lo = (uint32_t)iova;
		src_sge->addr_hi = iova >> 32;
	}
	src_sge->data_len.data_len_sl0 = jobs[i]->len;

	if (likely(jobs[i]->flags & RTE_QDMA_JOB_DEST_PHY)) {
		dst_sge->addr_lo = (uint32_t)jobs[i]->dest;
		dst_sge->addr_hi = (jobs[i]->dest >> 32);
	} else {
		iova = DPAA2_VADDR_TO_IOVA(jobs[i]->dest);
		dst_sge->addr_lo = (uint32_t)iova;
		dst_sge->addr_hi = iova >> 32;
	}
	dst_sge->data_len.data_len_sl0 = jobs[i]->len;
	total_len += jobs[i]->len;

	src_sge->ctrl.f = QDMA_SG_F;
	dst_sge->ctrl.f = QDMA_SG_F;

	return total_len;
}

static inline uint32_t
populate_sg_entry(struct rte_qdma_job **jobs,
	struct qdma_sg_entry *src_sge,
	struct qdma_sg_entry *dst_sge,
	uint16_t nb_jobs)
{
	uint16_t i;
	uint32_t total_len = 0;
	uint64_t iova;

	for (i = 0; i < nb_jobs; i++) {
		/* source SG */
		if (likely(jobs[i]->flags & RTE_QDMA_JOB_SRC_PHY)) {
			src_sge->addr_lo = (uint32_t)jobs[i]->src;
			src_sge->addr_hi = (jobs[i]->src >> 32);
		} else {
			iova = DPAA2_VADDR_TO_IOVA(jobs[i]->src);
			src_sge->addr_lo = (uint32_t)iova;
			src_sge->addr_hi = iova >> 32;
		}
		src_sge->data_len.data_len_sl0 = jobs[i]->len;
		src_sge->ctrl.sl = QDMA_SG_SL_LONG;
		src_sge->ctrl.fmt = QDMA_SG_FMT_SDB;
#ifdef RTE_LIBRTE_DPAA2_USE_PHYS_IOVA
		src_sge->ctrl.bmt = QDMA_SG_BMT_ENABLE;
#else
		src_sge->ctrl.bmt = QDMA_SG_BMT_DISABLE;
#endif
		/* destination SG */
		if (likely(jobs[i]->flags & RTE_QDMA_JOB_DEST_PHY)) {
			dst_sge->addr_lo = (uint32_t)jobs[i]->dest;
			dst_sge->addr_hi = (jobs[i]->dest >> 32);
		} else {
			iova = DPAA2_VADDR_TO_IOVA(jobs[i]->dest);
			dst_sge->addr_lo = (uint32_t)iova;
			dst_sge->addr_hi = iova >> 32;
		}
		dst_sge->data_len.data_len_sl0 = jobs[i]->len;
		dst_sge->ctrl.sl = QDMA_SG_SL_LONG;
		dst_sge->ctrl.fmt = QDMA_SG_FMT_SDB;
#ifdef RTE_LIBRTE_DPAA2_USE_PHYS_IOVA
		dst_sge->ctrl.bmt = QDMA_SG_BMT_ENABLE;
#else
		dst_sge->ctrl.bmt = QDMA_SG_BMT_DISABLE;
#endif
		total_len += jobs[i]->len;

		if (i == (nb_jobs - 1)) {
			src_sge->ctrl.f = QDMA_SG_F;
			dst_sge->ctrl.f = QDMA_SG_F;
		} else {
			src_sge->ctrl.f = 0;
			dst_sge->ctrl.f = 0;
		}
		src_sge++;
		dst_sge++;
	}

	return total_len;
}

static void
fle_sdd_pre_populate(struct qdma_fle_elem *elem,
	struct rte_qdma_rbp *rbp, uint64_t src, uint64_t dest,
	uint32_t flags, uint32_t fmt)
{
	struct qbman_fle *fle = elem->fle;
	struct qdma_sdd *sdd = elem->sdd;
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
	if (flags & RTE_QDMA_JOB_SRC_PHY) {
		DPAA2_SET_FLE_ADDR(&fle[DPAA2_QDMA_SRC_FLE], src);
		DPAA2_SET_FLE_BMT(&fle[DPAA2_QDMA_SRC_FLE]);
	} else {
		DPAA2_SET_FLE_ADDR(&fle[DPAA2_QDMA_SRC_FLE],
			DPAA2_VADDR_TO_IOVA(src));
	}
	fle[DPAA2_QDMA_SRC_FLE].word4.fmt = fmt;

	/* destination frame list to destination buffer */
	if (flags & RTE_QDMA_JOB_DEST_PHY) {
		DPAA2_SET_FLE_ADDR(&fle[DPAA2_QDMA_DST_FLE], dest);
		DPAA2_SET_FLE_BMT(&fle[DPAA2_QDMA_DST_FLE]);
	} else {
		DPAA2_SET_FLE_ADDR(&fle[DPAA2_QDMA_DST_FLE],
			DPAA2_VADDR_TO_IOVA(dest));
	}
	fle[DPAA2_QDMA_DST_FLE].word4.fmt = fmt;

	/* Final bit: 1, for last frame list */
	DPAA2_SET_FLE_FIN(&fle[DPAA2_QDMA_DST_FLE]);
}

static void
fle_elem_pre_populate(struct qdma_fle_elem *elem,
	struct qdma_virt_queue *qdma_vq)
{
	struct rte_qdma_rbp *rbp = &qdma_vq->rbp;
	uint32_t flags;

	memset(elem, 0, sizeof(struct qdma_fle_elem));

#ifdef RTE_LIBRTE_DPAA2_USE_PHYS_IOVA
	flags = RTE_QDMA_JOB_SRC_PHY | RTE_QDMA_JOB_DEST_PHY;
#else
	flags = 0;
#endif

	fle_sdd_pre_populate(elem, rbp,
		0, 0, flags, QBMAN_FLE_WORD4_FMT_SBF);
}

static inline int
dpdmai_dev_set_fd(struct qdma_virt_queue *qdma_vq,
	struct qbman_fd *fd, struct rte_qdma_job **job,
	uint16_t nb_jobs)
{
	struct rte_qdma_rbp *rbp = &qdma_vq->rbp;
	uint16_t i;
	int ret, total_len = 0;
	struct qdma_fle_elem *elem;
	struct qdma_fle_elem *elems[RTE_QDMA_BURST_NB_MAX];
	struct qbman_fle *fle;
	struct qdma_sdd *sdd;
	uint64_t elem_iova, fle_iova, sdd_iova;

	if (!(qdma_vq->flags & RTE_QDMA_VQ_NO_RESPONSE)) {
		ret = rte_mempool_get_bulk(qdma_vq->fle_pool,
			(void **)elems, nb_jobs);
		if (ret) {
			DPAA2_QDMA_DP_DEBUG("Memory alloc failed for FLE");
			return ret;
		}
	}

	for (i = 0; i < nb_jobs; i++) {
		if (qdma_vq->flags & RTE_QDMA_VQ_NO_RESPONSE) {
			elem = job[i]->usr_elem;
			if (qdma_vq->flags & RTE_QDMA_VQ_NO_RSP_DRAIN)
				DPAA2_SET_FD_FRC(&fd[i], QDMA_SER_CTX);
		} else {
			elem = elems[i];
			elem->single_job = job[i];
			job[i]->vq_id = qdma_vq->vq_id;
			DPAA2_SET_FD_FRC(&fd[i], QDMA_SER_CTX);
		}
		total_len += job[i]->len;
#ifdef RTE_LIBRTE_DPAA2_USE_PHYS_IOVA
		elem_iova = rte_mempool_virt2iova(elem);
#else
		elem_iova = DPAA2_VADDR_TO_IOVA(elem);
#endif

		fle = elem->fle;
		fle_iova = elem_iova +
			offsetof(struct qdma_fle_elem, fle);

		DPAA2_SET_FD_ADDR(&fd[i], fle_iova);
		DPAA2_SET_FD_COMPOUND_FMT(&fd[i]);

		if (qdma_vq->fle_pre_populate) {
			if (unlikely(!fle[DPAA2_QDMA_SRC_FLE].length)) {
				fle_elem_pre_populate(elem, qdma_vq);
				/* Recover dq context.*/
				elem->single_job = job[i];
			}

			post_populate_fle(fle,
				job[i]->src, job[i]->dest,
				job[i]->len);
		} else {
			sdd = elem->sdd;
			sdd_iova = elem_iova +
				offsetof(struct qdma_fle_elem, sdd);
			populate_fle(fle, sdd, sdd_iova, rbp,
				job[i]->src, job[i]->dest, job[i]->len,
				job[i]->flags, QBMAN_FLE_WORD4_FMT_SBF);
		}
	}

	return total_len;
}

static void
sg_entry_pre_populate(struct qdma_fle_sg_elem *elem)
{
	uint16_t i;
	struct qdma_sg_entry *src_sge = elem->sg_src_entry;
	struct qdma_sg_entry *dst_sge = elem->sg_dst_entry;

	for (i = 0; i < DPAA2_QDMA_MAX_SG_NB; i++) {
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
fle_sdd_sg_pre_populate(struct qdma_fle_sg_elem *elem,
	struct qdma_virt_queue *qdma_vq)
{
	struct qdma_sg_entry *src_sge = elem->sg_src_entry;
	struct qdma_sg_entry *dst_sge = elem->sg_dst_entry;
	uint64_t src_sge_iova, dst_sge_iova;
	struct rte_qdma_rbp *rbp = &qdma_vq->rbp;
	uint32_t flags;

	memset(elem, 0, sizeof(struct qdma_fle_sg_elem));

	src_sge_iova = DPAA2_VADDR_TO_IOVA(src_sge);
	dst_sge_iova = DPAA2_VADDR_TO_IOVA(dst_sge);
#ifdef RTE_LIBRTE_DPAA2_USE_PHYS_IOVA
	flags = RTE_QDMA_JOB_SRC_PHY | RTE_QDMA_JOB_DEST_PHY;
#else
	flags = 0;
#endif

	sg_entry_pre_populate(elem);
	fle_sdd_pre_populate(&elem->fle_elem,
		rbp, src_sge_iova, dst_sge_iova,
		flags, QBMAN_FLE_WORD4_FMT_SGE);
}

static inline int
dpdmai_dev_set_sg_fd(struct qdma_virt_queue *qdma_vq,
	struct qbman_fd *fd, struct rte_qdma_job **job,
	uint16_t nb_jobs)
{
	struct qdma_fle_sg_elem *sg_elem;
	struct qdma_fle_elem *fle_elem;
	struct qbman_fle *fle;
	struct qdma_sdd *sdd;
	uint64_t sg_elem_iova, fle_elem_iova;
	uint64_t fle_iova, sdd_iova, src, dst;
	int ret = 0, i;
	struct qdma_sg_entry *src_sge, *dst_sge;
	uint32_t len;

	/*
	 * Get an FLE/SDD from FLE pool.
	 * Note: IO metadata is before the FLE and SDD memory.
	 */
	if (qdma_vq->flags & RTE_QDMA_VQ_NO_RESPONSE) {
		sg_elem = job[0]->usr_elem;
		sg_elem->fle_elem.sg_job_nb_len = 0;
		if (qdma_vq->flags & RTE_QDMA_VQ_NO_RSP_DRAIN)
			DPAA2_SET_FD_FRC(fd, QDMA_SER_CTX);
	} else {
		ret = rte_mempool_get(qdma_vq->fle_pool,
			(void **)&sg_elem);
		if (ret < 0) {
			DPAA2_QDMA_DP_DEBUG("Memory alloc failed for FLE");
			return ret;
		}
		sg_elem->fle_elem.sg_job_nb_len = 0;
		FLE_SG_JOB_SET_NB(sg_elem->fle_elem.sg_job_nb_len,
			nb_jobs);
		for (i = 0; i < nb_jobs; i++)
			sg_elem->sg_jobs[i] = job[i];

		sg_elem->sg_jobs[0]->vq_id = qdma_vq->vq_id;
		DPAA2_SET_FD_FRC(fd, QDMA_SER_CTX);
	}

#ifdef RTE_LIBRTE_DPAA2_USE_PHYS_IOVA
	sg_elem_iova = rte_mempool_virt2iova(sg_elem);
#else
	sg_elem_iova = DPAA2_VADDR_TO_IOVA(sg_elem);
#endif

	fle_elem = &sg_elem->fle_elem;
	fle_elem_iova = sg_elem_iova +
		offsetof(struct qdma_fle_sg_elem, fle_elem);
	fle = fle_elem->fle;
	fle_iova = fle_elem_iova +
			offsetof(struct qdma_fle_elem, fle);

	DPAA2_SET_FD_ADDR(fd, fle_iova);
	DPAA2_SET_FD_COMPOUND_FMT(fd);

	/* Populate FLE */
	src_sge = sg_elem->sg_src_entry;
	dst_sge = sg_elem->sg_dst_entry;
	if (likely(qdma_vq->fle_pre_populate)) {
		if (unlikely(!fle[DPAA2_QDMA_SRC_FLE].length)) {
			fle_sdd_sg_pre_populate(sg_elem, qdma_vq);

			/* Recover sg dq context.*/
			sg_elem->fle_elem.sg_job_nb_len = 0;
			FLE_SG_JOB_SET_NB(sg_elem->fle_elem.sg_job_nb_len,
				nb_jobs);
			for (i = 0; i < nb_jobs; i++)
				sg_elem->sg_jobs[i] = job[i];

			sg_elem->sg_jobs[0]->vq_id = qdma_vq->vq_id;
		}
		len = post_populate_sg_entry(job,
			src_sge, dst_sge, nb_jobs);
		FLE_SG_JOB_SET_SIZE(fle_elem->sg_job_nb_len,
			len);
		post_populate_sg_fle(fle, len);

		return len;
	}

	sdd = fle_elem->sdd;
	sdd_iova = fle_elem_iova +
			offsetof(struct qdma_fle_elem, sdd);
	src = sg_elem_iova +
		offsetof(struct qdma_fle_sg_elem, sg_src_entry);
	dst = sg_elem_iova +
		offsetof(struct qdma_fle_sg_elem, sg_dst_entry);
	len = populate_sg_entry(job, src_sge, dst_sge, nb_jobs);

	FLE_SG_JOB_SET_SIZE(fle_elem->sg_job_nb_len,
		len);

	populate_fle(fle, sdd, sdd_iova,
		&qdma_vq->rbp, src, dst, len,
		RTE_QDMA_JOB_SRC_PHY | RTE_QDMA_JOB_DEST_PHY,
		QBMAN_FLE_WORD4_FMT_SGE);

	return len;
}

static inline uint32_t
dpdmai_dev_get_job_us(__rte_unused struct qdma_virt_queue *qdma_vq,
	const struct qbman_fd *fd, struct rte_qdma_job **job,
	uint16_t *nb_jobs, uint16_t *vqid)
{
	size_t iova;
	struct rte_qdma_job **ppjob;

	if (fd->simple_pci.srbp)
		iova = (size_t)(((uint64_t)fd->simple_pci.daddr_hi) << 32
				| (uint64_t)fd->simple_pci.daddr_lo);
	else if (fd->simple_pci.drbp)
		iova = (size_t)(((uint64_t)fd->simple_pci.saddr_hi) << 32
				| (uint64_t)fd->simple_pci.saddr_lo);
	else if (fd->simple_pci.saddr_hi & (QDMA_PCIE_BASE_ADDRESS_MASK >> 32))
		iova = (size_t)(((uint64_t)fd->simple_pci.daddr_hi) << 32
				| (uint64_t)fd->simple_pci.daddr_lo);
	else
		iova = (size_t)(((uint64_t)fd->simple_pci.saddr_hi) << 32
				| (uint64_t)fd->simple_pci.saddr_lo);

	ppjob = (struct rte_qdma_job **)DPAA2_IOVA_TO_VADDR(iova) - 1;
	*job = (struct rte_qdma_job *)*ppjob;
	(*job)->status = (fd->simple_pci.acc_err << 8) |
					(fd->simple_pci.error);
	*nb_jobs = 1;
	if (vqid)
		*vqid = (*job)->vq_id;

	return (*job)->len;
}

static inline uint32_t
dpdmai_dev_get_job(struct qdma_virt_queue *qdma_vq,
	const struct qbman_fd *fd, struct rte_qdma_job **job,
	uint16_t *nb_jobs, uint16_t *vqid)
{
	struct qbman_fle *fle;
	struct qdma_fle_elem *fle_elem;
	uint16_t status;

	/*
	 * Fetch metadata from FLE. job and vq_id were set
	 * in metadata in the enqueue operation.
	 */
	fle = (struct qbman_fle *)
			DPAA2_IOVA_TO_VADDR(DPAA2_GET_FD_ADDR(fd));
	fle_elem = container_of(fle, struct qdma_fle_elem, fle[0]);

	*nb_jobs = 1;
	*job = fle_elem->single_job;

	status = (DPAA2_GET_FD_ERR(fd) << 8) |
		(DPAA2_GET_FD_FRC(fd) & 0xFF);
	(*job)->status = status;
	if (vqid)
		*vqid = (*job)->vq_id;

	/* Free FLE to the pool */
	rte_mempool_put(qdma_vq->fle_pool, fle_elem);

	return (*job)->len;
}

static inline uint32_t
dpdmai_dev_get_sg_job(struct qdma_virt_queue *qdma_vq,
	const struct qbman_fd *fd, struct rte_qdma_job **job,
	uint16_t *nb_jobs, uint16_t *vqid)
{
	struct qbman_fle *fle;
	struct qdma_fle_elem *fle_elem;
	struct qdma_fle_sg_elem *fle_sg_elem;
	uint16_t i, status;

	/*
	 * Fetch metadata from FLE. job and vq_id were set
	 * in metadata in the enqueue operation.
	 */
	fle = (struct qbman_fle *)
			DPAA2_IOVA_TO_VADDR(DPAA2_GET_FD_ADDR(fd));
	fle_elem = container_of(fle, struct qdma_fle_elem, fle[0]);
	if (qdma_vq->flags & RTE_QDMA_VQ_NO_RSP_DRAIN)
		return FLE_SG_JOB_GET_SIZE(fle_elem->sg_job_nb_len);

	fle_sg_elem = container_of(fle_elem,
		struct qdma_fle_sg_elem, fle_elem);
	*nb_jobs = FLE_SG_JOB_GET_NB(fle_elem->sg_job_nb_len);
	status = (DPAA2_GET_FD_ERR(fd) << 8) |
		(DPAA2_GET_FD_FRC(fd) & 0xFF);

	if (vqid) {
		for (i = 0; i < (*nb_jobs); i++) {
			job[i] = fle_sg_elem->sg_jobs[i];
			job[i]->status = status;
			vqid[i] = job[i]->vq_id;
		}
	} else {
		for (i = 0; i < (*nb_jobs); i++) {
			job[i] = fle_sg_elem->sg_jobs[i];
			job[i]->status = status;
		}
	}

	/* Free FLE to the pool */
	rte_mempool_put(qdma_vq->fle_pool, fle_sg_elem);

	return FLE_SG_JOB_GET_SIZE(fle_elem->sg_job_nb_len);
}

/* Function to receive a QDMA job for a given device and queue*/
static int
dpdmai_dev_dequeue_prefetch(struct qdma_virt_queue *qdma_vq,
	uint16_t *vq_id, struct rte_qdma_job **job,
	uint16_t nb_jobs)
{
	struct qdma_hw_queue *qdma_pq = qdma_vq->hw_queue;
	struct dpaa2_dpdmai_dev *dpdmai_dev = qdma_pq->dpdmai_dev;
	uint16_t rxq_id = qdma_pq->queue_id;

	struct dpaa2_queue *rxq;
	struct qbman_result *dq_storage, *dq_storage1 = NULL;
	struct qbman_pull_desc pulldesc;
	struct qbman_swp *swp;
	struct queue_storage_info_t *q_storage;
	uint32_t fqid, dq_bytes;
	uint8_t status, pending;
	uint8_t num_rx = 0;
	const struct qbman_fd *fd;
	uint16_t num_rx_ret;
	int ret, pull_size;

	if (qdma_vq->flags & RTE_QDMA_VQ_FD_SG_FORMAT) {
		/** Make sure there are enough space to get jobs.*/
		if (unlikely(nb_jobs < DPAA2_QDMA_MAX_SG_NB))
			return -EINVAL;
		nb_jobs = 1;
	}

	if (unlikely(!DPAA2_PER_LCORE_DPIO)) {
		ret = dpaa2_affine_qbman_swp();
		if (ret) {
			DPAA2_QDMA_ERR(
				"Failed to allocate IO portal, tid: %d\n",
				rte_gettid());
			return 0;
		}
	}
	swp = DPAA2_PER_LCORE_PORTAL;

	pull_size = (nb_jobs > dpaa2_dqrr_size) ? dpaa2_dqrr_size : nb_jobs;
	rxq = &(dpdmai_dev->rx_queue[rxq_id]);
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
				DPAA2_QDMA_DP_WARN(
					"VDQ command not issued.QBMAN busy\n");
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

		dq_bytes = qdma_vq->get_job(qdma_vq, fd, &job[num_rx],
					&num_rx_ret, vq_id);
		qdma_vq->bytes_in_dma -= dq_bytes;

		dq_storage++;
		num_rx += num_rx_ret;
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
			DPAA2_QDMA_DP_WARN(
				"VDQ command is not issued. QBMAN is busy (2)\n");
			continue;
		}
		break;
	}

	q_storage->active_dqs = dq_storage1;
	q_storage->active_dpio_id = DPAA2_PER_LCORE_DPIO->index;
	set_swp_active_dqs(DPAA2_PER_LCORE_DPIO->index, dq_storage1);

	return num_rx;
}

static int
dpdmai_dev_dequeue(struct qdma_virt_queue *qdma_vq,
	uint16_t *vq_id, struct rte_qdma_job **job,
	uint16_t nb_jobs)
{
	struct qdma_hw_queue *qdma_pq = qdma_vq->hw_queue;
	struct dpaa2_dpdmai_dev *dpdmai_dev = qdma_pq->dpdmai_dev;
	uint16_t rxq_id = qdma_pq->queue_id;

	struct dpaa2_queue *rxq;
	struct qbman_result *dq_storage;
	struct qbman_pull_desc pulldesc;
	struct qbman_swp *swp;
	uint32_t fqid, dq_bytes;
	uint8_t status, pending;
	uint8_t num_rx = 0;
	const struct qbman_fd *fd;
	uint16_t num_rx_ret;
	int ret, next_pull, num_pulled = 0;

	if (qdma_vq->flags & RTE_QDMA_VQ_FD_SG_FORMAT) {
		/** Make sure there are enough space to get jobs.*/
		if (unlikely(nb_jobs < DPAA2_QDMA_MAX_SG_NB))
			return -EINVAL;
		nb_jobs = 1;
	}

	next_pull = nb_jobs;

	if (unlikely(!DPAA2_PER_LCORE_DPIO)) {
		ret = dpaa2_affine_qbman_swp();
		if (ret) {
			DPAA2_QDMA_ERR(
				"Failed to allocate IO portal, tid: %d\n",
				rte_gettid());
			return 0;
		}
	}
	swp = DPAA2_PER_LCORE_PORTAL;

	rxq = &(dpdmai_dev->rx_queue[rxq_id]);
	fqid = rxq->fqid;

	do {
		dq_storage = rxq->q_storage->dq_storage[0];
		/* Prepare dequeue descriptor */
		qbman_pull_desc_clear(&pulldesc);
		qbman_pull_desc_set_fq(&pulldesc, fqid);
		qbman_pull_desc_set_storage(&pulldesc, dq_storage,
			(uint64_t)(DPAA2_VADDR_TO_IOVA(dq_storage)), 1);

		if (next_pull > dpaa2_dqrr_size) {
			qbman_pull_desc_set_numframes(&pulldesc,
					dpaa2_dqrr_size);
			next_pull -= dpaa2_dqrr_size;
		} else {
			qbman_pull_desc_set_numframes(&pulldesc, next_pull);
			next_pull = 0;
		}

		while (1) {
			if (qbman_swp_pull(swp, &pulldesc)) {
				DPAA2_QDMA_DP_WARN(
					"VDQ command not issued. QBMAN busy");
				/* Portal was busy, try again */
				continue;
			}
			break;
		}

		rte_prefetch0((void *)((size_t)(dq_storage + 1)));
		/* Check if the previous issued command is completed. */
		while (!qbman_check_command_complete(dq_storage))
			;

		num_pulled = 0;
		pending = 1;

		do {
			/* Loop until dq_storage is updated
			 * with new token by QBMAN
			 */
			while (!qbman_check_new_result(dq_storage))
				;
			rte_prefetch0((void *)((size_t)(dq_storage + 2)));

			if (qbman_result_DQ_is_pull_complete(dq_storage)) {
				pending = 0;
				/* Check for valid frame. */
				status = qbman_result_DQ_flags(dq_storage);
				if (unlikely((status &
					QBMAN_DQ_STAT_VALIDFRAME) == 0))
					continue;
			}
			fd = qbman_result_DQ_fd(dq_storage);

			dq_bytes = qdma_vq->get_job(qdma_vq, fd,
					&job[num_rx], &num_rx_ret, vq_id);
			qdma_vq->bytes_in_dma -= dq_bytes;

			dq_storage++;
			num_rx += num_rx_ret;
			num_pulled++;

		} while (pending);
	/* Last VDQ provided all packets and more packets are requested */
	} while (next_pull && num_pulled == dpaa2_dqrr_size);

	return num_rx;
}

static int
dpdmai_dev_enqueue(struct qdma_virt_queue *qdma_vq,
	struct rte_qdma_job **job, uint16_t nb_jobs)
{
	struct qdma_hw_queue *qdma_pq = qdma_vq->hw_queue;
	struct dpaa2_dpdmai_dev *dpdmai_dev = qdma_pq->dpdmai_dev;
	uint16_t txq_id = qdma_pq->queue_id;

	struct qbman_fd fd[RTE_QDMA_BURST_NB_MAX];
	uint32_t eq_len[RTE_QDMA_BURST_NB_MAX];
	struct dpaa2_queue *txq;
	struct qbman_eq_desc eqdesc;
	struct qbman_swp *swp;
	int ret, loop;
	uint32_t num_to_send = 0;
	uint16_t num_tx = 0;
	uint32_t enqueue_loop, retry_count;

	if (unlikely(!DPAA2_PER_LCORE_DPIO)) {
		ret = dpaa2_affine_qbman_swp();
		if (ret) {
			DPAA2_QDMA_ERR(
				"Failed to allocate IO portal, tid: %d\n",
				rte_gettid());
			return 0;
		}
	}
	swp = DPAA2_PER_LCORE_PORTAL;

	txq = &(dpdmai_dev->tx_queue[txq_id]);

	/* Prepare enqueue descriptor */
	qbman_eq_desc_clear(&eqdesc);
	qbman_eq_desc_set_fq(&eqdesc, txq->fqid);
	qbman_eq_desc_set_no_orp(&eqdesc, 0);
	qbman_eq_desc_set_response(&eqdesc, 0, 0);

	if (qdma_vq->flags & RTE_QDMA_VQ_FD_SG_FORMAT) {
		uint16_t fd_nb;
		uint16_t sg_entry_nb = nb_jobs > DPAA2_QDMA_MAX_SG_NB ?
								DPAA2_QDMA_MAX_SG_NB : nb_jobs;
		uint16_t job_idx = 0;
		uint16_t fd_sg_nb[8];
		uint16_t nb_jobs_ret = 0;

		if (nb_jobs % DPAA2_QDMA_MAX_SG_NB)
			fd_nb = nb_jobs / DPAA2_QDMA_MAX_SG_NB + 1;
		else
			fd_nb = nb_jobs / DPAA2_QDMA_MAX_SG_NB;

		memset(&fd[0], 0, sizeof(struct qbman_fd) * fd_nb);

		for (loop = 0; loop < fd_nb; loop++) {
			ret = qdma_vq->set_fd(qdma_vq, &fd[loop], &job[job_idx],
								sg_entry_nb);
			if (unlikely(ret < 0))
				return 0;
			fd_sg_nb[loop] = sg_entry_nb;
			eq_len[loop] = ret;

			nb_jobs -= sg_entry_nb;
			job_idx += sg_entry_nb;
			sg_entry_nb = nb_jobs > DPAA2_QDMA_MAX_SG_NB ?
							DPAA2_QDMA_MAX_SG_NB : nb_jobs;
		}

		/* Enqueue the packet to the QBMAN */
		enqueue_loop = 0; retry_count = 0;

		while (enqueue_loop < fd_nb) {
			ret = qbman_swp_enqueue_multiple(swp,
					&eqdesc, &fd[enqueue_loop],
					NULL, fd_nb - enqueue_loop);
			if (unlikely(ret < 0)) {
				retry_count++;
				if (retry_count > DPAA2_MAX_TX_RETRY_COUNT)
					return nb_jobs_ret;
			} else {
				for (loop = 0; loop < ret; loop++) {
					nb_jobs_ret += fd_sg_nb[enqueue_loop + loop];
					qdma_vq->bytes_in_dma +=
						eq_len[enqueue_loop + loop];
				}
				enqueue_loop += ret;
				retry_count = 0;
			}
		}

		return nb_jobs_ret;
	}

	memset(fd, 0, nb_jobs * sizeof(struct qbman_fd));

	while (nb_jobs > 0) {
		num_to_send = (nb_jobs > dpaa2_eqcr_size) ?
			dpaa2_eqcr_size : nb_jobs;

		ret = qdma_vq->set_fd(qdma_vq, &fd[num_tx],
						&job[num_tx], num_to_send);
		if (unlikely(ret < 0))
			break;

		/* Enqueue the packet to the QBMAN */
		enqueue_loop = 0; retry_count = 0;
		loop = num_to_send;

		while ((int)enqueue_loop < loop) {
			ret = qbman_swp_enqueue_multiple(swp,
						&eqdesc,
						&fd[num_tx + enqueue_loop],
						NULL,
						loop - enqueue_loop);
			if (unlikely(ret < 0)) {
				retry_count++;
				if (retry_count > DPAA2_MAX_TX_RETRY_COUNT)
					return num_tx;
			} else {
				int eq_idx;
				struct rte_qdma_job **job_start;

				job_start = &job[num_tx + enqueue_loop];
				for (eq_idx = 0; eq_idx < ret; eq_idx++) {
					qdma_vq->bytes_in_dma +=
						job_start[eq_idx]->len;
				}
				enqueue_loop += ret;
				retry_count = 0;
			}
		}
		num_tx += num_to_send;
		nb_jobs -= loop;
	}
	return num_tx;
}

static struct qdma_hw_queue *
alloc_hw_queue(uint32_t lcore_id)
{
	struct qdma_hw_queue *queue = NULL;

	DPAA2_QDMA_FUNC_TRACE();

	/* Get a free queue from the list */
	TAILQ_FOREACH(queue, &qdma_queue_list, next) {
		if (queue->num_users == 0) {
			queue->lcore_id = lcore_id;
			queue->num_users++;
			break;
		}
	}

	return queue;
}

static void
free_hw_queue(struct qdma_hw_queue *queue)
{
	DPAA2_QDMA_FUNC_TRACE();

	queue->num_users--;
}


static struct qdma_hw_queue *
get_hw_queue(struct qdma_device *qdma_dev, uint32_t lcore_id)
{
	struct qdma_per_core_info *core_info;
	struct qdma_hw_queue *queue, *temp;
	uint32_t least_num_users;
	int num_hw_queues, i;

	DPAA2_QDMA_FUNC_TRACE();

	core_info = &qdma_core_info[lcore_id];
	num_hw_queues = core_info->num_hw_queues;

	/*
	 * Allocate a HW queue if there are less queues
	 * than maximum per core queues configured
	 */
	if (num_hw_queues < qdma_dev->max_hw_queues_per_core) {
		queue = alloc_hw_queue(lcore_id);
		if (queue) {
			core_info->hw_queues[num_hw_queues] = queue;
			core_info->num_hw_queues++;
			return queue;
		}
	}

	queue = core_info->hw_queues[0];
	/* In case there is no queue associated with the core return NULL */
	if (!queue)
		return NULL;

	/* Fetch the least loaded H/W queue */
	least_num_users = core_info->hw_queues[0]->num_users;
	for (i = 0; i < num_hw_queues; i++) {
		temp = core_info->hw_queues[i];
		if (temp->num_users < least_num_users)
			queue = temp;
	}

	if (queue)
		queue->num_users++;

	return queue;
}

static void
put_hw_queue(struct qdma_hw_queue *queue)
{
	struct qdma_per_core_info *core_info;
	int lcore_id, num_hw_queues, i;

	DPAA2_QDMA_FUNC_TRACE();

	/*
	 * If this is the last user of the queue free it.
	 * Also remove it from QDMA core info.
	 */
	if (queue->num_users == 1) {
		free_hw_queue(queue);

		/* Remove the physical queue from core info */
		lcore_id = queue->lcore_id;
		core_info = &qdma_core_info[lcore_id];
		num_hw_queues = core_info->num_hw_queues;
		for (i = 0; i < num_hw_queues; i++) {
			if (queue == core_info->hw_queues[i])
				break;
		}
		for (; i < num_hw_queues - 1; i++)
			core_info->hw_queues[i] = core_info->hw_queues[i + 1];
		core_info->hw_queues[i] = NULL;
	} else {
		queue->num_users--;
	}
}

static int
dpaa2_qdma_attr_get(struct rte_rawdev *rawdev,
		    __rte_unused const char *attr_name,
		    uint64_t *attr_value)
{
	struct dpaa2_dpdmai_dev *dpdmai_dev = rawdev->dev_private;
	struct qdma_device *qdma_dev = dpdmai_dev->qdma_dev;
	struct rte_qdma_attr *qdma_attr = (struct rte_qdma_attr *)attr_value;

	DPAA2_QDMA_FUNC_TRACE();

	qdma_attr->num_hw_queues = qdma_dev->num_hw_queues;

	return 0;
}

static int
dpaa2_qdma_reset(struct rte_rawdev *rawdev)
{
	struct qdma_hw_queue *queue;
	struct dpaa2_dpdmai_dev *dpdmai_dev = rawdev->dev_private;
	struct qdma_device *qdma_dev = dpdmai_dev->qdma_dev;
	int i;

	DPAA2_QDMA_FUNC_TRACE();

	/* In case QDMA device is not in stopped state, return -EBUSY */
	if (qdma_dev->state == 1) {
		DPAA2_QDMA_ERR(
			"Device is in running state. Stop before reset.");
		return -EBUSY;
	}

	/* In case there are pending jobs on any VQ, return -EBUSY */
	for (i = 0; i < qdma_dev->max_vqs; i++) {
		if (qdma_dev->vqs[i].in_use && (qdma_dev->vqs[i].num_enqueues !=
		    qdma_dev->vqs[i].num_dequeues)) {
			DPAA2_QDMA_ERR("Jobs are still pending on VQ: %d", i);
			return -EBUSY;
		}
	}

	/* Reset HW queues */
	TAILQ_FOREACH(queue, &qdma_queue_list, next)
		queue->num_users = 0;

	/* Reset and free virtual queues */
	for (i = 0; i < qdma_dev->max_vqs; i++) {
		if (qdma_dev->vqs[i].status_ring)
			rte_ring_free(qdma_dev->vqs[i].status_ring);
	}
	if (qdma_dev->vqs)
		rte_free(qdma_dev->vqs);
	qdma_dev->vqs = NULL;

	/* Reset per core info */
	memset(&qdma_core_info, 0,
		sizeof(struct qdma_per_core_info) * RTE_MAX_LCORE);

	/* Reset QDMA device structure */
	qdma_dev->max_hw_queues_per_core = 0;
	qdma_dev->fle_queue_pool_cnt = 0;
	qdma_dev->max_vqs = 0;

	return 0;
}

static int
dpaa2_qdma_configure(const struct rte_rawdev *rawdev,
			 rte_rawdev_obj_t config)
{
	char name[32]; /* RTE_MEMZONE_NAMESIZE = 32 */
	struct rte_qdma_config *qdma_config = (struct rte_qdma_config *)config;
	struct dpaa2_dpdmai_dev *dpdmai_dev = rawdev->dev_private;
	struct qdma_device *qdma_dev = dpdmai_dev->qdma_dev;
	uint16_t i;

	DPAA2_QDMA_FUNC_TRACE();

	/* In case QDMA device is not in stopped state, return -EBUSY */
	if (qdma_dev->state == 1) {
		DPAA2_QDMA_ERR(
			"Device is in running state. Stop before config.");
		return -1;
	}

	/* Set max HW queue per core */
	if (qdma_config->max_hw_queues_per_core > MAX_HW_QUEUE_PER_CORE) {
		DPAA2_QDMA_ERR("H/W queues per core is more than: %d",
			       MAX_HW_QUEUE_PER_CORE);
		return -EINVAL;
	}
	qdma_dev->max_hw_queues_per_core =
		qdma_config->max_hw_queues_per_core;

	/* Allocate Virtual Queues */
	sprintf(name, "qdma_%d_vq", rawdev->dev_id);
	qdma_dev->vqs = rte_zmalloc(name,
			(sizeof(struct qdma_virt_queue) * qdma_config->max_vqs),
			RTE_CACHE_LINE_SIZE);
	if (!qdma_dev->vqs) {
		DPAA2_QDMA_ERR("qdma_virtual_queues allocation failed");
		return -ENOMEM;
	}
	for (i = 0; i < qdma_config->max_vqs; i++)
		qdma_dev->vqs[i].vq_id = i;
	qdma_dev->max_vqs = qdma_config->max_vqs;
	qdma_dev->fle_queue_pool_cnt = qdma_config->fle_queue_pool_cnt;

	return 0;
}

static int
dpaa2_qdma_start(struct rte_rawdev *rawdev)
{
	struct dpaa2_dpdmai_dev *dpdmai_dev = rawdev->dev_private;
	struct qdma_device *qdma_dev = dpdmai_dev->qdma_dev;

	DPAA2_QDMA_FUNC_TRACE();

	qdma_dev->state = 1;

	return 0;
}

static int
check_devargs_handler(__rte_unused const char *key, const char *value,
		      __rte_unused void *opaque)
{
	if (strcmp(value, "1"))
		return -1;

	return 0;
}

static int
dpaa2_get_devargs(struct rte_devargs *devargs, const char *key)
{
	struct rte_kvargs *kvlist;

	if (!devargs)
		return 0;

	kvlist = rte_kvargs_parse(devargs->args, NULL);
	if (!kvlist)
		return 0;

	if (!rte_kvargs_count(kvlist, key)) {
		rte_kvargs_free(kvlist);
		return 0;
	}

	if (rte_kvargs_process(kvlist, key,
			       check_devargs_handler, NULL) < 0) {
		rte_kvargs_free(kvlist);
		return 0;
	}
	rte_kvargs_free(kvlist);

	return 1;
}

static void
fle_pool_elem_init(__rte_unused struct rte_mempool *mempool,
	void *arg, void *element, __rte_unused unsigned int n)
{
	uint32_t *psize = arg;

	RTE_ASSERT((*psize) == sizeof(struct qdma_fle_elem) ||
		(*psize) == sizeof(struct qdma_fle_sg_elem));
	memset(element, 0, *psize);
}

static int
dpaa2_qdma_fle_pool_init(struct qdma_virt_queue *vq,
	uint32_t count)
{
	char pool_name[64];
	uint32_t pool_size;
	char *fle_prepare_env = NULL;

	fle_prepare_env = getenv("DPAA2_QDMA_FLE_PRE_POPULATE");

	if (fle_prepare_env ||
		vq->flags & RTE_QDMA_VQ_FLE_PRE_POPULATE)
		vq->fle_pre_populate = 1;
	else
		vq->fle_pre_populate = 0;

	if (vq->flags & RTE_QDMA_VQ_FD_SG_FORMAT) {
		if (!(vq->flags & RTE_QDMA_VQ_EXCLUSIVE_PQ)) {
			DPAA2_QDMA_ERR("SG format only supports PQ");
			return -ENODEV;
		}
		if (!(vq->flags & RTE_QDMA_VQ_FD_LONG_FORMAT)) {
			DPAA2_QDMA_ERR("SG format only supports FLE");
			return -ENODEV;
		}
		pool_size = sizeof(struct qdma_fle_sg_elem);
	} else {
		pool_size = sizeof(struct qdma_fle_elem);
	}

	if (!(vq->flags & RTE_QDMA_VQ_NO_RESPONSE)) {
		snprintf(pool_name, sizeof(pool_name),
			"qdma_fle_pool%u_queue%d", getpid(), vq->vq_id);
		vq->fle_pool = rte_mempool_create(pool_name,
			count, pool_size,
			QDMA_FLE_CACHE_SIZE(count),
			0, NULL, NULL, fle_pool_elem_init, &pool_size,
			SOCKET_ID_ANY, 0);
		if (!vq->fle_pool) {
			DPAA2_QDMA_ERR("qdma_fle_pool %s create for failed",
				pool_name);
			return -ENOMEM;
		}
	}

	return 0;
}

static int
dpaa2_qdma_queue_setup(struct rte_rawdev *rawdev,
			  __rte_unused uint16_t queue_id,
			  rte_rawdev_obj_t queue_conf)
{
	char ring_name[32];
	int i, ret;
	struct dpaa2_dpdmai_dev *dpdmai_dev = rawdev->dev_private;
	struct qdma_device *qdma_dev = dpdmai_dev->qdma_dev;
	struct rte_qdma_queue_config *q_config =
		(struct rte_qdma_queue_config *)queue_conf;

	DPAA2_QDMA_FUNC_TRACE();

	rte_spinlock_lock(&qdma_dev->lock);

	/* Get a free Virtual Queue */
	for (i = 0; i < qdma_dev->max_vqs; i++) {
		if (qdma_dev->vqs[i].in_use == 0)
			break;
	}

	/* Return in case no VQ is free */
	if (i == qdma_dev->max_vqs) {
		rte_spinlock_unlock(&qdma_dev->lock);
		DPAA2_QDMA_ERR("Unable to get lock on QDMA device");
		return -ENODEV;
	}

	if (q_config->flags & RTE_QDMA_VQ_EXCLUSIVE_PQ) {
		/* Allocate HW queue for a VQ */
		qdma_dev->vqs[i].hw_queue = alloc_hw_queue(q_config->lcore_id);
		qdma_dev->vqs[i].exclusive_hw_queue = 1;
	} else {
		/* Allocate a Ring for Virutal Queue in VQ mode */
		snprintf(ring_name, sizeof(ring_name), "status ring %d", i);
		qdma_dev->vqs[i].status_ring = rte_ring_create(ring_name,
			qdma_dev->fle_queue_pool_cnt, rte_socket_id(), 0);
		if (!qdma_dev->vqs[i].status_ring) {
			DPAA2_QDMA_ERR("Status ring creation failed for vq");
			rte_spinlock_unlock(&qdma_dev->lock);
			return rte_errno;
		}

		/* Get a HW queue (shared) for a VQ */
		qdma_dev->vqs[i].hw_queue = get_hw_queue(qdma_dev,
						    q_config->lcore_id);
		qdma_dev->vqs[i].exclusive_hw_queue = 0;
	}

	if (qdma_dev->vqs[i].hw_queue == NULL) {
		DPAA2_QDMA_ERR("No H/W queue available for VQ");
		if (qdma_dev->vqs[i].status_ring)
			rte_ring_free(qdma_dev->vqs[i].status_ring);
		qdma_dev->vqs[i].status_ring = NULL;
		rte_spinlock_unlock(&qdma_dev->lock);
		return -ENODEV;
	}

	qdma_dev->vqs[i].flags = q_config->flags;
	qdma_dev->vqs[i].in_use = 1;
	qdma_dev->vqs[i].lcore_id = q_config->lcore_id;
	memset(&qdma_dev->vqs[i].rbp, 0, sizeof(struct rte_qdma_rbp));

	if (q_config->rbp != NULL) {
		memcpy(&qdma_dev->vqs[i].rbp, q_config->rbp,
			sizeof(struct rte_qdma_rbp));
	}

	if (q_config->flags & RTE_QDMA_VQ_FD_LONG_FORMAT) {
		ret = dpaa2_qdma_fle_pool_init(&qdma_dev->vqs[i],
			qdma_dev->fle_queue_pool_cnt);
		if (ret) {
			rte_spinlock_unlock(&qdma_dev->lock);
			return ret;
		}
		if (q_config->flags & RTE_QDMA_VQ_FD_SG_FORMAT) {
			qdma_dev->vqs[i].set_fd = dpdmai_dev_set_sg_fd;
			qdma_dev->vqs[i].get_job = dpdmai_dev_get_sg_job;
		} else {
			qdma_dev->vqs[i].set_fd = dpdmai_dev_set_fd;
			qdma_dev->vqs[i].get_job = dpdmai_dev_get_job;
		}
	} else {
		qdma_dev->vqs[i].set_fd = dpdmai_dev_set_fd_us;
		qdma_dev->vqs[i].get_job = dpdmai_dev_get_job_us;
	}

	if (dpaa2_get_devargs(rawdev->device->devargs,
			DPAA2_QDMA_NO_PREFETCH) ||
			(getenv("DPAA2_NO_QDMA_PREFETCH_RX"))) {
		/* If no prefetch is configured. */
		qdma_dev->vqs[i].dequeue_job =
				dpdmai_dev_dequeue;
		DPAA2_QDMA_INFO("No Prefetch RX Mode enabled");
	} else {
		qdma_dev->vqs[i].dequeue_job =
			dpdmai_dev_dequeue_prefetch;
	}

	qdma_dev->vqs[i].enqueue_job = dpdmai_dev_enqueue;

	rte_spinlock_unlock(&qdma_dev->lock);

	return i;
}

static int
dpaa2_qdma_enqueue(struct rte_rawdev *rawdev,
		  __rte_unused struct rte_rawdev_buf **buffers,
		  unsigned int nb_jobs,
		  rte_rawdev_obj_t context)
{
	struct dpaa2_dpdmai_dev *dpdmai_dev = rawdev->dev_private;
	struct rte_qdma_enqdeq *e_context =
		(struct rte_qdma_enqdeq *)context;
	struct qdma_virt_queue *qdma_vq =
		&dpdmai_dev->qdma_dev->vqs[e_context->vq_id];
	int ret;

	ret = qdma_vq->enqueue_job(qdma_vq, e_context->job, nb_jobs);
	if (ret < 0) {
		DPAA2_QDMA_ERR("DPDMAI device enqueue failed: %d", ret);
		return ret;
	}

	qdma_vq->num_enqueues += ret;

	return ret;
}

static int
dpaa2_qdma_dequeue(struct rte_rawdev *rawdev,
		   __rte_unused struct rte_rawdev_buf **buffers,
		   unsigned int nb_jobs,
		   rte_rawdev_obj_t cntxt)
{
	struct dpaa2_dpdmai_dev *dpdmai_dev = rawdev->dev_private;
	struct qdma_device *qdma_dev = dpdmai_dev->qdma_dev;
	struct rte_qdma_enqdeq *context =
		(struct rte_qdma_enqdeq *)cntxt;
	struct qdma_virt_queue *qdma_vq = &qdma_dev->vqs[context->vq_id];
	struct qdma_virt_queue *temp_qdma_vq;
	int ret = 0, i;
	unsigned int ring_count;

	if (qdma_vq->flags & RTE_QDMA_VQ_FD_SG_FORMAT) {
		/** Make sure there are enough space to get jobs.*/
		if (unlikely(nb_jobs < DPAA2_QDMA_MAX_SG_NB))
			return -EINVAL;
	}

	/* Only dequeue when there are pending jobs on VQ */
	if (qdma_vq->num_enqueues == qdma_vq->num_dequeues)
		return 0;

	if (!(qdma_vq->flags & RTE_QDMA_VQ_FD_SG_FORMAT) &&
		qdma_vq->num_enqueues < (qdma_vq->num_dequeues + nb_jobs))
		nb_jobs = (qdma_vq->num_enqueues - qdma_vq->num_dequeues);

	if (qdma_vq->exclusive_hw_queue) {
		/* In case of exclusive queue directly fetch from HW queue */
		ret = qdma_vq->dequeue_job(qdma_vq, NULL,
					context->job, nb_jobs);
		if (ret < 0) {
			DPAA2_QDMA_ERR(
				"Dequeue from DPDMAI device failed: %d", ret);
			return ret;
		}
		qdma_vq->num_dequeues += ret;
	} else {
		uint16_t temp_vq_id[RTE_QDMA_BURST_NB_MAX];
		/*
		 * Get the QDMA completed jobs from the software ring.
		 * In case they are not available on the ring poke the HW
		 * to fetch completed jobs from corresponding HW queues
		 */
		ring_count = rte_ring_count(qdma_vq->status_ring);
		if (ring_count < nb_jobs) {
			/* TODO - How to have right budget */
			ret = qdma_vq->dequeue_job(qdma_vq,
					temp_vq_id, context->job, nb_jobs);
			for (i = 0; i < ret; i++) {
				temp_qdma_vq = &qdma_dev->vqs[temp_vq_id[i]];
				rte_ring_enqueue(temp_qdma_vq->status_ring,
					(void *)(context->job[i]));
			}
			ring_count = rte_ring_count(
					qdma_vq->status_ring);
		}

		if (ring_count) {
			/* Dequeue job from the software ring
			 * to provide to the user
			 */
			ret = rte_ring_dequeue_bulk(qdma_vq->status_ring,
						    (void **)context->job,
						    ring_count, NULL);
			if (ret)
				qdma_vq->num_dequeues += ret;
		}
	}

	return ret;
}

void
rte_qdma_vq_stats(struct rte_rawdev *rawdev,
		uint16_t vq_id,
		struct rte_qdma_vq_stats *vq_status)
{
	struct dpaa2_dpdmai_dev *dpdmai_dev = rawdev->dev_private;
	struct qdma_device *qdma_dev = dpdmai_dev->qdma_dev;
	struct qdma_virt_queue *qdma_vq = &qdma_dev->vqs[vq_id];

	if (qdma_vq->in_use) {
		vq_status->exclusive_hw_queue = qdma_vq->exclusive_hw_queue;
		vq_status->lcore_id = qdma_vq->lcore_id;
		vq_status->num_enqueues = qdma_vq->num_enqueues;
		vq_status->num_dequeues = qdma_vq->num_dequeues;
		vq_status->num_pending_jobs = vq_status->num_enqueues -
				vq_status->num_dequeues;
	}
}

static int
dpaa2_qdma_queue_release(struct rte_rawdev *rawdev,
			 uint16_t vq_id)
{
	struct dpaa2_dpdmai_dev *dpdmai_dev = rawdev->dev_private;
	struct qdma_device *qdma_dev = dpdmai_dev->qdma_dev;

	struct qdma_virt_queue *qdma_vq = &qdma_dev->vqs[vq_id];

	DPAA2_QDMA_FUNC_TRACE();

	/* In case there are pending jobs on any VQ, return -EBUSY */
	if (qdma_vq->num_enqueues != qdma_vq->num_dequeues)
		return -EBUSY;

	rte_spinlock_lock(&qdma_dev->lock);

	if (qdma_vq->exclusive_hw_queue)
		free_hw_queue(qdma_vq->hw_queue);
	else {
		if (qdma_vq->status_ring)
			rte_ring_free(qdma_vq->status_ring);

		put_hw_queue(qdma_vq->hw_queue);
	}

	if (qdma_vq->fle_pool)
		rte_mempool_free(qdma_vq->fle_pool);

	memset(qdma_vq, 0, sizeof(struct qdma_virt_queue));

	rte_spinlock_unlock(&qdma_dev->lock);

	return 0;
}

static void
dpaa2_qdma_stop(struct rte_rawdev *rawdev)
{
	struct dpaa2_dpdmai_dev *dpdmai_dev = rawdev->dev_private;
	struct qdma_device *qdma_dev = dpdmai_dev->qdma_dev;

	DPAA2_QDMA_FUNC_TRACE();

	qdma_dev->state = 0;
}

static int
dpaa2_qdma_close(struct rte_rawdev *rawdev)
{
	DPAA2_QDMA_FUNC_TRACE();

	dpaa2_qdma_reset(rawdev);

	return 0;
}

static int
dpaa2_qdma_xstats_get(const struct rte_rawdev *rawdev,
	__rte_unused const unsigned int ids[],
	uint64_t values[], __rte_unused unsigned int n)
{
	struct dpaa2_dpdmai_dev *dpdmai_dev = rawdev->dev_private;
	struct qdma_device *qdma_dev = dpdmai_dev->qdma_dev;
	int i;

	values[0] = 0;
	for (i = 0; i < qdma_dev->max_vqs; i++) {
		if (!qdma_dev->vqs[i].in_use)
			break;
		values[0] += qdma_dev->vqs[i].bytes_in_dma;
	}

	return 1;
}

static struct rte_rawdev_ops dpaa2_qdma_ops = {
	.dev_configure            = dpaa2_qdma_configure,
	.dev_start                = dpaa2_qdma_start,
	.dev_stop                 = dpaa2_qdma_stop,
	.dev_reset                = dpaa2_qdma_reset,
	.dev_close                = dpaa2_qdma_close,
	.queue_setup		  = dpaa2_qdma_queue_setup,
	.queue_release		  = dpaa2_qdma_queue_release,
	.attr_get		  = dpaa2_qdma_attr_get,
	.enqueue_bufs		  = dpaa2_qdma_enqueue,
	.dequeue_bufs		  = dpaa2_qdma_dequeue,
	.xstats_get = dpaa2_qdma_xstats_get,
};

static int
add_hw_queues_to_list(struct dpaa2_dpdmai_dev *dpdmai_dev)
{
	struct qdma_hw_queue *queue;
	int i;

	DPAA2_QDMA_FUNC_TRACE();

	for (i = 0; i < dpdmai_dev->num_queues; i++) {
		queue = rte_zmalloc(NULL, sizeof(struct qdma_hw_queue), 0);
		if (!queue) {
			DPAA2_QDMA_ERR(
				"Memory allocation failed for QDMA queue");
			return -ENOMEM;
		}

		queue->dpdmai_dev = dpdmai_dev;
		queue->queue_id = i;

		TAILQ_INSERT_TAIL(&qdma_queue_list, queue, next);
		dpdmai_dev->qdma_dev->num_hw_queues++;
	}

	return 0;
}

static void
remove_hw_queues_from_list(struct dpaa2_dpdmai_dev *dpdmai_dev)
{
	struct qdma_hw_queue *queue = NULL;
	struct qdma_hw_queue *tqueue = NULL;

	DPAA2_QDMA_FUNC_TRACE();

	TAILQ_FOREACH_SAFE(queue, &qdma_queue_list, next, tqueue) {
		if (queue->dpdmai_dev == dpdmai_dev) {
			TAILQ_REMOVE(&qdma_queue_list, queue, next);
			rte_free(queue);
			queue = NULL;
		}
	}
}

static int
dpaa2_dpdmai_dev_uninit(struct rte_rawdev *rawdev)
{
	struct dpaa2_dpdmai_dev *dpdmai_dev = rawdev->dev_private;
	int ret, i;

	DPAA2_QDMA_FUNC_TRACE();

	/* Remove HW queues from global list */
	remove_hw_queues_from_list(dpdmai_dev);

	ret = dpdmai_disable(&dpdmai_dev->dpdmai, CMD_PRI_LOW,
			     dpdmai_dev->token);
	if (ret)
		DPAA2_QDMA_ERR("dmdmai disable failed");

	/* Set up the DQRR storage for Rx */
	for (i = 0; i < dpdmai_dev->num_queues; i++) {
		struct dpaa2_queue *rxq = &(dpdmai_dev->rx_queue[i]);

		if (rxq->q_storage) {
			dpaa2_free_dq_storage(rxq->q_storage);
			rte_free(rxq->q_storage);
		}
	}

	/* Close the device at underlying layer*/
	ret = dpdmai_close(&dpdmai_dev->dpdmai, CMD_PRI_LOW, dpdmai_dev->token);
	if (ret)
		DPAA2_QDMA_ERR("Failure closing dpdmai device");

	return 0;
}

static int
dpaa2_dpdmai_dev_init(struct rte_rawdev *rawdev, int dpdmai_id)
{
	struct dpaa2_dpdmai_dev *dpdmai_dev = rawdev->dev_private;
	struct dpdmai_rx_queue_cfg rx_queue_cfg;
	struct dpdmai_attr attr;
	struct dpdmai_rx_queue_attr rx_attr;
	struct dpdmai_tx_queue_attr tx_attr;
	int ret, i;

	DPAA2_QDMA_FUNC_TRACE();

	/* Open DPDMAI device */
	dpdmai_dev->dpdmai_id = dpdmai_id;
	dpdmai_dev->dpdmai.regs = dpaa2_get_mcp_ptr(MC_PORTAL_INDEX);
	dpdmai_dev->qdma_dev = &q_dev;
	ret = dpdmai_open(&dpdmai_dev->dpdmai, CMD_PRI_LOW,
			  dpdmai_dev->dpdmai_id, &dpdmai_dev->token);
	if (ret) {
		DPAA2_QDMA_ERR("dpdmai_open() failed with err: %d", ret);
		return ret;
	}

	/* Get DPDMAI attributes */
	ret = dpdmai_get_attributes(&dpdmai_dev->dpdmai, CMD_PRI_LOW,
				    dpdmai_dev->token, &attr);
	if (ret) {
		DPAA2_QDMA_ERR("dpdmai get attributes failed with err: %d",
			       ret);
		goto init_err;
	}
	dpdmai_dev->num_queues = attr.num_of_queues;

	/* Set up Rx Queues */
	for (i = 0; i < dpdmai_dev->num_queues; i++) {
		struct dpaa2_queue *rxq;

		memset(&rx_queue_cfg, 0, sizeof(struct dpdmai_rx_queue_cfg));
		ret = dpdmai_set_rx_queue(&dpdmai_dev->dpdmai,
					  CMD_PRI_LOW,
					  dpdmai_dev->token,
					  i, 0, &rx_queue_cfg);
		if (ret) {
			DPAA2_QDMA_ERR("Setting Rx queue failed with err: %d",
				       ret);
			goto init_err;
		}

		/* Allocate DQ storage for the DPDMAI Rx queues */
		rxq = &(dpdmai_dev->rx_queue[i]);
		rxq->q_storage = rte_malloc("dq_storage",
					    sizeof(struct queue_storage_info_t),
					    RTE_CACHE_LINE_SIZE);
		if (!rxq->q_storage) {
			DPAA2_QDMA_ERR("q_storage allocation failed");
			ret = -ENOMEM;
			goto init_err;
		}

		memset(rxq->q_storage, 0, sizeof(struct queue_storage_info_t));
		ret = dpaa2_alloc_dq_storage(rxq->q_storage);
		if (ret) {
			DPAA2_QDMA_ERR("dpaa2_alloc_dq_storage failed");
			goto init_err;
		}
	}

	/* Get Rx and Tx queues FQID's */
	for (i = 0; i < dpdmai_dev->num_queues; i++) {
		ret = dpdmai_get_rx_queue(&dpdmai_dev->dpdmai, CMD_PRI_LOW,
					  dpdmai_dev->token, i, 0, &rx_attr);
		if (ret) {
			DPAA2_QDMA_ERR("Reading device failed with err: %d",
				       ret);
			goto init_err;
		}
		dpdmai_dev->rx_queue[i].fqid = rx_attr.fqid;

		ret = dpdmai_get_tx_queue(&dpdmai_dev->dpdmai, CMD_PRI_LOW,
					  dpdmai_dev->token, i, 0, &tx_attr);
		if (ret) {
			DPAA2_QDMA_ERR("Reading device failed with err: %d",
				       ret);
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

	/* Add the HW queue to the global list */
	ret = add_hw_queues_to_list(dpdmai_dev);
	if (ret) {
		DPAA2_QDMA_ERR("Adding H/W queue to list failed");
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

	rte_spinlock_init(&dpdmai_dev->qdma_dev->lock);

	return 0;
init_err:
	dpaa2_dpdmai_dev_uninit(rawdev);
	return ret;
}

static int
rte_dpaa2_qdma_probe(struct rte_dpaa2_driver *dpaa2_drv,
		     struct rte_dpaa2_device *dpaa2_dev)
{
	struct rte_rawdev *rawdev;
	int ret;

	DPAA2_QDMA_FUNC_TRACE();

	rawdev = rte_rawdev_pmd_allocate(dpaa2_dev->device.name,
			sizeof(struct dpaa2_dpdmai_dev),
			rte_socket_id());
	if (!rawdev) {
		DPAA2_QDMA_ERR("Unable to allocate rawdevice");
		return -EINVAL;
	}

	dpaa2_dev->rawdev = rawdev;
	rawdev->dev_ops = &dpaa2_qdma_ops;
	rawdev->device = &dpaa2_dev->device;
	rawdev->driver_name = dpaa2_drv->driver.name;

	/* Invoke PMD device initialization function */
	ret = dpaa2_dpdmai_dev_init(rawdev, dpaa2_dev->object_id);
	if (ret) {
		rte_rawdev_pmd_release(rawdev);
		return ret;
	}

	/* Reset the QDMA device */
	ret = dpaa2_qdma_reset(rawdev);
	if (ret) {
		DPAA2_QDMA_ERR("Resetting QDMA failed");
		return ret;
	}

	return 0;
}

static int
rte_dpaa2_qdma_remove(struct rte_dpaa2_device *dpaa2_dev)
{
	struct rte_rawdev *rawdev = dpaa2_dev->rawdev;
	int ret;

	DPAA2_QDMA_FUNC_TRACE();

	dpaa2_dpdmai_dev_uninit(rawdev);

	ret = rte_rawdev_pmd_release(rawdev);
	if (ret)
		DPAA2_QDMA_ERR("Device cleanup failed");

	return 0;
}

static struct rte_dpaa2_driver rte_dpaa2_qdma_pmd = {
	.drv_flags = RTE_DPAA2_DRV_IOVA_AS_VA,
	.drv_type = DPAA2_QDMA,
	.probe = rte_dpaa2_qdma_probe,
	.remove = rte_dpaa2_qdma_remove,
};

RTE_PMD_REGISTER_DPAA2(dpaa2_qdma, rte_dpaa2_qdma_pmd);
RTE_PMD_REGISTER_PARAM_STRING(dpaa2_qdma,
	"no_prefetch=<int> ");

RTE_INIT(dpaa2_qdma_init_log)
{
	dpaa2_qdma_logtype = rte_log_register("pmd.raw.dpaa2.qdma");
	if (dpaa2_qdma_logtype >= 0)
		rte_log_set_level(dpaa2_qdma_logtype, RTE_LOG_INFO);
}
