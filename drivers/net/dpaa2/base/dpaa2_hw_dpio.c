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
#include <sys/queue.h>
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

/* DPAA2 Base interface files */
#include <dpaa2_hw_dpbp.h>
#include <dpaa2_hw_dpni.h>
#include <dpaa2_hw_dpio.h>

#define NUM_HOST_CPUS RTE_MAX_LCORE

__thread struct thread_io_info_t thread_io_info;

TAILQ_HEAD(dpio_device_list, dpaa2_dpio_dev);
static struct dpio_device_list *dpio_dev_list; /*!< DPIO device list */
static uint32_t io_space_count;

#define DPAA2_CORE_CLUSTER_GET(sdest, cpu_id) \
do { \
	if (cpu_id == 0 || cpu_id == 1) \
		sdest = DPAA2_CORE_CLUSTER_FIRST; \
	else if (cpu_id == 2 || cpu_id == 3) \
		sdest = DPAA2_CORE_CLUSTER_SECOND; \
	else if (cpu_id == 4 || cpu_id == 5) \
		sdest = DPAA2_CORE_CLUSTER_THIRD; \
	else \
		sdest = DPAA2_CORE_CLUSTER_FOURTH; \
} while (0)

static int
configure_dpio_qbman_swp(struct dpaa2_dpio_dev *dpio_dev)
{
	struct qbman_swp_desc p_des;
	struct dpio_attr attr;

	dpio_dev->dpio = malloc(sizeof(struct fsl_mc_io));
	if (!dpio_dev->dpio) {
		PMD_DRV_LOG(ERR, "Memory allocation failure\n");
		return -1;
	}

	PMD_DRV_LOG(INFO, "\t Alocated  DPIO[%p]", dpio_dev->dpio);
	dpio_dev->dpio->regs = dpio_dev->mc_portal;
	if (dpio_open(dpio_dev->dpio, CMD_PRI_LOW, dpio_dev->hw_id,
		      &dpio_dev->token)) {
		PMD_DRV_LOG(ERR, "Failed to allocate IO space\n");
		free(dpio_dev->dpio);
		return -1;
	}

	if (dpio_reset(dpio_dev->dpio, CMD_PRI_LOW, dpio_dev->token)) {
		PMD_DRV_LOG(ERR, "Failed to reset dpio\n");
		dpio_close(dpio_dev->dpio, CMD_PRI_LOW, dpio_dev->token);
		free(dpio_dev->dpio);
		return -1;
	}

	if (dpio_enable(dpio_dev->dpio, CMD_PRI_LOW, dpio_dev->token)) {
		PMD_DRV_LOG(ERR, "Failed to Enable dpio\n");
		dpio_close(dpio_dev->dpio, CMD_PRI_LOW, dpio_dev->token);
		free(dpio_dev->dpio);
		return -1;
	}

	if (dpio_get_attributes(dpio_dev->dpio, CMD_PRI_LOW,
				dpio_dev->token, &attr)) {
		PMD_DRV_LOG(ERR, "DPIO Get attribute failed\n");
		dpio_disable(dpio_dev->dpio, CMD_PRI_LOW, dpio_dev->token);
		dpio_close(dpio_dev->dpio, CMD_PRI_LOW,  dpio_dev->token);
		free(dpio_dev->dpio);
		return -1;
	}

	PMD_DRV_LOG(INFO, "Qbman Portal ID %d", attr.qbman_portal_id);
	PMD_DRV_LOG(INFO, "Portal CE addr 0x%lX", attr.qbman_portal_ce_offset);
	PMD_DRV_LOG(INFO, "Portal CI addr 0x%lX", attr.qbman_portal_ci_offset);

	/* Configure & setup SW portal */
	p_des.block = NULL;
	p_des.idx = attr.qbman_portal_id;
	p_des.cena_bar = (void *)(dpio_dev->qbman_portal_ce_paddr);
	p_des.cinh_bar = (void *)(dpio_dev->qbman_portal_ci_paddr);
	p_des.irq = -1;
	p_des.qman_version = attr.qbman_version;

	PMD_DRV_LOG(INFO, "Portal CE addr 0x%p", p_des.cena_bar);
	PMD_DRV_LOG(INFO, "Portal CI addr 0x%p", p_des.cinh_bar);

	dpio_dev->sw_portal = qbman_swp_init(&p_des);
	if (dpio_dev->sw_portal == NULL) {
		PMD_DRV_LOG(ERR, " QBMan SW Portal Init failed\n");
		dpio_close(dpio_dev->dpio, CMD_PRI_LOW, dpio_dev->token);
		free(dpio_dev->dpio);
		return -1;
	}

	PMD_DRV_LOG(INFO, "QBMan SW Portal 0x%p\n", dpio_dev->sw_portal);

	return 0;
}

static int
dpaa2_configure_stashing(struct dpaa2_dpio_dev *dpio_dev)
{
	int sdest;
	int cpu_id, ret;

	/* Set the Stashing Destination */
	cpu_id = rte_lcore_id();
	if (cpu_id < 0) {
		cpu_id = rte_get_master_lcore();
		if (cpu_id < 0) {
			PMD_DRV_LOG(ERR, "\tGetting CPU Index failed\n");
			return -1;
		}
	}

	/*
	 *  In case of running DPDK on the Virtual Machine the Stashing
	 *  Destination gets set in the H/W w.r.t. the Virtual CPU ID's.
	 *  As a W.A. environment variable HOST_START_CPU tells which
	 *  the offset of the host start core of the Virtual Machine threads.
	 */
	if (getenv("HOST_START_CPU")) {
		cpu_id +=
		atoi(getenv("HOST_START_CPU"));
		cpu_id = cpu_id % NUM_HOST_CPUS;
	}

	/* Set the STASH Destination depending on Current CPU ID.
	   Valid values of SDEST are 4,5,6,7. Where,
	   CPU 0-1 will have SDEST 4
	   CPU 2-3 will have SDEST 5.....and so on.
	*/
	DPAA2_CORE_CLUSTER_GET(sdest, cpu_id);
	PMD_DRV_LOG(INFO, "Portal= %d  CPU= %u SDEST= %d\n",
		    dpio_dev->index, cpu_id, sdest);

	ret = dpio_set_stashing_destination(dpio_dev->dpio, CMD_PRI_LOW,
					    dpio_dev->token, sdest);
	if (ret) {
		PMD_DRV_LOG(ERR, "%d ERROR in SDEST\n",  ret);
		return -1;
	}

	return 0;
}

static inline struct dpaa2_dpio_dev *dpaa2_get_qbman_swp(void)
{
	struct dpaa2_dpio_dev *dpio_dev = NULL;
	int ret;

	/* Get DPIO dev handle from list using index */
	TAILQ_FOREACH(dpio_dev, dpio_dev_list, next) {
		if (dpio_dev && rte_atomic16_test_and_set(&dpio_dev->ref_count))
			break;
	}
	if (!dpio_dev)
		return NULL;

	ret = dpaa2_configure_stashing(dpio_dev);
	if (ret) {
		RTE_LOG(ERR, EAL, "dpaa2_configure_stashing failed");
	}
	return dpio_dev;
}

int
dpaa2_affine_qbman_swp(void)
{
	if (thread_io_info.dpio_dev)
		return 0;

	/* Populate the thread_io_info structure */
	thread_io_info.dpio_dev = dpaa2_get_qbman_swp();
	if (thread_io_info.dpio_dev)
		return 0;
	else
		return -1;
}

int
dpaa2_affine_qbman_swp_sec(void)
{
	if (thread_io_info.sec_dpio_dev)
		return 0;

	/* Populate the thread_io_info structure */
	thread_io_info.sec_dpio_dev = dpaa2_get_qbman_swp();
	if (thread_io_info.sec_dpio_dev)
		return 0;
	else
		return -1;
}

int
dpaa2_create_dpio_device(struct fsl_vfio_device *vdev,
			 struct vfio_device_info *obj_info,
		int object_id)
{
	struct dpaa2_dpio_dev *dpio_dev;
	struct vfio_region_info reg_info = { .argsz = sizeof(reg_info)};

	if (obj_info->num_regions < NUM_DPIO_REGIONS) {
		PMD_DRV_LOG(ERR, "ERROR, Not sufficient number "
				"of DPIO regions.\n");
		return -1;
	}

	if (!dpio_dev_list) {
		dpio_dev_list = malloc(sizeof(struct dpio_device_list));
		if (NULL == dpio_dev_list) {
			PMD_DRV_LOG(ERR, "Memory alloc failed for DPIO list\n");
			return -1;
		}

		/* Initialize the DPIO List */
		TAILQ_INIT(dpio_dev_list);
	}

	dpio_dev = malloc(sizeof(struct dpaa2_dpio_dev));
	if (!dpio_dev) {
		PMD_DRV_LOG(ERR, "Memory allocation failed for DPIO Device\n");
		return -1;
	}

	PMD_DRV_LOG(INFO, "\t Aloocated DPIO [%p]", dpio_dev);
	dpio_dev->dpio = NULL;
	dpio_dev->hw_id = object_id;
	dpio_dev->vfio_fd = vdev->fd;
	rte_atomic16_init(&dpio_dev->ref_count);
	/* Using single portal  for all devices */
	dpio_dev->mc_portal = mcp_ptr_list[MC_PORTAL_INDEX];

	reg_info.index = 0;
	if (ioctl(dpio_dev->vfio_fd, VFIO_DEVICE_GET_REGION_INFO, &reg_info)) {
		printf("vfio: error getting region info\n");
		return -1;
	}

	PMD_DRV_LOG(INFO, "\t  Region Offset = %llx", reg_info.offset);
	PMD_DRV_LOG(INFO, "\t  Region Size = %llx", reg_info.size);
	dpio_dev->ce_size = reg_info.size;
	dpio_dev->qbman_portal_ce_paddr = (uint64_t)mmap(NULL, reg_info.size,
				PROT_WRITE | PROT_READ, MAP_SHARED,
				dpio_dev->vfio_fd, reg_info.offset);

	/* Create Mapping for QBMan Cache Enabled area. This is a fix for
	   SMMU fault for DQRR statshing transaction. */
	if (vfio_dmamap_mem_region(dpio_dev->qbman_portal_ce_paddr,
				   reg_info.offset, reg_info.size)) {
		PMD_DRV_LOG(ERR, "DMAMAP for Portal CE area failed.\n");
		return -1;
	}

	reg_info.index = 1;
	if (ioctl(dpio_dev->vfio_fd, VFIO_DEVICE_GET_REGION_INFO, &reg_info)) {
		printf("vfio: error getting region info\n");
		return -1;
	}

	PMD_DRV_LOG(INFO, "\t  Region Offset = %llx", reg_info.offset);
	PMD_DRV_LOG(INFO, "\t  Region Size = %llx", reg_info.size);
	dpio_dev->ci_size = reg_info.size;
	dpio_dev->qbman_portal_ci_paddr = (uint64_t)mmap(NULL, reg_info.size,
				PROT_WRITE | PROT_READ, MAP_SHARED,
				dpio_dev->vfio_fd, reg_info.offset);

	if (configure_dpio_qbman_swp(dpio_dev)) {
		PMD_DRV_LOG(ERR,
			    "Fail to configure the dpio qbman portal for %d\n",
			 dpio_dev->hw_id);
		return -1;
	}

	io_space_count++;
	dpio_dev->index = io_space_count;
	TAILQ_INSERT_HEAD(dpio_dev_list, dpio_dev, next);

	return 0;
}
