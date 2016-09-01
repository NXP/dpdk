/*-
 *   BSD LICENSE
 *
 *   Copyright (c) 2014 Freescale Semiconductor, Inc. All rights reserved.
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

#ifndef _EAL_VFIO_FSL_MC_H_
#define _EAL_VFIO_FSL_MC_H_

#include <rte_memory.h>
#include <rte_atomic.h>
#include "eal_vfio.h"

#define FSL_VENDOR_ID		0x1957
#define FSL_MC_DPNI_DEVID	7
#define FSL_MC_DPSECI_DEVID	3

#define VFIO_MAX_GRP		1
#define VFIO_MAX_CONTAINERS	1

#define DPAA2_MBUF_HW_ANNOTATION	64
#define DPAA2_FD_PTA_SIZE		64

#if (DPAA2_MBUF_HW_ANNOTATION + DPAA2_FD_PTA_SIZE) > RTE_PKTMBUF_HEADROOM
#error "Annotation requirement is more than RTE_PKTMBUF_HEADROOM"
#endif

/* we will re-use the HEADROOM for annotation in RX */
#define DPAA2_HW_BUF_RESERVE	0
#define DPAA2_PACKET_LAYOUT_ALIGN	64 /*changing from 256 */

typedef struct fsl_vfio_device {
	int fd; /* fsl_mc root container device ?? */
	int index; /*index of child object */
	struct fsl_vfio_device *child; /* Child object */
} fsl_vfio_device;

typedef struct fsl_vfio_group {
	int fd; /* /dev/vfio/"groupid" */
	int groupid;
	struct fsl_vfio_container *container;
	int object_index;
	struct fsl_vfio_device *vfio_device;
} fsl_vfio_group;

typedef struct fsl_vfio_container {
	int fd; /* /dev/vfio/vfio */
	int used;
	int index; /* index in group list */
	struct fsl_vfio_group *group_list[VFIO_MAX_GRP];
} fsl_vfio_container;

int vfio_dmamap_mem_region(
	uint64_t vaddr,
	uint64_t iova,
	uint64_t size);

/* initialize the NXP/FSL dpaa2 accelerators */
int rte_eal_dpaa2_init(void);
int rte_eal_dpaa2_dmamap(void);

int dpaa2_create_dpio_device(struct fsl_vfio_device *vdev,
			     struct vfio_device_info *obj_info,
			int object_id);

int dpaa2_create_dpbp_device(int dpbp_id);

int dpaa2_affine_qbman_swp(void);

int dpaa2_affine_qbman_swp_sec(void);

#endif

