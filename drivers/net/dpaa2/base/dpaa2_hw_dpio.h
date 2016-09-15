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

#ifndef _DPAA2_HW_DPIO_H_
#define _DPAA2_HW_DPIO_H_

/*Stashing Macros*/
#define DPAA2_CORE_CLUSTER_BASE		0x04
#define DPAA2_CORE_CLUSTER_FIRST	(DPAA2_CORE_CLUSTER_BASE + 0)
#define DPAA2_CORE_CLUSTER_SECOND	(DPAA2_CORE_CLUSTER_BASE + 1)
#define DPAA2_CORE_CLUSTER_THIRD	(DPAA2_CORE_CLUSTER_BASE + 2)
#define DPAA2_CORE_CLUSTER_FOURTH	(DPAA2_CORE_CLUSTER_BASE + 3)

/* TODO */
int dpaa2_affine_qbman_swp(void);

/* TODO */
int dpaa2_affine_qbman_swp_sec(void);

/* TODO */
int dpaa2_create_dpio_device(struct fsl_vfio_device *vdev,
			     struct vfio_device_info *obj_info,
			     int object_id);

#endif /* _DPAA2_HW_DPIO_H_ */
