/* SPDX-License-Identifier: BSD-3-Clause
 *
 *   Copyright (c) 2015-2016 Freescale Semiconductor, Inc. All rights reserved.
 *   Copyright 2016,2019-2023 NXP
 *
 */

#ifndef _FSLMC_VFIO_H_
#define _FSLMC_VFIO_H_

#include <rte_vfio.h>

#ifndef __hot
#define __hot __attribute__((hot))
#endif

/* Pathname of FSL-MC devices directory. */
#define SYSFS_FSL_MC_DEVICES	"/sys/bus/fsl-mc/devices"
#define DPAA2_MC_DPNI_DEVID	7
#define DPAA2_MC_DPSECI_DEVID	3
#define DPAA2_MC_DPCON_DEVID	5
#define DPAA2_MC_DPIO_DEVID	9
#define DPAA2_MC_DPBP_DEVID	10
#define DPAA2_MC_DPCI_DEVID	11

struct fslmc_vfio_device {
	LIST_ENTRY(fslmc_vfio_device) next;
	int fd; /* fslmc root container device ?? */
	int index; /*index of child object */
	char dev_name[64];
	struct fslmc_vfio_device *child; /* Child object */
};

struct fslmc_vfio_group {
	LIST_ENTRY(fslmc_vfio_group) next;
	int fd; /* /dev/vfio/"groupid" */
	int groupid;
	int connected;
	char group_name[64]; /* dprc.x*/
	int iommu_type;
	LIST_HEAD(, fslmc_vfio_device) vfio_devices;
};

struct fslmc_vfio_container {
	int fd; /* /dev/vfio/vfio */
	LIST_HEAD(, fslmc_vfio_group) groups;
};

extern char *fslmc_container;
int rte_dpaa2_intr_enable(struct rte_intr_handle *intr_handle, int index);
int rte_dpaa2_intr_disable(struct rte_intr_handle *intr_handle, int index);

int rte_dpaa2_vfio_setup_intr(struct rte_intr_handle *intr_handle,
			      int vfio_dev_fd,
			      int num_irqs);

int fslmc_vfio_setup_group(void);
int fslmc_vfio_process_group(void);
int fslmc_vfio_close_group(void);
char *fslmc_get_container(void);
int fslmc_get_container_group(const char *group_name, int *gropuid);
int rte_fslmc_vfio_dmamap(void);
uint64_t
rte_fslmc_cold_mem_vaddr_to_iova(void *vaddr,
	uint64_t size);
void *
rte_fslmc_cold_mem_iova_to_vaddr(uint64_t iova,
	uint64_t size);
__hot uint64_t
rte_fslmc_mem_vaddr_to_iova(void *vaddr);
__hot void *
rte_fslmc_mem_iova_to_vaddr(uint64_t iova);
uint64_t
rte_fslmc_io_vaddr_to_iova(void *vaddr);
void *
rte_fslmc_io_iova_to_vaddr(uint64_t iova);

__rte_experimental
int rte_fslmc_vfio_mem_dmamap(uint64_t vaddr, uint64_t iova,
	uint64_t size);
__rte_experimental
int rte_fslmc_vfio_mem_dmaunmap(uint64_t iova,
	uint64_t size);

#endif /* _FSLMC_VFIO_H_ */
