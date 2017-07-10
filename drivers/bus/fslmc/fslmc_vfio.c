/*-
 *   BSD LICENSE
 *
 *   Copyright (c) 2015-2016 Freescale Semiconductor, Inc. All rights reserved.
 *   Copyright 2016 NXP. All rights reserved.
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
#include <dirent.h>
#include <sys/eventfd.h>

#include <eal_filesystem.h>
#include <eal_private.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_string_fns.h>
#include <rte_cycles.h>
#include <rte_kvargs.h>
#include <rte_dev.h>
#include <rte_ethdev.h>

#include "fslmc_vfio.h"
#include "debug.h"

#include "portal/dpaa2_hw_pvt.h"
#include "portal/dpaa2_hw_dpio.h"

#define VFIO_MAX_CONTAINERS	1

#define FSLMC_VFIO_LOG(level, fmt, args...) \
	RTE_LOG(level, EAL, "%s(): " fmt "\n", __func__, ##args)

/** Pathname of FSL-MC devices directory. */
#define SYSFS_FSL_MC_DEVICES "/sys/bus/fsl-mc/devices"

#define IRQ_SET_BUF_LEN  (sizeof(struct vfio_irq_set) + sizeof(int))

unsigned short kernel_major_ver; /**< Running Linux major version number */
unsigned short kernel_minor_ver; /**< Running Linux minor version number */

/* Number of VFIO containers & groups with in */
static struct fslmc_vfio_group vfio_groups[VFIO_MAX_GRP];
static struct fslmc_vfio_container vfio_containers[VFIO_MAX_CONTAINERS];
static int container_device_fd;
static uint32_t *msi_intr_vaddr;
void *(*rte_mcp_ptr_list);
static uint32_t mcp_id;
static int is_dma_done;

static int vfio_connect_container(struct fslmc_vfio_group *vfio_group)
{
	struct fslmc_vfio_container *container;
	int i, fd, ret;

	/* Try connecting to vfio container if already created */
	for (i = 0; i < VFIO_MAX_CONTAINERS; i++) {
		container = &vfio_containers[i];
		if (!ioctl(vfio_group->fd, VFIO_GROUP_SET_CONTAINER,
			   &container->fd)) {
			FSLMC_VFIO_LOG(INFO, "Container pre-exists with"
				    " FD[0x%x] for this group",
				    container->fd);
			vfio_group->container = container;
			return 0;
		}
	}

	/* Opens main vfio file descriptor which represents the "container" */
	fd = vfio_get_container_fd();
	if (fd < 0) {
		FSLMC_VFIO_LOG(ERR, "Failed to open VFIO container");
		return -errno;
	}

	/* Check whether support for SMMU type IOMMU present or not */
	if (ioctl(fd, VFIO_CHECK_EXTENSION, VFIO_TYPE1_IOMMU)) {
		/* Connect group to container */
		ret = ioctl(vfio_group->fd, VFIO_GROUP_SET_CONTAINER, &fd);
		if (ret) {
			FSLMC_VFIO_LOG(ERR, "Failed to setup group container");
			close(fd);
			return -errno;
		}

		ret = ioctl(fd, VFIO_SET_IOMMU, VFIO_TYPE1_IOMMU);
		if (ret) {
			FSLMC_VFIO_LOG(ERR, "Failed to setup VFIO iommu");
			close(fd);
			return -errno;
		}
	} else {
		FSLMC_VFIO_LOG(ERR, "No supported IOMMU available");
		close(fd);
		return -EINVAL;
	}

	container = NULL;
	for (i = 0; i < VFIO_MAX_CONTAINERS; i++) {
		if (vfio_containers[i].used)
			continue;
		container = &vfio_containers[i];
	}
	if (!container) {
		FSLMC_VFIO_LOG(ERR, "No free container found");
		close(fd);
		return -ENOMEM;
	}

	container->used = 1;
	container->fd = fd;
	container->group_list[container->index] = vfio_group;
	vfio_group->container = container;
	container->index++;
	return 0;
}

static int vfio_map_irq_region(struct fslmc_vfio_group *group)
{
	int ret;
	unsigned long *vaddr = NULL;
	struct vfio_iommu_type1_dma_map map = {
		.argsz = sizeof(map),
		.flags = VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE,
		.vaddr = 0x6030000,
		.iova = 0x6030000,
		.size = 0x1000,
	};

	vaddr = (unsigned long *)mmap(NULL, 0x1000, PROT_WRITE |
		PROT_READ, MAP_SHARED, container_device_fd, 0x6030000);
	if (vaddr == MAP_FAILED) {
		FSLMC_VFIO_LOG(ERR, "Unable to map region (errno = %d)", errno);
		return -errno;
	}

	msi_intr_vaddr = (uint32_t *)((char *)(vaddr) + 64);
	map.vaddr = (unsigned long)vaddr;
	ret = ioctl(group->container->fd, VFIO_IOMMU_MAP_DMA, &map);
	if (ret == 0)
		return 0;

	FSLMC_VFIO_LOG(ERR, "VFIO_IOMMU_MAP_DMA fails (errno = %d)", errno);
	return -errno;
}

int vfio_dmamap_mem_region(uint64_t vaddr,
			   uint64_t iova,
			   uint64_t size)
{
	struct fslmc_vfio_group *group;
	struct vfio_iommu_type1_dma_map dma_map = {
		.argsz = sizeof(dma_map),
		.flags = VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE,
	};

	dma_map.vaddr = vaddr;
	dma_map.size = size;
	dma_map.iova = iova;

	/* SET DMA MAP for IOMMU */
	group = &vfio_groups[0];
	if (ioctl(group->container->fd, VFIO_IOMMU_MAP_DMA, &dma_map)) {
		FSLMC_VFIO_LOG(ERR, "VFIO_IOMMU_MAP_DMA (errno = %d)", errno);
		return -1;
	}
	return 0;
}

int rte_fslmc_vfio_dmamap(void)
{
	int ret;
	struct fslmc_vfio_group *group;
	struct vfio_iommu_type1_dma_map dma_map = {
		.argsz = sizeof(struct vfio_iommu_type1_dma_map),
		.flags = VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE,
	};

	int i;
	const struct rte_memseg *memseg;

	if (is_dma_done)
		return 0;

	memseg = rte_eal_get_physmem_layout();
	if (memseg == NULL) {
		FSLMC_VFIO_LOG(ERR, "Cannot get physical layout.");
		return -ENODEV;
	}

	for (i = 0; i < RTE_MAX_MEMSEG; i++) {
		if (memseg[i].addr == NULL && memseg[i].len == 0) {
			FSLMC_VFIO_LOG(DEBUG, "Total %d segments found.", i);
			break;
		}

		dma_map.size = memseg[i].len;
		dma_map.vaddr = memseg[i].addr_64;
#ifdef RTE_LIBRTE_DPAA2_USE_PHYS_IOVA
		dma_map.iova = memseg[i].phys_addr;
#else
		dma_map.iova = dma_map.vaddr;
#endif

		/* SET DMA MAP for IOMMU */
		group = &vfio_groups[0];

		if (!group->container) {
			FSLMC_VFIO_LOG(ERR, "Container is not connected ");
			return -1;
		}

		FSLMC_VFIO_LOG(DEBUG, "-->Initial SHM Virtual ADDR %llX",
			     dma_map.vaddr);
		FSLMC_VFIO_LOG(DEBUG, "-----> DMA size 0x%llX", dma_map.size);
		ret = ioctl(group->container->fd, VFIO_IOMMU_MAP_DMA,
			    &dma_map);
		if (ret) {
			FSLMC_VFIO_LOG(ERR, "VFIO_IOMMU_MAP_DMA API"
				       "(errno = %d)", errno);
			return ret;
		}
	}

	/* Verifying that at least single segment is available */
	if (i <= 0) {
		FSLMC_VFIO_LOG(ERR, "No Segments found for VFIO Mapping");
		return -1;
	}

	/* For Linux version < 4.9, VFIO doesn't add the mapping of IRQ region
	 * in SMMU. This needs to be done explicitly.
	 */
	if (kernel_major_ver == 4 && kernel_minor_ver <= 4) {
		/* Only applicable for Linux 4.1 and Linux 4.4 */
		vfio_map_irq_region(group);
	}

	is_dma_done = 1;

	return 0;
}

static int64_t vfio_map_mcp_obj(struct fslmc_vfio_group *group, char *mcp_obj)
{
	int64_t v_addr = (int64_t)MAP_FAILED;
	int32_t ret, mc_fd;

	struct vfio_device_info d_info = { .argsz = sizeof(d_info) };
	struct vfio_region_info reg_info = { .argsz = sizeof(reg_info) };

	/* getting the mcp object's fd*/
	mc_fd = ioctl(group->fd, VFIO_GROUP_GET_DEVICE_FD, mcp_obj);
	if (mc_fd < 0) {
		FSLMC_VFIO_LOG(ERR, "error in VFIO get device %s fd from group"
			    " %d", mcp_obj, group->fd);
		return v_addr;
	}

	/* getting device info*/
	ret = ioctl(mc_fd, VFIO_DEVICE_GET_INFO, &d_info);
	if (ret < 0) {
		FSLMC_VFIO_LOG(ERR, "error in VFIO getting DEVICE_INFO");
		goto MC_FAILURE;
	}

	/* getting device region info*/
	ret = ioctl(mc_fd, VFIO_DEVICE_GET_REGION_INFO, &reg_info);
	if (ret < 0) {
		FSLMC_VFIO_LOG(ERR, "error in VFIO getting REGION_INFO");
		goto MC_FAILURE;
	}

	FSLMC_VFIO_LOG(DEBUG, "region offset = %llx  , region size = %llx",
		     reg_info.offset, reg_info.size);

	v_addr = (uint64_t)mmap(NULL, reg_info.size,
		PROT_WRITE | PROT_READ, MAP_SHARED,
		mc_fd, reg_info.offset);

MC_FAILURE:
	close(mc_fd);

	return v_addr;
}

int dpaa2_intr_enable(struct rte_intr_handle *intr_handle, int index)
{
	int len, ret;
	char irq_set_buf[IRQ_SET_BUF_LEN];
	struct vfio_irq_set *irq_set;
	int *fd_ptr;

	len = sizeof(irq_set_buf);

	irq_set = (struct vfio_irq_set *)irq_set_buf;
	irq_set->argsz = len;
	irq_set->count = 1;
	irq_set->flags =
		VFIO_IRQ_SET_DATA_EVENTFD | VFIO_IRQ_SET_ACTION_TRIGGER;
	irq_set->index = index;
	irq_set->start = 0;
	fd_ptr = (int *)&irq_set->data;
	*fd_ptr = intr_handle->fd;

	ret = ioctl(intr_handle->vfio_dev_fd, VFIO_DEVICE_SET_IRQS, irq_set);
	if (ret) {
		RTE_LOG(ERR, EAL, "Error:dpaa2 SET IRQs fd=%d, err = %d(%s)\n",
			intr_handle->fd, errno, strerror(errno));
		return ret;
	}

	return ret;
}

int dpaa2_intr_disable(struct rte_intr_handle *intr_handle, int index)
{
	struct vfio_irq_set *irq_set;
	char irq_set_buf[IRQ_SET_BUF_LEN];
	int len, ret;

	len = sizeof(struct vfio_irq_set);

	irq_set = (struct vfio_irq_set *)irq_set_buf;
	irq_set->argsz = len;
	irq_set->flags = VFIO_IRQ_SET_DATA_NONE | VFIO_IRQ_SET_ACTION_TRIGGER;
	irq_set->index = index;
	irq_set->start = 0;
	irq_set->count = 0;

	ret = ioctl(intr_handle->vfio_dev_fd, VFIO_DEVICE_SET_IRQS, irq_set);
	if (ret)
		RTE_LOG(ERR, EAL,
			"Error disabling dpaa2 interrupts for fd %d\n",
			intr_handle->fd);

	return ret;
}

/* set up interrupt support (but not enable interrupts) */
int
dpaa2_vfio_setup_intr(struct rte_intr_handle *intr_handle,
		      int vfio_dev_fd,
		      int num_irqs)
{
	int i, ret;

	/* start from MSI-X interrupt type */
	for (i = 0; i < num_irqs; i++) {
		struct vfio_irq_info irq_info = { .argsz = sizeof(irq_info) };
		int fd = -1;

		irq_info.index = i;

		ret = ioctl(vfio_dev_fd, VFIO_DEVICE_GET_IRQ_INFO, &irq_info);
		if (ret < 0) {
			FSLMC_VFIO_LOG(ERR, "  cannot get IRQ (%d) info, "
					"error %i (%s)", i, errno,
					strerror(errno));
			return -1;
		}

		FSLMC_VFIO_LOG(DEBUG, "IRQ Info (Count=%d, Flags=%d)",
			     irq_info.count, irq_info.flags);

		/* if this vector cannot be used with eventfd,
		 * fail if we explicitly
		 * specified interrupt type, otherwise continue
		 */
		if ((irq_info.flags & VFIO_IRQ_INFO_EVENTFD) == 0) {
			if (internal_config.vfio_intr_mode
			    != RTE_INTR_MODE_NONE) {
				FSLMC_VFIO_LOG(ERR, "  interrupt vector does not"
						 " support eventfd!\n");
				return -1;
			}
			continue;
		}

		/* set up an eventfd for interrupts */
		fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
		if (fd < 0) {
			FSLMC_VFIO_LOG(ERR, "  cannot set up eventfd, error %i"
					 "(%s)\n", errno, strerror(errno));
			return -1;
		}

		intr_handle->fd = fd;
		intr_handle->type = RTE_INTR_HANDLE_VFIO_MSI;
		intr_handle->vfio_dev_fd = vfio_dev_fd;

		return 0;
	}

	/* if we're here, we haven't found a suitable interrupt vector */
	return -1;
}

/* Following function shall fetch total available list of MC devices
 * from VFIO container & populate private list of devices and other
 * data structures
 */
int fslmc_vfio_process_group(void)
{
	struct fslmc_vfio_device *vdev;
	struct vfio_device_info device_info = { .argsz = sizeof(device_info) };
	char *temp_obj, *object_type, *mcp_obj, *dev_name;
	int32_t object_id, i, dev_fd, ret;
	DIR *d;
	struct dirent *dir;
	char path[PATH_MAX];
	int64_t v_addr;
	int ndev_count;
	int dpio_count = 0, dpbp_count = 0;
	struct fslmc_vfio_group *group = &vfio_groups[0];
	static int process_once;

	/* if already done once */
	if (process_once) {
		FSLMC_VFIO_LOG(DEBUG, "Already scanned once - re-scan "
			    "not supported");
		return 0;
	}
	process_once = 0;

	sprintf(path, "/sys/kernel/iommu_groups/%d/devices", group->groupid);

	d = opendir(path);
	if (!d) {
		FSLMC_VFIO_LOG(ERR, "Unable to open directory %s", path);
		return -1;
	}

	/*Counting the number of devices in a group and getting the mcp ID*/
	ndev_count = 0;
	mcp_obj = NULL;
	while ((dir = readdir(d)) != NULL) {
		if (dir->d_type == DT_LNK) {
			ndev_count++;
			if (!strncmp("dpmcp", dir->d_name, 5)) {
				if (mcp_obj)
					free(mcp_obj);
				mcp_obj = malloc(sizeof(dir->d_name));
				if (!mcp_obj) {
					FSLMC_VFIO_LOG(ERR, "mcp obj:Unable to"
						    " allocate memory");
					closedir(d);
					return -ENOMEM;
				}
				strcpy(mcp_obj, dir->d_name);
				temp_obj = strtok(dir->d_name, ".");
				temp_obj = strtok(NULL, ".");
				sscanf(temp_obj, "%d", &mcp_id);
			}
		}
	}
	closedir(d);
	d = NULL;
	if (!mcp_obj) {
		FSLMC_VFIO_LOG(ERR, "DPAA2 MCP Object not Found");
		return -ENODEV;
	}
	RTE_LOG(INFO, EAL, "fslmc: DPRC contains = %d devices\n", ndev_count);

	/* Allocate the memory depends upon number of objects in a group*/
	group->vfio_device = (struct fslmc_vfio_device *)malloc(ndev_count *
			     sizeof(struct fslmc_vfio_device));
	if (!(group->vfio_device)) {
		FSLMC_VFIO_LOG(ERR, "vfio device: Unable to allocate memory\n");
		free(mcp_obj);
		return -ENOMEM;
	}

	/* Allocate memory for MC Portal list */
	rte_mcp_ptr_list = malloc(sizeof(void *) * 1);
	if (!rte_mcp_ptr_list) {
		FSLMC_VFIO_LOG(ERR, "portal list: Unable to allocate memory!");
		free(mcp_obj);
		goto FAILURE;
	}

	v_addr = vfio_map_mcp_obj(group, mcp_obj);
	free(mcp_obj);
	if (v_addr == (int64_t)MAP_FAILED) {
		FSLMC_VFIO_LOG(ERR, "Error mapping region (errno = %d)", errno);
		goto FAILURE;
	}

	rte_mcp_ptr_list[0] = (void *)v_addr;

	d = opendir(path);
	if (!d) {
		FSLMC_VFIO_LOG(ERR, "Unable to open %s Directory", path);
		goto FAILURE;
	}

	i = 0;
	/* Parsing each object and initiating them*/
	while ((dir = readdir(d)) != NULL) {
		if (dir->d_type != DT_LNK)
			continue;
		if (!strncmp("dprc", dir->d_name, 4) ||
		    !strncmp("dpmcp", dir->d_name, 5))
			continue;
		dev_name = malloc(sizeof(dir->d_name));
		if (!dev_name) {
			FSLMC_VFIO_LOG(ERR, "name: Unable to allocate memory");
			goto FAILURE;
		}
		strcpy(dev_name, dir->d_name);
		object_type = strtok(dir->d_name, ".");
		temp_obj = strtok(NULL, ".");
		sscanf(temp_obj, "%d", &object_id);

		/* getting the device fd*/
		dev_fd = ioctl(group->fd, VFIO_GROUP_GET_DEVICE_FD, dev_name);
		if (dev_fd < 0) {
			FSLMC_VFIO_LOG(ERR, "VFIO_GROUP_GET_DEVICE_FD error"
				    " Device fd: %s, Group: %d",
				    dev_name, group->fd);
			free(dev_name);
			goto FAILURE;
		}

		free(dev_name);
		vdev = &group->vfio_device[group->object_index++];
		vdev->fd = dev_fd;
		vdev->index = i;
		i++;
		/* Get Device inofrmation */
		if (ioctl(vdev->fd, VFIO_DEVICE_GET_INFO, &device_info)) {
			FSLMC_VFIO_LOG(ERR, "DPAA2 VFIO_DEVICE_GET_INFO fail");
			goto FAILURE;
		}

		if (!strcmp(object_type, "dpni")) {
			ret = dpaa2_create_dpni_dev(vdev,
						    &device_info,
						    object_id);
		} else if (!strcmp(object_type, "dpseci")) {
			ret = dpaa2_create_dpseci_dev(vdev,
						      &device_info,
						      object_id);
		} else if (!strcmp(object_type, "dpio")) {
			ret = dpaa2_create_dpio_dev(vdev,
						    &device_info,
						    object_id);
			if (!ret)
				dpio_count++;
		} else if (!strcmp(object_type, "dpbp")) {
			ret = dpaa2_create_dpbp_dev(object_id);
			if (!ret)
				dpbp_count++;
		} else {
			FSLMC_VFIO_LOG(DEBUG, "%s-%d Not supported",
				       object_type, object_id);
			continue;
		}
		if (ret)
			FSLMC_VFIO_LOG(ERR, "%s-%d create failed",
				       object_type, object_id);

	}
	closedir(d);

	ret = dpaa2_affine_qbman_swp();
	if (ret) {
		FSLMC_VFIO_LOG(ERR, "Error in affining qbman swp %d", ret);
		return ret;
	}

	FSLMC_VFIO_LOG(DEBUG, "DPAA2: Added dpio_count = %d dpio_count=%d",
		      dpbp_count, dpio_count);
	return 0;

FAILURE:
	if (d)
		closedir(d);
	if (rte_mcp_ptr_list) {
		free(rte_mcp_ptr_list);
		rte_mcp_ptr_list = NULL;
	}

	free(group->vfio_device);
	group->vfio_device = NULL;
	return -1;
}

int fslmc_vfio_setup_group(void)
{
	struct fslmc_vfio_group *group = NULL;
	int groupid;
	int ret, i;
	char *container;
	struct vfio_group_status status = { .argsz = sizeof(status) };

	/* if already done once */
	if (container_device_fd)
		return 0;

	container = getenv("DPRC");

	if (container == NULL) {
		FSLMC_VFIO_LOG(ERR, "VFIO container not set in env DPRC");
		return -EOPNOTSUPP;
	}

	/* get group number */
	ret = vfio_get_group_no(SYSFS_FSL_MC_DEVICES, container, &groupid);
	if (ret == 0) {
		RTE_LOG(WARNING, EAL, "%s not managed by VFIO, skipping\n",
			container);
		return -EOPNOTSUPP;
	}

	/* if negative, something failed */
	if (ret < 0)
		return ret;

	FSLMC_VFIO_LOG(DEBUG, "VFIO iommu group id = %d", groupid);

	/* Check if group already exists */
	for (i = 0; i < VFIO_MAX_GRP; i++) {
		group = &vfio_groups[i];
		if (group->groupid == groupid) {
			FSLMC_VFIO_LOG(ERR, "groupid already exists %d",
				       groupid);
			return 0;
		}
	}

	/* get the actual group fd */
	ret = vfio_get_group_fd(groupid);
	if (ret < 0)
		return ret;
	group->fd = ret;

	/*
	 * at this point, we know that this group is viable (meaning,
	 * all devices are either bound to VFIO or not bound to anything)
	 */

	ret = ioctl(group->fd, VFIO_GROUP_GET_STATUS, &status);
	if (ret) {
		FSLMC_VFIO_LOG(ERR, " VFIO error getting group status");
		close(group->fd);
		return ret;
	}

	if (!(status.flags & VFIO_GROUP_FLAGS_VIABLE)) {
		FSLMC_VFIO_LOG(ERR, "VFIO group not viable");
		close(group->fd);
		return -EPERM;
	}
	/* Since Group is VIABLE, Store the groupid */
	group->groupid = groupid;

	/* check if group does not have a container yet */
	if (!(status.flags & VFIO_GROUP_FLAGS_CONTAINER_SET)) {
		/* Now connect this IOMMU group to given container */
		ret = vfio_connect_container(group);
		if (ret) {
			FSLMC_VFIO_LOG(ERR, "VFIO error connecting container"
				       " with groupid %d", groupid);
			close(group->fd);
			return ret;
		}
	}

	/* Get Device information */
	ret = ioctl(group->fd, VFIO_GROUP_GET_DEVICE_FD, container);
	if (ret < 0) {
		FSLMC_VFIO_LOG(ERR, "VFIO error getting device %s fd from"
			       " group  %d", container, group->groupid);
		return ret;
	}
	container_device_fd = ret;
	FSLMC_VFIO_LOG(DEBUG, "VFIO Container FD is [0x%X]",
		     container_device_fd);

	return 0;
}

static int
get_kernel_version_info(void) {
	int ret;
	FILE *version_file;

	version_file = fopen(LINUX_VERSION_FILE, "r");
	if (!version_file)
		return -1;

	ret = fscanf(version_file, "Linux version %hi.%hi",
		     &kernel_major_ver, &kernel_minor_ver);
	if (ret <= 0) {
		return -1;
	}

	FSLMC_VFIO_LOG(DEBUG, "Kernel major.minor = %hi.%hi",
		       kernel_major_ver, kernel_minor_ver);

	fclose(version_file);

	return 0;
}

/* Init the FSL-MC- LS2 EAL subsystem */
int
rte_eal_dpaa2_init(void)
{
	int ret;

	ret = get_kernel_version_info();
	if (ret) {
		FSLMC_VFIO_LOG(ERR, "Unable to get Linux kernel version.");
		return -1;
	}

#ifdef VFIO_PRESENT
	if (fslmc_vfio_setup_group()) {
		FSLMC_VFIO_LOG(DEBUG, "dpaa2_setup_vfio_grp");
		FSLMC_VFIO_LOG(ERR, "DPAA2: Unable to setup VFIO");
		return -1;
	}
	if (fslmc_vfio_process_group()) {
		FSLMC_VFIO_LOG(DEBUG, "vfio_process_group_devices");
		FSLMC_VFIO_LOG(ERR, "DPAA2: Unable to setup devices");
		return -1;
	}
	if (dpaa2_platform_debug_init()) {
		RTE_LOG(INFO, PMD, "DPAA2 Platform debug init failed.\n");
	}
	RTE_LOG(INFO, PMD, "DPAA2: Device setup completed\n");
#endif
	return 0;
}
