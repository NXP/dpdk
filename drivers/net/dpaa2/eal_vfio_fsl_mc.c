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

#include <eal_vfio.h>

#include <rte_log.h>

#include <rte_eth_dpaa2_pvt.h>
#include <eal_vfio_fsl_mc.h>

#include <eal_filesystem.h>
#include <eal_private.h>

#ifndef VFIO_MAX_GROUPS
#define VFIO_MAX_GROUPS 64
#endif

/** Pathname of FSL-MC devices directory. */
#define SYSFS_FSL_MC_DEVICES "/sys/bus/fsl-mc/devices"

/* Number of VFIO containers & groups with in */
static struct fsl_vfio_group vfio_groups[VFIO_MAX_GRP];
static struct fsl_vfio_container vfio_containers[VFIO_MAX_CONTAINERS];
static int container_device_fd;
static uint32_t *msi_intr_vaddr;
void *(*mcp_ptr_list);
static uint32_t mcp_id;

static int vfio_connect_container(struct fsl_vfio_group *vfio_group)
{
	struct fsl_vfio_container *container;
	int i, fd, ret;

	/* Try connecting to vfio container if already created */
	for (i = 0; i < VFIO_MAX_CONTAINERS; i++) {
		container = &vfio_containers[i];
		if (!ioctl(vfio_group->fd, VFIO_GROUP_SET_CONTAINER, &container->fd)) {
			RTE_LOG(ERR, EAL, "Container pre-exists with FD[0x%x]"
					" for this group\n", container->fd);
			vfio_group->container = container;
			return 0;
		}
	}

	/* Opens main vfio file descriptor which represents the "container" */
	fd = open("/dev/vfio/vfio", O_RDWR);
	if (fd < 0) {
		RTE_LOG(ERR, EAL, "vfio: failed to open /dev/vfio/vfio\n");
		return -errno;
	}

	ret = ioctl(fd, VFIO_GET_API_VERSION);
	if (ret != VFIO_API_VERSION) {
		RTE_LOG(ERR, EAL, "vfio: supported vfio version: %d, "
			"reported version: %d", VFIO_API_VERSION, ret);
		close(fd);
		return -EINVAL;
	}
	/* Check whether support for SMMU type IOMMU prresent or not */
	if (ioctl(fd, VFIO_CHECK_EXTENSION, VFIO_TYPE1_IOMMU)) {
		/* Connect group to container */
		ret = ioctl(vfio_group->fd, VFIO_GROUP_SET_CONTAINER, &fd);
		if (ret) {
			RTE_LOG(ERR, EAL, "vfio: failed to set group container:\n");
			close(fd);
			return -errno;
		}

		ret = ioctl(fd, VFIO_SET_IOMMU, VFIO_TYPE1_IOMMU);
		if (ret) {
			RTE_LOG(ERR, EAL, "vfio: failed to set iommu for container:\n");
			close(fd);
			return -errno;
		}
	} else {
		RTE_LOG(ERR, EAL, "vfio error: No supported IOMMU\n");
		close(fd);
		return -EINVAL;
	}

	container = NULL;
	for (i = 0; i < VFIO_MAX_CONTAINERS; i++) {
		if (vfio_containers[i].used)
			continue;
		RTE_LOG(ERR, EAL, "DPAA2-Unused container at index %d\n", i);
		container = &vfio_containers[i];
	}
	if (!container) {
		RTE_LOG(ERR, EAL, "vfio error: No Free Container Found\n");
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

static int vfio_map_irq_region(struct fsl_vfio_group *group)
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
		RTE_LOG(ERR, EAL, " mapping GITS region (errno = %d)", errno);
		return -errno;
	}

	msi_intr_vaddr = (uint32_t *)((char *)(vaddr) + 64);
	map.vaddr = (unsigned long)vaddr;
	ret = ioctl(group->container->fd, VFIO_IOMMU_MAP_DMA, &map);
	if (ret == 0)
		return 0;

	RTE_LOG(ERR, EAL, "vfio_map_irq_region fails (errno = %d)", errno);
	return -errno;
}

int vfio_dmamap_mem_region(uint64_t vaddr,
			   uint64_t iova,
			   uint64_t size)
{
	struct fsl_vfio_group *group;
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
		RTE_LOG(ERR, EAL, "SWP: VFIO_IOMMU_MAP_DMA API Error %d.\n", errno);
		return -1;
	}
	return 0;
}

static int32_t setup_dmamap(void)
{
	int ret;
	struct fsl_vfio_group *group;
	struct vfio_iommu_type1_dma_map dma_map = {
		.argsz = sizeof(struct vfio_iommu_type1_dma_map),
		.flags = VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE,
	};

	int i;
	const struct rte_memseg *memseg;

	for (i = 0; i < RTE_MAX_MEMSEG; i++) {
		memseg = rte_eal_get_physmem_layout();
		if (memseg == NULL) {
			RTE_LOG(ERR, EAL,
				"\nError Cannot get physical layout\n");
			return -ENODEV;
		}

		if (memseg[i].addr == NULL && memseg[i].len == 0) {
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

		printf("-->Initial SHM Virtual ADDR %llX\n", dma_map.vaddr);
		printf("-----> DMA size 0x%llX\n", dma_map.size);
		ret = ioctl(group->container->fd, VFIO_IOMMU_MAP_DMA, &dma_map);
		if (ret) {
			RTE_LOG(ERR, EAL,
				"\nErr: VFIO_IOMMU_MAP_DMA API Error %d.\n",
				errno);
			return ret;
		}
		printf("-----> dma_map.vaddr = 0x%llX\n", dma_map.vaddr);
	}

	/* TODO - This is a W.A. as VFIO currently does not add the mapping of
	    the interrupt region to SMMU. This should be removed once the
	    support is added in the Kernel.
	 */
	vfio_map_irq_region(group);

	return 0;
}

static int32_t dpaa2_setup_vfio_grp(void)
{
	char path[PATH_MAX];
	char iommu_group_path[PATH_MAX], *group_name;
	struct fsl_vfio_group *group = NULL;
	struct stat st;
	int groupid;
	int ret, len, i;
	char *container;
	struct vfio_group_status status = { .argsz = sizeof(status) };

	/* if already done once */
	if (container_device_fd)
		return 0;

	container = getenv("DPRC");

	if (container == NULL) {
		RTE_LOG(WARNING, EAL, "vfio container not set in env DPRC\n");
		return -1;
	}
	printf("\tProcessing Container = %s\n", container);
	snprintf(path, sizeof(path), "%s/%s", SYSFS_FSL_MC_DEVICES, container);

	/* Check whether fsl-mc container exists or not */
	RTE_LOG(INFO, EAL, "\tcontainer device path = %s\n", path);
	if (stat(path, &st) < 0) {
		RTE_LOG(ERR, EAL, "vfio: Error (%d) getting FSL-MC device (%s)\n",
			errno,  path);
		return -errno;
	}

	/* DPRC container exists. Now checkout the IOMMU Group */
	strncat(path, "/iommu_group", sizeof(path) - strlen(path) - 1);

	len = readlink(path, iommu_group_path, PATH_MAX);
	if (len == -1) {
		RTE_LOG(ERR, EAL, "\tvfio: error no iommu_group for device\n");
		RTE_LOG(ERR, EAL, "\t%s: len = %d, errno = %d\n",
			path, len, errno);
		return -errno;
	}

	iommu_group_path[len] = 0;
	group_name = basename(iommu_group_path);
	if (sscanf(group_name, "%d", &groupid) != 1) {
		RTE_LOG(ERR, EAL, "\tvfio: error reading %s: %m\n", path);
		return -errno;
	}

	RTE_LOG(INFO, EAL, "\tvfio: iommu group id = %d\n", groupid);

	/* Check if group already exists */
	for (i = 0; i < VFIO_MAX_GRP; i++) {
		group = &vfio_groups[i];
		if (group->groupid == groupid) {
			RTE_LOG(ERR, EAL, "groupid already exists %d\n", groupid);
			return 0;
		}
	}

	/* Open the VFIO file corresponding to the IOMMU group */
	snprintf(path, sizeof(path), "/dev/vfio/%d", groupid);

	group->fd = open(path, O_RDWR);
	if (group->fd < 0) {
		RTE_LOG(ERR, EAL, "vfio: error opening %s\n", path);
		return -1;
	}

	/* Test & Verify that group is VIABLE & AVAILABLE */
	if (ioctl(group->fd, VFIO_GROUP_GET_STATUS, &status)) {
		RTE_LOG(ERR, EAL, "vfio: error getting group status\n");
		close(group->fd);
		return -1;
	}
	if (!(status.flags & VFIO_GROUP_FLAGS_VIABLE)) {
		RTE_LOG(ERR, EAL, "vfio: group not viable\n");
		close(group->fd);
		return -1;
	}
	/* Since Group is VIABLE, Store the groupid */
	group->groupid = groupid;

	/* check if group does not have a container yet */
	if (!(status.flags & VFIO_GROUP_FLAGS_CONTAINER_SET)) {
		/* Now connect this IOMMU group to given container */
		if (vfio_connect_container(group)) {
			RTE_LOG(ERR, EAL,
				"vfio: error sonnecting container with group %d\n",
				groupid);
			close(group->fd);
			return -1;
		}
	}

	/* Get Device information */
	ret = ioctl(group->fd, VFIO_GROUP_GET_DEVICE_FD, container);
	if (ret < 0) {
		RTE_LOG(ERR, EAL, "\tvfio: error getting device %s fd from group %d\n",
			container, group->groupid);
		return ret;
	}
	container_device_fd = ret;
	RTE_LOG(INFO, EAL, "vfio: Container FD is [0x%X]\n", container_device_fd);
	/* Set up SMMU */
	ret = setup_dmamap();
	if (ret) {
		RTE_LOG(ERR, EAL, ": Setting dma map\n");
		return ret;
	}

	return 0;
}

static int64_t vfio_map_mcp_obj(struct fsl_vfio_group *group, char *mcp_obj)
{
	int64_t v_addr = (int64_t)MAP_FAILED;
	int32_t ret, mc_fd;

	struct vfio_device_info d_info = { .argsz = sizeof(d_info) };
	struct vfio_region_info reg_info = { .argsz = sizeof(reg_info) };

	/* getting the mcp object's fd*/
	mc_fd = ioctl(group->fd, VFIO_GROUP_GET_DEVICE_FD, mcp_obj);
	if (mc_fd < 0) {
		RTE_LOG(ERR, EAL, "vfio: error getting device %s fd from group %d\n",
			mcp_obj, group->fd);
		return v_addr;
	}

	/* getting device info*/
	ret = ioctl(mc_fd, VFIO_DEVICE_GET_INFO, &d_info);
	if (ret < 0) {
		RTE_LOG(ERR, EAL, "vfio: error getting DEVICE_INFO\n");
		goto MC_FAILURE;
	}

	/* getting device region info*/
	ret = ioctl(mc_fd, VFIO_DEVICE_GET_REGION_INFO, &reg_info);
	if (ret < 0) {
		RTE_LOG(ERR, EAL, "vfio: error getting REGION_INFO\n");
		goto MC_FAILURE;
	}

	RTE_LOG(INFO, EAL, "region offset = %llx  , region size = %llx\n",
		reg_info.offset, reg_info.size);

	v_addr = (uint64_t)mmap(NULL, reg_info.size,
		PROT_WRITE | PROT_READ, MAP_SHARED,
		mc_fd, reg_info.offset);

MC_FAILURE:
	close(mc_fd);

	return v_addr;
}

/* Following function shall fetch total available list of MC devices
 * from VFIO container & populate private list of devices and other
 * data structures
 */
static int vfio_process_group_devices(void)
{
	struct fsl_vfio_device *vdev;
	struct vfio_device_info device_info = { .argsz = sizeof(device_info) };
	char *temp_obj, *object_type, *mcp_obj, *dev_name;
	int32_t object_id, i, dev_fd, ret;
	DIR *d;
	struct dirent *dir;
	char path[PATH_MAX];
	int64_t v_addr;
	int ndev_count;
	struct fsl_vfio_group *group = &vfio_groups[0];
	static int process_once;

	/* if already done once */
	if (process_once) {
		printf("\n %s - Already scanned once - re-scan not supported",
			__func__);
		return 0;
	}
	process_once = 0;

	sprintf(path, "/sys/kernel/iommu_groups/%d/devices", group->groupid);

	d = opendir(path);
	if (!d) {
		RTE_LOG(ERR, EAL, "Unable to open directory %s\n", path);
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
					RTE_LOG(ERR, EAL,
						"Unable to allocate memory\n");
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

	if (!mcp_obj) {
		RTE_LOG(ERR, EAL, "MCP Object not Found\n");
		return -ENODEV;
	}
	RTE_LOG(INFO, EAL, "Total devices in conatiner = %d, MCP ID = %d\n",
		ndev_count, mcp_id);

	/* Allocate the memory depends upon number of objects in a group*/
	group->vfio_device = (struct fsl_vfio_device *)malloc(ndev_count * sizeof(struct fsl_vfio_device));
	if (!(group->vfio_device)) {
		RTE_LOG(ERR, EAL, "Unable to allocate memory\n");
		free(mcp_obj);
		return -ENOMEM;
	}

	/* Allocate memory for MC Portal list */
	mcp_ptr_list = malloc(sizeof(void *) * 1);
	if (!mcp_ptr_list) {
		RTE_LOG(ERR, EAL, "NO Memory!\n");
		free(mcp_obj);
		goto FAILURE;
	}

	v_addr = vfio_map_mcp_obj(group, mcp_obj);
	free(mcp_obj);
	if (v_addr == (int64_t)MAP_FAILED) {
		RTE_LOG(ERR, EAL, "mapping region (errno = %d)\n", errno);
		goto FAILURE;
	}

	RTE_LOG(INFO, EAL, "MC has VIR_ADD = 0x%ld\n", v_addr);

	mcp_ptr_list[0] = (void *)v_addr;

	d = opendir(path);
	if (!d) {
		RTE_LOG(ERR, EAL, "Directory %s not able to open\n", path);
		goto FAILURE;
	}

	i = 0;
	printf("\nDPAA2 - Parsing MC Device Objects:\n");
	/* Parsing each object and initiating them*/
	while ((dir = readdir(d)) != NULL) {
		if (dir->d_type != DT_LNK)
			continue;
		if (!strncmp("dprc", dir->d_name, 4) || !strncmp("dpmcp", dir->d_name, 5))
			continue;
		dev_name = malloc(sizeof(dir->d_name));
		if (!dev_name) {
			RTE_LOG(ERR, EAL, "Unable to allocate memory\n");
			goto FAILURE;
		}
		strcpy(dev_name, dir->d_name);
		object_type = strtok(dir->d_name, ".");
		temp_obj = strtok(NULL, ".");
		sscanf(temp_obj, "%d", &object_id);
		RTE_LOG(INFO, EAL, "%s ", dev_name);

		/* getting the device fd*/
		dev_fd = ioctl(group->fd, VFIO_GROUP_GET_DEVICE_FD, dev_name);
		if (dev_fd < 0) {
			RTE_LOG(ERR, EAL, "vfio getting device %s fd from group %d\n",
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
			RTE_LOG(ERR, EAL, "VFIO_DEVICE_FSL_MC_GET_INFO failed\n");
			goto FAILURE;
		}

		if (!strcmp(object_type, "dpni") ||
		    !strcmp(object_type, "dpseci")) {
			struct rte_pci_device *dev;

			dev = malloc(sizeof(struct rte_pci_device));
			if (dev == NULL) {
				return -1;
			}
			memset(dev, 0, sizeof(*dev));
			/* store hw_id of dpni/dpseci device */
			dev->addr.devid = object_id;
			dev->id.vendor_id = FSL_VENDOR_ID;
			dev->id.device_id = (strcmp(object_type, "dpseci")) ?
					FSL_MC_DPNI_DEVID : FSL_MC_DPSECI_DEVID;
			dev->addr.function = dev->id.device_id;

			TAILQ_INSERT_TAIL(&pci_device_list, dev, next);
		}

		if (!strcmp(object_type, "dpio")) {
			dpaa2_create_dpio_device(vdev, &device_info, object_id);
		}

		if (!strcmp(object_type, "dpbp")) {
			dpaa2_create_dpbp_device(object_id);
		}
	}
	closedir(d);

	ret = dpaa2_affine_qbman_swp();
	if (ret)
		RTE_LOG(ERR, EAL, "%s(): Err in affining qbman swp\n", __func__);

	return 0;

FAILURE:
	free(group->vfio_device);
	group->vfio_device = NULL;
	return -1;
}

/* Init the FSL-MC- LS2 EAL subsystem */
int
rte_eal_dpaa2_init(void)
{
#ifdef VFIO_PRESENT
	if (dpaa2_setup_vfio_grp()) {
		RTE_LOG(ERR, EAL, "dpaa2_setup_vfio_grp\n");
		return -1;
	}
	if (vfio_process_group_devices()) {
		RTE_LOG(ERR, EAL, "vfio_process_group_devices\n");
		return -1;
	}
#endif
	return 0;
}
