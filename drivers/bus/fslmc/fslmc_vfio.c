/*-
 *   BSD LICENSE
 *
 *   Copyright (c) 2015-2016 Freescale Semiconductor, Inc. All rights reserved.
 *   Copyright 2016 NXP
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
#include <sys/mman.h>
#include <sys/vfs.h>
#include <libgen.h>
#include <dirent.h>
#include <sys/eventfd.h>

#include <eal_filesystem.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_string_fns.h>
#include <rte_cycles.h>
#include <rte_kvargs.h>
#include <rte_dev.h>
#include <rte_bus.h>

#include "rte_fslmc.h"
#include "fslmc_vfio.h"
#include "fslmc_logs.h"
#include <mc/fsl_dpmng.h>

#include "portal/dpaa2_hw_pvt.h"
#include "portal/dpaa2_hw_dpio.h"

#define FSLMC_CONTAINER_MAX_LEN 8 /**< Of the format dprc.XX */

/* Number of VFIO containers & groups with in */
static struct fslmc_vfio_group vfio_group;
static struct fslmc_vfio_container vfio_container;
static int container_device_fd;
char *fslmc_container;
static int fslmc_iommu_type;
static uint32_t *msi_intr_vaddr;
void *(*rte_mcp_ptr_list);
static int is_dma_done;

static struct rte_dpaa2_object_list dpaa2_obj_list =
	TAILQ_HEAD_INITIALIZER(dpaa2_obj_list);

/*register a fslmc bus based dpaa2 driver */
void
rte_fslmc_object_register(struct rte_dpaa2_object *object)
{
	RTE_VERIFY(object);

	TAILQ_INSERT_TAIL(&dpaa2_obj_list, object, next);
}

int
fslmc_get_container_group(int *groupid)
{
	int ret;
	char *container;

	if (!fslmc_container) {
		container = getenv("DPRC");
		if (container == NULL) {
			DPAA2_BUS_INFO("DPAA2: DPRC not available");
			return -EINVAL;
		}

		if (strlen(container) >= FSLMC_CONTAINER_MAX_LEN) {
			DPAA2_BUS_ERR("Invalid container name: %s", container);
			return -1;
		}

		fslmc_container = strdup(container);
		if (!fslmc_container) {
			DPAA2_BUS_ERR("Mem alloc failure; Container name");
			return -ENOMEM;
		}
	}

	fslmc_iommu_type = (rte_vfio_noiommu_is_enabled() == 1) ?
		RTE_VFIO_NOIOMMU : VFIO_TYPE1_IOMMU;

	/* get group number */
	ret = vfio_get_group_no(SYSFS_FSL_MC_DEVICES, fslmc_container, groupid);
	if (ret <= 0) {
		DPAA2_BUS_ERR("Unable to find %s IOMMU group", fslmc_container);
		return -1;
	}

	DPAA2_BUS_DEBUG("Container: %s has VFIO iommu group id = %d",
			fslmc_container, *groupid);

	return 0;
}

static int
vfio_connect_container(void)
{
	int fd, ret;

	if (vfio_container.used) {
		DPAA2_BUS_DEBUG("No container available");
		return -1;
	}

	/* Try connecting to vfio container if already created */
	if (!ioctl(vfio_group.fd, VFIO_GROUP_SET_CONTAINER,
		&vfio_container.fd)) {
		DPAA2_BUS_DEBUG(
		    "Container pre-exists with FD[0x%x] for this group",
		    vfio_container.fd);
		vfio_group.container = &vfio_container;
		return 0;
	}

	/* Opens main vfio file descriptor which represents the "container" */
	fd = vfio_get_container_fd();
	if (fd < 0) {
		DPAA2_BUS_ERR("Failed to open VFIO container");
		return -errno;
	}

	/* Check whether support for SMMU type IOMMU present or not */
	if (ioctl(fd, VFIO_CHECK_EXTENSION, fslmc_iommu_type)) {
		/* Connect group to container */
		ret = ioctl(vfio_group.fd, VFIO_GROUP_SET_CONTAINER, &fd);
		if (ret) {
			DPAA2_BUS_ERR("Failed to setup group container");
			close(fd);
			return -errno;
		}

		ret = ioctl(fd, VFIO_SET_IOMMU, fslmc_iommu_type);
		if (ret) {
			DPAA2_BUS_ERR("Failed to setup VFIO iommu");
			close(fd);
			return -errno;
		}
	} else {
		DPAA2_BUS_ERR("No supported IOMMU available");
		close(fd);
		return -EINVAL;
	}

	vfio_container.used = 1;
	vfio_container.fd = fd;
	vfio_container.group = &vfio_group;
	vfio_group.container = &vfio_container;

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
		DPAA2_BUS_ERR("Unable to map region (errno = %d)", errno);
		return -errno;
	}

	msi_intr_vaddr = (uint32_t *)((char *)(vaddr) + 64);
	map.vaddr = (unsigned long)vaddr;
	ret = ioctl(group->container->fd, VFIO_IOMMU_MAP_DMA, &map);
	if (ret == 0)
		return 0;

	DPAA2_BUS_ERR("Unable to map DMA address (errno = %d)", errno);
	return -errno;
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

	if (fslmc_iommu_type == RTE_VFIO_NOIOMMU) {
		DPAA2_BUS_DEBUG("Running in NOIOMMU mode");
		return 0;
	}

	if (is_dma_done)
		return 0;

	memseg = rte_eal_get_physmem_layout();
	if (memseg == NULL) {
		DPAA2_BUS_ERR("Cannot get physical layout");
		return -ENODEV;
	}

	for (i = 0; i < RTE_MAX_MEMSEG; i++) {
		if (memseg[i].addr == NULL && memseg[i].len == 0) {
			DPAA2_BUS_DEBUG("Total %d segments found", i);
			break;
		}

		dma_map.size = memseg[i].len;
		dma_map.vaddr = memseg[i].addr_64;
#ifdef RTE_LIBRTE_DPAA2_USE_PHYS_IOVA
		if (rte_eal_iova_mode() == RTE_IOVA_VA)
			dma_map.iova = dma_map.vaddr;
		else
			dma_map.iova = memseg[i].iova;
#else
		dma_map.iova = dma_map.vaddr;
#endif

		/* SET DMA MAP for IOMMU */
		group = &vfio_group;

		if (!group->container) {
			DPAA2_BUS_ERR("Container is not connected");
			return -1;
		}

		DPAA2_BUS_DEBUG("-->Initial SHM Virtual ADDR %llX",
				dma_map.vaddr);
		DPAA2_BUS_DEBUG("-----> DMA size 0x%llX", dma_map.size);
		ret = ioctl(group->container->fd, VFIO_IOMMU_MAP_DMA,
			    &dma_map);
		if (ret) {
			DPAA2_BUS_ERR("Unable to map DMA address (errno = %d)",
				      errno);
			return ret;
		}
	}

	/* Verifying that at least single segment is available */
	if (i <= 0) {
		DPAA2_BUS_ERR("No Segments found for VFIO Mapping");
		return -1;
	}

	/* TODO - This is a W.A. as VFIO currently does not add the mapping of
	 * the interrupt region to SMMU. This should be removed once the
	 * support is added in the Kernel.
	 */
	vfio_map_irq_region(group);

	is_dma_done = 1;

	return 0;
}

int
fslmc_vfio_setup_device(const char *sysfs_base, const char *dev_addr,
		int *vfio_dev_fd, struct vfio_device_info *device_info)
{
	struct vfio_group_status group_status = {
			.argsz = sizeof(group_status)
	};
	int vfio_group_fd, vfio_container_fd, iommu_group_no, ret;

	/* get group number */
	ret = vfio_get_group_no(sysfs_base, dev_addr, &iommu_group_no);
	if (ret < 0)
		return -1;

	/* get the actual group fd */
	vfio_group_fd = vfio_get_group_fd(iommu_group_no);
	if (vfio_group_fd < 0)
		return -1;

	/* if group_fd == 0, that means the device isn't managed by VFIO */
	if (vfio_group_fd == 0) {
		RTE_LOG(WARNING, EAL, " %s not managed by VFIO driver, skipping\n",
				dev_addr);
		return 1;
	}

	/* Opens main vfio file descriptor which represents the "container" */
	vfio_container_fd = vfio_get_container_fd();
	if (vfio_container_fd < 0) {
		DPAA2_BUS_ERR("Failed to open VFIO container");
		return -errno;
	}

	/* check if the group is viable */
	ret = ioctl(vfio_group_fd, VFIO_GROUP_GET_STATUS, &group_status);
	if (ret) {
		DPAA2_BUS_ERR("  %s cannot get group status, "
				"error %i (%s)\n", dev_addr, errno, strerror(errno));
		close(vfio_group_fd);
		rte_vfio_clear_group(vfio_group_fd);
		return -1;
	} else if (!(group_status.flags & VFIO_GROUP_FLAGS_VIABLE)) {
		DPAA2_BUS_ERR("  %s VFIO group is not viable!\n", dev_addr);
		close(vfio_group_fd);
		rte_vfio_clear_group(vfio_group_fd);
		return -1;
	}
	/* At this point, we know that this group is viable (meaning, all devices
	 * are either bound to VFIO or not bound to anything)
	 */

	/* check if group does not have a container yet */
	if (!(group_status.flags & VFIO_GROUP_FLAGS_CONTAINER_SET)) {

		/* add group to a container */
		ret = ioctl(vfio_group_fd, VFIO_GROUP_SET_CONTAINER,
				&vfio_container_fd);
		if (ret) {
			DPAA2_BUS_ERR("  %s cannot add VFIO group to container, "
					"error %i (%s)\n", dev_addr, errno, strerror(errno));
			close(vfio_group_fd);
			close(vfio_container_fd);
			rte_vfio_clear_group(vfio_group_fd);
			return -1;
		}

		/*
		 * set an IOMMU type for container
		 *
		 */
		if (ioctl(vfio_container_fd, VFIO_CHECK_EXTENSION, fslmc_iommu_type)) {
			ret = ioctl(vfio_container_fd, VFIO_SET_IOMMU, fslmc_iommu_type);
			if (ret) {
				DPAA2_BUS_ERR("Failed to setup VFIO iommu");
				close(vfio_group_fd);
				close(vfio_container_fd);
				return -errno;
			}
		} else {
			DPAA2_BUS_ERR("No supported IOMMU available");
			close(vfio_group_fd);
			close(vfio_container_fd);
			return -EINVAL;
		}
	}

	/* get a file descriptor for the device */
	*vfio_dev_fd = ioctl(vfio_group_fd, VFIO_GROUP_GET_DEVICE_FD, dev_addr);
	if (*vfio_dev_fd < 0) {
		/* if we cannot get a device fd, this implies a problem with
		 * the VFIO group or the container not having IOMMU configured.
		 */

		DPAA2_BUS_WARN("Getting a vfio_dev_fd for %s failed", dev_addr);
		close(vfio_group_fd);
		close(vfio_container_fd);
		rte_vfio_clear_group(vfio_group_fd);
		return -1;
	}

	/* test and setup the device */
	ret = ioctl(*vfio_dev_fd, VFIO_DEVICE_GET_INFO, device_info);
	if (ret) {
		DPAA2_BUS_ERR("  %s cannot get device info, error %i (%s)",
				dev_addr, errno, strerror(errno));
		close(*vfio_dev_fd);
		close(vfio_group_fd);
		close(vfio_container_fd);
		rte_vfio_clear_group(vfio_group_fd);
		return -1;
	}

	return 0;
}


static int64_t vfio_map_mcp_obj(const char *mcp_obj)
{
	int64_t v_addr = (int64_t)MAP_FAILED;
	int32_t ret, mc_fd;
	struct vfio_group_status status = { .argsz = sizeof(status) };

	struct vfio_device_info d_info = { .argsz = sizeof(d_info) };
	struct vfio_region_info reg_info = { .argsz = sizeof(reg_info) };


	fslmc_vfio_setup_device(SYSFS_FSL_MC_DEVICES, mcp_obj,
			&mc_fd, &d_info);

	/* getting device region info*/
	ret = ioctl(mc_fd, VFIO_DEVICE_GET_REGION_INFO, &reg_info);
	if (ret < 0) {
		DPAA2_BUS_ERR("Error in VFIO getting REGION_INFO");
		goto MC_FAILURE;
	}

	v_addr = (size_t)mmap(NULL, reg_info.size,
		PROT_WRITE | PROT_READ, MAP_SHARED,
		mc_fd, reg_info.offset);

MC_FAILURE:
	close(mc_fd);

	return v_addr;
}

#define IRQ_SET_BUF_LEN  (sizeof(struct vfio_irq_set) + sizeof(int))

int rte_dpaa2_intr_enable(struct rte_intr_handle *intr_handle, int index)
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
		DPAA2_BUS_ERR("Error:dpaa2 SET IRQs fd=%d, err = %d(%s)",
			      intr_handle->fd, errno, strerror(errno));
		return ret;
	}

	return ret;
}

int rte_dpaa2_intr_disable(struct rte_intr_handle *intr_handle, int index)
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
		DPAA2_BUS_ERR(
			"Error disabling dpaa2 interrupts for fd %d",
			intr_handle->fd);

	return ret;
}

/* set up interrupt support (but not enable interrupts) */
int
rte_dpaa2_vfio_setup_intr(struct rte_intr_handle *intr_handle,
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
			DPAA2_BUS_ERR("Cannot get IRQ(%d) info, error %i (%s)",
				      i, errno, strerror(errno));
			return -1;
		}

		/* if this vector cannot be used with eventfd,
		 * fail if we explicitly
		 * specified interrupt type, otherwise continue
		 */
		if ((irq_info.flags & VFIO_IRQ_INFO_EVENTFD) == 0)
			continue;

		/* set up an eventfd for interrupts */
		fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
		if (fd < 0) {
			DPAA2_BUS_ERR("Cannot set up eventfd, error %i (%s)",
				      errno, strerror(errno));
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

/*
 * fslmc_process_iodevices for processing only IO (ETH, CRYPTO, and possibly
 * EVENT) devices.
 */
static int
fslmc_process_iodevices(struct rte_dpaa2_device *dev)
{
	int dev_fd;
	struct vfio_device_info device_info = { .argsz = sizeof(device_info) };
	struct rte_dpaa2_object *object = NULL;

	fslmc_vfio_setup_device(SYSFS_FSL_MC_DEVICES, dev->device.name,
			&dev_fd, &device_info);

	switch (dev->dev_type) {
	case DPAA2_ETH:
		rte_dpaa2_vfio_setup_intr(&dev->intr_handle, dev_fd,
					  device_info.num_irqs);
		break;
	case DPAA2_CON:
	case DPAA2_IO:
	case DPAA2_CI:
	case DPAA2_BPOOL:
		TAILQ_FOREACH(object, &dpaa2_obj_list, next) {
			if (dev->dev_type == object->dev_type)
				object->create(dev_fd, &device_info,
					       dev->object_id);
			else
				continue;
		}
		break;
	default:
		break;
	}

	DPAA2_BUS_LOG(DEBUG, "Device (%s) abstracted from VFIO",
		      dev->device.name);
	return 0;
}

static int
fslmc_process_mcp(struct rte_dpaa2_device *dev)
{
	intptr_t v_addr;
	char *dev_name;
	struct fsl_mc_io dpmng  = {0};
	struct mc_version mc_ver_info = {0};

	rte_mcp_ptr_list = malloc(sizeof(void *) * 1);
	if (!rte_mcp_ptr_list) {
		DPAA2_BUS_ERR("Unable to allocate MC portal memory");
		return -ENOMEM;
	}

	dev_name = strdup(dev->device.name);
	if (!dev_name) {
		DPAA2_BUS_ERR("Unable to allocate MC device name memory");
		free(rte_mcp_ptr_list);
		rte_mcp_ptr_list = NULL;
		return -ENOMEM;
	}

	v_addr = vfio_map_mcp_obj(dev->device.name);
	if (v_addr == (intptr_t)MAP_FAILED) {
		DPAA2_BUS_ERR("Error mapping region (errno = %d)", errno);
		free(rte_mcp_ptr_list);
		rte_mcp_ptr_list = NULL;
		return -1;
	}

	/* check the MC version compatibility */
	dpmng.regs = (void *)v_addr;
	if (mc_get_version(&dpmng, CMD_PRI_LOW, &mc_ver_info)) {
		DPAA2_BUS_ERR("Unable to obtain MC version");
		return -1;
	}

	if ((mc_ver_info.major != MC_VER_MAJOR) ||
	    (mc_ver_info.minor < MC_VER_MINOR)) {
		DPAA2_BUS_ERR("DPAA2 MC version not compatible!"
			      " Expected %d.%d.x, Detected %d.%d.%d",
			      MC_VER_MAJOR, MC_VER_MINOR,
			      mc_ver_info.major, mc_ver_info.minor,
			      mc_ver_info.revision);
		free(rte_mcp_ptr_list);
		rte_mcp_ptr_list = NULL;
		return -1;
	}
	rte_mcp_ptr_list[0] = (void *)v_addr;

	return 0;
}

int
fslmc_vfio_process_group(void)
{
	int ret;
	int found_mportal = 0;
	struct rte_dpaa2_device *dev, *dev_temp;

	/* Search the MCP as that should be initialized first. */
	TAILQ_FOREACH_SAFE(dev, &rte_fslmc_bus.device_list, next, dev_temp) {
		if (dev->dev_type == DPAA2_MPORTAL) {
			ret = fslmc_process_mcp(dev);
			if (ret) {
				DPAA2_BUS_ERR("Unable to map MC Portal");
				return -1;
			}
			if (!found_mportal)
				found_mportal = 1;

			TAILQ_REMOVE(&rte_fslmc_bus.device_list, dev, next);
			free(dev);
			dev = NULL;
			/* Ideally there is only a single dpmcp, but in case
			 * multiple exists, looping on remaining devices.
			 */
		}
	}

	/* Cannot continue if there is not even a single mportal */
	if (!found_mportal) {
		DPAA2_BUS_ERR("No MC Portal device found. Not continuing");
		return -1;
	}

	TAILQ_FOREACH_SAFE(dev, &rte_fslmc_bus.device_list, next, dev_temp) {
		if (!dev)
			break;

		switch (dev->dev_type) {
		case DPAA2_ETH:
		case DPAA2_CRYPTO:
		case DPAA2_QDMA:
			ret = fslmc_process_iodevices(dev);
			if (ret) {
				DPAA2_BUS_DEBUG("Dev (%s) init failed",
						dev->device.name);
				return ret;
			}
			break;
		case DPAA2_CON:
		case DPAA2_IO:
		case DPAA2_CI:
		case DPAA2_BPOOL:
			/* Call the object creation routine and remove the
			 * device entry from device list
			 */
			ret = fslmc_process_iodevices(dev);
			if (ret) {
				DPAA2_BUS_DEBUG("Dev (%s) init failed",
						dev->device.name);
				return -1;
			}

			/* This device is not required to be in the DPDK
			 * exposed device list.
			 */
			TAILQ_REMOVE(&rte_fslmc_bus.device_list, dev, next);
			free(dev);
			dev = NULL;
			break;
		case DPAA2_UNKNOWN:
		default:
			/* Unknown - ignore */
			DPAA2_BUS_DEBUG("Found unknown device (%s)",
					dev->device.name);
			TAILQ_REMOVE(&rte_fslmc_bus.device_list, dev, next);
			free(dev);
			dev = NULL;
		}
	}

	return 0;
}

int
fslmc_vfio_setup_group(void)
{
	int groupid;
	int ret;
	struct vfio_group_status status = { .argsz = sizeof(status) };

	/* if already done once */
	if (container_device_fd)
		return 0;

	ret = fslmc_get_container_group(&groupid);
	if (ret)
		return ret;

	/* Get the actual group fd */
	ret = vfio_get_group_fd(groupid);
	if (ret < 0)
		return ret;
	vfio_group.fd = ret;

	/* Check group viability */
	ret = ioctl(vfio_group.fd, VFIO_GROUP_GET_STATUS, &status);
	if (ret) {
		DPAA2_BUS_ERR("VFIO error getting group status");
		close(vfio_group.fd);
		rte_vfio_clear_group(vfio_group.fd);
		return ret;
	}

	if (!(status.flags & VFIO_GROUP_FLAGS_VIABLE)) {
		DPAA2_BUS_ERR("VFIO group not viable");
		close(vfio_group.fd);
		rte_vfio_clear_group(vfio_group.fd);
		return -EPERM;
	}
	/* Since Group is VIABLE, Store the groupid */
	vfio_group.groupid = groupid;

	/* check if group does not have a container yet */
	if (!(status.flags & VFIO_GROUP_FLAGS_CONTAINER_SET)) {
		/* Now connect this IOMMU group to given container */
		ret = vfio_connect_container();
		if (ret) {
			DPAA2_BUS_ERR(
				"Error connecting container with groupid %d",
				groupid);
			close(vfio_group.fd);
			rte_vfio_clear_group(vfio_group.fd);
			return ret;
		}
	}

	/* Get Device information */
	ret = ioctl(vfio_group.fd, VFIO_GROUP_GET_DEVICE_FD, fslmc_container);
	if (ret < 0) {
		DPAA2_BUS_ERR("Error getting device %s fd from group %d",
			      fslmc_container, vfio_group.groupid);
		close(vfio_group.fd);
		rte_vfio_clear_group(vfio_group.fd);
		return ret;
	}
	container_device_fd = ret;
	DPAA2_BUS_DEBUG("VFIO Container FD is [0x%X]",
			container_device_fd);

	return 0;
}
