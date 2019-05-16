/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019 NXP
 */

#include <assert.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>

#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_debug.h>
#include <rte_dev.h>
#include <rte_eal.h>
#include <rte_kvargs.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_lcore.h>
#include <rte_bus_vdev.h>
#include <rte_mempool.h>
#include <rte_rawdev.h>
#include <rte_rawdev_pmd.h>

#include <geul_ipc_dev.h>
#include <rte_pmd_geul_ipc_rawdev.h>

/* Dynamic log type identifier */
int geulipc_pmd_logtype;

/* Count of instances */
static uint16_t geuldev_dev_count;

#define GEULIPC_PMD_NAME geul_ipc_dev

static struct rte_vdev_driver geulipc_pmd_drv;

/**
 * Configure the host channel by calling ipc_host_init
 */
static int
geulipc_rawdev_configure(const struct rte_rawdev *dev,
			 rte_rawdev_obj_t config)
{
	struct geulipc_rawdev *geuldev;
	geulipc_rawdev_config_t *gc;

	GEULIPC_PMD_FUNC_TRACE();

	RTE_FUNC_PTR_OR_ERR_RET(dev, -EINVAL);

	gc = (geulipc_rawdev_config_t *)config;
	geuldev = geulipc_rawdev_get_priv(dev);

	geuldev->device_id = gc->device_id;
	geuldev->instance_handle = gc->instance_handle;

	GEULIPC_PMD_INFO("Configured Host for device:%d\n", gc->device_id);

	return 0;
}

static void geulipc_rawdev_info_get(struct rte_rawdev *dev,
				     rte_rawdev_obj_t dev_info)
{
	struct geulipc_rawdev *geuldev;
	geulipc_rawdev_config_t *gc;

	GEULIPC_PMD_FUNC_TRACE();

	if (!dev_info) {
		GEULIPC_PMD_ERR("Invalid request");
		return;
	}

	geuldev = geulipc_rawdev_get_priv(dev);

	gc = dev_info;

	gc->instance_handle = geuldev->instance_handle;
	gc->device_id = geuldev->device_id;
}

static const struct rte_rawdev_ops geulipc_rawdev_ops = {
	.dev_info_get = geulipc_rawdev_info_get,
	.dev_configure = geulipc_rawdev_configure,
};

static int
geulipc_rawdev_create(const char *name,
		      struct rte_vdev_device *vdev,
		  int socket_id)
{
	int ret = 0;
	struct rte_rawdev *rawdev = NULL;
	struct geulipc_rawdev *geuldev = NULL;

	if (!name) {
		GEULIPC_PMD_ERR("Invalid name of the device (NULL)!");
		ret = -EINVAL;
		goto cleanup;
	}

	/* Allocate device structure */
	rawdev = rte_rawdev_pmd_allocate(name, sizeof(struct geulipc_rawdev),
					 socket_id);
	if (rawdev == NULL) {
		GEULIPC_PMD_ERR("Unable to allocate rawdevice");
		ret = -EINVAL;
		goto cleanup;
	}

	rawdev->dev_ops = &geulipc_rawdev_ops;
	rawdev->device = &vdev->device;

	geuldev = geulipc_rawdev_get_priv(rawdev);
	/* TODO: Only a single device is supported. If not, this needs to be
	 * extracted from the name of the device, probably: geulipc_rawdev_0
	 */
	geuldev->device_id = GEULIPC_DEVICE_ID;

	return ret;

cleanup:
	if (rawdev)
		rte_rawdev_pmd_release(rawdev);

	return ret;
}

static int
geulipc_rawdev_probe(struct rte_vdev_device *vdev)
{
	const char *name;
	int ret;

	name = rte_vdev_device_name(vdev);
	
	GEULIPC_PMD_INFO("Init %s on NUMA node %d", name, rte_socket_id());

	ret = geulipc_rawdev_create(name, vdev, rte_socket_id());
	if (ret) {
		return -1;
	}

	/* Increment the device instance count */
	geuldev_dev_count ++;

	return ret;
}

static int
geulipc_rawdev_remove(struct rte_vdev_device *vdev __rte_unused)
{
	return 0;
}

static struct rte_vdev_driver geulipc_pmd_drv = {
	.probe = geulipc_rawdev_probe,
	.remove = geulipc_rawdev_remove
};

RTE_PMD_REGISTER_VDEV(GEULIPC_PMD_NAME, geulipc_pmd_drv);

RTE_INIT(geulipc_pmd_init_log)
{
	geulipc_pmd_logtype = rte_log_register("rawdev.geulipc");
	if (geulipc_pmd_logtype >= 0)
		rte_log_set_level(geulipc_pmd_logtype, RTE_LOG_DEBUG);
}
