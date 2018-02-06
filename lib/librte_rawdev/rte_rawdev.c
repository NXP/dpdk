/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2017 NXP
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>

#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_debug.h>
#include <rte_dev.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_errno.h>

#include "rte_rawdev.h"
#include "rte_rawdev_pmd.h"

/* dynamic log identifier */
int librawdev_logtype;

struct rte_rawdev rte_rawdevices[RTE_RAWDEV_MAX_DEVS];

struct rte_rawdev *rte_rawdevs = &rte_rawdevices[0];

static struct rte_rawdev_global rawdev_globals = {
	.nb_devs		= 0
};

struct rte_rawdev_global *rte_rawdev_globals = &rawdev_globals;

/* Raw device, northbound API implementation */
uint8_t
rte_rawdev_count(void)
{
	return rte_rawdev_globals->nb_devs;
}

uint16_t
rte_rawdev_get_dev_id(const char *name)
{
	uint16_t i;

	if (!name)
		return -EINVAL;

	for (i = 0; i < rte_rawdev_globals->nb_devs; i++)
		if ((strcmp(rte_rawdevices[i].name, name)
				== 0) &&
				(rte_rawdevices[i].attached ==
						RTE_RAWDEV_ATTACHED))
			return i;
	return -ENODEV;
}

int
rte_rawdev_socket_id(uint16_t dev_id)
{
	struct rte_rawdev *dev;

	RTE_RAWDEV_VALID_DEVID_OR_ERR_RET(dev_id, -EINVAL);
	dev = &rte_rawdevs[dev_id];

	return dev->socket_id;
}

int
rte_rawdev_info_get(uint16_t dev_id, struct rte_rawdev_info *dev_info)
{
	struct rte_rawdev *rawdev;

	RTE_RAWDEV_VALID_DEVID_OR_ERR_RET(dev_id, -EINVAL);
	RTE_FUNC_PTR_OR_ERR_RET(dev_info, -EINVAL);

	if (dev_info == NULL)
		return -EINVAL;

	rawdev = &rte_rawdevs[dev_id];

	RTE_FUNC_PTR_OR_ERR_RET(*rawdev->dev_ops->dev_info_get, -ENOTSUP);
	(*rawdev->dev_ops->dev_info_get)(rawdev, dev_info->dev_private);

	if (dev_info) {

		dev_info->driver_name = rawdev->driver_name;
		dev_info->device = rawdev->device;
	}

	return 0;
}

int
rte_rawdev_configure(uint16_t dev_id, struct rte_rawdev_info *dev_conf)
{
	struct rte_rawdev *dev;
	int diag;

	RTE_RAWDEV_VALID_DEVID_OR_ERR_RET(dev_id, -EINVAL);
	RTE_FUNC_PTR_OR_ERR_RET(dev_conf, -EINVAL);

	dev = &rte_rawdevs[dev_id];

	RTE_FUNC_PTR_OR_ERR_RET(*dev->dev_ops->dev_configure, -ENOTSUP);

	if (dev->started) {
		RTE_RDEV_ERR(
		   "device %d must be stopped to allow configuration", dev_id);
		return -EBUSY;
	}

	/* Configure the device */
	diag = (*dev->dev_ops->dev_configure)(dev, dev_conf->dev_private);
	if (diag != 0)
		RTE_RDEV_ERR("dev%d dev_configure = %d", dev_id, diag);
	else
		dev->attached = 1;

	return diag;
}

int
rte_rawdev_queue_conf_get(uint16_t dev_id,
			  uint16_t queue_id,
			  rte_rawdev_obj_t queue_conf)
{
	struct rte_rawdev *dev;

	RTE_RAWDEV_VALID_DEVID_OR_ERR_RET(dev_id, -EINVAL);
	dev = &rte_rawdevs[dev_id];

	RTE_FUNC_PTR_OR_ERR_RET(*dev->dev_ops->queue_def_conf, -ENOTSUP);
	(*dev->dev_ops->queue_def_conf)(dev, queue_id, queue_conf);
	return 0;
}

int
rte_rawdev_queue_setup(uint16_t dev_id,
		       uint16_t queue_id,
		       rte_rawdev_obj_t queue_conf)
{
	struct rte_rawdev *dev;

	RTE_RAWDEV_VALID_DEVID_OR_ERR_RET(dev_id, -EINVAL);
	dev = &rte_rawdevs[dev_id];

	RTE_FUNC_PTR_OR_ERR_RET(*dev->dev_ops->queue_setup, -ENOTSUP);
	return (*dev->dev_ops->queue_setup)(dev, queue_id, queue_conf);
}

int
rte_rawdev_queue_release(uint16_t dev_id, uint16_t queue_id)
{
	struct rte_rawdev *dev;

	RTE_RAWDEV_VALID_DEVID_OR_ERR_RET(dev_id, -EINVAL);
	dev = &rte_rawdevs[dev_id];

	RTE_FUNC_PTR_OR_ERR_RET(*dev->dev_ops->queue_release, -ENOTSUP);
	return (*dev->dev_ops->queue_release)(dev, queue_id);
}

int
rte_rawdev_get_attr(uint16_t dev_id,
		    const char *attr_name,
		    uint64_t *attr_value)
{
	struct rte_rawdev *dev;

	RTE_RAWDEV_VALID_DEVID_OR_ERR_RET(dev_id, -EINVAL);
	dev = &rte_rawdevs[dev_id];

	RTE_FUNC_PTR_OR_ERR_RET(*dev->dev_ops->attr_get, -ENOTSUP);
	return (*dev->dev_ops->attr_get)(dev, attr_name, attr_value);
}

int
rte_rawdev_set_attr(uint16_t dev_id,
		    const char *attr_name,
		    const uint64_t attr_value)
{
	struct rte_rawdev *dev;

	RTE_RAWDEV_VALID_DEVID_OR_ERR_RET(dev_id, -EINVAL);
	dev = &rte_rawdevs[dev_id];

	RTE_FUNC_PTR_OR_ERR_RET(*dev->dev_ops->attr_set, -ENOTSUP);
	return (*dev->dev_ops->attr_set)(dev, attr_name, attr_value);
}

int
rte_rawdev_dump(uint16_t dev_id, FILE *f)
{
	struct rte_rawdev *dev;

	RTE_RAWDEV_VALID_DEVID_OR_ERR_RET(dev_id, -EINVAL);
	dev = &rte_rawdevs[dev_id];

	RTE_FUNC_PTR_OR_ERR_RET(*dev->dev_ops->dump, -ENOTSUP);
	return (*dev->dev_ops->dump)(dev, f);
}

int
rte_rawdev_start(uint16_t dev_id)
{
	struct rte_rawdev *dev;
	int diag;

	RTE_RDEV_DEBUG("Start dev_id=%" PRIu8, dev_id);

	RTE_RAWDEV_VALID_DEVID_OR_ERR_RET(dev_id, -EINVAL);
	dev = &rte_rawdevs[dev_id];
	RTE_FUNC_PTR_OR_ERR_RET(*dev->dev_ops->dev_start, -ENOTSUP);

	if (dev->started != 0) {
		RTE_RDEV_ERR("Device with dev_id=%" PRIu8 "already started",
			     dev_id);
		return 0;
	}

	diag = (*dev->dev_ops->dev_start)(dev);
	if (diag == 0)
		dev->started = 1;
	else
		return diag;

	return 0;
}

void
rte_rawdev_stop(uint16_t dev_id)
{
	struct rte_rawdev *dev;

	RTE_RDEV_DEBUG("Stop dev_id=%" PRIu8, dev_id);

	RTE_RAWDEV_VALID_DEVID_OR_RET(dev_id);
	dev = &rte_rawdevs[dev_id];

	RTE_FUNC_PTR_OR_RET(*dev->dev_ops->dev_stop);

	if (dev->started == 0) {
		RTE_RDEV_ERR("Device with dev_id=%" PRIu8 "already stopped",
			dev_id);
		return;
	}

	(*dev->dev_ops->dev_stop)(dev);
	dev->started = 0;
}

int
rte_rawdev_close(uint16_t dev_id)
{
	struct rte_rawdev *dev;

	RTE_RAWDEV_VALID_DEVID_OR_ERR_RET(dev_id, -EINVAL);
	dev = &rte_rawdevs[dev_id];

	RTE_FUNC_PTR_OR_ERR_RET(*dev->dev_ops->dev_close, -ENOTSUP);
	/* Device must be stopped before it can be closed */
	if (dev->started == 1) {
		RTE_RDEV_ERR("Device %u must be stopped before closing",
			     dev_id);
		return -EBUSY;
	}

	return (*dev->dev_ops->dev_close)(dev);
}

int
rte_rawdev_reset(uint16_t dev_id)
{
	struct rte_rawdev *dev;

	RTE_RAWDEV_VALID_DEVID_OR_ERR_RET(dev_id, -EINVAL);
	dev = &rte_rawdevs[dev_id];

	RTE_FUNC_PTR_OR_ERR_RET(*dev->dev_ops->dev_reset, -ENOTSUP);
	/* Reset is not dependent on state of the device */
	return (*dev->dev_ops->dev_reset)(dev);
}

static inline uint8_t
rte_rawdev_find_free_device_index(void)
{
	uint16_t dev_id;

	for (dev_id = 0; dev_id < RTE_RAWDEV_MAX_DEVS; dev_id++) {
		if (rte_rawdevs[dev_id].attached ==
				RTE_RAWDEV_DETACHED)
			return dev_id;
	}

	return RTE_RAWDEV_MAX_DEVS;
}

struct rte_rawdev *
rte_rawdev_pmd_allocate(const char *name, size_t dev_priv_size, int socket_id)
{
	struct rte_rawdev *rawdev;
	uint16_t dev_id;

	if (rte_rawdev_pmd_get_named_dev(name) != NULL) {
		RTE_RDEV_ERR("Event device with name %s already allocated!",
			     name);
		return NULL;
	}

	dev_id = rte_rawdev_find_free_device_index();
	if (dev_id == RTE_RAWDEV_MAX_DEVS) {
		RTE_RDEV_ERR("Reached maximum number of raw devices");
		return NULL;
	}

	rawdev = &rte_rawdevs[dev_id];

	rawdev->dev_private = rte_zmalloc_socket("rawdev private",
				     dev_priv_size,
				     RTE_CACHE_LINE_SIZE,
				     socket_id);
	if (!rawdev->dev_private) {
		RTE_RDEV_ERR("Unable to allocate memory to Skeleton dev");
		return NULL;
	}


	rawdev->dev_id = dev_id;
	rawdev->socket_id = socket_id;
	rawdev->started = 0;
	snprintf(rawdev->name, RTE_RAWDEV_NAME_MAX_LEN, "%s", name);

	rawdev->attached = RTE_RAWDEV_ATTACHED;
	rawdev_globals.nb_devs++;

	return rawdev;
}

int
rte_rawdev_pmd_release(struct rte_rawdev *rawdev)
{
	int ret;

	if (rawdev == NULL)
		return -EINVAL;

	ret = rte_rawdev_close(rawdev->dev_id);
	if (ret < 0)
		return ret;

	rawdev->attached = RTE_RAWDEV_DETACHED;
	rawdev_globals.nb_devs--;

	rawdev->dev_id = 0;
	rawdev->socket_id = 0;
	rawdev->dev_ops = NULL;
	if (rawdev->dev_private) {
		rte_free(rawdev->dev_private);
		rawdev->dev_private = NULL;
	}

	return 0;
}

RTE_INIT(librawdev_init_log);

static void
librawdev_init_log(void)
{
	librawdev_logtype = rte_log_register("lib.rawdev");
	if (librawdev_logtype >= 0)
		rte_log_set_level(librawdev_logtype, RTE_LOG_INFO);
}
