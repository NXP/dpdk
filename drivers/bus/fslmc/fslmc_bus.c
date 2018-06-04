/*-
 *   BSD LICENSE
 *
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
 *     * Neither the name of NXP nor the names of its
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

#include <string.h>
#include <dirent.h>
#include <stdbool.h>

#include <rte_log.h>
#include <rte_bus.h>
#include <rte_eal_memconfig.h>
#include <rte_malloc.h>
#include <rte_devargs.h>
#include <rte_memcpy.h>
#include <rte_ethdev.h>

#include <rte_fslmc.h>
#include <fslmc_vfio.h>
#include "fslmc_logs.h"

int dpaa2_logtype_bus;

#define VFIO_IOMMU_GROUP_PATH "/sys/kernel/iommu_groups"
#define FSLMC_BUS_NAME	fslmc

struct rte_fslmc_bus rte_fslmc_bus;
uint8_t dpaa2_virt_mode;

uint32_t
rte_fslmc_get_device_count(enum rte_dpaa2_dev_type device_type)
{
	if (device_type >= DPAA2_DEVTYPE_MAX)
		return 0;
	return rte_fslmc_bus.device_count[device_type];
}

RTE_DEFINE_PER_LCORE(struct dpaa2_portal_dqrr, dpaa2_held_bufs);

static void
cleanup_fslmc_device_list(void)
{
	struct rte_dpaa2_device *dev;
	struct rte_dpaa2_device *t_dev;

	TAILQ_FOREACH_SAFE(dev, &rte_fslmc_bus.device_list, next, t_dev) {
		TAILQ_REMOVE(&rte_fslmc_bus.device_list, dev, next);
		free(dev);
		dev = NULL;
	}
}

static int
compare_dpaa2_devname(struct rte_dpaa2_device *dev1,
		      struct rte_dpaa2_device *dev2)
{
	int comp;

	if (dev1->dev_type > dev2->dev_type) {
		comp = 1;
	} else if (dev1->dev_type < dev2->dev_type) {
		comp = -1;
	} else {
		/* Check the ID as types match */
		if (dev1->object_id > dev2->object_id)
			comp = 1;
		else if (dev1->object_id < dev2->object_id)
			comp = -1;
		else
			comp = 0; /* Duplicate device name */
	}

	return comp;
}

static void
insert_in_device_list(struct rte_dpaa2_device *newdev)
{
	int comp, inserted = 0;
	struct rte_dpaa2_device *dev = NULL;
	struct rte_dpaa2_device *tdev = NULL;

	TAILQ_FOREACH_SAFE(dev, &rte_fslmc_bus.device_list, next, tdev) {
		comp = compare_dpaa2_devname(newdev, dev);
		if (comp < 0) {
			TAILQ_INSERT_BEFORE(dev, newdev, next);
			inserted = 1;
			break;
		}
	}

	if (!inserted)
		TAILQ_INSERT_TAIL(&rte_fslmc_bus.device_list, newdev, next);
}

static struct rte_devargs *
fslmc_devargs_lookup(struct rte_dpaa2_device *dev)
{
	struct rte_devargs *devargs;
	struct rte_bus *pbus;
	char dev_name[32];

	pbus = rte_bus_find_by_name(RTE_STR(FSLMC_BUS_NAME));
	TAILQ_FOREACH(devargs, &devargs_list, next) {
		if (devargs->bus != pbus)
			continue;
		devargs->bus->parse(devargs->name, &dev_name);
		if (strcmp(dev_name, dev->device.name) == 0) {
			DPAA2_BUS_INFO("**Devargs matched %s", dev_name);
			return devargs;
		}
	}
	return NULL;
}

static void
dump_device_list(void)
{
	struct rte_dpaa2_device *dev;
	uint32_t global_log_level;
	int local_log_level;

	/* Only if the log level has been set to Debugging, print list */
	global_log_level = rte_log_get_global_level();
	local_log_level = rte_log_get_level(dpaa2_logtype_bus);
	if (global_log_level == RTE_LOG_DEBUG ||
	    local_log_level == RTE_LOG_DEBUG) {
		DPAA2_BUS_LOG(DEBUG, "List of devices scanned on bus:");
		TAILQ_FOREACH(dev, &rte_fslmc_bus.device_list, next) {
			DPAA2_BUS_LOG(DEBUG, "\t\t%s", dev->device.name);
		}
	}
}

static int
scan_one_fslmc_device(char *dev_name)
{
	char *dup_dev_name, *t_ptr;
	struct rte_dpaa2_device *dev = NULL;
	enum rte_dpaa2_dev_type dev_type;
	int ret = -1;

	/* Creating a temporary copy to perform cut-parse over string */
	dup_dev_name = strdup(dev_name);
	if (!dup_dev_name) {
		DPAA2_BUS_ERR("Unable to allocate device name memory");
		return -ENOMEM;
	}

	/* Parse the device name and ID */
	t_ptr = strtok(dup_dev_name, ".");
	if (!t_ptr) {
		DPAA2_BUS_ERR("Incorrect device name observed");
		goto cleanup;
	}
	if (!strncmp("dpni", t_ptr, 4))
		dev_type = DPAA2_ETH;
	else if (!strncmp("dpseci", t_ptr, 6))
		dev_type = DPAA2_CRYPTO;
	else if (!strncmp("dpcon", t_ptr, 5))
		dev_type = DPAA2_CON;
	else if (!strncmp("dpbp", t_ptr, 4))
		dev_type = DPAA2_BPOOL;
	else if (!strncmp("dpio", t_ptr, 4))
		dev_type = DPAA2_IO;
	else if (!strncmp("dpci", t_ptr, 4))
		dev_type = DPAA2_CI;
	else if (!strncmp("dpmcp", t_ptr, 5))
		dev_type = DPAA2_MPORTAL;
	else if (!strncmp("dpdmai", t_ptr, 6))
		dev_type = DPAA2_QDMA;
	else {
		dev_type = DPAA2_UNKNOWN;
		DPAA2_BUS_DEBUG("Unknown device string observed.");
		ret = 0;
		goto cleanup;
	}

	/* For all other devices, we allocate rte_dpaa2_device.
	 * For those devices where there is no driver, probe would release
	 * the memory associated with the rte_dpaa2_device after necessary
	 * initialization.
	 */
	dev = calloc(1, sizeof(struct rte_dpaa2_device));
	if (!dev) {
		DPAA2_BUS_ERR("Unable to allocate device object");
		ret =  -ENOMEM;
		goto cleanup;
	}

	/* Update the device found into the device_count table */
	dev->dev_type = dev_type;
	rte_fslmc_bus.device_count[dev->dev_type]++;

	t_ptr = strtok(NULL, ".");
	if (!t_ptr) {
		DPAA2_BUS_ERR("Incorrect device string observed (%s)", t_ptr);
		goto cleanup;
	}

	sscanf(t_ptr, "%hu", &dev->object_id);
	dev->device.name = strdup(dev_name);
	if (!dev->device.name) {
		DPAA2_BUS_ERR("Unable to clone device name. Out of memory");
		goto cleanup;
	}
	dev->device.devargs = fslmc_devargs_lookup(dev);

	/* Add device in the fslmc device list */
	insert_in_device_list(dev);

	/* Don't need the duplicated device filesystem entry anymore */
	if (dup_dev_name)
		free(dup_dev_name);

	return 0;

cleanup:
	if (dev)
		free(dev);

	if (dup_dev_name)
		free(dup_dev_name);

	return ret;
}

static int
rte_fslmc_parse(const char *name, void *addr)
{
	uint16_t dev_id;
	char *t_ptr;
	char *sep = strchr(name, ':');

	if (strncmp(name, RTE_STR(FSLMC_BUS_NAME),
		strlen(RTE_STR(FSLMC_BUS_NAME)))) {
		return -EINVAL;
	}

	if (!sep) {
		DPAA2_BUS_ERR("Incorrect device name observed");
		return -EINVAL;
	}

	t_ptr = (char *)(sep + 1);

	if (strncmp("dpni", t_ptr, 4) &&
	    strncmp("dpseci", t_ptr, 6) &&
	    strncmp("dpcon", t_ptr, 5) &&
	    strncmp("dpbp", t_ptr, 4) &&
	    strncmp("dpio", t_ptr, 4) &&
	    strncmp("dpci", t_ptr, 4) &&
	    strncmp("dpmcp", t_ptr, 5) &&
	    strncmp("dpdmai", t_ptr, 6)) {
		DPAA2_BUS_ERR("Unknown or unsupported device");
		return -EINVAL;
	}

	t_ptr = strchr(name, '.');
	if (!t_ptr) {
		DPAA2_BUS_ERR("Incorrect device string observed (%s)", t_ptr);
		return -EINVAL;
	}

	t_ptr = (char *)(t_ptr + 1);
	if (sscanf(t_ptr, "%hu", &dev_id) <= 0) {
		DPAA2_BUS_ERR("Incorrect device string observed (%s)", t_ptr);
		return -EINVAL;
	}

	if (addr)
		strcpy(addr, (char *)(sep + 1));
	return 0;
}

static int
rte_fslmc_scan(void)
{
	int ret;
	int device_count = 0;
	char fslmc_dirpath[PATH_MAX];
	DIR *dir;
	struct dirent *entry;
	static int process_once;
	int groupid;

	if (process_once) {
		DPAA2_BUS_DEBUG("Fslmc bus already scanned. Not rescanning");
		return 0;
	}
	process_once = 1;

	ret = fslmc_get_container_group(&groupid);
	if (ret != 0)
		goto scan_fail;

	/* Scan devices on the group */
	sprintf(fslmc_dirpath, "%s/%s", SYSFS_FSL_MC_DEVICES, fslmc_container);

	dir = opendir(fslmc_dirpath);
	if (!dir) {
		DPAA2_BUS_ERR("Unable to open VFIO group directory");
		goto scan_fail;
	}

	while ((entry = readdir(dir)) != NULL) {
		if (entry->d_name[0] == '.' || entry->d_type != DT_DIR)
			continue;

		ret = scan_one_fslmc_device(entry->d_name);
		if (ret != 0) {
			/* Error in parsing directory - exit gracefully */
			goto scan_fail_cleanup;
		}
		device_count += 1;
	}

	closedir(dir);

	DPAA2_BUS_INFO("FSLMC Bus scan completed");
	/* If debugging is enabled, device list is dumped to log output */
	dump_device_list();

	return 0;

scan_fail_cleanup:
	closedir(dir);

	/* Remove all devices in the list */
	cleanup_fslmc_device_list();
scan_fail:
	DPAA2_BUS_INFO("FSLMC Bus Not Available. Skipping");
	/* Irrespective of failure, scan only return success */
	return 0;
}

static int
rte_fslmc_match(struct rte_dpaa2_driver *dpaa2_drv,
		struct rte_dpaa2_device *dpaa2_dev)
{
	if (dpaa2_drv->drv_type == dpaa2_dev->dev_type)
		return 0;

	return 1;
}

static int
rte_fslmc_probe(void)
{
	int ret = 0;
	int probe_all;

	struct rte_dpaa2_device *dev;
	struct rte_dpaa2_driver *drv;

	if (TAILQ_EMPTY(&rte_fslmc_bus.device_list))
		return 0;

	ret = fslmc_vfio_setup_group();
	if (ret) {
		DPAA2_BUS_ERR("Unable to setup VFIO %d", ret);
		return 0;
	}

	ret = fslmc_vfio_process_group();
	if (ret) {
		DPAA2_BUS_ERR("Unable to setup devices %d", ret);
		return 0;
	}

	probe_all = rte_fslmc_bus.bus.conf.scan_mode != RTE_BUS_SCAN_WHITELIST;

	TAILQ_FOREACH(dev, &rte_fslmc_bus.device_list, next) {
		TAILQ_FOREACH(drv, &rte_fslmc_bus.driver_list, next) {
			ret = rte_fslmc_match(drv, dev);
			if (ret)
				continue;

			if (!drv->probe)
				continue;

			if (dev->device.devargs &&
			  dev->device.devargs->policy == RTE_DEV_BLACKLISTED) {
				DPAA2_BUS_LOG(DEBUG, "%s Blacklisted, skipping",
					      dev->device.name);
				continue;
			}

			if (probe_all ||
			   (dev->device.devargs &&
			   dev->device.devargs->policy ==
			   RTE_DEV_WHITELISTED)) {
				ret = drv->probe(drv, dev);
				if (ret)
					DPAA2_BUS_ERR("Unable to probe");
			}
			break;
		}
	}

	if (rte_eal_iova_mode() == RTE_IOVA_VA)
		dpaa2_virt_mode = 1;

	return 0;
}

static struct rte_device *
rte_fslmc_find_device(const struct rte_device *start, rte_dev_cmp_t cmp,
		      const void *data)
{
	struct rte_dpaa2_device *dev;

	TAILQ_FOREACH(dev, &rte_fslmc_bus.device_list, next) {
		if (start != NULL) {
			if (&dev->device == start)
				start = NULL;  /* starting point found */
			continue;
		}

		if (cmp(&dev->device, data) == 0)
			return &dev->device;
	}

	return NULL;
}

/*register a fslmc bus based dpaa2 driver */
void
rte_fslmc_driver_register(struct rte_dpaa2_driver *driver)
{
	RTE_VERIFY(driver);

	TAILQ_INSERT_TAIL(&rte_fslmc_bus.driver_list, driver, next);
	/* Update Bus references */
	driver->fslmc_bus = &rte_fslmc_bus;
}

/*un-register a fslmc bus based dpaa2 driver */
void
rte_fslmc_driver_unregister(struct rte_dpaa2_driver *driver)
{
	struct rte_fslmc_bus *fslmc_bus;

	fslmc_bus = driver->fslmc_bus;

	TAILQ_REMOVE(&fslmc_bus->driver_list, driver, next);
	/* Update Bus references */
	driver->fslmc_bus = NULL;
}

/*
 * All device has iova as va
 */
static inline int
fslmc_all_device_support_iova(void)
{
	int ret = 0;
	struct rte_dpaa2_device *dev;
	struct rte_dpaa2_driver *drv;

	TAILQ_FOREACH(dev, &rte_fslmc_bus.device_list, next) {
		TAILQ_FOREACH(drv, &rte_fslmc_bus.driver_list, next) {
			ret = rte_fslmc_match(drv, dev);
			if (ret)
				continue;
			/* if the driver is not supporting IOVA */
			if (!(drv->drv_flags & RTE_DPAA2_DRV_IOVA_AS_VA))
				return 0;
		}
	}
	return 1;
}

/*
 * Get iommu class of DPAA2 devices on the bus.
 */
static enum rte_iova_mode
rte_dpaa2_get_iommu_class(void)
{
	bool is_vfio_noiommu_enabled = 1;
	bool has_iova_va;

	if (TAILQ_EMPTY(&rte_fslmc_bus.device_list))
		return RTE_IOVA_DC;

	/* check if all devices on the bus support Virtual addressing or not */
	has_iova_va = fslmc_all_device_support_iova();

#ifdef VFIO_PRESENT
	is_vfio_noiommu_enabled = rte_vfio_noiommu_is_enabled() == true ?
						true : false;
#endif

	if (has_iova_va && !is_vfio_noiommu_enabled)
		return RTE_IOVA_VA;

	return RTE_IOVA_PA;
}

struct rte_fslmc_bus rte_fslmc_bus = {
	.bus = {
		.scan = rte_fslmc_scan,
		.probe = rte_fslmc_probe,
		.parse = rte_fslmc_parse,
		.find_device = rte_fslmc_find_device,
		.get_iommu_class = rte_dpaa2_get_iommu_class,
	},
	.device_list = TAILQ_HEAD_INITIALIZER(rte_fslmc_bus.device_list),
	.driver_list = TAILQ_HEAD_INITIALIZER(rte_fslmc_bus.driver_list),
	.device_count = {0},
};

RTE_REGISTER_BUS(FSLMC_BUS_NAME, rte_fslmc_bus.bus);

RTE_INIT(fslmc_init_log);
static void
fslmc_init_log(void)
{
	/* Bus level logs */
	dpaa2_logtype_bus = rte_log_register("bus.fslmc");
	if (dpaa2_logtype_bus >= 0)
		rte_log_set_level(dpaa2_logtype_bus, RTE_LOG_NOTICE);
}
