/* SPDX-License-Identifier: BSD-3-Clause
 *
 *   Copyright 2021-2023 NXP
 *
 */

#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <errno.h>

#include <rte_malloc.h>
#include <dev_driver.h>

#include "private.h"
#include <fslmc_logs.h>
#include <mc/fsl_dprc.h>
#include "portal/dpaa2_hw_pvt.h"

TAILQ_HEAD(dprc_dev_list, dpaa2_dprc_dev);
static struct dprc_dev_list dprc_dev_list
	= TAILQ_HEAD_INITIALIZER(dprc_dev_list); /*!< DPRC device list */

static int
rte_dpaa2_create_dprc_device(int vdev_fd __rte_unused,
	struct vfio_device_info *obj_info __rte_unused,
	struct rte_dpaa2_device *obj)
{
	struct dpaa2_dprc_dev *dprc_node;
	struct rte_dpaa2_device *dev, *dev_tmp;
	int ret, dprc_id = obj->object_id;

	/* Allocate DPAA2 dprc handle */
	dprc_node = rte_malloc(NULL, sizeof(struct dpaa2_dprc_dev), 0);
	if (!dprc_node) {
		DPAA2_BUS_ERR("Memory allocation failed for DPRC Device");
		return -ENOMEM;
	}

	/* Open the dprc object */
	dprc_node->dprc.regs = dpaa2_get_mcp_ptr(MC_PORTAL_INDEX);
	dprc_node->dprc_id = dprc_id;
	ret = dprc_open(&dprc_node->dprc,
			CMD_PRI_LOW, dprc_id, &dprc_node->token);
	if (ret) {
		DPAA2_BUS_ERR("Resource alloc failure with err code: %d", ret);
		rte_free(dprc_node);
		return ret;
	}

	RTE_TAILQ_FOREACH_SAFE(dev, &rte_fslmc_bus.device_list, next, dev_tmp) {
		/** DPRC is always created before it's children are created.*/
		dev->container = dprc_node;
	}

	TAILQ_INSERT_TAIL(&dprc_dev_list, dprc_node, next);

	return 0;
}

static struct rte_dpaa2_object rte_dpaa2_dprc_obj = {
	.dev_type = DPAA2_DPRC,
	.create = rte_dpaa2_create_dprc_device,
};

RTE_PMD_REGISTER_DPAA2_OBJECT(dprc, rte_dpaa2_dprc_obj);
