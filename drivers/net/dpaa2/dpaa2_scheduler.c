/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024-2025 NXP
 */

#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>

#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_string_fns.h>
#include <rte_cycles.h>
#include <rte_kvargs.h>
#include <dev_driver.h>
#include <ethdev_driver.h>

#include <bus_fslmc_driver.h>
#include <mc/fsl_dpcon.h>
#include <portal/dpaa2_hw_pvt.h>
#include <dpaa2_hw_dpio.h>
#include <compat.h>
#include "dpaa2_ethdev.h"
#include "dpaa2_pmd_logs.h"
#include "rte_pmd_dpaa2.h"

__rte_experimental
void *
rte_dpaa2_scheduler_init(void)
{
	struct dpaa2_dpcon_dev *dpcon_dev;
	void *scheduler_handle;

	dpcon_dev = dpaa2_alloc_dpcon_dev();
	if (!dpcon_dev)
		DPAA2_PMD_ERR("Failed dpaa2_alloc_dpcon_dev!!");

	scheduler_handle = (void *)dpcon_dev;
	return scheduler_handle;
}

__rte_experimental
int
rte_dpaa2_scheduler_start(void *scheduler_handle)
{
	uint32_t ret;
	struct dpaa2_dpcon_dev *dpcon_dev =
				(struct dpaa2_dpcon_dev *)scheduler_handle;

	ret = dpaa2_dpcon_start(dpcon_dev);
	if (ret) {
		DPAA2_PMD_ERR("Failed Conc - dpaa2_dev_start\n");
		return -1;
	}
	return 0;
}

__rte_experimental
int
rte_dpaa2_scheduler_destroy(void *scheduler_handle)
{
	struct dpaa2_dpcon_dev *dpcon_dev =
				(struct dpaa2_dpcon_dev *)scheduler_handle;
	int32_t ret;

	ret = dpaa2_dpcon_stop(dpcon_dev);
	if (ret) {
		DPAA2_PMD_ERR("Failed Conc - rte_dpaa2_schedule_destroy\n");
		return -1;
	}
	dpcon_dev = NULL;

	return 0;
}

__rte_experimental
int32_t
rte_dpaa2_scheduler_rx(void *scheduler_handle, struct rte_mbuf **mbuf,
		       uint16_t nb_pkts)
{
	struct dpaa2_dpcon_dev *dpcon_dev =
				(struct dpaa2_dpcon_dev *)scheduler_handle;
	int ret = 0;
	ret = dpaa2_dpcon_recv(dpcon_dev, mbuf, nb_pkts);
	if (ret > 0)
		return ret;
	return 0;
}
