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

	dpcon_dev = dpaa2_alloc_dpcon_dev();
	if (!dpcon_dev)
		DPAA2_PMD_ERR("Failed dpaa2_alloc_dpcon_dev!!");

	return dpcon_dev;
}

__rte_experimental
int
rte_dpaa2_scheduler_start(void *scheduler_handle)
{
	struct dpaa2_dpcon_dev *dpcon_dev = scheduler_handle;
	int32_t ret;

	ret = dpaa2_dpcon_start(dpcon_dev);
	if (ret) {
		DPAA2_PMD_ERR("Failed(%d) Conc - dpaa2_dev_start\n", ret);
		return ret;
	}
	return 0;
}

__rte_experimental
int
rte_dpaa2_scheduler_destroy(void *scheduler_handle)
{
	struct dpaa2_dpcon_dev *dpcon_dev = scheduler_handle;
	int32_t ret;

	ret = dpaa2_dpcon_stop(dpcon_dev);
	if (ret) {
		DPAA2_PMD_ERR("Failed(%d) Conc - rte_dpaa2_schedule_destroy\n",
			ret);
		return ret;
	}
	dpcon_dev = NULL;

	return 0;
}

__rte_experimental
int
rte_dpaa2_scheduler_add(void *scheduler_handle,
	uint16_t port_id, uint16_t rxq_id, uint8_t priority)
{
	int32_t ret;
	struct dpaa2_dpcon_dev *dpcon_dev = scheduler_handle;
	struct rte_eth_dev *dev;
	struct dpaa2_dev_priv *priv;
	struct fsl_mc_io *dpni;
	struct dpaa2_queue *dpaa2_q;
	struct dpni_queue *cfg;

	if (!rte_pmd_dpaa2_dev_is_dpaa2(port_id))
		return -ENODEV;

	dev = &rte_eth_devices[port_id];
	priv = dev->data->dev_private;
	if (rxq_id >= priv->nb_rx_queues) {
		DPAA2_PMD_ERR("rxq_id(%d) >= queue number(%d)\n",
			rxq_id, priv->nb_rx_queues);
		return -EINVAL;
	}
	dpni = dev->process_private;
	dpaa2_q = priv->rx_vq[rxq_id];
	cfg = dpaa2_q->cfg;
	if (!cfg) {
		DPAA2_PMD_ERR("%s: %s'rxq[%d] has not been configured!\n",
			__func__, dev->data->name, rxq_id);
		return -EINVAL;
	}

	cfg->destination.type = DPNI_DEST_DPCON;
	cfg->destination.id = dpcon_dev->dpcon_id;
	cfg->destination.priority = priority;
	dpaa2_q->options |= DPNI_QUEUE_OPT_DEST;

	ret = dpni_set_queue(dpni, CMD_PRI_LOW, priv->token,
		DPNI_QUEUE_RX, dpaa2_q->tc_index, dpaa2_q->flow_id,
		dpaa2_q->options, cfg);
	if (ret) {
		DPAA2_PMD_ERR("%s: Error in setting the rx queue: = %d\n",
			__func__, ret);
		return ret;
	}

	return 0;
}

__rte_experimental
uint16_t
rte_dpaa2_scheduler_rx(void *scheduler_handle, struct rte_mbuf **mbuf,
	uint16_t nb_pkts)
{
	struct dpaa2_dpcon_dev *dpcon_dev = scheduler_handle;

	return dpcon_dev->rx_schedule(dpcon_dev, mbuf, nb_pkts);
}
