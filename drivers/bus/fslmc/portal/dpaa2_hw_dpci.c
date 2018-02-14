/*-
 *   BSD LICENSE
 *
 *   Copyright 2017 NXP
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

#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_string_fns.h>
#include <rte_cycles.h>
#include <rte_kvargs.h>
#include <rte_dev.h>
#include <rte_ethdev.h>

#include <fslmc_logs.h>
#include <rte_fslmc.h>
#include <mc/fsl_dpci.h>
#include "portal/dpaa2_hw_pvt.h"
#include "portal/dpaa2_hw_dpio.h"

TAILQ_HEAD(dpci_dev_list, dpaa2_dpci_dev);
static struct dpci_dev_list dpci_dev_list
	= TAILQ_HEAD_INITIALIZER(dpci_dev_list); /*!< DPCI device list */

static int
rte_dpaa2_create_dpci_device(int vdev_fd __rte_unused,
			     struct vfio_device_info *obj_info __rte_unused,
			     int dpci_id)
{
	struct dpaa2_dpci_dev *dpci_node;
	struct dpci_attr attr;
	struct dpci_rx_queue_cfg rx_queue_cfg;
	struct dpci_rx_queue_attr rx_attr;
	struct dpci_tx_queue_attr tx_attr;
	int ret, i;

	/* Allocate DPAA2 dpci handle */
	dpci_node = rte_malloc(NULL, sizeof(struct dpaa2_dpci_dev), 0);
	if (!dpci_node) {
		PMD_INIT_LOG(ERR, "Memory allocation failed for DPCI Device");
		return -1;
	}

	/* Open the dpci object */
	dpci_node->dpci.regs = rte_mcp_ptr_list[MC_PORTAL_INDEX];
	ret = dpci_open(&dpci_node->dpci,
			CMD_PRI_LOW, dpci_id, &dpci_node->token);
	if (ret) {
		PMD_INIT_LOG(ERR, "Resource alloc failure with err code: %d",
			     ret);
		rte_free(dpci_node);
		return -1;
	}

	/* Get the device attributes */
	ret = dpci_get_attributes(&dpci_node->dpci,
				  CMD_PRI_LOW, dpci_node->token, &attr);
	if (ret != 0) {
		PMD_INIT_LOG(ERR, "Reading device failed with err code: %d",
			     ret);
		rte_free(dpci_node);
		return -1;
	}

	/* Set up the Rx Queue */
	for (i = 0; i < DPAA2_DPCI_MAX_QUEUES; i++) {
		struct dpaa2_queue *rxq;

		memset(&rx_queue_cfg, 0, sizeof(struct dpci_rx_queue_cfg));
		ret = dpci_set_rx_queue(&dpci_node->dpci,
					CMD_PRI_LOW,
					dpci_node->token,
					i, &rx_queue_cfg);
		if (ret) {
			PMD_INIT_LOG(ERR, "Setting Rx queue failed with err code: %d",
				     ret);
			rte_free(dpci_node);
			return -1;
		}

		/* Allocate DQ storage for the DPCI Rx queues */
		rxq = &(dpci_node->rx_queue[i]);
		rxq->q_storage = rte_malloc("dq_storage",
					sizeof(struct queue_storage_info_t),
					RTE_CACHE_LINE_SIZE);
		if (!rxq->q_storage) {
			PMD_INIT_LOG(ERR, "q_storage allocation failed\n");
			rte_free(dpci_node);
			return -ENOMEM;
		}

		memset(rxq->q_storage, 0, sizeof(struct queue_storage_info_t));
		if (dpaa2_alloc_dq_storage(rxq->q_storage)) {
			PMD_INIT_LOG(ERR, "dpaa2_alloc_dq_storage failed\n");
			rte_free(dpci_node);
			return -ENOMEM;
		}
	}

	/* Enable the device */
	ret = dpci_enable(&dpci_node->dpci,
			  CMD_PRI_LOW, dpci_node->token);
	if (ret != 0) {
		PMD_INIT_LOG(ERR, "Enabling device failed with err code: %d",
			     ret);
		rte_free(dpci_node);
		return -1;
	}

	for (i = 0; i < DPAA2_DPCI_MAX_QUEUES; i++) {
		/* Get the Rx FQID's */
		ret = dpci_get_rx_queue(&dpci_node->dpci,
					CMD_PRI_LOW,
					dpci_node->token, i,
					&rx_attr);
		if (ret != 0) {
			PMD_INIT_LOG(ERR,
				     "Reading device failed with err code: %d",
				ret);
			rte_free(dpci_node);
			return -1;
		}
		dpci_node->rx_queue[i].fqid = rx_attr.fqid;

		ret = dpci_get_tx_queue(&dpci_node->dpci,
					CMD_PRI_LOW,
					dpci_node->token, i,
					&tx_attr);
		if (ret != 0) {
			PMD_INIT_LOG(ERR,
				     "Reading device failed with err code: %d",
				ret);
			rte_free(dpci_node);
			return -1;
		}
		dpci_node->tx_queue[i].fqid = tx_attr.fqid;
	}

	dpci_node->dpci_id = dpci_id;
	rte_atomic16_init(&dpci_node->in_use);

	TAILQ_INSERT_TAIL(&dpci_dev_list, dpci_node, next);

	RTE_LOG(DEBUG, PMD, "DPAA2: Added [dpci.%d]\n", dpci_id);

	return 0;
}

struct dpaa2_dpci_dev *rte_dpaa2_alloc_dpci_dev(void)
{
	struct dpaa2_dpci_dev *dpci_dev = NULL;

	/* Get DPCI dev handle from list using index */
	TAILQ_FOREACH(dpci_dev, &dpci_dev_list, next) {
		if (dpci_dev && rte_atomic16_test_and_set(&dpci_dev->in_use))
			break;
	}

	return dpci_dev;
}

void rte_dpaa2_free_dpci_dev(struct dpaa2_dpci_dev *dpci)
{
	struct dpaa2_dpci_dev *dpci_dev = NULL;

	/* Match DPCI handle and mark it free */
	TAILQ_FOREACH(dpci_dev, &dpci_dev_list, next) {
		if (dpci_dev == dpci) {
			rte_atomic16_dec(&dpci_dev->in_use);
			return;
		}
	}
}

static struct rte_dpaa2_object rte_dpaa2_dpci_obj = {
	.dev_type = DPAA2_CI,
	.create = rte_dpaa2_create_dpci_device,
};

RTE_PMD_REGISTER_DPAA2_OBJECT(dpci, rte_dpaa2_dpci_obj);
