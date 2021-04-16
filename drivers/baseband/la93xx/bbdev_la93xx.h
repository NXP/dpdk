/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2021 NXP
 */

#ifndef __BBDEV_LA93XX_H__
#define __BBDEV_LA93XX_H__

#include "la93xx_ipc.h"

#define MAX_RAW_QUEUES		1

/* private data structure */
struct bbdev_la93xx_private {
	ipc_userspace_t *ipc_priv;
	uint32_t num_valid_queues;
	int8_t modem_id;
	/* Private memory for queues */
	struct bbdev_la93xx_q_priv *queues_priv[32];
};

struct hugepage_info {
	void *vaddr;
	phys_addr_t paddr;
	size_t len;
};

struct bbdev_la93xx_q_priv {
	struct bbdev_la93xx_private *bbdev_priv;
	uint32_t q_id;	/**< Channel ID */
	uint8_t en_napi; /* 0: napi disabled, 1: napi enabled */
	uint16_t queue_size;	/**< Queue depth */
	int32_t eventfd;	/**< Event FD value */
	enum rte_bbdev_op_type op_type; /**< Operation type */
	struct rte_mempool *mp; /**< Pool from where buffers would be cut */
	void *bbdev_op[MAX_CHANNEL_DEPTH];
			/**< Stores bbdev op for each index */
	void *msg_ch_vaddr[MAX_CHANNEL_DEPTH];
			/**< Stores msg channel addr for modem->host */
	uint32_t host_pi;	/**< Producer_Index for HOST->MODEM */
	uint32_t host_ci;	/**< Consumer Index for MODEM->HOST */
	host_ipc_params_t *host_params; /**< Host parameters */
};

#define lower_32_bits(x) ((uint32_t)((uint64_t)x))
#define upper_32_bits(x) ((uint32_t)(((uint64_t)(x) >> 16) >> 16))
#define join_32_bits(upper, lower) \
	((uint64_t)(((uint64_t)(upper) << 32) | (uint32_t)(lower)))
#endif

