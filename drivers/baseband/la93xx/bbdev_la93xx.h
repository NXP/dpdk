/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2021-2024 NXP
 */

#ifndef __BBDEV_LA93XX_H__
#define __BBDEV_LA93XX_H__

#include "la93xx_bbdev_ipc.h"
#include "la93xx_ipc_ioctl.h"

#define MAX_RAW_QUEUES		IPC_MAX_CHANNEL_COUNT

typedef struct ipc_channel_us_priv {
	int32_t		eventfd;
	uint32_t	channel_id;
} ipc_channel_us_t;

typedef struct ipc_priv_t {
	int instance_id;
	int dev_ipc;
	int dev_mem;
	sys_map_t sys_map;
	mem_range_t modem_ccsrbar;
	mem_range_t tcml_start;
	mem_range_t mhif_start;
	mem_range_t hugepg_start;
	mem_range_t nlm_ops;
	ipc_channel_us_t *channels[IPC_MAX_CHANNEL_COUNT];
	ipc_instance_t	*instance;
	ipc_instance_t	*instance_bk;
} ipc_userspace_t;

#define MODEM_PHY2VIRT(A, ipcu) \
	((uint64_t) ((unsigned long) (A) \
			+ (unsigned long)(ipcu->tcml_start.host_vaddr)))

/* private data structure */
struct bbdev_la93xx_private {
	ipc_userspace_t *ipc_priv;
	uint32_t num_valid_queues;
	int8_t modem_id;
	struct rte_mempool *mp;
	struct wdog *wdog;
	/* Private memory for queues */
	struct bbdev_la93xx_q_priv *queues_priv[IPC_MAX_CHANNEL_COUNT];
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
	struct rte_bbdev_queue_conf qconf;
	struct rte_mempool *mp; /**< Pool from where buffers would be cut */
	void *bbdev_op[IPC_MAX_DEPTH];
			/**< Stores bbdev op for each index */
	void *msg_ch_vaddr[IPC_MAX_DEPTH];
			/**< Stores msg channel addr for modem->host */
	void *internal_bufs[IPC_MAX_DEPTH];
			/**< Internal buffers for host->modem */
	uint32_t host_pi;	/**< Producer_Index for HOST->MODEM */
	uint32_t host_ci;	/**< Consumer Index for MODEM->HOST */
	host_ipc_params_t *host_params; /**< Host parameters */
};

#define lower_32_bits(x) ((uint32_t)((uint64_t)x))
#define upper_32_bits(x) ((uint32_t)(((uint64_t)(x) >> 16) >> 16))
#define join_32_bits(upper, lower) \
	((size_t)(((uint64_t)(upper) << 32) | (uint32_t)(lower)))
#endif

