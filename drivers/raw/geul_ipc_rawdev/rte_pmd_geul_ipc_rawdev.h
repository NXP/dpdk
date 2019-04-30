/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019 NXP
 */

#ifndef __RTE_PMD_GEUL_IPC_RAWDEV_H__
#define __RTE_PMD_GEUL_IPC_RAWDEV_H__

/**
 * @file
 *
 * GEUL IPC Driver exposed APIs
 * These APIs are to be used by the application layer for
 * IPC functions/features.
 *
 */

#include <geul_ipc_api.h>

#define GEUL_IPC_RAWDEV_NAME_PREFIX "geul_ipc_dev"

/* Channels between Host and Modem */
enum geulipc_channel_list {
/* Message Channels from Host (l2) to Modem (l1) */
	L2_TO_L1_MSG_CH_1 = 0,
	L2_TO_L1_MSG_CH_2,
	L2_TO_L1_MSG_CH_3,
/* Message Channels from Modem (l1) towards Host (l2) */
	L1_TO_L2_MSG_CH_4,
	L1_TO_L2_MSG_CH_5,
/* Pointer Channels from Modem (l1) towards Host (l2) */
	L1_TO_L2_PRT_CH_1,
	L1_TO_L2_PRT_CH_2,
	CHANNELS_MAX
};

#define POISON 0x12345678 /* Fills all bytes of a word */

typedef struct geulipc_channel {
	uint16_t depth;	/**< Depth of the channel, for PTR channel case */
	uint32_t channel_id;	/**< Channel ID */
	enum ipc_ch_type type;  /**< Channel type */
	struct rte_mempool *mp; /**< Pool from where buffers would be cut */
} geulipc_channel_t;

/* Configuration structure for Geul Device */
typedef struct geulipc_rawdev_config {
	uint32_t device_id;
	ipc_t instance_handle;
} geulipc_rawdev_config_t;

#endif /* __RTE_PMD_GEUL_IPC_RAWDEV_H__*/
