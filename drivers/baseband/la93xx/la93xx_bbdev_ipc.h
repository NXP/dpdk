/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2021 NXP
 */

#ifndef LA93XX_BBDEV_IPC_H_
#define LA93XX_BBDEV_IPC_H_

#include "la93xx_ipc.h"

/**
 * @file        bbdev_ipc.h
 * @brief       BBDEV_IPC related APIs.
 * @addtogroup  BBDEV_API
 * @{
 */

#define LA93XX_MAX_QUEUES IPC_MAX_CHANNEL_COUNT
#define MAX_CHANNEL_DEPTH IPC_MAX_DEPTH

/** Structure specifying enqueue operation (enqueue at LA1224) */
struct bbdev_ipc_enqueue_op {
	/** Status of operation that was performed */
	int32_t status;
	/** CRC Status of SD operation that was performed */
	int32_t crc_stat_addr;
	/** HARQ Output buffer memory length for Shared Decode.
	 * Output buffer length for RAW op.
	 * Filled by LA12xx.
	 */
	uint32_t out_len;
	/** Reserved (for 8 byte alignment) */
	uint32_t rsvd;
};

/** Structure specifying raw operation */
struct bbdev_ipc_raw_op_t {
	/** RAW operation flags.
	 *  BBDEV_IPC_RAW_OP_IN_VALID / BBDEV_IPC_RAW_OP_OUT_VALID
	 */
	uint32_t raw_op_flags;
	uint32_t status;	/**< Status of operation */
	uint32_t in_addr;	/**< Input buffer memory address */
	uint32_t in_len;	/**< Input buffer memory length */
	uint32_t out_addr;	/**< Output buffer memory address */
	uint32_t out_len;	/**< Output buffer memory length */
};

/** @} */
#endif /* LA93XX_BBDEV_IPC_H_ */
