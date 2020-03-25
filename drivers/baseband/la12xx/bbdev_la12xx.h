/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 NXP
 */

#ifndef __BBDEV_LA12XX_H__
#define __BBDEV_LA12XX_H__

#define BBDEV_IPC_ENC_OP_TYPE	1
#define BBDEV_IPC_DEC_OP_TYPE	2

/* private data structure */
struct bbdev_la12xx_private {
	ipc_userspace_t *ipc_priv;
};

struct hugepage_info {
	void *vaddr;
	phys_addr_t paddr;
	size_t len;
};

struct bbdev_la12xx_q_priv {
	struct bbdev_la12xx_private *bbdev_priv;
	uint8_t en_napi; /* 0: napi disabled, 1: napi enabled */
	uint16_t depth;	/**< Depth of the channel, for PTR channel case */
	uint32_t q_id;	/**< Channel ID */
	int32_t eventfd;	/**< Event FD value */
	enum ipc_ch_type type;  /**< Channel type */
	struct rte_mempool *mp; /**< Pool from where buffers would be cut */
};

#define lower_32_bits(x) ((uint32_t)(x))
#define upper_32_bits(x) ((uint32_t)(((x) >> 16) >> 16))

#endif
