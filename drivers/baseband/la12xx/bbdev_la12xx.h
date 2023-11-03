/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020-2023 NXP
 */

#ifndef __BBDEV_LA12XX_H__
#define __BBDEV_LA12XX_H__

#define BBDEV_IPC_ENC_OP_TYPE	1
#define BBDEV_IPC_DEC_OP_TYPE	2
#define BBDEV_IPC_POLAR_OP_TYPE	3
#define BBDEV_IPC_RAW_OP_TYPE	4

#define FECA_HRAM_SIZE		6291456		/* 6 MB */

#define VSPA_ADDRESS(_core)	(0x1000000 + _core * 0x4000)
#define VSPA_LSB_OFFSET		0x684
#define VSPA_MSB_OFFSET		0x680

#define LA12XX_MAX_QUEUES 20

/* private data structure */
struct bbdev_la12xx_private {
	ipc_userspace_t *ipc_priv;
	uint32_t per_queue_hram_size;

	uint32_t max_queues;
	uint32_t num_valid_queues;
	uint8_t num_ldpc_enc_queues;
	uint8_t num_ldpc_dec_queues;
	uint8_t num_polar_enc_queues;
	uint8_t num_polar_dec_queues;
	uint8_t num_raw_queues;

	int8_t la12xx_polar_enc_core;
	int8_t la12xx_polar_dec_core;
	int8_t modem_id;

	struct wdog *wdog;
	/* Private memory for queues */
	struct bbdev_la12xx_q_priv *queues_priv[IPC_MAX_CHANNEL_COUNT];
};

struct hugepage_info {
	void *vaddr;
	phys_addr_t paddr;
	size_t len;
};

struct vspa_desc {
	volatile uint16_t host_flag;	/* Host Flags */
	volatile uint16_t vspa_flag;	/* VSPA Flags */
	uint32_t in_addr;		/* Input buffer address */
	uint32_t in_len;		/* Length of input buffer */
	uint32_t out_addr;		/* Output buffer address */
	uint32_t out_len;		/* Length of output buffer */
	uint32_t meta_addr;		/* Metadata address */
	uint32_t host_cnxt_hi;		/* Host Context hi address */
	uint32_t host_cnxt_lo;		/* Host Context low address */
	uint32_t rsvd[8];		/* Aligned to 64 bytes */
};

struct bbdev_la12xx_q_priv {
	struct bbdev_la12xx_private *bbdev_priv;
	uint32_t q_id;	/**< Channel ID */
	uint32_t feca_blk_id;	/**< FECA block ID for processing */
	uint32_t feca_blk_id_be32; /**< FECA Block ID for this queue */
	uint8_t en_napi; /**< 0: napi disabled, 1: napi enabled */
	uint8_t per_op_hw_id; /**< per OP or per queue HW ID */
	uint16_t queue_size;	/**< Queue depth */
	int32_t eventfd;	/**< Event FD value */
	enum rte_bbdev_op_type op_type; /**< Operation type */
	uint32_t la12xx_core_id;
		/** LA12xx core ID on which this will be scheduled
		 * OR VSPA Core ID for VSPA IPC channel
		 */
	uint32_t feca_input_circ_size;	/* FECA transport block input circular buffer size */
	struct rte_mempool *mp; /**< Pool from where buffers would be cut */
	void *bbdev_op[IPC_MAX_DEPTH];
			/**< Stores bbdev op for each index */
	void *msg_ch_vaddr[IPC_MAX_DEPTH];
			/**< Stores msg channel addr for modem->host */
	struct vspa_desc *vspa_ring;	/**< Shared ring between Host and VSPA */
	feca_job_t *feca_jobs[IPC_MAX_DEPTH];	/**< FECA jobs associated with queues */
	int vspa_desc_wr_index;	/**< Write desc index for VSPA */
	int vspa_desc_rd_index;	/**< Write desc index for VSPA */
	uint32_t host_pi;	/**< Producer_Index for HOST->MODEM */
	uint32_t host_ci;	/**< Consumer Index for MODEM->HOST */
	host_ipc_params_t *host_params; /**< Host parameters */
	uint32_t is_host_to_modem;	/**< Direction of operation */
	uint32_t conf_enable;		/**< Confirmation mode enabled/disabled */
	uint32_t cd_crc_stat_addr;	/**< CRC status address for CD */
};

#define lower_32_bits(x) ((uint32_t)((uint64_t)x))
#define upper_32_bits(x) ((uint32_t)(((uint64_t)(x) >> 16) >> 16))
#define join_32_bits(upper, lower) \
	((size_t)(((uint64_t)(upper) << 32) | (uint32_t)(lower)))
#endif
