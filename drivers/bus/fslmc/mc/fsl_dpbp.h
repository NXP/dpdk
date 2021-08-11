/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 * Copyright 2013-2016 Freescale Semiconductor Inc.
 * Copyright 2016-2021 NXP
 *
 */
#ifndef __FSL_DPBP_H
#define __FSL_DPBP_H

/*
 * Data Path Buffer Pool API
 * Contains initialization APIs and runtime control APIs for DPBP
 */

struct fsl_mc_io;

int dpbp_open(struct fsl_mc_io *mc_io,
	      uint32_t cmd_flags,
	      int dpbp_id,
	      uint16_t *token);

int dpbp_close(struct fsl_mc_io *mc_io,
	       uint32_t cmd_flags,
	       uint16_t token);

/**
 * struct dpbp_cfg - Structure representing DPBP configuration
 * @options:	place holder
 */
struct dpbp_cfg {
	uint32_t options;
};

int dpbp_create(struct fsl_mc_io *mc_io,
		uint16_t dprc_token,
		uint32_t cmd_flags,
		const struct dpbp_cfg *cfg,
		uint32_t *obj_id);

int dpbp_destroy(struct fsl_mc_io *mc_io,
		 uint16_t dprc_token,
		 uint32_t cmd_flags,
		 uint32_t obj_id);

int dpbp_enable(struct fsl_mc_io *mc_io,
		uint32_t cmd_flags,
		uint16_t token);

int dpbp_disable(struct fsl_mc_io *mc_io,
		 uint32_t cmd_flags,
		 uint16_t token);

int dpbp_is_enabled(struct fsl_mc_io *mc_io,
		    uint32_t cmd_flags,
		    uint16_t token,
		    int *en);

int dpbp_reset(struct fsl_mc_io *mc_io,
	       uint32_t cmd_flags,
	       uint16_t token);

/**
 * struct dpbp_irq_cfg - IRQ configuration
 * @addr:	Address that must be written to signal a message-based interrupt
 * @val:	Value to write into irq_addr address
 * @irq_num:	A user defined number associated with this IRQ
 */
struct dpbp_irq_cfg {
	     uint64_t addr;
	     uint32_t val;
	     int irq_num;
};

int dpbp_set_irq_enable(struct fsl_mc_io *mc_io,
			uint32_t cmd_flags,
			uint16_t token,
			uint8_t irq_index,
			uint8_t en);

int dpbp_get_irq_enable(struct fsl_mc_io *mc_io,
			uint32_t cmd_flags,
			uint16_t token,
			uint8_t irq_index,
			uint8_t *en);

int dpbp_set_irq_mask(struct fsl_mc_io	*mc_io,
		      uint32_t cmd_flags,
		      uint16_t token,
		      uint8_t irq_index,
		      uint32_t mask);

int dpbp_get_irq_mask(struct fsl_mc_io	*mc_io,
		      uint32_t cmd_flags,
		      uint16_t token,
		      uint8_t irq_index,
		      uint32_t *mask);

int dpbp_get_irq_status(struct fsl_mc_io *mc_io,
			uint32_t cmd_flags,
			uint16_t token,
			uint8_t irq_index,
			uint32_t *status);

int dpbp_clear_irq_status(struct fsl_mc_io *mc_io,
			  uint32_t cmd_flags,
			  uint16_t token,
			  uint8_t irq_index,
			  uint32_t status);

/**
 * struct dpbp_attr - Structure representing DPBP attributes
 * @id:		DPBP object ID
 * @bpid:	Hardware buffer pool ID; should be used as an argument in
 *		acquire/release operations on buffers
 */
struct dpbp_attr {
	int id;
	uint16_t bpid;
};

int dpbp_get_attributes(struct fsl_mc_io *mc_io,
			uint32_t cmd_flags,
			uint16_t token,
			struct dpbp_attr *attr);

/**
 *  DPBP notifications options
 */

/**
 * BPSCN write will attempt to allocate into a cache (coherent write)
 */
#define DPBP_NOTIF_OPT_COHERENT_WRITE	0x00000001
/* Target of BP depletion SCNs is WRIOP DCP (#0) */
#define DPBP_NOTIF_OPT_WRIOP		0x00010000
/* Target of BP depletion SCNs is AIOP DCP (#1) */
#define DPBP_NOTIF_OPT_AIOP		0x00020000

/**
 * struct dpbp_notification_cfg - Structure representing DPBP notifications
 *	towards software
 * @depletion_entry: below this threshold the pool is "depleted";
 *	set it to '0' to disable it
 * @depletion_exit: greater than or equal to this threshold the pool exit its
 *	"depleted" state
 * @surplus_entry: above this threshold the pool is in "surplus" state;
 *	set it to '0' to disable it
 * @surplus_exit: less than or equal to this threshold the pool exit its
 *	"surplus" state
 * @message_iova: MUST be given if either 'depletion_entry' or 'surplus_entry'
 *	is not '0' (enable); I/O virtual address (must be in DMA-able memory),
 *	must be 16B aligned.
 * @message_ctx: The context that will be part of the BPSCN message and will
 *	be written to 'message_iova'
 * @options: Mask of available options; use 'DPBP_NOTIF_OPT_<X>' values
 */
struct dpbp_notification_cfg {
	uint32_t depletion_entry;
	uint32_t depletion_exit;
	uint32_t surplus_entry;
	uint32_t surplus_exit;
	uint64_t message_iova;
	uint64_t message_ctx;
	uint32_t options;
};

int dpbp_set_notifications(struct fsl_mc_io *mc_io,
			   uint32_t cmd_flags,
			   uint16_t token,
			   struct dpbp_notification_cfg *cfg);

int dpbp_get_notifications(struct fsl_mc_io *mc_io,
			   uint32_t cmd_flags,
			   uint16_t token,
			   struct dpbp_notification_cfg *cfg);

int dpbp_get_api_version(struct fsl_mc_io *mc_io,
			 uint32_t cmd_flags,
			 uint16_t *major_ver,
			 uint16_t *minor_ver);

int dpbp_get_num_free_bufs(struct fsl_mc_io *mc_io,
			   uint32_t cmd_flags,
			   uint16_t token,
			   uint32_t *num_free_bufs);

#endif /* __FSL_DPBP_H */
