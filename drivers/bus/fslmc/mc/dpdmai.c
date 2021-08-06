/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018-2021 NXP
 */

#include <fsl_mc_sys.h>
#include <fsl_mc_cmd.h>
#include <fsl_dpdmai.h>
#include <fsl_dpdmai_cmd.h>

/**
 * dpdmai_open() - Open a control session for the specified object
 * @mc_io:	Pointer to MC portal's I/O object
 * @cmd_flags:	Command flags; one or more of 'MC_CMD_FLAG_'
 * @dpdmai_id:	DPDMAI unique ID
 * @token:	Returned token; use in subsequent API calls
 *
 * This function can be used to open a control session for an
 * already created object; an object may have been declared in
 * the DPL or by calling the dpdmai_create() function.
 * This function returns a unique authentication token,
 * associated with the specific object ID and the specific MC
 * portal; this token must be used in all subsequent commands for
 * this specific object.
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpdmai_open(struct fsl_mc_io *mc_io,
		uint32_t cmd_flags,
		int dpdmai_id,
		uint16_t *token)
{
	struct dpdmai_cmd_open *cmd_params;
	struct mc_command cmd = { 0 };
	int err;

	/* prepare command */
	cmd.header = mc_encode_cmd_header(DPDMAI_CMDID_OPEN,
					  cmd_flags,
					  0);
	cmd_params = (struct dpdmai_cmd_open *)cmd.params;
	cmd_params->dpdmai_id = cpu_to_le32(dpdmai_id);

	/* send command to mc*/
	err = mc_send_command(mc_io, &cmd);
	if (err)
		return err;

	/* retrieve response parameters */
	*token = mc_cmd_hdr_read_token(&cmd);

	return 0;
}

/**
 * dpdmai_close() - Close the control session of the object
 * @mc_io:	Pointer to MC portal's I/O object
 * @cmd_flags:	Command flags; one or more of 'MC_CMD_FLAG_'
 * @token:	Token of DPDMAI object
 *
 * After this function is called, no further operations are
 * allowed on the object without opening a new control session.
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpdmai_close(struct fsl_mc_io *mc_io,
		 uint32_t cmd_flags,
		 uint16_t token)
{
	struct mc_command cmd = { 0 };

	/* prepare command */
	cmd.header = mc_encode_cmd_header(DPDMAI_CMDID_CLOSE,
					  cmd_flags, token);

	/* send command to mc*/
	return mc_send_command(mc_io, &cmd);
}

/**
 * dpdmai_create() - Create the DPDMAI object
 * @mc_io:	Pointer to MC portal's I/O object
 * @dprc_token:	Parent container token; '0' for default container
 * @cmd_flags:	Command flags; one or more of 'MC_CMD_FLAG_'
 * @cfg:	Configuration structure
 * @obj_id:	Returned object id
 *
 * Create the DPDMAI object, allocate required resources and
 * perform required initialization.
 *
 * The object can be created either by declaring it in the
 * DPL file, or by calling this function.
 *
 * The function accepts an authentication token of a parent
 * container that this object should be assigned to. The token
 * can be '0' so the object will be assigned to the default container.
 * The newly created object can be opened with the returned
 * object id and using the container's associated tokens and MC portals.
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpdmai_create(struct fsl_mc_io *mc_io,
		  uint16_t dprc_token,
		  uint32_t cmd_flags,
		  const struct dpdmai_cfg *cfg,
		  uint32_t *obj_id)
{
	struct dpdmai_cmd_create *cmd_params;
	struct mc_command cmd = { 0 };
	int err;

	/* prepare command */
	cmd.header = mc_encode_cmd_header(DPDMAI_CMDID_CREATE,
					  cmd_flags,
					  dprc_token);
	cmd_params = (struct dpdmai_cmd_create *)cmd.params;
	cmd_params->num_queues = cfg->num_queues;
	cmd_params->priorities[0] = cfg->priorities[0];
	cmd_params->priorities[1] = cfg->priorities[1];
	cmd_params->options = cpu_to_le32(cfg->adv.options);

	/* send command to mc*/
	err = mc_send_command(mc_io, &cmd);
	if (err)
		return err;

	/* retrieve response parameters */
	*obj_id = mc_cmd_read_object_id(&cmd);

	return 0;
}

/**
 * dpdmai_destroy() - Destroy the DPDMAI object and release all its resources.
 * @mc_io:	Pointer to MC portal's I/O object
 * @dprc_token: Parent container token; '0' for default container
 * @cmd_flags:	Command flags; one or more of 'MC_CMD_FLAG_'
 * @object_id:	The object id; it must be a valid id within the container that
 *		created this object;
 *
 * The function accepts the authentication token of the parent container that
 * created the object (not the one that currently owns the object). The object
 * is searched within parent using the provided 'object_id'.
 * All tokens to the object must be closed before calling destroy.
 *
 * Return:	'0' on Success; error code otherwise.
 */
int dpdmai_destroy(struct fsl_mc_io *mc_io,
		   uint16_t dprc_token,
		   uint32_t cmd_flags,
		   uint32_t object_id)
{
	struct dpdmai_cmd_destroy *cmd_params;
	struct mc_command cmd = { 0 };

	/* prepare command */
	cmd.header = mc_encode_cmd_header(DPDMAI_CMDID_DESTROY,
					  cmd_flags,
					  dprc_token);
	cmd_params = (struct dpdmai_cmd_destroy *)cmd.params;
	cmd_params->dpdmai_id = cpu_to_le32(object_id);

	/* send command to mc*/
	return mc_send_command(mc_io, &cmd);
}

/**
 * dpdmai_enable() - Enable the DPDMAI, allow sending and receiving frames.
 * @mc_io:	Pointer to MC portal's I/O object
 * @cmd_flags:	Command flags; one or more of 'MC_CMD_FLAG_'
 * @token:	Token of DPDMAI object
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpdmai_enable(struct fsl_mc_io *mc_io,
		  uint32_t cmd_flags,
		  uint16_t token)
{
	struct mc_command cmd = { 0 };

	/* prepare command */
	cmd.header = mc_encode_cmd_header(DPDMAI_CMDID_ENABLE,
					  cmd_flags,
					  token);

	/* send command to mc*/
	return mc_send_command(mc_io, &cmd);
}

/**
 * dpdmai_disable() - Disable the DPDMAI, stop sending and receiving frames.
 * @mc_io:	Pointer to MC portal's I/O object
 * @cmd_flags:	Command flags; one or more of 'MC_CMD_FLAG_'
 * @token:	Token of DPDMAI object
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpdmai_disable(struct fsl_mc_io *mc_io,
		   uint32_t cmd_flags,
		   uint16_t token)
{
	struct mc_command cmd = { 0 };

	/* prepare command */
	cmd.header = mc_encode_cmd_header(DPDMAI_CMDID_DISABLE,
					  cmd_flags,
					  token);

	/* send command to mc*/
	return mc_send_command(mc_io, &cmd);
}

/**
 * dpdmai_is_enabled() - Check if the DPDMAI is enabled.
 * @mc_io:	Pointer to MC portal's I/O object
 * @cmd_flags:	Command flags; one or more of 'MC_CMD_FLAG_'
 * @token:	Token of DPDMAI object
 * @en:		Returns '1' if object is enabled; '0' otherwise
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpdmai_is_enabled(struct fsl_mc_io *mc_io,
		      uint32_t cmd_flags,
		      uint16_t token,
		      int *en)
{
	struct dpdmai_rsp_is_enabled *rsp_params;
	struct mc_command cmd = { 0 };
	int err;

	/* prepare command */
	cmd.header = mc_encode_cmd_header(DPDMAI_CMDID_IS_ENABLED,
					  cmd_flags,
					  token);

	/* send command to mc*/
	err = mc_send_command(mc_io, &cmd);
	if (err)
		return err;

	/* retrieve response parameters */
	rsp_params = (struct dpdmai_rsp_is_enabled *)cmd.params;
	*en = dpdmai_get_field(rsp_params->en, ENABLE);

	return 0;
}

/**
 * dpdmai_reset() - Reset the DPDMAI, returns the object to initial state.
 * @mc_io:	Pointer to MC portal's I/O object
 * @cmd_flags:	Command flags; one or more of 'MC_CMD_FLAG_'
 * @token:	Token of DPDMAI object
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpdmai_reset(struct fsl_mc_io *mc_io,
		 uint32_t cmd_flags,
		 uint16_t token)
{
	struct mc_command cmd = { 0 };

	/* prepare command */
	cmd.header = mc_encode_cmd_header(DPDMAI_CMDID_RESET,
					  cmd_flags,
					  token);

	/* send command to mc*/
	return mc_send_command(mc_io, &cmd);
}

/**
 * dpdmai_get_irq_enable() - Get overall interrupt state
 * @mc_io:	Pointer to MC portal's I/O object
 * @cmd_flags:	Command flags; one or more of 'MC_CMD_FLAG_'
 * @token:	Token of DPDMAI object
 * @irq_index:	The interrupt index to configure
 * @en:		Returned Interrupt state - enable = 1, disable = 0
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpdmai_get_irq_enable(struct fsl_mc_io *mc_io,
			  uint32_t cmd_flags,
			  uint16_t token,
			  uint8_t irq_index,
			  uint8_t *en)
{
	struct dpdmai_cmd_get_irq_enable *cmd_params;
	struct dpdmai_rsp_get_irq_enable *rsp_params;
	struct mc_command cmd = { 0 };
	int err;

	/* prepare command */
	cmd.header = mc_encode_cmd_header(DPDMAI_CMDID_GET_IRQ_ENABLE,
					  cmd_flags,
					  token);
	cmd_params = (struct dpdmai_cmd_get_irq_enable *)cmd.params;
	cmd_params->irq_index = irq_index;

	/* send command to mc*/
	err = mc_send_command(mc_io, &cmd);
	if (err)
		return err;

	/* retrieve response parameters */
	rsp_params = (struct dpdmai_rsp_get_irq_enable *)cmd.params;
	*en = rsp_params->enable_state;

	return 0;
}

/**
 * dpdmai_set_irq_enable() - Set overall interrupt state.
 * @mc_io:	Pointer to MC portal's I/O object
 * @cmd_flags:	Command flags; one or more of 'MC_CMD_FLAG_'
 * @token:	Token of DPDMAI object
 * @irq_index:	The interrupt index to configure
 * @en:		Interrupt state - enable = 1, disable = 0
 *
 * Allows GPP software to control when interrupts are generated.
 * Each interrupt can have up to 32 causes.  The enable/disable control's the
 * overall interrupt state. if the interrupt is disabled no causes will cause
 * an interrupt
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpdmai_set_irq_enable(struct fsl_mc_io *mc_io,
			  uint32_t cmd_flags,
			  uint16_t token,
			  uint8_t irq_index,
			  uint8_t en)
{
	struct dpdmai_cmd_set_irq_enable *cmd_params;
	struct mc_command cmd = { 0 };

	/* prepare command */
	cmd.header = mc_encode_cmd_header(DPDMAI_CMDID_SET_IRQ_ENABLE,
					  cmd_flags,
					  token);
	cmd_params = (struct dpdmai_cmd_set_irq_enable *)cmd.params;
	cmd_params->enable_state = en;
	cmd_params->irq_index = irq_index;

	/* send command to mc*/
	return mc_send_command(mc_io, &cmd);
}

/**
 * dpdmai_get_irq_mask() - Get interrupt mask.
 * @mc_io:	Pointer to MC portal's I/O object
 * @cmd_flags:	Command flags; one or more of 'MC_CMD_FLAG_'
 * @token:	Token of DPDMAI object
 * @irq_index:	The interrupt index to configure
 * @mask:	Returned event mask to trigger interrupt
 *
 * Every interrupt can have up to 32 causes and the interrupt model supports
 * masking/unmasking each cause independently
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpdmai_get_irq_mask(struct fsl_mc_io *mc_io,
			uint32_t cmd_flags,
			uint16_t token,
			uint8_t irq_index,
			uint32_t *mask)
{
	struct dpdmai_cmd_get_irq_mask *cmd_params;
	struct dpdmai_rsp_get_irq_mask *rsp_params;
	struct mc_command cmd = { 0 };
	int err;

	/* prepare command */
	cmd.header = mc_encode_cmd_header(DPDMAI_CMDID_GET_IRQ_MASK,
					  cmd_flags,
					  token);
	cmd_params = (struct dpdmai_cmd_get_irq_mask *)cmd.params;
	cmd_params->irq_index = irq_index;

	/* send command to mc*/
	err = mc_send_command(mc_io, &cmd);
	if (err)
		return err;

	/* retrieve response parameters */
	rsp_params = (struct dpdmai_rsp_get_irq_mask *)cmd.params;
	*mask = le32_to_cpu(rsp_params->mask);

	return 0;
}

/**
 * dpdmai_set_irq_mask() - Set interrupt mask.
 * @mc_io:	Pointer to MC portal's I/O object
 * @cmd_flags:	Command flags; one or more of 'MC_CMD_FLAG_'
 * @token:	Token of DPDMAI object
 * @irq_index:	The interrupt index to configure
 * @mask:	Event mask to trigger interrupt;
 *		each bit:
 *			0 = ignore event
 *			1 = consider event for asserting IRQ
 *
 * Every interrupt can have up to 32 causes and the interrupt model supports
 * masking/unmasking each cause independently
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpdmai_set_irq_mask(struct fsl_mc_io *mc_io,
			uint32_t cmd_flags,
			uint16_t token,
			uint8_t irq_index,
			uint32_t mask)
{
	struct dpdmai_cmd_set_irq_mask *cmd_params;
	struct mc_command cmd = { 0 };

	/* prepare command */
	cmd.header = mc_encode_cmd_header(DPDMAI_CMDID_SET_IRQ_MASK,
					  cmd_flags,
					  token);
	cmd_params = (struct dpdmai_cmd_set_irq_mask *)cmd.params;
	cmd_params->mask = cpu_to_le32(mask);
	cmd_params->irq_index = irq_index;

	/* send command to mc*/
	return mc_send_command(mc_io, &cmd);
}

/**
 * dpdmai_get_irq_status() - Get the current status of any pending interrupts
 * @mc_io:	Pointer to MC portal's I/O object
 * @cmd_flags:	Command flags; one or more of 'MC_CMD_FLAG_'
 * @token:	Token of DPDMAI object
 * @irq_index:	The interrupt index to configure
 * @status:	Returned interrupts status - one bit per cause:
 *			0 = no interrupt pending
 *			1 = interrupt pending
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpdmai_get_irq_status(struct fsl_mc_io *mc_io,
			  uint32_t cmd_flags,
			  uint16_t token,
			  uint8_t irq_index,
			  uint32_t *status)
{
	struct dpdmai_cmd_get_irq_status *cmd_params;
	struct dpdmai_rsp_get_irq_status *rsp_params;
	struct mc_command cmd = { 0 };
	int err;

	/* prepare command */
	cmd.header = mc_encode_cmd_header(DPDMAI_CMDID_GET_IRQ_STATUS,
					  cmd_flags,
					  token);
	cmd_params = (struct dpdmai_cmd_get_irq_status *)cmd.params;
	cmd_params->status = cpu_to_le32(*status);
	cmd_params->irq_index = irq_index;

	/* send command to mc*/
	err = mc_send_command(mc_io, &cmd);
	if (err)
		return err;

	/* retrieve response parameters */
	rsp_params = (struct dpdmai_rsp_get_irq_status *)cmd.params;
	*status = le32_to_cpu(rsp_params->status);

	return 0;
}

/**
 * dpdmai_clear_irq_status() - Clear a pending interrupt's status
 * @mc_io:	Pointer to MC portal's I/O object
 * @cmd_flags:	Command flags; one or more of 'MC_CMD_FLAG_'
 * @token:	Token of DPDMAI object
 * @irq_index:	The interrupt index to configure
 * @status:	Bits to clear (W1C) - one bit per cause:
 *			0 = don't change
 *			1 = clear status bit
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpdmai_clear_irq_status(struct fsl_mc_io *mc_io,
			    uint32_t cmd_flags,
			    uint16_t token,
			    uint8_t irq_index,
			    uint32_t status)
{
	struct dpdmai_cmd_clear_irq_status *cmd_params;
	struct mc_command cmd = { 0 };

	/* prepare command */
	cmd.header = mc_encode_cmd_header(DPDMAI_CMDID_CLEAR_IRQ_STATUS,
					  cmd_flags,
					  token);
	cmd_params = (struct dpdmai_cmd_clear_irq_status *)cmd.params;
	cmd_params->status = cpu_to_le32(status);
	cmd_params->irq_index = irq_index;

	/* send command to mc*/
	return mc_send_command(mc_io, &cmd);
}

/**
 * dpdmai_get_attributes() - Retrieve DPDMAI attributes.
 * @mc_io:	Pointer to MC portal's I/O object
 * @cmd_flags:	Command flags; one or more of 'MC_CMD_FLAG_'
 * @token:	Token of DPDMAI object
 * @attr:	Returned object's attributes
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpdmai_get_attributes(struct fsl_mc_io *mc_io,
			  uint32_t cmd_flags,
			  uint16_t token,
			  struct dpdmai_attr *attr)
{
	struct dpdmai_rsp_get_attr *rsp_params;
	struct mc_command cmd = { 0 };
	int err;

	/* prepare command */
	cmd.header = mc_encode_cmd_header(DPDMAI_CMDID_GET_ATTR,
					  cmd_flags,
					  token);

	/* send command to mc*/
	err = mc_send_command(mc_io, &cmd);
	if (err)
		return err;

	/* retrieve response parameters */
	rsp_params = (struct dpdmai_rsp_get_attr *)cmd.params;
	attr->id = le32_to_cpu(rsp_params->id);
	attr->num_of_priorities = rsp_params->num_of_priorities;
	attr->num_of_queues = rsp_params->num_of_queues;
	attr->options = le32_to_cpu(rsp_params->options);

	return 0;
}

/**
 * dpdmai_set_rx_queue() - Set Rx queue configuration
 * @mc_io:	Pointer to MC portal's I/O object
 * @cmd_flags:	Command flags; one or more of 'MC_CMD_FLAG_'
 * @token:	Token of DPDMAI object
 * @queue_idx: Rx queue index. Accepted values are form 0 to num_queues
 *		parameter provided in dpdmai_create
 * @priority:	Select the queue relative to number of
 *		priorities configured at DPDMAI creation; use
 *		DPDMAI_ALL_QUEUES to configure all Rx queues
 *		identically.
 * @cfg:	Rx queue configuration
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpdmai_set_rx_queue(struct fsl_mc_io *mc_io,
			uint32_t cmd_flags,
			uint16_t token,
			uint8_t queue_idx,
			uint8_t priority,
			const struct dpdmai_rx_queue_cfg *cfg)
{
	struct dpdmai_cmd_set_rx_queue *cmd_params;
	struct mc_command cmd = { 0 };

	/* prepare command */
	cmd.header = mc_encode_cmd_header(DPDMAI_CMDID_SET_RX_QUEUE,
					  cmd_flags,
					  token);
	cmd_params = (struct dpdmai_cmd_set_rx_queue *)cmd.params;
	cmd_params->dest_id = cpu_to_le32(cfg->dest_cfg.dest_id);
	cmd_params->dest_priority = cfg->dest_cfg.priority;
	cmd_params->priority = priority;
	cmd_params->queue_idx = queue_idx;
	cmd_params->user_ctx = cpu_to_le64(cfg->user_ctx);
	cmd_params->options = cpu_to_le32(cfg->options);
	dpdmai_set_field(cmd_params->dest_type,
			 DEST_TYPE,
			 cfg->dest_cfg.dest_type);

	/* send command to mc*/
	return mc_send_command(mc_io, &cmd);
}

/**
 * dpdmai_get_rx_queue() - Retrieve Rx queue attributes.
 * @mc_io:	Pointer to MC portal's I/O object
 * @cmd_flags:	Command flags; one or more of 'MC_CMD_FLAG_'
 * @token:	Token of DPDMAI object
 * @queue_idx: Rx queue index. Accepted values are form 0 to num_queues
 *		parameter provided in dpdmai_create
 * @priority:	Select the queue relative to number of
 *		priorities configured at DPDMAI creation
 * @attr:	Returned Rx queue attributes
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpdmai_get_rx_queue(struct fsl_mc_io *mc_io,
			uint32_t cmd_flags,
			uint16_t token,
			uint8_t queue_idx,
			uint8_t priority,
			struct dpdmai_rx_queue_attr *attr)
{
	struct dpdmai_cmd_get_queue *cmd_params;
	struct dpdmai_rsp_get_rx_queue *rsp_params;
	struct mc_command cmd = { 0 };
	int err;

	/* prepare command */
	cmd.header = mc_encode_cmd_header(DPDMAI_CMDID_GET_RX_QUEUE,
					  cmd_flags,
					  token);
	cmd_params = (struct dpdmai_cmd_get_queue *)cmd.params;
	cmd_params->priority = priority;
	cmd_params->queue_idx = queue_idx;

	/* send command to mc*/
	err = mc_send_command(mc_io, &cmd);
	if (err)
		return err;

	/* retrieve response parameters */
	rsp_params = (struct dpdmai_rsp_get_rx_queue *)cmd.params;
	attr->user_ctx = le64_to_cpu(rsp_params->user_ctx);
	attr->fqid = le32_to_cpu(rsp_params->fqid);
	attr->dest_cfg.dest_id = le32_to_cpu(rsp_params->dest_id);
	attr->dest_cfg.priority = le32_to_cpu(rsp_params->dest_priority);
	attr->dest_cfg.dest_type = dpdmai_get_field(rsp_params->dest_type,
						    DEST_TYPE);

	return 0;
}

/**
 * dpdmai_get_tx_queue() - Retrieve Tx queue attributes.
 * @mc_io:	Pointer to MC portal's I/O object
 * @cmd_flags:	Command flags; one or more of 'MC_CMD_FLAG_'
 * @token:	Token of DPDMAI object
 * @queue_idx: Tx queue index. Accepted values are form 0 to num_queues
 *		parameter provided in dpdmai_create
 * @priority:	Select the queue relative to number of
 *		priorities configured at DPDMAI creation
 * @attr:	Returned Tx queue attributes
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpdmai_get_tx_queue(struct fsl_mc_io *mc_io,
			uint32_t cmd_flags,
			uint16_t token,
			uint8_t queue_idx,
			uint8_t priority,
			struct dpdmai_tx_queue_attr *attr)
{
	struct dpdmai_cmd_get_queue *cmd_params;
	struct dpdmai_rsp_get_tx_queue *rsp_params;
	struct mc_command cmd = { 0 };
	int err;

	/* prepare command */
	cmd.header = mc_encode_cmd_header(DPDMAI_CMDID_GET_TX_QUEUE,
					  cmd_flags,
					  token);
	cmd_params = (struct dpdmai_cmd_get_queue *)cmd.params;
	cmd_params->priority = priority;
	cmd_params->queue_idx = queue_idx;

	/* send command to mc*/
	err = mc_send_command(mc_io, &cmd);
	if (err)
		return err;

	/* retrieve response parameters */
	rsp_params = (struct dpdmai_rsp_get_tx_queue *)cmd.params;
	attr->fqid = le32_to_cpu(rsp_params->fqid);

	return 0;
}

/**
 * dpdmai_set_rx_congestion_notification() - Set Rx congestion notification configuration.
 * @mc_io:	Pointer to MC portal's I/O object
 * @cmd_flags:	Command flags; one or more of 'MC_CMD_FLAG_'
 * @token:	Token of DPDMAI object
 * @priority:	Select the queue priority relative to number of
 *		priorities configured at DPDMAI creation
 * @cfg: congestion notification configuration
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpdmai_set_rx_congestion_notification(struct fsl_mc_io *mc_io,
			uint32_t cmd_flags,
			uint16_t token,
			uint8_t priority,
			struct dpdmai_congestion_notification_cfg *cfg)
{
	struct dpdmai_cmd_set_cgn *cmd_params;
	struct mc_command cmd = { 0 };

	/* prepare command */
	cmd.header = mc_encode_cmd_header(DPDMAI_CMDID_SET_RX_CONGESTION_NOTIFICATION,
					  cmd_flags,
					  token);
	cmd_params = (struct dpdmai_cmd_set_cgn *)cmd.params;
	cmd_params->priority = priority;
	dpdmai_set_field(cmd_params->units, CG_UNITS, cfg->units);
	cmd_params->notification_mode = cpu_to_le16(cfg->notification_mode);
	cmd_params->threshold_entry = cpu_to_le32(cfg->threshold_entry);
	cmd_params->threshold_exit = cpu_to_le32(cfg->threshold_exit);
	cmd_params->message_ctx = cpu_to_le64(cfg->message_ctx);
	cmd_params->message_iova = cpu_to_le64(cfg->message_iova);

	/* send command to mc*/
	return mc_send_command(mc_io, &cmd);
}

/**
 * dpdmai_set_tx_congestion_notification() - Set Tx congestion notification configuration.
 * @mc_io:	Pointer to MC portal's I/O object
 * @cmd_flags:	Command flags; one or more of 'MC_CMD_FLAG_'
 * @token:	Token of DPDMAI object
 * @priority:	Select the queue priority relative to number of
 *		priorities configured at DPDMAI creation
 * @cfg: congestion notification configuration
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpdmai_set_tx_congestion_notification(struct fsl_mc_io *mc_io,
			uint32_t cmd_flags,
			uint16_t token,
			uint8_t priority,
			struct dpdmai_congestion_notification_cfg *cfg)
{
	struct dpdmai_cmd_set_cgn *cmd_params;
	struct mc_command cmd = { 0 };

	/* prepare command */
	cmd.header = mc_encode_cmd_header(DPDMAI_CMDID_SET_TX_CONGESTION_NOTIFICATION,
					  cmd_flags,
					  token);
	cmd_params = (struct dpdmai_cmd_set_cgn *)cmd.params;
	cmd_params->priority = priority;
	dpdmai_set_field(cmd_params->units, CG_UNITS, cfg->units);
	cmd_params->notification_mode = cpu_to_le16(cfg->notification_mode);
	cmd_params->threshold_entry = cpu_to_le32(cfg->threshold_entry);
	cmd_params->threshold_exit = cpu_to_le32(cfg->threshold_exit);
	cmd_params->message_ctx = cpu_to_le64(cfg->message_ctx);
	cmd_params->message_iova = cpu_to_le64(cfg->message_iova);

	/* send command to mc*/
	return mc_send_command(mc_io, &cmd);
}

/**
 * dpdmai_get_rx_congestion_notification() - Get Rx congestion notification configuration.
 * @mc_io:	Pointer to MC portal's I/O object
 * @cmd_flags:	Command flags; one or more of 'MC_CMD_FLAG_'
 * @token:	Token of DPDMAI object
 * @priority:	Specify the desired queue priority relative to number of
 *		priorities configured at DPDMAI creation
 * @cfg: pointer to receive congestion notification configuration
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpdmai_get_rx_congestion_notification(struct fsl_mc_io *mc_io,
			uint32_t cmd_flags,
			uint16_t token,
			uint8_t priority,
			struct dpdmai_congestion_notification_cfg *cfg)
{
	struct dpdmai_cmd_get_cgn *cmd_params;
	struct dpdmai_rsp_get_cgn *rsp_params;
	struct mc_command cmd = { 0 };
	int err;

	/* prepare command */
	cmd.header = mc_encode_cmd_header(DPDMAI_CMDID_GET_RX_CONGESTION_NOTIFICATION,
					  cmd_flags,
					  token);
	cmd_params = (struct dpdmai_cmd_get_cgn *)cmd.params;
	cmd_params->priority = priority;

	/* send command to mc*/
	err = mc_send_command(mc_io, &cmd);
	if (err)
		return err;

	/* retrieve response parameters */
	rsp_params = (struct dpdmai_rsp_get_cgn *)cmd.params;
	cfg->units = dpdmai_get_field(rsp_params->units, CG_UNITS);
	cfg->notification_mode = le16_to_cpu(rsp_params->notification_mode);
	cfg->threshold_entry = le32_to_cpu(rsp_params->threshold_entry);
	cfg->threshold_exit = le32_to_cpu(rsp_params->threshold_exit);
	cfg->message_ctx = le64_to_cpu(rsp_params->message_ctx);
	cfg->message_iova = le64_to_cpu(rsp_params->message_iova);

	return 0;
}

/**
 * dpdmai_get_tx_congestion_notification() - Get Tx congestion notification configuration.
 * @mc_io:	Pointer to MC portal's I/O object
 * @cmd_flags:	Command flags; one or more of 'MC_CMD_FLAG_'
 * @token:	Token of DPDMAI object
 * @priority:	Specify the desired queue priority relative to number of
 *		priorities configured at DPDMAI creation
 * @cfg: pointer to receive congestion notification configuration
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpdmai_get_tx_congestion_notification(struct fsl_mc_io *mc_io,
			uint32_t cmd_flags,
			uint16_t token,
			uint8_t priority,
			struct dpdmai_congestion_notification_cfg *cfg)
{
	struct dpdmai_cmd_get_cgn *cmd_params;
	struct dpdmai_rsp_get_cgn *rsp_params;
	struct mc_command cmd = { 0 };
	int err;

	/* prepare command */
	cmd.header = mc_encode_cmd_header(DPDMAI_CMDID_GET_TX_CONGESTION_NOTIFICATION,
					  cmd_flags,
					  token);
	cmd_params = (struct dpdmai_cmd_get_cgn *)cmd.params;
	cmd_params->priority = priority;

	/* send command to mc*/
	err = mc_send_command(mc_io, &cmd);
	if (err)
		return err;

	/* retrieve response parameters */
	rsp_params = (struct dpdmai_rsp_get_cgn *)cmd.params;
	cfg->units = dpdmai_get_field(rsp_params->units, CG_UNITS);
	cfg->notification_mode = le16_to_cpu(rsp_params->notification_mode);
	cfg->threshold_entry = le32_to_cpu(rsp_params->threshold_entry);
	cfg->threshold_exit = le32_to_cpu(rsp_params->threshold_exit);
	cfg->message_ctx = le64_to_cpu(rsp_params->message_ctx);
	cfg->message_iova = le64_to_cpu(rsp_params->message_iova);

	return 0;
}

/**
 * dpdmai_get_api_version() - Get Data Path DMA API version
 * @mc_io:  Pointer to MC portal's I/O object
 * @cmd_flags:	Command flags; one or more of 'MC_CMD_FLAG_'
 * @major_ver:	Major version of data path dma API
 * @minor_ver:	Minor version of data path dma API
 *
 * Return:  '0' on Success; Error code otherwise.
 */
int dpdmai_get_api_version(struct fsl_mc_io *mc_io,
			   uint32_t cmd_flags,
			   uint16_t *major_ver,
			   uint16_t *minor_ver)
{
	struct dpdmai_rsp_get_api_version *rsp_params;
	struct mc_command cmd = { 0 };
	int err;

	cmd.header = mc_encode_cmd_header(DPDMAI_CMDID_GET_API_VERSION,
					cmd_flags,
					0);

	err = mc_send_command(mc_io, &cmd);
	if (err)
		return err;

	rsp_params = (struct dpdmai_rsp_get_api_version *)cmd.params;
	*major_ver = le16_to_cpu(rsp_params->major);
	*minor_ver = le16_to_cpu(rsp_params->minor);

	return 0;
}
