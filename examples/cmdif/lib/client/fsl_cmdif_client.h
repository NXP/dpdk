/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 * Copyright 2014-2015 Freescale Semiconductor Inc.
 * Copyright 2018-2019 NXP
 */

#ifndef __FSL_CMDIF_CLIENT_H__
#define __FSL_CMDIF_CLIENT_H__

/**
 * @file
 *
 * CMDIF Client specific API's
 *
 */

#ifdef __cplusplus
extern "C" {
#endif

/** Low Priority */
#define CMDIF_PRI_LOW		0
/** High Priority */
#define CMDIF_PRI_HIGH		1

/** Bit to be used for cmd_id to identify asynchronous commands */
#define CMDIF_ASYNC_CMD		0x2000
/** Bit to be used for commands that don't need response */
#define CMDIF_NORESP_CMD	0x1000

/** Memory size required by cmdif_open() */
#define CMDIF_OPEN_SIZE		64

/* Additional space required for async commands */
#define CMDIF_ASYNC_OVERHEAD 16

/** Command interface descriptor. */
struct cmdif_desc {
	/**
	 * Pointer to transport layer device for sending commands;
	 * On GPP the user should pass DPAA2 device (a separate DPAA2 device
	 * for each descriptor).
	 * On AIOP the user should pass dpci_id as known by GPP SW context
	 * Must be set by the user.
	 */
	void *regs;
	/**
	 * Opaque handle for the use of the command interface;
	 * user should not modify it.
	 */
	void *dev;
};

/**
 * Command callback.
 *
 * User provides this function. Driver invokes it for all asynchronous commands
 * that had been sent through cidesc.
 *
 * Please make sure to modify only size bytes of the data.
 * Automatic expansion of the buffer is not available.
 *
 * @param async_ctx
 *   User context that was setup during cmdif_open()
 * @param err
 *   Error as returned by server
 * @param cmd_id
 *   Id of command
 * @param size
 *   Size of the data.
 *   On the AIOP side use PRC_GET_SEGMENT_LENGTH() to determine the
 *   size of presented data.
 * @param data
 *   Data of the command.
 *   On the AIOP side it is the pointer to segment presentation
 *   address; use fdma_modify_default_segment_data() if needed.
 *   On GPP side it should be virtual address that belongs
 *   to current SW context.
 *
 * @returns
 *   - 0: Success.
 *   - <0: Error code.
 */
typedef int (cmdif_cb_t)(void *async_ctx,
			 int err,
			 uint16_t cmd_id,
			 uint32_t size,
			 void *data);

/**
 * Set the timeout parameters for CMDIF sync command.
 *
 * @param wait_interval_us
 *   wait interval in micro-seconds
 * @param num_tries
 *   number of tries to poll for sync command completion
 */
void cmdif_sync_set_timeout_params(uint64_t wait_interval_us,
				   uint64_t num_tries);

/**
 * Open command interface device for the specified module
 *
 * @param cidesc
 *   Command interface descriptor, cmdif device will
 *   be returned inside this descriptor.
 *   Sharing of the same cidesc by multiple threads requires locks
 *   outside CMDIF API, as an alternative each thread can open it's
 *   own session by calling cmdif_open().
 *   Only cidesc.regs must be set by user see struct cmdif_desc.
 * @param module_name
 *   Module name, up to 8 characters.
 * @param instance_id
 *   Instance id which will be passed to #open_cb_t
 * @param data
 *   8 bytes aligned buffer for internal use of the
 *   command interface.
 *   This address should be accessible by Server and Client.
 *   This buffer can be freed only after cmdif_close().
 *   On AIOP, set data as NULL.
 * @param size
 *   Size of the data buffer. If the size is not
 *   enough cmdif_open() will return -ENOMEM.
 *   By default, set it to #CMDIF_OPEN_SIZE bytes.
 *
 * @returns
 *   - 0: Success.
 *   - <0: Error code.
 */
int cmdif_open(struct cmdif_desc *cidesc,
	       const char *module_name,
	       uint8_t instance_id,
	       void *data,
	       uint32_t size);

/**
 * Close this command interface device and free this instance entry
 * on the Server.
 *
 * It's not yet supported by the AIOP client.
 *
 * @param[in] cidesc
 *   Command interface descriptor which was setup by cmdif_open().
 *
 * @returns
 *   - 0: Success.
 *   - <0: Error code.
 */
int cmdif_close(struct cmdif_desc *cidesc);

/**
 * Send command to the module device that was created during cmdif_open().
 *
 * This function may be activated in synchronous and asynchronous mode.
 *
 * @param cidesc
 *   Command interface descriptor which was setup by cmdif_open().
 * @param cmd_id
 *   Id which represent command on the module that was
 *   registered on Server; Application may use bits 11-0.
 * @param size
 *   Size of the data including extra 16 bytes for
 *   cmdif_cb_t in case of CMDIF_ASYNC_CMD.
 * @param priority
 *   High or low priority queue.
 * @param data
 *   Data of the command or buffer allocated by user which
 *   will be used inside command.
 *   This address should be accessible by Server and Client.
 *   It should be virtual address that belongs to current SW context.
 *   In case of asynchronous command last 16 bytes must be reserved
 *   for cmdif usage.
 *   On GPP it must be from Write-Back Cacheable and Outer Shareable memory.
 * @param async_cb
 *   Callback to be called on response of asynchronous command.
 * @param async_ctx
 *   Context to be received with asynchronous command response
 *   inside async_cb().
 *
 * @returns
 *   - 0: Success.
 *   - <0: Error code.
 */
int cmdif_send(struct cmdif_desc *cidesc,
	       uint16_t cmd_id,
	       uint32_t size,
	       int priority,
	       uint64_t data,
	       cmdif_cb_t *async_cb,
	       void *async_ctx);

/**
 * Check the response queue for new responses,
 * de-queue and activate the callback function for each response
 *
 * This function is not blocking;
 * if nothing was found it will return error code.
 * Note, this functionality is not relevant for AIOP client.
 * @param cidesc
 *   Command interface descriptor which was setup by cmdif_open().
 * @param priority
 *   High or low priority queue to be checked.
 *
 * @returns
 *   - 0: Success.
 *   - <0: Error code.
 */
int cmdif_resp_read(struct cmdif_desc *cidesc, int priority);

#ifdef __cplusplus
}
#endif

#endif /* __FSL_CMDIF_CLIENT_H__ */
