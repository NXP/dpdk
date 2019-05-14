/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 * Copyright 2014-2015 Freescale Semiconductor Inc.
 * Copyright 2018-2019 NXP
 */

#ifndef __FSL_CMDIF_FLIB_C_H__
#define __FSL_CMDIF_FLIB_C_H__

/**
 * @file
 *
 * API to be used for FD based command interface implementation
 *
 * This is external API that is used to implement the final API as defined at
 * fsl_cmdif_client.h and fsl_cmdif_server.h. For client and server external use
 * only the API from fsl_cmdif_client.h and fsl_cmdif_server.h.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <fsl_cmdif_client.h>
#include <fsl_cmdif_flib_fd.h>

/**
 * Build open command.
 *
 * Should be used for building frame descriptor for open command.
 *
 * @param cidesc
 *   Command interface descriptor
 * @param m_name
 *   Module name, up to 8 characters
 * @param instance_id
 *   Instance id which will be passed to open_cb_t
 * @param v_data
 *   Core virtual address of the buffer to be used by command interface.
 *   The core is going to access the buffer through this address.
 *   This address should be accessible by Server and Client.
 *   Must be 8 byte aligned.
 * @param p_data
 *   Physical address or SMMU virtual address of the
 *   v_data buffer to be set inside the fd of command.
 * @param size
 *   Size of the v_data buffer. If the size if not
 *   enough cmdif_open() will return -ENOMEM.
 * @param fd
 *   Frame descriptor relevant fields for cmdif. This is an
 *   ouptut parameter created by this API.
 *
 * @returns
 *   - 0: Success.
 *   - <0: Error code.
 */
int cmdif_open_cmd(struct cmdif_desc *cidesc,
		   const char *m_name,
		   uint8_t instance_id,
		   uint8_t *v_data,
		   uint64_t p_data,
		   uint32_t size,
		   struct cmdif_fd *fd);

/**
 * Synchronous/Blocking mode done indication.
 *
 * Should be used for implementation of cmdif_send() in synchronous mode.
 *
 * @param cidesc
 *   Command interface descriptor
 *
 * @returns
 *   - '0' if the command is not finished yet;
 *   - non '0' if it has finished.
 */
int cmdif_sync_ready(struct cmdif_desc *cidesc);

/**
 * Synchronous command done.
 *
 * Should be used for implementation of cmdif_send() in synchronous mode.
 * Should the last call before return inside from cmdif_send().
 *
 * @param cidesc
 *   Command interface descriptor
 *
 * @returns
 *   - 0: Success.
 *   - <0: Error code.
 */
int cmdif_sync_cmd_done(struct cmdif_desc *cidesc);

/**
 * Open command done.
 *
 * Should be used for implementation of cmdif_open().
 * Should the last call before return inside from cmdif_open().
 *
 * @param cidesc
 *   Command interface descriptor
 *
 * @returns
 *   - 0: Success.
 *   - <0: Error code.
 */
int cmdif_open_done(struct cmdif_desc *cidesc);

/**
 * Build close command.
 *
 * Should be used for building frame descriptor for close command.
 *
 * @param cidesc
 *   Command interface descriptor
 * @param fd
 *   Frame descriptor relevant fields for cmdif. This is an out parameter and
 *   is filled in by cmdif_close_cmd.
 *
 * @returns
 *   - 0: Success.
 *   - <0: Error code.
 */
int cmdif_close_cmd(struct cmdif_desc *cidesc, struct cmdif_fd *fd);

/**
 * Close command done.
 *
 * Should be used for implementation of cmdif_close().
 * Should the last call before return inside from cmdif_close().
 *
 * @param cidesc
 *   Command interface descriptor
 *
 * @returns
 *   - 0: Success.
 *   - <0: Error code.
 */
int cmdif_close_done(struct cmdif_desc *cidesc);

/**
 * Synchronous/Blocking mode indication.
 *
 * Should be used for implementation of cmdif_send() in synchronous mode.
 *
 * @param cmd_id
 *   Command id that was sent
 *
 * @returns
 *   - 0: Success.
 *   - <0: Error code.
 */
int cmdif_is_sync_cmd(uint16_t cmd_id);

/**
 * Build command.
 *
 * Should be used for building frame descriptor for command.
 *
 * @param cidesc
 *   Command interface descriptor
 * @param cmd_id
 *   Command id that was sent
 * @param size
 *   Size of data
 * @param data
 *   Physical address or SMMU virtual address of the
 *   command buffer to be set inside the fd of the command.
 * @param async_cb
 *   Callback to be called on response of asynchronous command.
 * @param async_ctx
 *   Context to be received with asynchronous command response
 *   inside async_cb()
 * @param fd
 *   Frame descriptor relevant fields for cmdif. This is an out parameter and
 *   is filled in by cmdif_close_cmd.
 *
 * @returns
 *   - 0: Success.
 *   - <0: Error code.
 */
int cmdif_cmd(struct cmdif_desc *cidesc,
	      uint16_t cmd_id,
	      uint32_t size,
	      uint64_t data,
	      cmdif_cb_t *async_cb,
	      void *async_ctx,
	      struct cmdif_fd *fd);

/**
 * Call asynchronous callback of the received frame descriptor
 *
 * @param fd
 *   Pointer to received frame descriptor
 *
 * @returns
 *   - 0: Success.
 *   - <0: Error code.
 */
int cmdif_async_cb(struct cmdif_fd *fd);

#ifdef __cplusplus
}
#endif

#endif /* __FSL_CMDIF_FLIB_H__ */
