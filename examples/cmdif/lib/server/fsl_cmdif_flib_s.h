/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 * Copyright 2014-2015 Freescale Semiconductor Inc.
 * Copyright 2018-2019 NXP
 */

#ifndef __FSL_CMDIF_FLIB_S_H__
#define __FSL_CMDIF_FLIB_S_H__

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
#include <fsl_cmdif_server.h>
#include <fsl_cmdif_flib_fd.h>

/** Special command for cmdif_session_open() */
#define CMD_ID_NOTIFY_OPEN    0xF000
/** Special command for cmdif_session_close() */
#define CMD_ID_NOTIFY_CLOSE   0xE000

/**
 * Allocate server handle to be used by server FLIBs.
 *
 * Should be used one time during server initialization.
 *
 * @param fast_malloc
 *   Malloc function for fast memory allocation that is accessed
 *   for every command.
 * @param slow_malloc
 *   Malloc function for slow memory allocation, this memory will
 *   be used to malloc data that is accessed only during initialization.
 *
 * @returns
 *   - Valid pointer on success
 *   - NULL in case of error
 */
void *cmdif_srv_allocate(void *(*fast_malloc)(int),
			 void *(*slow_malloc)(int));

/**
 * Deallocate server handle allocated by cmdif_srv_allocate().
 *
 * Should be used one time during server shutdown.
 *
 * @param srv
 *   Server handle allocated by cmdif_srv_allocate()
 * @param free
 *   Function to be used to free server allocated memory.
 *
 * @returns
 *   void
 */
void cmdif_srv_deallocate(void *srv,
			  void (*free)(void *ptr));

/**
 * Unregister module under server.
 *
 * Should be used to implement cmdif_unregister_module.
 * This function is not multitask protected.
 * Wrap it with locks if required.
 *
 * @param srv
 *   Server handle allocated by cmdif_srv_allocate()
 * @param m_name
 *   Module name to unregister
 *
 * @returns
 *   - 0: Success.
 *   - <0: Error code.
 */
int cmdif_srv_unregister(void *srv,
			 const char *m_name);

/**
 * Register module under server.
 *
 * Should be used to implement cmdif_register_module.
 * This function is not multitask protected.
 * Wrap it with locks if required.
 *
 * @param srv
 *   Server handle allocated by cmdif_srv_allocate()
 * @param m_name
 *   Module name to unregister
 * @param ops
 *   Module callback functions
 *
 * @returns
 *   - 0: Success.
 *   - <0: Error code.
 */
int cmdif_srv_register(void *srv,
		       const char *m_name,
		       struct cmdif_module_ops *ops);

/**
 * Open session on server
 *
 * Should be used for implementation of cmdif_session_open()
 * or inside cmdif_srv_cb().
 * This API is to be used to create a session on server.
 * Session information will be placed inside v_data, this buffer can be send to
 * the other side using #CMD_ID_NOTIFY_OPEN command.
 *
 * @param srv
 *   Server handle allocated by cmdif_srv_allocate()
 * @param m_name
 *   Name of the module that have been registered using
 *                         cmdif_srv_register()
 * @param inst_id
 *   Instance id which will be passed to #open_cb_t
 * @param size
 *   Size of v_data buffer.
 * @param dev_id
 *   Transport device id to be used for this session.
 * @param v_data
 *   Buffer allocated by user. If not NULL this buffer will carry all
 *   the information of this session.
 *   Must be 8 bytes aligned.
 * @param auth_id
 *   Session id as returned by server. This is an out parameter.
 *
 * @returns
 *   - 0: Success.
 *   - <0: Error code.
 */
int cmdif_srv_open(void *srv,
		   const char *m_name,
		   uint8_t inst_id,
		   uint32_t dev_id,
		   uint32_t size,
		   void *v_data,
		   uint16_t *auth_id);

/**
 * Close session on server
 *
 * Should be used for implementation of cmdif_session_close()
 * or inside cmdif_srv_cb().
 * This API is to be used to close a session on server.
 * Session information will be placed inside v_data, this buffer can be send to
 * the other side using #CMD_ID_NOTIFY_CLOSE command.
 *
 * @param srv
 *   Server handle allocated by cmdif_srv_allocate()
 * @param auth_id
 *   Session id as returned by cmdif_srv_open().
 * @param dev_id
 *   Transport device id to be used for this session.
 * @param size
 *   Size of v_data buffer.
 * @param v_data
 *   Buffer allocated by user. If not NULL this buffer will carry all
 *   the information of this session.
 *
 * @returns
 *   - 0: Success.
 *   - <0: Error code.
 */
int cmdif_srv_close(void *srv,
		    uint16_t auth_id,
		    uint32_t dev_id,
		    uint32_t size,
		    void *v_data);

/**
 * Server handle command function
 *
 * Should be called upon every command frame that have been dequeued.
 * Use it inside cmdif_srv_cb()
 *
 * @param srv
 *   Server handle allocated by cmdif_srv_allocate()
 * @param cfd
 *   CMDIF input frame descriptor
 * @param v_addr
 *   Virtual address to be used for ctrl cb.
 *   This is workaround for SMMU disable mode, set it to NULL if
 *   cfd->u_addr.d_addr can be passed as #ctrl_cb_t data.
 *   Otherwise set v_addr as virtual address of cfd->u_addr.d_addr.
 * @param cfd_out
 *   CMDIF output frame descriptor, if response is required. This is an
 *   out parameter and is filled in by the API.
 * @param send_resp
 *   Response indication. If set to 1 the response FD must be sent.
 *   This is an out parameter and is filled in by the API.
 *
 * @returns
 *   - 0: Success.
 *   - <0: Error code.
 */
int cmdif_srv_cmd(void *srv,
		  struct cmdif_fd *cfd,
		  void   *v_addr,
		  struct cmdif_fd *cfd_out,
		  uint8_t *send_resp);

#ifdef __cplusplus
}
#endif

#endif /* __FSL_CMDIF_FLIB_H__ */
