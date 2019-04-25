/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 * Copyright 2014-2015 Freescale Semiconductor Inc.
 * Copyright 2018-2019 NXP
 */

#ifndef __CMDIF_CLIENT_FLIB_H__
#define __CMDIF_CLIENT_FLIB_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <fsl_cmdif_client.h>

/* Common settings for Server and Client */
#define CMD_ID_OPEN        0x8000
#define CMD_ID_CLOSE       0x4000
#define OPEN_AUTH_ID       0xFFFF
#define M_NAME_CHARS       8
#define CMDIF_OPEN_SIZEOF (sizeof(struct cmdif_dev) + sizeof(union cmdif_data))

#define CMDIF_DEV_SET(FD, PTR) \
	do { \
		(FD)->u_flc.cmd.dev_h = \
		(uint8_t)((((uint64_t)(PTR)) & 0xFF00000000) >> 32); \
		(FD)->u_frc.cmd.dev_l = ((uint32_t)((uint64_t)(PTR))); \
	} while (0)

#define CMDIF_DEV_GET(FD) \
	((struct cmdif_dev *)((uint64_t)(((uint64_t)((FD)->u_frc.cmd.dev_l)) \
		| (((uint64_t)((FD)->u_flc.cmd.dev_h)) << 32))))

#define CMDIF_ASYNC_ADDR_GET(DATA, SIZE) \
		((uint64_t)(DATA) + (SIZE))

#define CMDIF_DEV_RESERVED_BYTES 12

#define CMDIF_CMD_FD_SET(FD, DEV, DATA, SIZE, CMD) \
	do { \
		(FD)->u_addr.d_addr     = DATA; \
		(FD)->d_size            = (SIZE); \
		(FD)->u_flc.flc         = 0; \
		(FD)->u_flc.cmd.auth_id = (DEV)->auth_id; \
		(FD)->u_flc.cmd.cmid    = CPU_TO_SRV16(CMD); \
		(FD)->u_flc.cmd.epid    = CPU_TO_BE16(CMDIF_EPID); \
		CMDIF_DEV_SET((FD), (DEV)); \
		(FD)->u_flc.flc = CPU_TO_BE64((FD)->u_flc.flc); \
	} while (0)

/** Structure to hold the asynch context data */
struct cmdif_async {
	/** Pointer to asynchronous callback */
	uint64_t async_cb;
	/** Pointer to asynchronous context */
	uint64_t async_ctx;
};

/**
 * The command interface device
 *
 * Order of the open buffer is:
 * 1) struct cmdif_dev
 * 2) union cmdif_data
 * Do not change those structures because of possible unaligned memory accesses
 */
struct cmdif_dev {
	/** Physical address of sync_done */
	uint64_t   p_sync_done;
	/** 4 bytes to be used for synchronous commands */
	void       *sync_done;
	/** Authentication ID to be used for session with server*/
	uint16_t   auth_id;
	uint8_t    reserved[CMDIF_DEV_RESERVED_BYTES];
};

/**
 * FD[ADDR] content of the buffer to be sent with open command
 * when sending to AIOP server
 */
union cmdif_data {
	struct {
		/** Reserved for done on response */
		uint8_t done;
		/** Module name that was registered */
		char m_name[M_NAME_CHARS];
	} send;
	struct {
		/** Reserved for done on response */
		uint8_t  done;
		/** Reserved for done on response */
		int8_t   err;
		/** New authentication id */
		uint16_t auth_id;
	} resp;
};

#ifdef __cplusplus
}
#endif

#endif /* __CMDIF_CLIENT_FLIB_H__ */
