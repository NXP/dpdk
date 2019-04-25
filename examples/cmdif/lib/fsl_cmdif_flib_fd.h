/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 * Copyright 2014-2015 Freescale Semiconductor Inc.
 * Copyright 2018-2019 NXP
 */

#ifndef __FSL_CMDIF_FLIB_FD_H__
#define __FSL_CMDIF_FLIB_FD_H__

/**
 * @file
 *
 * API to be used for FD based command interface implementation.
 *
 * This is external API that is used to implement the final API as defined at
 * fsl_cmdif_client.h and fsl_cmdif_server.h. For client and server external use
 * only the API from fsl_cmdif_client.h and fsl_cmdif_server.h.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>

/**
 * The following are the FD fields that are used by CMDIF
 * cmdif_fd.fls, cmdif_fd.frc, cmdif_fd.d_addr, cmdif_fd.d_size
 * should be copied into real FD
 */
struct cmdif_fd {
	/**
	 * FD[FLC] Frame descriptor relevant fields as should be set
	 * by cmdif client side when sending commands to AIOP server
	 */
	union {
		/** Full FLC field */
		uint64_t flc;
		/** FLC field for command after the session is open */
		struct {
			/** Authentication id */
			uint16_t auth_id;
			/** 7 high bits of cmdif_desc.dev */
			uint8_t dev_h;
			/** Reserved for error on response*/
			uint8_t err;
			/** Command id */
			uint16_t cmid;
			/** Reserved fog EPID */
			uint16_t epid;
		} cmd;
		/** FLC field for open command */
		struct {
			/** Authentication id */
			uint16_t auth_id;
			/** Module instance id*/
			uint8_t inst_id;
			uint8_t reserved0;
			/** Command id */
			uint16_t cmid;
			/** Reserved fog EPID */
			uint16_t epid;
		} open;
		/** FLC field for close command */
		struct {
			/** Authentication id */
			uint16_t auth_id;
			uint8_t reserved[2];
			/** Command id */
			uint16_t cmid;
			/** Reserved fog EPID */
			uint16_t epid;
		} close;
		uint32_t word[2];
	} u_flc;

	/**
	 * FD[FRC] Frame descriptor relevant fields as should be set
	 * by cmdif client side when sending commands to AIOP server
	 */
	union  {
		/** Full FRC field */
		uint32_t frc;
		/** FRC field for command after the session is open */
		struct {
			/** 32 low bit of cmdif_desc.dev */
			uint32_t dev_l;
		} cmd;
	} u_frc;

	/** Data length */
	uint32_t d_size;

	/**
	 * FD[ADDR] Frame descriptor relevant field as should be set
	 * by cmdif client side when sending commands to AIOP server
	 */
	union {
		/** Data address */
		uint64_t d_addr;
		uint32_t word[2];
	} u_addr;
};

#ifdef __cplusplus
}
#endif

#endif /* __FSL_CMDIF_FD_H__ */
