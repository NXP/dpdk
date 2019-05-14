/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 * Copyright 2014-2015 Freescale Semiconductor Inc.
 * Copyright 2018-2019 NXP
 */

#ifndef __CMDIF_SRV_FLIB_H__
#define __CMDIF_SRV_FLIB_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <fsl_cmdif_server.h>

/* FLC */
#define CMD_ID_MASK	   0x00000000FFFF0000
#define CMD_ID_OFF	   16

/* FLC[hash] */
#define AUTH_ID_MASK	   0xFFFF000000000000
#define AUTH_ID_OFF	   48
/* FLC[hash] */
#define ERROR_MASK	   0x000000FF00000000
#define ERROR_OFF	   32
/* FLC[hash] */
#define DEV_H_MASK	   0x0000FF0000000000
#define DEV_H_OFF	   40
/* FLC[hash] */
#define INST_ID_MASK	   DEV_H_MASK
#define INST_ID_OFF	   DEV_H_OFF

#define CMD_ID_OPEN           0x8000
#define CMD_ID_CLOSE          0x4000
/* Must be power of 2 */
#define M_NUM_OF_INSTANCES    512
#define M_NUM_OF_MODULES      64
#define M_NAME_CHARS          8
/* 1 Byte must be reserved for done bit */
#define SYNC_BUFF_RESERVED    1

/** auth_id that will be sent as hash value for open commands */
#define OPEN_AUTH_ID          0xFFFF
#define CMDIF_SESSION_OPEN_SIZEOF (sizeof(struct cmdif_session_data))

/** Structure to hold CMDIF server info */
struct cmdif_srv {
	/** pointer to arrays of module name per module, DDR */
	char         (*m_name)[M_NAME_CHARS + 1];
	/** open(init) callbacks, one per module, DDR */
	open_cb_t    **open_cb;
	/** close(de-init) callbacks, one per module, DDR*/
	close_cb_t   **close_cb;
	/** execution callbacks one per module, SHRAM */
	ctrl_cb_t    **ctrl_cb;
	/** array of instances handels(converted from the authentication ID)
	 * in the size of M_NUM_OF_INSTANCES, SHRAM
	 */
	void         **inst_dev;
	/** array of physical addresses per instance for setting done
	 * for synchronious commands, SHRAM
	 */
	uint64_t     *sync_done;
	/** converts auth_id to module for cb, SHRAM */
	uint8_t      *m_id;
	/** counter for instance handlers */
	uint16_t     inst_count;
};

/**
 * Structure to hold CMDIF sesstion data
 * Must remain in this order because of client side
 */
struct cmdif_session_data {
	/** Reserved for done on response */
	uint8_t  done;
	/** Reserved for done on response */
	int8_t   err;
	uint16_t auth_id;
	/** CI device id, DPCI id */
	uint32_t dev_id;
	uint8_t  inst_id;
	char     m_name[M_NAME_CHARS + 1];
};

#ifdef __cplusplus
}
#endif

#endif /* __CMDIF_SRV_H__ */
