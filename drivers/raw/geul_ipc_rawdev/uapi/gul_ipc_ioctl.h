/*
 * @ gul_ipc_ioctl
 *
 * Copyright 2019 NXP
 *
 * Author: Naveen Burmi <naveen.burmi@nxp.com>
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the BSD-3-Clause
 * license mentioned below:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the names of the copyright holders nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 */


#ifndef __GUL_IPC_IOCTL__
#define __GUL_IPC_IOCTL__

#include <linux/ioctl.h>
#include "geul_ipc_errorcodes.h"

#define GUL_IPC_DEVNAME_PREFIX  "gulipc"

enum gul_ipc_flags {
	GUL_IPC_NONBLOCK = 0,
	GUL_IPC_BLOCK,
};

struct ipc_msg {
	int chid;
	void *addr;
	uint32_t len;
	uint8_t flags;
};

#define GUL_IPC_MAGIC	'R'

#define IOCTL_GUL_IPC_GET_SYS_MAP		_IOW(GUL_IPC_MAGIC, 1, struct ipc_msg *)
#define IOCTL_GUL_IPC_REGISTER_SIGNAL	_IOWR(GUL_IPC_MAGIC, 2, struct ipc_msg *)

typedef struct {
        uint64_t host_phys;
        uint32_t modem_phys;
        uint32_t size;
} mem_strt_addr_t;

typedef struct {
        mem_strt_addr_t         modem_ccsrbar;
        mem_strt_addr_t         peb_start; /* PEB meta data */
        mem_strt_addr_t         mhif_start; /* MHIF meta daat */
        mem_strt_addr_t         hugepg_start; /* create outbound for Modem to access hugepage */
} sys_map_t;

#endif /*__GUL_IPC_IOCTL__*/
