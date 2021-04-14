/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 * Copyright 2020-2021 NXP
 *
 */
#ifndef __GUL_IPC_IOCTL__
#define __GUL_IPC_IOCTL__

#include <linux/ioctl.h>

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
#define IOCTL_GUL_IPC_CHANNEL_REGISTER		_IOWR(GUL_IPC_MAGIC, 4, struct ipc_msg *)
#define IOCTL_GUL_IPC_CHANNEL_DEREGISTER	_IOWR(GUL_IPC_MAGIC, 5, struct ipc_msg *)
#define IOCTL_GUL_IPC_CHANNEL_RAISE_INTERRUPT   _IOW(GUL_IPC_MAGIC, 6, int *)

typedef struct {
	uint64_t host_phys;
	uint32_t modem_phys;
	uint32_t size;
} mem_strt_addr_t;

typedef struct {
	mem_strt_addr_t		modem_ccsrbar;
	mem_strt_addr_t		tcml_start; /* TCML meta data */
	mem_strt_addr_t		mhif_start; /* MHIF meta daat */
	mem_strt_addr_t		hugepg_start; /* create outbound for Modem to access hugepage */
} sys_map_t;

typedef struct ipc_eventfd {
	uint32_t	efd;
	uint32_t	ipc_channel_num;
	uint32_t	msi_value;
} ipc_eventfd_t;

#endif /*__GUL_IPC_IOCTL__*/
