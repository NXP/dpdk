/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 NXP
 */

#ifndef __BBDEV_LA12XX_H__
#define __BBDEV_LA12XX_H__

/* private data structure */
struct bbdev_la12xx_private {
	ipc_userspace_t *ipc_priv;
};

struct hugepage_info {
	void *vaddr;
	phys_addr_t paddr;
	size_t len;
};

#endif
