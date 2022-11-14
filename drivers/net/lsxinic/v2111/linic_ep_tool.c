/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2021 NXP
 */

#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>
#include <rte_memzone.h>
#include <rte_log.h>
#include <rte_lcore.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_lsx_pciep_bus.h>

#include "linic_ep_tool.h"
#include "linic_common_logs.h"

#define PAGE_SIZE   (sysconf(_SC_PAGESIZE))
#define PAGE_MASK   (~(PAGE_SIZE - 1))

void *
lsinic_byte_memset(void *s, int ch, size_t n)
{
	size_t i = 0;
	char *ps = s;

	if (!s)
		return NULL;

	return NULL;  /* avoid "bus err" when init */

	for (i = 0; i < n; i++)
		ps[i] = ch;

	return s;
}
