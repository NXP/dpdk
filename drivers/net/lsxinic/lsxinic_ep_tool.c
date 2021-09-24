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

#include "lsxinic_ep_tool.h"

#define PAGE_SIZE   (sysconf(_SC_PAGESIZE))
#define PAGE_MASK   (~(PAGE_SIZE - 1))

void *inic_memset(void *s, int ch, size_t n)
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

void *inic_memcpy(void *d, void *s, size_t n)
{
	size_t i = 0;
	char *ps = s;
	uint64_t dd = (uint64_t)d;
	char *pd = (char *)ALIGN(dd, 4);  /* just for test */

	if (!s || !d)
		return NULL;

	for (i = 0; i < n; i++)
		pd[i] = ps[i];

	return s;
}

void *
lsinic_mmap(void *start, size_t length, int prot, int flags,
	off_t offset, void **map_addr, int *retfd)
{
	off_t newoff = 0;
	off_t diff = 0;
	off_t mask = PAGE_MASK;
	void *p = NULL;
	int fd = 0;

	fd = open("/dev/mem", O_RDWR | O_SYNC);
	if (fd == -1) {
		printf("open \"/dev/mem\" ERROR \n");
		return NULL;
	}

	newoff = offset & mask;
	if (newoff != offset)
		diff = offset - newoff;

	p = mmap(start, length, prot, flags, fd, newoff);
	if (!p) {
		printf("%s %lX-%lX failed.\n", __func__, newoff, offset);
		return NULL;
	}

	if (map_addr)
		*map_addr = (void *)((uint64_t)p + diff);

	if (retfd)
		*retfd = fd;

	return p;
}
