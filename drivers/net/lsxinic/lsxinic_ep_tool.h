/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2021 NXP
 */

#ifndef _LSXINIC_EP_TOOL_H_
#define _LSXINIC_EP_TOOL_H_

#include <stdbool.h>
#include <rte_common.h>
#include <rte_byteorder.h>
#include <sys/mman.h>
#include <rte_memzone.h>
#include <rte_io.h>

#ifndef DMA_64BIT_MASK
#define DMA_64BIT_MASK  0xffffffffffffffffULL
#endif

#ifndef DMA_32BIT_MASK
#define DMA_32BIT_MASK  0x00000000ffffffffULL
#endif

#define ALIGN(x, a) \
	(((x) + ((typeof(x))(a) - 1)) & \
	~((typeof(x))(a) - 1))

void *
lsinic_byte_memset(void *s, int ch, size_t n);

void *
lsinic_byte_memcpy(void *d, void *s, size_t n);

void *
lsinic_mmap(size_t length, int prot, int flags,
	off_t offset, void **map_addr, int *retfd);
#endif /* _LSXINIC_EP_TOOL_H_ */
