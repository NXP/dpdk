/* Copyright (c) 2011 Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *	 notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *	 notice, this list of conditions and the following disclaimer in the
 *	 documentation and/or other materials provided with the distribution.
 *     * Neither the name of Freescale Semiconductor nor the
 *	 names of its contributors may be used to endorse or promote products
 *	 derived from this software without specific prior written permission.
 *
 *
 * ALTERNATIVELY, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") as published by the Free Software
 * Foundation, either version 2 of that License or (at your option) any
 * later version.
 *
 * THIS SOFTWARE IS PROVIDED BY Freescale Semiconductor ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Freescale Semiconductor BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __PROCESS_INTERNAL_H
#define	__PROCESS_INTERNAL_H

/* Some parts of <linux/fsl_usdpaa.h> are duplicated here for use in the
 * driver-internal interface. The other parts (ioctl() specifics) are private to
 * the process driver itself. */

#include <usdpaa/compat.h>
#include <usdpaa/fsl_qman.h>
#include <internal/compat.h>

/******************************/
/* Allocation of resource IDs */
/******************************/

/* Allocation of resource IDs uses a generic interface. This enum is used to
 * distinguish between the type of underlying object being manipulated. */
enum usdpaa_id_type {
	usdpaa_id_fqid,
	usdpaa_id_bpid,
	usdpaa_id_qpool,
	usdpaa_id_cgrid,
	usdpaa_id_ceetm0_lfqid,
	usdpaa_id_ceetm0_channelid,
	usdpaa_id_ceetm1_lfqid,
	usdpaa_id_ceetm1_channelid,
	usdpaa_id_max /* <-- not a valid type, represents the number of types */
};

int process_alloc(enum usdpaa_id_type id_type, uint32_t *base, uint32_t num,
		  uint32_t align, int partial);
void process_release(enum usdpaa_id_type id_type, uint32_t base, uint32_t num);

int process_reserve(enum usdpaa_id_type id_type, uint32_t base, uint32_t num);

/**********************/
/* Mapping DMA memory */
/**********************/

/* Maximum length for a map name, including NULL-terminator */
#define USDPAA_DMA_NAME_MAX 16
/* Flags for requesting DMA maps. Maps are private+unnamed or sharable+named.
 * For a sharable and named map, specify _SHARED (whether creating one or
 * binding to an existing one). If _SHARED is specified and _CREATE is not, then
 * the mapping must already exist. If _SHARED and _CREATE are specified and the
 * mapping doesn't already exist, it will be created. If _SHARED and _CREATE are
 * specified and the mapping already exists, the mapping will fail unless _LAZY
 * is specified. When mapping to a pre-existing sharable map, the length must be
 * an exact match. Lengths must be a power-of-4 multiple of page size.
 *
 * Note that this does not actually map the memory to user-space, that is done
 * by a subsequent mmap() using the page offset returned from this ioctl(). The
 * ioctl() is what gives the process permission to do this, and a page-offset
 * with which to do so.
 */
#define USDPAA_DMA_FLAG_SHARE    0x01
#define USDPAA_DMA_FLAG_CREATE   0x02
#define USDPAA_DMA_FLAG_LAZY     0x04
#define USDPAA_DMA_FLAG_RDONLY   0x08
struct usdpaa_ioctl_dma_map {
	/* Output parameters - virtual and physical addresses */
	void *ptr;
	uint64_t phys_addr;
	/* Input parameter, the length of the region to be created (or if
	 * mapping an existing region, this must match it). Must be a power-of-4
	 * multiple of page size. */
	uint64_t len;
	/* Input parameter, the USDPAA_DMA_FLAG_* settings. */
	uint32_t flags;
	/* If _FLAG_SHARE is specified, the name of the region to be created (or
	 * of the existing mapping to use). */
	char name[USDPAA_DMA_NAME_MAX];
	/* If this ioctl() creates the mapping, this is an input parameter
	 * stating whether the region supports locking. If mapping an existing
	 * region, this is a return value indicating the same thing. */
	int has_locking;
	/* In the case of a successful map with _CREATE and _LAZY, this return
	 * value indicates whether we created the mapped region or whether it
	 * already existed. */
	int did_create;
};

/* Although usdpaa_ioctl_dma_map returns 'pa_offset', this API will also take
 * care of the mmap(), hence the return of 'ptr'. */
int process_dma_map(struct usdpaa_ioctl_dma_map *params);
int process_dma_unmap(void *ptr);

int process_dma_lock(void *ptr);
int process_dma_unlock(void *ptr);

/***************************************/
/* Mapping and using QMan/BMan portals */
/***************************************/
enum usdpaa_portal_type {
	usdpaa_portal_qman,
	usdpaa_portal_bman,
};
struct usdpaa_ioctl_portal_map {
	/* Input parameter, is a qman or bman portal required. */
	enum usdpaa_portal_type type;
	/* Specifes a specific portal index to map or 0xffffffff
	   for don't care */
	uint32_t index;

	/* Return value if the map succeeds, this gives the mapped
	 * cache-inhibited (cinh) and cache-enabled (cena) addresses. */
	struct usdpaa_portal_map {
		void *cinh;
		void *cena;
	} addr;
	/* Qman-specific return values */
	u16 channel;
	uint32_t pools;
};

int process_portal_map(struct usdpaa_ioctl_portal_map *params);
int process_portal_unmap(struct usdpaa_portal_map *map);

struct usdpaa_ioctl_irq_map {
	enum usdpaa_portal_type type; /* Type of portal to map */
	int fd; /* File descriptor that contains the portal */
	void *portal_cinh; /* Cache inhibited area to identify the portal */
};

int process_portal_irq_map(int fd,  struct usdpaa_ioctl_irq_map *irq);
int process_portal_irq_unmap(int fd);

int process_query_dma_mem(uint64_t *free_bytes, uint64_t *total_bytes);


#endif	/*  __PROCESS_INTERNAL_H */
