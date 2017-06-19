/* Copyright (c) 2010-2011 Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Freescale Semiconductor nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
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

#ifndef __DMA_MEM_H
#define __DMA_MEM_H

#include <compat.h>

/* These types are for linux-compatibility, eg. they're used by single-source
 * qbman drivers. Only dma_addr_t is in compat.h, because it is required by
 * fsl_qman.h. The remaining definitions are here because they're only required
 * by the the "dma_mem" driver interface. */
enum dma_data_direction {
	DMA_BIDIRECTIONAL = 0,
	DMA_TO_DEVICE = 1,
	DMA_FROM_DEVICE = 2,
	DMA_NONE = 3,
};

#define DMA_BIT_MASK(n) (((uint64_t)1 << (n)) - 1)
int dma_set_mask(void *dev __always_unused, uint64_t v __always_unused);
dma_addr_t dma_map_single(void *dev __always_unused, void *cpu_addr,
			  size_t size __maybe_unused,
			enum dma_data_direction direction __always_unused);
int dma_mapping_error(void *dev __always_unused,
		      dma_addr_t dma_addr __always_unused);

/* The following definitions and interfaces are USDPAA-specific */

struct dma_mem;

struct dma_mem *dma_mem_map_memzone(void *vaddr, dma_addr_t paddr,
				     size_t len);

/* With the _SHARED flag, <name> can and should be non-NULL, and will name the
 * mapped region so that it may be mapped multiple times (usually from distinct
 * processes). Without _SHARED, <name> should be NULL and a private region will
 * be created (_NEW and _LAZY are not required). */
#define DMA_MAP_FLAG_SHARED 0x01
/* With the _ALLOC flag, an allocator will be implemented for the mapped region
 * allowing dma_mem_memalign() and related APIs to be used. Without _ALLOC, the
 * user owns the entire region and must manage its use via dma_mem_raw(). Note
 * that if _ALLOC and _SHARED are both set, kernel-assisted locking will be used
 * to synchronise (de)allocations across multiple processes, however this will
 * not protect against leaks when processes exit without deallocating buffers
 * from regions that are shared with other processes. */
#define DMA_MAP_FLAG_ALLOC    0x10
/* This flag only makes sense when _SHARED is set. If this _NEW flag is not set,
 * then the named region must already exist. */
#define DMA_MAP_FLAG_NEW      0x02
/* This flag only makes sense when _SHARED and _NEW are set. If this flag is not
 * set, then the named region must not already exist. Conversely, if this flag
 * is set then if the region already exists, it will be mapped anyway as if the
 * _NEW flag hadn't been specified. Ie. multiple processes could use this flag
 * to "lazy-initialise" the memory region. */
#define DMA_MAP_FLAG_LAZY     0x04
/* This flag only makes sense when _SHARED is set and _ALLOC is not set. */
#define DMA_MAP_FLAG_READONLY 0x08
/* See the above flags for semantics. Note that 'map_name' must be shorter than
 * 16 characters in length if it is non-NULL. */
struct dma_mem *dma_mem_create(uint32_t flags, const char *map_name,
			       size_t len);

/* Tears down a map */
void dma_mem_destroy(struct dma_mem *map);

/* Return the params for a given map */
void dma_mem_params(struct dma_mem *map, uint32_t *flags, const char **map_name,
		    size_t *len);

/* This global variable is used by any drivers or application code that need
 * generic memory for DMA. Eg. accelerators use this for allocating DMA-able
 * contexts. The driver defines this variable and it defaults to NULL, so it
 * must be set non-NULL by the application in order to use such drivers. */
extern struct dma_mem *dma_mem_generic;

/* For maps created without _ALLOC, this returns the base address (and if len is
 * non-NULL, also the length) of the mapped memory region. */
void *dma_mem_raw(struct dma_mem *map, size_t *len);

/* For maps created with _ALLOC, memory blocks are (de)allocated. */
void *dma_mem_memalign(struct dma_mem *map, size_t boundary, size_t size);
void dma_mem_free(struct dma_mem *map, void *ptr);

/* Find the map of a given user-virtual ("v") or physical ("p") address. */
struct dma_mem *dma_mem_findv(void *v);
struct dma_mem *dma_mem_findp(dma_addr_t p);

/* Conversion between user-virtual ("v") and physical ("p") address. Note, the
 * __dma_mem_addr structure and cast is respected by the implementation only to
 * allow these ptov/vtop routines to be implemented as inlines (they are
 * performance critical to many scenarios). No other assumptions about the size
 * or layout of the dma_map structure should be assumed. */
struct __dma_mem_addr {
	dma_addr_t phys;
	void *virt;
};

static inline void *dma_mem_ptov(struct dma_mem *map, dma_addr_t p)
{
	struct __dma_mem_addr *a = (struct __dma_mem_addr *)map;

	return (void *)((unsigned long)(p - a->phys) + (unsigned long)a->virt);
}

static inline dma_addr_t dma_mem_vtop(struct dma_mem *map, void *v)
{
	struct __dma_mem_addr *a = (struct __dma_mem_addr *)map;

	return a->phys + ((unsigned long)v - (unsigned long)a->virt);
}

/* Legacy replacements for the old routines that don't take 'map'. These all
 * assume memory is within the 'dma_mem_generic' map. NB, if you want ptov/vtop
 * routines that work for *any* map, then write your own wrapper that calls
 * dma_mem_findp()/dma_mem_findv() to determine the map. These wrappers don't do
 * that because doing so would necessarily be slower whereas vtop/ptov routines
 * are expected to be used in speed-critical code. When converting addresses, it
 * is wise to know in advance within which map they reside. */
static inline void *__dma_mem_ptov(dma_addr_t p)
{
	return dma_mem_ptov(dma_mem_generic, p);
}

static inline dma_addr_t __dma_mem_vtop(void *v)
{
	return dma_mem_vtop(dma_mem_generic, v);
}

static inline void *__dma_mem_memalign(size_t boundary, size_t size)
{
	return dma_mem_memalign(dma_mem_generic, boundary, size);
}

static inline void __dma_mem_free(void *ptr)
{
	return dma_mem_free(dma_mem_generic, ptr);
}

/* Debugging support - dump DMA map details to stdout */
void dma_mem_print(struct dma_mem *map);

/* Queries how much DMA memory has been used */
int dma_mem_query(uint64_t *free_bytes, uint64_t *total_bytes);

#endif	/* __DMA_MEM_H */
