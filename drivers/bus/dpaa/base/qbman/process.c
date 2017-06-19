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

#include <process.h>
#include <internal/conf.h>

#include <sys/ioctl.h>
#include <fsl_usd.h>

/* As higher-level drivers will be built on top of this (dma_mem, qbman, ...),
 * it's preferable that the process driver itself not provide any exported API.
 * As such, combined with the fact that none of these operations are performance
 * critical, it is justified to use lazy initialisation, so that's what the lock
 * is for. */
static int fd = -1;
static pthread_mutex_t fd_init_lock = PTHREAD_MUTEX_INITIALIZER;

static int check_fd(void)
{
	int ret;

	if (fd >= 0)
		return 0;
	ret = pthread_mutex_lock(&fd_init_lock);
	assert(!ret);
	/* check again with the lock held */
	if (fd < 0)
		fd = open(PROCESS_PATH, O_RDWR);
	ret = pthread_mutex_unlock(&fd_init_lock);
	assert(!ret);
	return (fd >= 0) ? 0 : -ENODEV;
}

/* Reproduce the definitions from <linux/fsl_usdpaa.h>. The only definitions
 * missing from here are in <process.h> in order to be available to the
 * inter-driver interface. */

/******************************/
/* Allocation of resource IDs */
/******************************/

#define USDPAA_IOCTL_MAGIC 'u'
struct usdpaa_ioctl_id_alloc {
	uint32_t base; /* Return value, the start of the allocated range */
	enum usdpaa_id_type id_type; /* what kind of resource(s) to allocate */
	uint32_t num; /* how many IDs to allocate (and return value) */
	uint32_t align; /* must be a power of 2, 0 is treated like 1 */
	int partial; /* whether to allow less than 'num' */
};

struct usdpaa_ioctl_id_release {
	/* Input; */
	enum usdpaa_id_type id_type;
	uint32_t base;
	uint32_t num;
};

struct usdpaa_ioctl_id_reserve {
	enum usdpaa_id_type id_type;
	uint32_t base;
	uint32_t num;
};

#define USDPAA_IOCTL_ID_ALLOC \
	_IOWR(USDPAA_IOCTL_MAGIC, 0x01, struct usdpaa_ioctl_id_alloc)
#define USDPAA_IOCTL_ID_RELEASE \
	_IOW(USDPAA_IOCTL_MAGIC, 0x02, struct usdpaa_ioctl_id_release)
#define USDPAA_IOCTL_ID_RESERVE \
	_IOW(USDPAA_IOCTL_MAGIC, 0x0A, struct usdpaa_ioctl_id_reserve)

int process_alloc(enum usdpaa_id_type id_type, uint32_t *base, uint32_t num,
		  uint32_t align, int partial)
{
	struct usdpaa_ioctl_id_alloc id = {
		.id_type = id_type,
		.num = num,
		.align = align,
		.partial = partial
	};
	int ret = check_fd();

	if (ret)
		return ret;
	ret = ioctl(fd, USDPAA_IOCTL_ID_ALLOC, &id);
	if (ret)
		return ret;
	for (ret = 0; ret < (int)id.num; ret++)
		base[ret] = id.base + ret;
	return id.num;
}

void process_release(enum usdpaa_id_type id_type, uint32_t base, uint32_t num)
{
	struct usdpaa_ioctl_id_release id = {
		.id_type = id_type,
		.base = base,
		.num = num
	};
	int ret = check_fd();

	if (ret) {
		fprintf(stderr, "Process FD failure\n");
		return;
	}
	ret = ioctl(fd, USDPAA_IOCTL_ID_RELEASE, &id);
	if (ret)
		fprintf(stderr, "Process FD ioctl failure type %d"
			" base 0x%x num %d\n", id_type, base, num);
}

int process_reserve(enum usdpaa_id_type id_type, uint32_t base, uint32_t num)
{
	struct usdpaa_ioctl_id_reserve id = {
		.id_type = id_type,
		.base = base,
		.num = num
	};
	int ret = check_fd();

	if (ret)
		return ret;
	return ioctl(fd, USDPAA_IOCTL_ID_RESERVE, &id);
}

/**********************/
/* Mapping DMA memory */
/**********************/

#define USDPAA_IOCTL_DMA_MAP \
	_IOWR(USDPAA_IOCTL_MAGIC, 0x03, struct usdpaa_ioctl_dma_map)
/* munmap() does not remove the DMA map, just the user-space mapping to it.
 * This ioctl will do both (though you can munmap() before calling the ioctl
 * too). */
#define USDPAA_IOCTL_DMA_UNMAP \
	_IOW(USDPAA_IOCTL_MAGIC, 0x04, unsigned char)
/* We implement a cross-process locking scheme per DMA map. Call this ioctl()
 * with a mmap()'d address, and the process will (interruptible) sleep if the
 * lock is already held by another process. Process destruction will
 * automatically clean up any held locks. */
#define USDPAA_IOCTL_DMA_LOCK \
	_IOW(USDPAA_IOCTL_MAGIC, 0x05, unsigned char)
#define USDPAA_IOCTL_DMA_UNLOCK \
	_IOW(USDPAA_IOCTL_MAGIC, 0x06, unsigned char)

int process_dma_map(struct usdpaa_ioctl_dma_map *params)
{
	int ret = check_fd();

	if (ret)
		return ret;

	ret = ioctl(fd, USDPAA_IOCTL_DMA_MAP, params);
	if (ret) {
		perror("ioctl(USDPAA_IOCTL_DMA_MAP)");
		return ret;
	}
	return 0;
}

int process_dma_unmap(void *ptr)
{
	int ret = check_fd();

	if (ret)
		return ret;

	ret = ioctl(fd, USDPAA_IOCTL_DMA_UNMAP, ptr);
	if (ret) {
		perror("ioctl(USDPAA_IOCTL_DMA_UNMAP)");
		return ret;
	}
	return 0;
}

int process_dma_lock(void *ptr)
{
	int ret = check_fd();

	if (ret)
		return ret;

	ret = ioctl(fd, USDPAA_IOCTL_DMA_LOCK, ptr);
	if (ret)
		perror("ioctl(USDPAA_IOCTL_DMA_LOCK)");
	return ret;
}

int process_dma_unlock(void *ptr)
{
	int ret = check_fd();

	if (ret)
		return ret;

	ret = ioctl(fd, USDPAA_IOCTL_DMA_UNLOCK, ptr);
	if (ret)
		perror("ioctl(USDPAA_IOCTL_DMA_UNLOCK)");
	return ret;
}

/***************************************/
/* Mapping and using QMan/BMan portals */
/***************************************/

#define USDPAA_IOCTL_PORTAL_MAP \
	_IOWR(USDPAA_IOCTL_MAGIC, 0x07, struct usdpaa_ioctl_portal_map)
#define USDPAA_IOCTL_PORTAL_UNMAP \
	_IOW(USDPAA_IOCTL_MAGIC, 0x08, struct usdpaa_portal_map)

int process_portal_map(struct usdpaa_ioctl_portal_map *params)
{
	int ret = check_fd();

	if (ret)
		return ret;

	ret = ioctl(fd, USDPAA_IOCTL_PORTAL_MAP, params);
	if (ret) {
		perror("ioctl(USDPAA_IOCTL_PORTAL_MAP)");
		return ret;
	}
	return 0;
}

int process_portal_unmap(struct usdpaa_portal_map *map)
{
	int ret = check_fd();

	if (ret)
		return ret;

	ret = ioctl(fd, USDPAA_IOCTL_PORTAL_UNMAP, map);
	if (ret) {
		perror("ioctl(USDPAA_IOCTL_PORTAL_UNMAP)");
		return ret;
	}
	return 0;
}

#define USDPAA_IOCTL_PORTAL_IRQ_MAP \
	_IOW(USDPAA_IOCTL_MAGIC, 0x09, struct usdpaa_ioctl_irq_map)

int process_portal_irq_map(int ifd, struct usdpaa_ioctl_irq_map *map)
{
	map->fd = fd;
	return ioctl(ifd, USDPAA_IOCTL_PORTAL_IRQ_MAP, map);
}

int process_portal_irq_unmap(int ifd)
{
	return close(ifd);
}

/* ioctl to query the amount of DMA memory used in the system */
struct usdpaa_ioctl_dma_used {
	uint64_t free_bytes;
	uint64_t total_bytes;
};

#define USDPAA_IOCTL_DMA_USED \
	_IOR(USDPAA_IOCTL_MAGIC, 0x0B, struct usdpaa_ioctl_dma_used)

int process_query_dma_mem(uint64_t *free_bytes, uint64_t *total_bytes)
{
	struct usdpaa_ioctl_dma_used result;
	int ret;

	ret = ioctl(fd, USDPAA_IOCTL_DMA_USED, &result);
	if (ret) {
		perror("ioctl(USDPAA_IOCTL_DMA_USED)");
		return ret;
	}
	if (free_bytes)
		*free_bytes = result.free_bytes;
	if (total_bytes)
		*total_bytes = result.total_bytes;
	return 0;
}

struct usdpaa_ioctl_raw_portal {
	/* inputs */
	enum usdpaa_portal_type type; /* Type of portal to allocate */

	uint8_t enable_stash; /* set to non zero to turn on stashing */
	/* Stashing attributes for the portal */
	uint32_t cpu;
	uint32_t cache;
	uint32_t window;
	/* Specifies the stash request queue this portal should use */
	uint8_t sdest;

	/* Specifes a specific portal index to map or QBMAN_ANY_PORTAL_IDX
	   for don't care.  The portal index will be populated by the
	   driver when the ioctl() successfully completes */
	uint32_t index;

	/* outputs */
	uint64_t cinh;
	uint64_t cena;
};

#define USDPAA_IOCTL_ALLOC_RAW_PORTAL \
	_IOWR(USDPAA_IOCTL_MAGIC, 0x0C, struct usdpaa_ioctl_raw_portal)

#define USDPAA_IOCTL_FREE_RAW_PORTAL \
	_IOR(USDPAA_IOCTL_MAGIC, 0x0D, struct usdpaa_ioctl_raw_portal)

static int process_portal_allocate(struct usdpaa_ioctl_raw_portal *portal)
{
	int ret = check_fd();

	if (ret)
		return ret;

	ret = ioctl(fd, USDPAA_IOCTL_ALLOC_RAW_PORTAL, portal);
	if (ret) {
		perror("ioctl(USDPAA_IOCTL_ALLOC_RAW_PORTAL)");
		return ret;
	}
	return 0;
}

static int process_portal_free(struct usdpaa_ioctl_raw_portal *portal)
{
	int ret = check_fd();

	if (ret)
		return ret;

	ret = ioctl(fd, USDPAA_IOCTL_FREE_RAW_PORTAL, portal);
	if (ret) {
		perror("ioctl(USDPAA_IOCTL_FREE_RAW_PORTAL)");
		return ret;
	}
	return 0;
}

int qman_allocate_raw_portal(struct usdpaa_raw_portal *portal)
{
	struct usdpaa_ioctl_raw_portal input;
	int ret;

	input.type = usdpaa_portal_qman;
	input.index = portal->index;
	input.enable_stash = portal->enable_stash;
	input.cpu = portal->cpu;
	input.cache = portal->cache;
	input.window = portal->window;
	input.sdest = portal->sdest;

	ret =  process_portal_allocate(&input);
	if (ret)
		return ret;
	portal->index = input.index;
	portal->cinh = input.cinh;
	portal->cena  = input.cena;
	return 0;
}

int qman_free_raw_portal(struct usdpaa_raw_portal *portal)
{
	struct usdpaa_ioctl_raw_portal input;

	input.type = usdpaa_portal_qman;
	input.index = portal->index;
	input.cinh = portal->cinh;
	input.cena = portal->cena;

	return process_portal_free(&input);
}

int bman_allocate_raw_portal(struct usdpaa_raw_portal *portal)
{
	struct usdpaa_ioctl_raw_portal input;
	int ret;

	input.type = usdpaa_portal_bman;
	input.index = portal->index;
	input.enable_stash = 0;

	ret =  process_portal_allocate(&input);
	if (ret)
		return ret;
	portal->index = input.index;
	portal->cinh = input.cinh;
	portal->cena  = input.cena;
	return 0;
}

int bman_free_raw_portal(struct usdpaa_raw_portal *portal)
{
	struct usdpaa_ioctl_raw_portal input;

	input.type = usdpaa_portal_bman;
	input.index = portal->index;
	input.cinh = portal->cinh;
	input.cena = portal->cena;

	return process_portal_free(&input);
}
