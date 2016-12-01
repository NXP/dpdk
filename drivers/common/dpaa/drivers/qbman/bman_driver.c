/* Copyright (c) 2008-2011 Freescale Semiconductor, Inc.
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

#include <usdpaa/fsl_usd.h>
#include <internal/process.h>
#include "bman_private.h"
#include <sys/ioctl.h>
#include <rte_branch_prediction.h>
/*
 * Global variables of the max portal/pool number this bman version supported
 */
u16 bman_ip_rev;
EXPORT_SYMBOL(bman_ip_rev);
u16 bman_pool_max;
EXPORT_SYMBOL(bman_pool_max);
#ifdef CONFIG_FSL_BMAN_CONFIG
void *bman_ccsr_map;
#endif

/*****************/
/* Portal driver */
/*****************/
static struct bm_portal_config pcfg[QBMAN_MAX_PORTAL];
static __thread struct usdpaa_ioctl_portal_map map = {
	.type = usdpaa_portal_bman
};
static int fd[QBMAN_MAX_PORTAL];

#ifdef CONFIG_FSL_DPA_PORTAL_SHARE
static COMPAT_LIST_HEAD(master_list);
static pthread_mutex_t master_list_lock = PTHREAD_MUTEX_INITIALIZER;

struct bman_master {
	struct list_head node;
	u32 index;
	struct bman_portal *portal;
	unsigned int slave_refs;
};
#endif /* CONFIG_FSL_DPA_PORTAL_SHARE */

static int __init fsl_bman_portal_init(uint32_t index, int is_shared)
{
	cpu_set_t cpuset;
	struct bman_portal *portal;
	int cpu, loop, ret;
	struct usdpaa_ioctl_irq_map irq_map;

#ifdef CONFIG_FSL_DPA_PORTAL_SHARE
	struct bman_master *master;
#endif

	/* Verify the thread's cpu-affinity */
	ret = pthread_getaffinity_np(pthread_self(), sizeof(cpu_set_t),
				     &cpuset);
	if (ret) {
		error(0, ret, "pthread_getaffinity_np()");
		return ret;
	}
	cpu = -1;
	for (loop = 0; loop < CPU_SETSIZE; loop++)
		if (CPU_ISSET(loop, &cpuset)) {
			if (cpu != -1) {
				pr_err("Thread is not affine to 1 cpu\n");
				return -EINVAL;
			}
			cpu = loop;
		}
	if (cpu == -1) {
		pr_err("Bug in getaffinity handling!\n");
		return -EINVAL;
	}
	/* Allocate and map a bman portal */
	map.index = index;

	ret = process_portal_map(&map);
	if (ret) {
		error(0, ret, "process_portal_map()");
		return ret;
	}
	index = map.index;
	/* Make the portal's cache-[enabled|inhibited] regions */
	pcfg[index].public_cfg.cpu = loop;
	pcfg[index].addr_virt[DPA_PORTAL_CE] = map.addr.cena;
	pcfg[index].addr_virt[DPA_PORTAL_CI] = map.addr.cinh;
	pcfg[index].public_cfg.is_shared = is_shared;
	pcfg[index].public_cfg.index = map.index;
	bman_depletion_fill(&pcfg[index].public_cfg.mask);

	if (fd[index] == -1)
		fd[index] = open("/dev/fsl-usdpaa-irq", O_RDONLY);

	if (fd[index] == -1) {
		pr_err("BMan irq init failed\n");
		process_portal_unmap(&map.addr);
		return -EBUSY;
	}
	/* Use the IRQ FD as a unique IRQ number */
	pcfg[index].public_cfg.irq = fd[index];

	portal = bman_create_affine_portal(&pcfg[index]);
	if (!portal) {
		pr_err("Bman portal initialisation failed (%d)\n",
		       pcfg[index].public_cfg.cpu);
		process_portal_unmap(&map.addr);
		return -EBUSY;
	}

#ifdef CONFIG_FSL_DPA_PORTAL_SHARE
	master = calloc(1, sizeof(struct bman_master));
	if (!master) {
		pr_err("Memory allocation failed for bman master\n");
		bman_destroy_affine_portal();
		close(fd[index]);
		process_portal_unmap(&map.addr);
		return -ENOMEM;
	}

	master->portal = portal;
	master->index = bman_get_portal_config()->index;
	master->slave_refs = 0;

	ret = pthread_mutex_lock(&master_list_lock);
	assert(!ret);
	list_add(&master->node, &master_list);
	ret = pthread_mutex_unlock(&master_list_lock);
	assert(!ret);
#endif

	/* Set the IRQ number */
	irq_map.type = usdpaa_portal_bman;
	irq_map.portal_cinh = map.addr.cinh;
	process_portal_irq_map(fd[index], &irq_map);
	return 0;
}

static int fsl_bman_portal_finish(void)
{
	__maybe_unused const struct bm_portal_config *cfg;
	int ret;

#ifdef CONFIG_FSL_DPA_PORTAL_SHARE
	struct bman_master *master;
	__maybe_unused struct bman_portal *redirect = NULL;
	const struct bman_portal_config *portal_cfg;

	portal_cfg = bman_get_portal_config();

	ret = pthread_mutex_lock(&master_list_lock);
	assert(!ret);

	list_for_each_entry(master, &master_list, node) {
		if (master->index == portal_cfg->index) {
			redirect = master->portal;
			break;
		}
	}

	BUG_ON(!redirect);
	if (master->slave_refs) {
		ret = pthread_mutex_unlock(&master_list_lock);
		assert(!ret);
		return -EBUSY;
	}

	list_del(&master->node);
	ret = pthread_mutex_unlock(&master_list_lock);
	assert(!ret);

	free(master);
#endif

	process_portal_irq_unmap(fd[map.index]);

	cfg = bman_destroy_affine_portal();
	BUG_ON(cfg != &pcfg[map.index]);
	ret = process_portal_unmap(&map.addr);
	if (ret)
		error(0, ret, "process_portal_unmap()");
	return ret;
}

int bman_thread_init(void)
{
	/* Convert from contiguous/virtual cpu numbering to real cpu when
	 * calling into the code that is dependent on the device naming */
	return fsl_bman_portal_init(QBMAN_ANY_PORTAL_IDX, 0);
}

int bman_thread_init_idx(uint32_t idx)
{
	/* Convert from contiguous/virtual cpu numbering to real cpu when
	 * calling into the code that is dependent on the device naming */
	return fsl_bman_portal_init(idx, 0);
}

int bman_thread_init_idx_reuse(uint32_t idx)
{
	/* if specific portal, try to unmap it first */
	if (idx != QBMAN_ANY_PORTAL_IDX) {
		int ret;
		struct usdpaa_portal_map bmap;

		bmap.cena = pcfg[idx].addr_virt[DPA_PORTAL_CE];
		bmap.cinh = pcfg[idx].addr_virt[DPA_PORTAL_CI];

		process_portal_irq_unmap(fd[idx]);
		ret = process_portal_unmap(&bmap);
		if (ret)
			error(0, ret, "process_portal_unmap()");
	}

	/* Convert from contiguous/virtual cpu numbering to real cpu when
	 * calling into the code that is dependent on the device naming */
	return fsl_bman_portal_init(idx, 0);
}

int bman_thread_init_shared_idx(uint32_t idx)
{
	/* Convert from contiguous/virtual cpu numbering to real cpu when
	 * calling into the code that is dependent on the device naming */
	return fsl_bman_portal_init(idx, 1);
}

#ifdef CONFIG_FSL_DPA_PORTAL_SHARE

static int fsl_bman_slave_portal_init(const struct bman_portal_config *cfg)
{
	struct bman_portal *redirect = NULL;
	struct bman_master *master;
	struct bman_portal *p;
	int ret;

	ret = pthread_mutex_lock(&master_list_lock);
	assert(!ret);

	list_for_each_entry(master, &master_list, node) {
		if (master->index == cfg->index) {
			redirect = master->portal;
			break;
		}
	}

	if (!redirect) {
		pr_err("Given portal not found in master list: %p\n", cfg);
		ret = pthread_mutex_unlock(&master_list_lock);
		assert(!ret);
		return -ENODEV;
	}

	master->slave_refs++;
	ret = pthread_mutex_unlock(&master_list_lock);
	assert(!ret);

	p = bman_create_affine_slave(redirect);
	if (!p) {
		pr_err("Bman slave init failure for portal: %u\n", cfg->index);
		ret = pthread_mutex_lock(&master_list_lock);
		assert(!ret);
		master->slave_refs--;
		ret = pthread_mutex_unlock(&master_list_lock);
		assert(!ret);
		return -ENODEV;
	}

	return 0;
}

int bman_thread_init_shared(void)
{
	/* Convert from contiguous/virtual cpu numbering to real cpu when
	 * calling into the code that is dependent on the device naming */
	return fsl_bman_portal_init(QBMAN_ANY_PORTAL_IDX, 1);
}

int bman_thread_init_slave(const struct bman_portal_config *cfg)
{
	/* Convert from contiguous/virtual cpu numbering to real cpu when
	 * calling into the code that is dependent on the device naming */
	return fsl_bman_slave_portal_init(cfg);
}

int bman_thread_finish_slave(void)
{
	struct bman_master *master;
	__maybe_unused struct bman_portal *redirect = NULL;
	int ret = 0;
	u32 index = bman_get_portal_config()->index;

	bman_destroy_affine_portal();

	ret = pthread_mutex_lock(&master_list_lock);
	assert(!ret);

	list_for_each_entry(master, &master_list, node) {
		if (master->index == index) {
			redirect = master->portal;
			break;
		}
	}

	BUG_ON(!redirect);
	master->slave_refs--;
	ret = pthread_mutex_unlock(&master_list_lock);
	assert(!ret);

	return ret;
}

#endif /* CONFIG_FSL_DPA_PORTAL_SHARE */

int bman_thread_finish(void)
{
	return fsl_bman_portal_finish();
}

int bman_thread_fd(void)
{
	return fd[map.index];
}

void bman_thread_irq(void)
{
	qbman_invoke_irq(pcfg[map.index].public_cfg.irq);
	/* Now we need to uninhibit interrupts. This is the only code outside
	 * the regular portal driver that manipulates any portal register, so
	 * rather than breaking that encapsulation I am simply hard-coding the
	 * offset to the inhibit register here. */
	out_be32(pcfg[map.index].addr_virt[DPA_PORTAL_CI] + 0xe0c, 0);
}

#ifdef CONFIG_FSL_BMAN_CONFIG
int bman_have_ccsr(void)
{
	if (bman_ccsr_map != NULL)
		return 1;
	else
		return 0;
}

int bman_init_ccsr(const struct device_node *node)
{
	static int ccsr_map_fd;
	uint64_t phys_addr;
	const uint32_t *bman_addr;
	uint64_t regs_size;

	bman_addr = of_get_address(node, 0, &regs_size, NULL);
	if (!bman_addr) {
		pr_err("of_get_address cannot return BMan address\n");
		return -EINVAL;
	}
	phys_addr = of_translate_address(node, bman_addr);
	if (!phys_addr) {
		pr_err("of_translate_address failed\n");
		return -EINVAL;
	}

	ccsr_map_fd = open("/dev/mem", O_RDWR);
	if (unlikely(ccsr_map_fd < 0)) {
		pr_err("Can not open /dev/mem for BMan CCSR map\n");
		return ccsr_map_fd;
	}

	bman_ccsr_map = mmap(NULL, regs_size, PROT_READ | PROT_WRITE, MAP_SHARED,
			     ccsr_map_fd, phys_addr);
	if (bman_ccsr_map == MAP_FAILED) {
		pr_err("Can not map BMan CCSR base Bman: 0x%x Phys: 0x%lx size 0x%lx\n",
		       *bman_addr, phys_addr, regs_size);
		return -EINVAL;
	}

	return 0;
}
#endif

int bman_global_init(void)
{
	const struct device_node *dt_node;
	static int done;
	int i;

	if (done)
		return -EBUSY;
	/* Use the device-tree to determine IP revision until something better
	 * is devised. */
	dt_node = of_find_compatible_node(NULL, NULL, "fsl,bman-portal");
	if (!dt_node) {
		pr_err("No bman portals available for any CPU\n");
		return -ENODEV;
	}
	if (of_device_is_compatible(dt_node, "fsl,bman-portal-1.0") ||
	    of_device_is_compatible(dt_node, "fsl,bman-portal-1.0.0")) {
		bman_ip_rev = BMAN_REV10;
		bman_pool_max = 64;
	} else if (of_device_is_compatible(dt_node, "fsl,bman-portal-2.0") ||
		of_device_is_compatible(dt_node, "fsl,bman-portal-2.0.8")) {
		bman_ip_rev = BMAN_REV20;
		bman_pool_max = 8;
	} else if (of_device_is_compatible(dt_node, "fsl,bman-portal-2.1.0") ||
		of_device_is_compatible(dt_node, "fsl,bman-portal-2.1.1") ||
		of_device_is_compatible(dt_node, "fsl,bman-portal-2.1.2") ||
		of_device_is_compatible(dt_node, "fsl,bman-portal-2.1.3")) {
		bman_ip_rev = BMAN_REV21;
		bman_pool_max = 64;
	} else {
		pr_warn("unknown BMan version in portal node,"
				"default to rev1.0\n");
		bman_ip_rev = BMAN_REV10;
		bman_pool_max = 64;
	}

	if (!bman_ip_rev) {
		pr_err("Unknown bman portal version\n");
		return -ENODEV;
	}
#ifdef CONFIG_FSL_BMAN_CONFIG
	{
		const struct device_node *dn = of_find_compatible_node(NULL,
							NULL, "fsl,bman");
		if (!dn)
			pr_err("No bman device node available\n");

		if (bman_init_ccsr(dn))
			pr_err("BMan CCSR map failed.\n");
	}
#endif
	/* initialize fd with -1 */
	for (i = 0; i < QBMAN_MAX_PORTAL; i++)
		fd[i] = -1;

	done = 1;
	return 0;
}

#ifdef CONFIG_FSL_BMAN_CONFIG
#define BMAN_POOL_CONTENT(n) (0x0600 + ((n) * 0x04))
u32 bm_pool_free_buffers(u32 bpid)
{
	return in_be32(bman_ccsr_map + BMAN_POOL_CONTENT(bpid));
}

static u32 __generate_thresh(u32 val, int roundup)
{
	u32 e = 0;      /* co-efficient, exponent */
	int oddbit = 0;

	while (val > 0xff) {
		oddbit = val & 1;
		val >>= 1;
		e++;
		if (roundup && oddbit)
			val++;
	}
	DPA_ASSERT(e < 0x10);
	return (val | (e << 8));
}

#define POOL_SWDET(n)       (0x0000 + ((n) * 0x04))
#define POOL_HWDET(n)       (0x0100 + ((n) * 0x04))
#define POOL_SWDXT(n)       (0x0200 + ((n) * 0x04))
#define POOL_HWDXT(n)       (0x0300 + ((n) * 0x04))
int bm_pool_set(u32 bpid, const u32 *thresholds)
{
	if (!bman_ccsr_map)
		return -ENODEV;
	if (bpid >= bman_pool_max)
		return -EINVAL;
	out_be32(bman_ccsr_map + POOL_SWDET(bpid),
		 __generate_thresh(thresholds[0], 0));
	out_be32(bman_ccsr_map + POOL_SWDXT(bpid),
		 __generate_thresh(thresholds[1], 1));
	out_be32(bman_ccsr_map + POOL_HWDET(bpid),
		 __generate_thresh(thresholds[2], 0));
	out_be32(bman_ccsr_map + POOL_HWDXT(bpid),
		 __generate_thresh(thresholds[3], 1));
	return 0;
}

#define BMAN_LOW_DEFAULT_THRESH		0x40
#define BMAN_HIGH_DEFAULT_THRESH		0x80
int bm_pool_set_hw_threshold(u32 bpid, const u32 low_thresh, const u32 high_thresh)
{
	if (!bman_ccsr_map)
		return -ENODEV;
	if (bpid >= bman_pool_max)
		return -EINVAL;
	if (low_thresh && high_thresh) {
		out_be32(bman_ccsr_map + POOL_HWDET(bpid),
			 __generate_thresh(low_thresh, 0));
		out_be32(bman_ccsr_map + POOL_HWDXT(bpid),
			 __generate_thresh(high_thresh, 1));
	} else {
		out_be32(bman_ccsr_map + POOL_HWDET(bpid),
			 __generate_thresh(BMAN_LOW_DEFAULT_THRESH, 0));
		out_be32(bman_ccsr_map + POOL_HWDXT(bpid),
			 __generate_thresh(BMAN_HIGH_DEFAULT_THRESH, 1));
	}
	return 0;
}
#endif
