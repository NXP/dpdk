/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018-2023 NXP
 */

/* System headers */
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <stdarg.h>
#include <errno.h>
#include <pthread.h>
#include <getopt.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>

#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memzone.h>

#include <rte_interrupts.h>
#include <rte_pmd_dpaa2_qdma.h>
#include <stdint.h>
#include <sys/queue.h>
#include <rte_launch.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>
#include <rte_cycles.h>
#include <rte_bus_pci.h>
#include <rte_string_fns.h>

#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <dirent.h>
#include "qdma_demo.h"
#include <fslmc_vfio.h>

static int qdma_dev_id;
static float rate;
static uint64_t freq;
static rte_atomic32_t synchro;

static uint64_t g_dq_num[RTE_MAX_LCORE];
static uint64_t g_dq_num_last[RTE_MAX_LCORE];

static int g_vqid[RTE_MAX_LCORE];

#define CPU_INFO_FREQ_FILE \
	"/sys/devices/system/cpu/cpufreq/policy0/cpuinfo_max_freq"

#define RTE_LOGTYPE_qdma_demo RTE_LOGTYPE_USER1

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

struct qdma_demo_latency {
	double min;
	double max;
	double total;
	int count;
};

static struct qdma_demo_latency latency_data[RTE_MAX_LCORE] = {0};

static struct qdma_test_case test_case[] = {
	{"pci_to_pci", "EP mem to EP mem done from host", PCI_TO_PCI},
	{"mem_to_pci", "Host mem to EP mem done from host", MEM_TO_PCI},
	{"pci_to_mem", "EP me to host mem done from host", PCI_TO_MEM},
	{"mem_to_mem", "Host mem to Host mem done, pci_addr not needed",
		MEM_TO_MEM},
};

/*Configurable options*/
static int g_frame_format = RTE_QDMA_LONG_FORMAT;
static int g_test_path = MEM_TO_PCI;
static uint32_t g_arg_mask;
static uint64_t g_pci_phy = RTE_BAD_IOVA;
static uint8_t *g_pci_vir;
static uint32_t g_burst = 32;
static uint64_t g_pci_iova;

static uint64_t g_packet_size = 1024;
static uint64_t g_pci_size = TEST_PCI_DEFAULT_SIZE;
static uint32_t g_packet_num = (1 * 1024);
static uint32_t g_latency;
static uint32_t g_memcpy;
static int g_validate;
static uint32_t g_scatter_gather;

struct qdma_demo_job {
	struct rte_qdma_job job;
	uint64_t vsrc;
	uint64_t vdst;
};

static struct qdma_demo_job *g_jobs[RTE_MAX_LCORE];
static struct rte_ring *g_job_ring[RTE_MAX_LCORE];
static const struct rte_memzone *g_memz_src[RTE_MAX_LCORE];
static const struct rte_memzone *g_memz_dst[RTE_MAX_LCORE];

static uint8_t quit_signal;
uint32_t core_count;

static int TEST_DMA_INIT_FLAG;

#define START_ADDR(base, num) \
	((uint64_t)base + TEST_PACKET_SIZE * num)

struct qdma_demo_pci_bar {
	uint64_t phy_start[PCI_MAX_RESOURCE];
	uint64_t len[PCI_MAX_RESOURCE];
};

#define QDMA_DEMO_MAX_PCI_DEV 64
static struct qdma_demo_pci_bar g_pci_bar[QDMA_DEMO_MAX_PCI_DEV];

static int
qdma_demo_pci_parse_one_sysfs_resource(char *line,
	size_t len, uint64_t *phys_addr,
	uint64_t *end_addr)
{
	char *ptrs[PCI_RESOURCE_FMT_NVAL];
	int ret;

	ret = rte_strsplit(line, len, ptrs, PCI_RESOURCE_FMT_NVAL, ' ');
	if (ret != PCI_RESOURCE_FMT_NVAL) {
		RTE_LOG(ERR, qdma_demo,
			"%s(): bad resource format\n", __func__);
		return -ENOTSUP;
	}

	errno = 0;
	*phys_addr = strtoull(ptrs[0], NULL, 16);
	*end_addr = strtoull(ptrs[1], NULL, 16);
	if (errno != 0) {
		RTE_LOG(ERR, qdma_demo,
			"%s(): bad resource format\n", __func__);
		return -ENOTSUP;
	}

	return 0;
}

static int
qdma_demo_pci_parse_sysfs_resource(const char *filename,
	int dev_idx)
{
	FILE *f;
	char buf[BUFSIZ];
	int i, ret;
	uint64_t phys_addr, end_addr;
	struct qdma_demo_pci_bar *pci_bar;

	if (dev_idx >= QDMA_DEMO_MAX_PCI_DEV) {
		RTE_LOG(ERR, qdma_demo, "Too many PCI devices\n");
		return -ENOTSUP;
	}

	pci_bar = &g_pci_bar[dev_idx];

	f = fopen(filename, "r");
	if (!f) {
		RTE_LOG(ERR, qdma_demo, "Cannot open %s\n", filename);
		return -errno;
	}

	for (i = 0; i < PCI_MAX_RESOURCE; i++) {
		if (!fgets(buf, sizeof(buf), f)) {
			RTE_LOG(ERR, qdma_demo,
				"%s(): cannot read resource\n", __func__);
			fclose(f);
			return -EIO;
		}
		ret = qdma_demo_pci_parse_one_sysfs_resource(buf,
				sizeof(buf), &phys_addr,
				&end_addr);
		if (ret < 0) {
			fclose(f);
			return ret;
		}

		pci_bar->phy_start[i] = phys_addr;
		pci_bar->len[i] = end_addr - phys_addr + 1;
	}

	fclose(f);
	return 0;
}

static int
qdma_demo_pci_scan_one(const char *dirname, int dev_idx)
{
	char filename[PATH_MAX];
	int ret;

	/* parse resources */
	snprintf(filename, sizeof(filename), "%s/resource", dirname);
	ret = qdma_demo_pci_parse_sysfs_resource(filename, dev_idx);
	if (ret) {
		RTE_LOG(ERR, qdma_demo, "%s(): cannot parse resource\n",
			__func__);
		return ret;
	}

	return 0;
}

static int
qdma_demo_pci_scan(void)
{
	struct dirent *e;
	DIR *dir;
	char dirname[PATH_MAX];
	int ret, dev_nb = 0;

	/* for debug purposes, PCI can be disabled */
	if (!rte_eal_has_pci())
		return 0;

	dir = opendir(rte_pci_get_sysfs_path());
	if (!dir) {
		RTE_LOG(ERR, EAL, "%s(): opendir failed: %s\n",
			__func__, strerror(errno));
		return -errno;
	}

	while ((e = readdir(dir)) != NULL) {
		if (e->d_name[0] == '.')
			continue;

		snprintf(dirname, sizeof(dirname), "%s/%s",
			rte_pci_get_sysfs_path(), e->d_name);

		ret = qdma_demo_pci_scan_one(dirname, dev_nb);
		if (ret) {
			closedir(dir);
			return ret;
		}
		dev_nb++;
	}

	closedir(dir);
	return 0;
}

static uint64_t
pci_find_bar_available_size(uint64_t pci_addr)
{
	uint64_t start, end, len;
	int i, j, ret;

	ret = qdma_demo_pci_scan();
	if (ret)
		return 0;

	for (i = 0; i < QDMA_DEMO_MAX_PCI_DEV; i++) {
		for (j = 0; j < PCI_MAX_RESOURCE; j++) {
			start = g_pci_bar[i].phy_start[j];
			len = g_pci_bar[i].len[j];
			end = start + len;
			if (pci_addr >= start && pci_addr < end)
				return len - (pci_addr - start);
		}
	}

	return 0;
}

static void *
pci_addr_mmap(void *start, size_t length, int prot,
	int flags, off_t offset, void **map_addr, int *retfd)
{
	off_t newoff = 0;
	off_t diff = 0;
	off_t mask = PAGE_MASK;
	void *p = NULL;
	int fd = 0;

	fd = open("/dev/mem", O_RDWR|O_SYNC);
	if (fd < 0) {
		RTE_LOG(ERR, qdma_demo,
			"Error in opening /dev/mem(fd=%d)\n", fd);
		return NULL;
	}

	newoff = offset & mask;
	if (newoff != offset)
		diff = offset - newoff;

	p = mmap(start, length, prot, flags, fd, newoff);
	if (p == MAP_FAILED) {
		RTE_LOG(ERR, qdma_demo, "Error in mmap address(%p + %lx)\n",
			start, newoff);
		close(fd);
		return NULL;
	}

	if (map_addr)
		*map_addr = (void *)((uint64_t)p + diff);

	if (retfd)
		*retfd = fd;
	else
		close(fd);

	return p;
}


static int test_dma_init(void)
{
	struct rte_qdma_config qdma_config;
	struct rte_qdma_info dev_conf;
	int ret;

	if (TEST_DMA_INIT_FLAG)
		return 0;

	qdma_config.max_vqs = QDMA_DEMO_MAX_VQS;

	dev_conf.dev_private = &qdma_config;
	ret = rte_qdma_configure(qdma_dev_id, &dev_conf);
	if (ret) {
		RTE_LOG(ERR, qdma_demo, "Failed to configure DMA(%d)\n", ret);
		return ret;
	}

	ret = rte_qdma_start(qdma_dev_id);
	if (ret) {
		RTE_LOG(ERR, qdma_demo, "Failed to start DMA(%d)\n", ret);
		return ret;
	}

	TEST_DMA_INIT_FLAG = 1;

	return 0;
}

static void
calculate_latency(unsigned int lcore_id, uint64_t cycle1,
	int pkt_cnt)
{
	uint64_t cycle2 = 0;
	uint64_t my_time_diff;
	struct qdma_demo_latency *core_latency = &latency_data[lcore_id];

	float ns_per_cyc = (1000 * rate) / freq;
	float time_us = 0.0;

	cycle2 = rte_get_timer_cycles();
	my_time_diff = cycle2 - cycle1;
	time_us = ns_per_cyc * my_time_diff / 1000;

	if (time_us < core_latency->min)
		core_latency->min = time_us;
	if (time_us > core_latency->max)
		core_latency->max = time_us;
	core_latency->total += time_us;
	core_latency->count++;

	RTE_LOG(INFO, qdma_demo,
		"cpu=%d pkt_cnt:%d, pkt_size %ld\n",
		lcore_id, pkt_cnt, TEST_PACKET_SIZE);
	RTE_LOG(INFO, qdma_demo,
		"min %.1f, max %.1f, mean %.1f\n",
		core_latency->min, core_latency->max,
		core_latency->total / core_latency->count);
	rte_delay_ms(1000);
}

static inline void
qdma_demo_validate_set(struct qdma_demo_job *job)
{
	int r_num;
	uint32_t i, j, len;

	if (!g_validate)
		return;

	r_num = rand();
	len = job->job.len;
	for (i = 0; i < len / 4; i++) {
		*((int *)(job->vsrc) + i) = r_num;
		*((int *)(job->vdst) + i) = 0;
	}
	j = 0;
	while ((i * 4 + j) < len) {
		*(uint8_t *)(job->vsrc + i * 4 + j) = r_num;
		*(uint8_t *)(job->vdst + i * 4 + j) = r_num;
		j++;
	}
}

static int
qdma_demo_validate_check(struct qdma_demo_job *job[],
	uint32_t job_num)
{
	int cmp_src, cmp_dst;
	uint32_t i, j, k, len;

	if (!g_validate)
		return 0;

	for (i = 0; i < job_num; i++) {
		len = job[i]->job.len;
		for (j = 0; j < len / 4; j++) {
			cmp_src = *((int *)(job[i]->vsrc) + j);
			cmp_dst = *((int *)(job[i]->vdst) + j);
			if (cmp_src != cmp_dst) {
				RTE_LOG(ERR, qdma_demo,
					"cmp_src(0x%08x) != cmp_dst(0x%08x)\n",
					cmp_src, cmp_dst);
				rte_exit(EXIT_FAILURE, "Validate failed\n");
				return -EINVAL;
			}
		}
		k = 0;
		while ((j * 4 + k) < len) {
			cmp_src = *(uint8_t *)(job[i]->vsrc + j * 4 + k);
			cmp_dst = *(uint8_t *)(job[i]->vdst + j * 4 + k);
			if (cmp_src != cmp_dst) {
				RTE_LOG(ERR, qdma_demo,
					"cmp_src(0x%08x) != cmp_dst(0x%08x)\n",
					cmp_src, cmp_dst);
				rte_exit(EXIT_FAILURE, "Validate failed\n");
				return -EINVAL;
			}
			k++;
		}
	}

	return 0;
}

static int
qdma_demo_memcpy_process(struct qdma_demo_job *job[],
	uint32_t job_num)
{
	uint32_t i, lcore_id, eq_ret;
	uint64_t cycle;
	int ret;

	lcore_id = rte_lcore_id();
	cycle = rte_get_timer_cycles();

	for (i = 0; i < job_num; i++) {
		qdma_demo_validate_set(job[i]);
		rte_memcpy((void *)job[i]->vdst,
			(void *)job[i]->vsrc, job[i]->job.len);
	}
	if (g_latency)
		calculate_latency(lcore_id, cycle, job_num);

	ret = qdma_demo_validate_check(job, job_num);

	eq_ret = rte_ring_enqueue_bulk(g_job_ring[lcore_id],
			(void **)job, job_num, NULL);
	if (job_num != eq_ret) {
		RTE_LOG(ERR, qdma_demo,
			"memcpy job recycle failed\n");
		rte_exit(EXIT_FAILURE,
			"memcpy job recycle failed\n");
		return -EINVAL;
	}
	g_dq_num[lcore_id] += job_num;

	return ret;
}

static int
lcore_qdma_process_loop(__attribute__((unused))void *arg)
{
	uint32_t lcore_id;
	uint64_t cycle1 = 0;
	int ret = 0, first_time = 1, need_eq_again = 0;

	uint32_t dq_num = 0, eq_num = 0;
	uint32_t burst_nb = g_scatter_gather ? 32 : g_burst;
	struct rte_ring *r_recycle;

	lcore_id = rte_lcore_id();

	/* wait synchro for slaves */
	do {
		ret = rte_atomic32_read(&synchro);
	} while (!ret);
	RTE_LOG(INFO, qdma_demo,
		"Processing coreid: %d ready, now!\n",
		lcore_id);
	r_recycle = g_job_ring[lcore_id];

	latency_data[lcore_id].min = 9999999.0;
	while (!quit_signal) {
		struct rte_qdma_job *job[burst_nb];
		struct qdma_demo_job *demo_job[burst_nb];
		struct rte_qdma_enqdeq e_context;
		uint32_t i, job_num, ring_eq;

		burst_nb = g_scatter_gather ? 32 : g_burst;
		if (g_latency)
			cycle1 = rte_get_timer_cycles();
		job_num = rte_ring_dequeue_bulk(r_recycle,
			(void **)demo_job, burst_nb, NULL);
		if (g_memcpy) {
			ret = qdma_demo_memcpy_process(demo_job, job_num);
			if (ret) {
				RTE_LOG(ERR, qdma_demo,
					"memcpy %d jobs failed(%d)\n",
					job_num, ret);
				return ret;
			}
			continue;
		}

		for (i = 0; i < job_num; i++) {
			qdma_demo_validate_set(demo_job[i]);
			job[i] = &demo_job[i]->job;
		}

		eq_num = 0;
		if (!job_num)
			goto skip_eq;

eq_again:
		e_context.vq_id = g_vqid[lcore_id];
		e_context.job = &job[eq_num];
		ret = rte_qdma_enqueue_buffers(qdma_dev_id,
			NULL, job_num - eq_num, &e_context);
		if (ret < 0) {
			RTE_LOG(ERR, qdma_demo,
				"eq dma %d jobs failed(%d)\n",
				job_num - eq_num, ret);
			return -EIO;
		}
		eq_num += ret;
		if (eq_num < job_num) {
			if (need_eq_again)
				goto eq_again;

			ring_eq = rte_ring_enqueue_bulk(r_recycle,
				(void **)&job[eq_num],
				job_num - eq_num, NULL);
			if (ring_eq != (job_num - eq_num)) {
				RTE_LOG(ERR, qdma_demo,
					"recycle %d jobs failed(%d)\n",
					job_num - eq_num, ring_eq);
				return -EIO;
			}

			if (g_latency)
				burst_nb = eq_num;
		} else if (eq_num > job_num) {
			RTE_LOG(ERR, qdma_demo,
				"eq dma %d jobs > (%d)\n",
				eq_num, job_num);
			return -EIO;
		}

skip_eq:
		if (g_scatter_gather)
			burst_nb = RTE_QDMA_SG_ENTRY_NB_MAX;
dequeue:
		e_context.vq_id = g_vqid[lcore_id];
		e_context.job = &job[dq_num];
		ret = rte_qdma_dequeue_buffers(qdma_dev_id, NULL,
				burst_nb - dq_num,
				&e_context);
		if (unlikely(ret < 0)) {
			RTE_LOG(ERR, qdma_demo,
				"dq dma %d jobs failed(%d)\n",
				burst_nb - dq_num, ret);
			return ret;
		}

		dq_num += ret;
		if (g_latency && dq_num < burst_nb)
			goto dequeue;
		for (i = 0; i < dq_num; i++) {
			if (!job[i]) {
				RTE_LOG(ERR, qdma_demo,
					"Invalid job[%d] de-queued\n", i);
				return -EIO;
			}
			demo_job[i] = (void *)job[i];
		}
		ret = qdma_demo_validate_check(demo_job, dq_num);
		if (ret) {
			RTE_LOG(ERR, qdma_demo,
				"Validate check %d jobs failed(%d)\n",
				dq_num, ret);
			return ret;
		}
		if (g_latency) {
			if (!first_time)
				calculate_latency(lcore_id, cycle1, dq_num);
			first_time = 0;
		}

		ring_eq = rte_ring_enqueue_bulk(r_recycle,
			(void **)demo_job, dq_num, NULL);
		if (ring_eq != dq_num) {
			RTE_LOG(ERR, qdma_demo,
				"recycle %d jobs failed(%d)\n",
				dq_num, ring_eq);
			return -EIO;
		}

		g_dq_num[lcore_id] += dq_num;
		dq_num = 0;
	}
	RTE_LOG(INFO, qdma_demo, "exit core %d\n", lcore_id);

	return 0;
}

static int
qdma_demo_jobs_init(struct qdma_demo_job *jobs,
	uint32_t lcore_id, uint32_t idx)
{
	int src_mem = 0, dst_mem = 0;
	char nm[RTE_MEMZONE_NAMESIZE];
	uint64_t total_size = TEST_PACKETS_NUM * TEST_PACKET_SIZE;
	uint32_t i;
	uint64_t src_iova, dst_iova;
	uint64_t src_va, dst_va;

	if (g_test_path == MEM_TO_MEM) {
		src_mem = 1;
		dst_mem = 1;
	} else if (g_test_path == MEM_TO_PCI) {
		src_mem = 1;
		dst_mem = 0;
	} else if (g_test_path == PCI_TO_MEM) {
		src_mem = 0;
		dst_mem = 1;
	} else if (g_test_path == PCI_TO_PCI) {
		src_mem = 0;
		dst_mem = 0;
	}

	if (src_mem) {
		sprintf(nm, "memz-src-%d", lcore_id);
		g_memz_src[lcore_id] = rte_memzone_reserve_aligned(nm,
			total_size, 0,
			RTE_MEMZONE_IOVA_CONTIG, 4096);
		if (!g_memz_src[lcore_id]) {
			RTE_LOG(ERR, qdma_demo,
				"src mem zone created failed on core%d\n",
				lcore_id);
			return -ENOMEM;
		}
		src_iova = g_memz_src[lcore_id]->iova;
		src_va = g_memz_src[lcore_id]->addr_64;
	} else {
		src_iova = g_pci_iova + idx * g_pci_size;
		src_va = (uint64_t)g_pci_vir + idx * g_pci_size;
	}

	if (dst_mem) {
		sprintf(nm, "memz-dst-%d", lcore_id);
		g_memz_dst[lcore_id] = rte_memzone_reserve_aligned(nm,
			total_size, 0,
			RTE_MEMZONE_IOVA_CONTIG, 4096);
		if (!g_memz_dst[lcore_id]) {
			RTE_LOG(ERR, qdma_demo,
				"src mem zone created failed on core%d\n",
				lcore_id);
			return -ENOMEM;
		}
		dst_iova = g_memz_dst[lcore_id]->iova;
		dst_va = g_memz_dst[lcore_id]->addr_64;
	} else {
		dst_iova = g_pci_iova + idx * g_pci_size;
		dst_va = (uint64_t)g_pci_vir + idx * g_pci_size;
	}

	for (i = 0; i < TEST_PACKETS_NUM; i++) {
		jobs[i].job.src = START_ADDR(src_iova, i);
		jobs[i].vsrc = START_ADDR(src_va, i);

		jobs[i].job.dest = START_ADDR(dst_iova, i);
		jobs[i].vdst = START_ADDR(dst_va, i);

		jobs[i].job.len = TEST_PACKET_SIZE;
		jobs[i].job.job_ref = i;
	}

	return 0;
}

static int
qdma_demo_job_ring_init(void)
{
	uint32_t lcore_id, cores = core_count, i, idx = 0;
	uint64_t total_size = TEST_PACKETS_NUM * TEST_PACKET_SIZE;
	char nm[RTE_MEMZONE_NAMESIZE];
	struct qdma_demo_job *job;
	int ret;

	if (g_pci_phy != RTE_BAD_IOVA) {
		g_pci_vir = pci_addr_mmap(NULL, g_pci_size,
			PROT_READ | PROT_WRITE, MAP_SHARED,
			g_pci_phy, NULL, NULL);
		if (!g_pci_vir) {
			RTE_LOG(ERR, qdma_demo,
				"Failed to mmap PCI addr %lx\n",
				g_pci_phy);
			return -ENOMEM;
		}
		if (rte_eal_iova_mode() == RTE_IOVA_PA)
			g_pci_iova = g_pci_phy;
		else
			g_pci_iova = (uint64_t)g_pci_vir;
		/* configure pci virtual address in SMMU via VFIO */
		rte_fslmc_vfio_mem_dmamap((uint64_t)g_pci_vir,
			g_pci_iova, g_pci_size);
	}

	if (g_test_path == PCI_TO_PCI)
		g_pci_size = g_pci_size / 2;
	g_pci_size = g_pci_size / (core_count - 1);
	if (g_test_path != MEM_TO_MEM) {
		while (g_pci_size < total_size)
			g_packet_num = g_packet_num / 2;

		if (g_packet_num < 32) {
			RTE_LOG(ERR, qdma_demo,
				"Too small pci size(%lx)\n",
				g_pci_size);
			return -EINVAL;
		}
	}
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		if (cores == 1)
			break;
		cores--;
		sprintf(nm, "job-ring-%d", lcore_id);
		g_job_ring[lcore_id] = rte_ring_create(nm,
			TEST_PACKETS_NUM * 2, 0, 0);
		if (!g_job_ring[lcore_id]) {
			RTE_LOG(ERR, qdma_demo,
				"job ring created failed on core%d\n",
				lcore_id);
			return -ENOMEM;
		}
		g_jobs[lcore_id] = rte_zmalloc("test qdma",
			TEST_PACKETS_NUM * sizeof(struct qdma_demo_job), 4096);
		if (!g_jobs[lcore_id]) {
			RTE_LOG(ERR, qdma_demo,
				"jobs created failed on core%d\n",
				lcore_id);
			return -ENOMEM;
		}

		ret = qdma_demo_jobs_init(g_jobs[lcore_id], lcore_id, idx);
		if (ret)
			return ret;

		job = g_jobs[lcore_id];
		for (i = 0; i < TEST_PACKETS_NUM; i++) {
			ret = rte_ring_enqueue(g_job_ring[lcore_id], job);
			if (ret) {
				RTE_LOG(ERR, qdma_demo,
					"eq job[%d] failed on core%d, err(%d)\n",
					i, lcore_id, ret);
				return ret;
			}
			job++;
		}

		idx++;
	}

	return 0;
}

static int
lcore_qdma_control_loop(__attribute__((unused))void *arg)
{
	uint32_t lcore_id, i;
	struct rte_qdma_queue_config q_config;
	uint64_t diff;
	float ns_per_cyc = (1000 * rate) / freq;
	uint64_t cycle1 = 0, cycle2 = 0, cycle_diff;
	float speed;
	int ret, offset, log_len;
	char perf_buf[1024];

	lcore_id = rte_lcore_id();

	/* wait synchro for slaves */
	if (!g_memcpy)
		test_dma_init();

	/* setup QDMA queues */
	for (i = 0; (!g_memcpy) && i < RTE_MAX_LCORE; i++) {
		if (!rte_lcore_is_enabled(i))
			continue;

		q_config.lcore_id = i;
		q_config.flags = 0;
		if (g_frame_format == RTE_QDMA_LONG_FORMAT)
			q_config.flags |= RTE_QDMA_VQ_FD_LONG_FORMAT;
		if (g_scatter_gather)
			q_config.flags |= RTE_QDMA_VQ_FD_SG_FORMAT;
		q_config.rbp = NULL;
		q_config.queue_size = TEST_PACKETS_NUM;
		g_vqid[i] = rte_qdma_queue_setup(qdma_dev_id, -1, &q_config);
		RTE_LOG(INFO, qdma_demo, "core id:%d g_vqid[%d]:%d\n",
			i, i, g_vqid[i]);
		if (g_vqid[i] < 0)
			return g_vqid[i];
	}

	ret = qdma_demo_job_ring_init();
	if (ret) {
		RTE_LOG(ERR, qdma_demo, "Failed to init job ring(%d)\n",
			ret);
		return ret;
	}

	RTE_LOG(INFO, qdma_demo,
		"%s to test: packet size %ldB, number %d\n",
		g_frame_format == RTE_QDMA_ULTRASHORT_FORMAT ?
		"Using short format" : "Using long format",
		TEST_PACKET_SIZE, TEST_PACKETS_NUM);

	switch (g_test_path) {
	case PCI_TO_MEM:
		RTE_LOG(INFO, qdma_demo, "PCI_TO_MEM\n");
		break;
	case MEM_TO_PCI:
		RTE_LOG(INFO, qdma_demo, "MEM_TO_PCI\n");
		break;
	case MEM_TO_MEM:
		RTE_LOG(INFO, qdma_demo, "MEM_TO_MEM\n");
		break;
	case PCI_TO_PCI:
		RTE_LOG(INFO, qdma_demo, "PCI_TO_PCI\n");
		break;
	default:
		RTE_LOG(ERR, qdma_demo, "unknown test case(%d)!\n",
			g_test_path);
	}
	RTE_LOG(INFO, qdma_demo, "Master coreid: %d ready, now!\n",
		lcore_id);

	rte_atomic32_set(&synchro, 1);

	while (!quit_signal) {
		cycle1 = rte_get_timer_cycles();
		rte_delay_ms(4000);
		diff = 0;

		if (g_latency)
			goto skip_print;

		cycle2 = rte_get_timer_cycles();
		cycle_diff = cycle2 - cycle1;
		for (i = 0; i < RTE_MAX_LCORE; i++) {
			diff += g_dq_num[i] - g_dq_num_last[i];
			g_dq_num_last[i] = g_dq_num[i];
		}
		speed = (float)diff /
			(ns_per_cyc * cycle_diff / (1000 * 1000 * 1000));
		speed = speed * TEST_PACKET_SIZE;

		offset = 0;

		log_len = sprintf(&perf_buf[offset], "Statistics:\n");
		offset += log_len;

		log_len = sprintf(&perf_buf[offset],
			"Time Spend :%.3f ms rcvd cnt:%ld\n",
			(ns_per_cyc * cycle_diff) / (1000 * 1000),
			diff);
		offset += log_len;

		log_len = sprintf(&perf_buf[offset],
			"Rate: %.3f Mbps OR %.3f Kpps\n",
			8 * speed / (1000 * 1000),
			speed / (TEST_PACKET_SIZE * 1000));
		offset += log_len;

		RTE_LCORE_FOREACH(lcore_id) {
			log_len = sprintf(&perf_buf[offset],
				"processed on core %d pkt cnt: %ld\n",
				lcore_id, g_dq_num[lcore_id]);
			offset += log_len;
		}
		log_len = sprintf(&perf_buf[offset], "\n");
		offset += log_len;
		RTE_LOG(INFO, qdma_demo, "%s", perf_buf);

skip_print:
		cycle1 = cycle2 = 0;
	}
	RTE_LOG(INFO, qdma_demo, "exit core %d\n", rte_lcore_id());

	return 0;
}


/* launch all the per-lcore test, and display the result */
static int
launch_cores(unsigned int cores)
{
	unsigned lcore_id;
	int ret = 0;
	unsigned cores_save = cores;

	rte_atomic32_set(&synchro, 0);

	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		if (cores == 1)
			break;
		cores--;
		rte_eal_remote_launch(lcore_qdma_process_loop, NULL, lcore_id);
	}

	/* start synchro and launch test on master */
	ret = lcore_qdma_control_loop(NULL);
	if (ret < 0)
		return ret;
	cores = cores_save;
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		if (cores == 1)
			break;
		cores--;

		ret = rte_eal_wait_lcore(lcore_id);
		if (ret < 0)
			break;
	}

	if (ret < 0) {
		RTE_LOG(ERR, qdma_demo, "per-lcore test returned(%d)\n", ret);
		return ret;
	}

	return 0;
}

static void
int_handler(int sig_num)
{
	RTE_LOG(INFO, qdma_demo, "Exiting on signal %d\n", sig_num);
	/* set quit flag for rx thread to exit */
	quit_signal = 1;
}

static uint64_t
get_tsc_freq_from_cpuinfo(void)
{
	char line[256];
	FILE *stream;
	double dmhz;

	stream = fopen(CPU_INFO_FREQ_FILE, "r");
	if (!stream) {
		RTE_LOG(WARNING, qdma_demo, "Unable to open %s\n",
			CPU_INFO_FREQ_FILE);
		return 0;
	}

	while (fgets(line, sizeof line, stream)) {
		if (sscanf(line, "%lf", &dmhz) == 1) {
			freq = (uint64_t)(dmhz / 1000);
			break;
		}
	}

	fclose(stream);
	return freq;
}

static void qdma_demo_usage(void)
{
	size_t i;
	char buf[2048];
	int pos = 0, j;

	j = sprintf(&buf[pos],
		"./qdma_demo [EAL options] -- -option --<args>=<value>\n");
	pos += j;
	j = sprintf(&buf[pos], "options	:\n");
	pos += j;
	j = sprintf(&buf[pos], "	: -c <hex core mask>\n");
	pos += j;
	j = sprintf(&buf[pos], "	: -h print usage\n");
	pos += j;
	j = sprintf(&buf[pos], "Args	:\n");
	pos += j;
	j = sprintf(&buf[pos], "	: --pci_addr <target_pci_addr>\n");
	pos += j;
	j = sprintf(&buf[pos], "	: --packet_size <bytes>\n");
	pos += j;
	j = sprintf(&buf[pos], "	: --test_case <test_case_name>\n");
	pos += j;
	for (i = 0; i < ARRAY_SIZE(test_case); i++) {
		j = sprintf(&buf[pos], "		%s - %s\n",
			test_case[i].name, test_case[i].help);
		pos += j;
	}
	j = sprintf(&buf[pos], "	: --latency_test\n");
	pos += j;
	j = sprintf(&buf[pos], "	: --memcpy\n");
	pos += j;
	j = sprintf(&buf[pos], "	: --scatter_gather\n");
	pos += j;
	j = sprintf(&buf[pos], "	: --burst\n");
	pos += j;
	j = sprintf(&buf[pos], "	: --packet_num\n");

	RTE_LOG(WARNING, qdma_demo, "%s", buf);
}

static int
qdma_parse_long_arg(char *optarg, struct option *lopt)
{
	int ret = 0;
	size_t i;

	switch (lopt->val) {
	case ARG_PCI_ADDR:
		ret = sscanf(optarg, "%lx", &g_pci_phy);
		if (ret == EOF) {
			RTE_LOG(ERR, qdma_demo, "Invalid PCI address\n");
			ret = -EINVAL;
			goto out;
		}
		ret = 0;
		RTE_LOG(INFO, qdma_demo, "PCI addr 0x%lx\n", g_pci_phy);
		break;
	case ARG_SIZE:
		ret = sscanf(optarg, "%lu", &g_packet_size);
		if (ret == EOF) {
			RTE_LOG(ERR, qdma_demo, "Invalid Packet size\n");
			ret = -EINVAL;
			goto out;
		}
		ret = 0;
		RTE_LOG(INFO, qdma_demo, "Pkt size %ld\n", g_packet_size);
		break;
	case ARG_TEST_ID:
		for (i = 0; i < ARRAY_SIZE(test_case); i++) {
			ret = strncmp(test_case[i].name, optarg,
				TEST_CASE_NAME_SIZE);
			if (!ret) {
				g_test_path = test_case[i].id;
				break;
			}
		}
		if (i == ARRAY_SIZE(test_case)) {
			RTE_LOG(ERR, qdma_demo, "Invalid test case\n");
			ret = -EINVAL;
			goto out;
		}
		ret = 0;
		RTE_LOG(INFO, qdma_demo, "test case %s\n",
			test_case[i].name);
		break;
	case ARG_LATENCY:
		g_latency = 1;
		break;
	case ARG_MEMCPY:
		g_memcpy = 1;
		break;
	case ARG_SCATTER_GATHER:
		g_frame_format = RTE_QDMA_LONG_FORMAT;
		g_scatter_gather = 1;
		break;
	case ARG_BURST:
		ret = sscanf(optarg, "%u", &g_burst);
		if (ret == EOF) {
			RTE_LOG(ERR, qdma_demo, "Invalid burst size\n");
			ret = -EINVAL;
			goto out;
		}
		ret = 0;
		if (g_burst > RTE_QDMA_BURST_NB_MAX || g_burst < 1)
			g_burst = RTE_QDMA_BURST_NB_MAX;

		RTE_LOG(INFO, qdma_demo, "burst size %u\n", g_burst);
		break;
	case ARG_NUM:
		ret = sscanf(optarg, "%d", &g_packet_num);
		if (ret == EOF) {
			RTE_LOG(ERR, qdma_demo, "Invalid Packet number\n");
			ret = -EINVAL;
			goto out;
		}
		ret = 0;
		RTE_LOG(INFO, qdma_demo, "Pkt num %d\n", g_packet_num);
		break;
	case ARG_VALIDATE:
		g_validate = 1;
		RTE_LOG(INFO, qdma_demo, "Validate data transfer\n");
		break;
	default:
		RTE_LOG(ERR, qdma_demo, "Unknown Argument\n");
		ret = -EINVAL;
		qdma_demo_usage();
		goto out;
	}

	g_arg_mask |= lopt->val;
out:
	return ret;
}

static int
qdma_demo_parse_args(int argc, char **argv)
{
	int opt, ret = 0, flg, option_index;
	struct option lopts[] = {
	 {"pci_addr", optional_argument, &flg, ARG_PCI_ADDR},
	 {"packet_size", optional_argument, &flg, ARG_SIZE},
	 {"test_case", required_argument, &flg, ARG_TEST_ID},
	 {"latency_test", optional_argument, &flg, ARG_LATENCY},
	 {"memcpy", optional_argument, &flg, ARG_MEMCPY},
	 {"scatter_gather", optional_argument, &flg, ARG_SCATTER_GATHER},
	 {"burst", optional_argument, &flg, ARG_BURST},
	 {"packet_num", optional_argument, &flg, ARG_NUM},
	 {"validate", optional_argument, &flg, ARG_VALIDATE},
	 {0, 0, 0, 0},
	};
	struct option *lopt_cur;

	while ((opt = getopt_long(argc, argv, "h;",
			lopts, &option_index)) != EOF) {

		switch (opt) {
		case 'h':
			qdma_demo_usage();
			ret = 1;
			break;
		/* long options */
		case 0:
			lopt_cur = &lopts[option_index];
			ret = qdma_parse_long_arg(optarg, lopt_cur);
			break;
		default:
			qdma_demo_usage();
			ret = -EINVAL;
		}
	}

	return ret;
}

/*Return 0 if arguments are valid, 1 otherwise */
static int qdma_demo_validate_args(void)
{
	int valid = 1;

	if (g_test_path != MEM_TO_MEM)
		valid = !!(g_arg_mask & ARG_PCI_ADDR);

	if (!(g_arg_mask & ARG_SIZE)) {
		RTE_LOG(WARNING, qdma_demo,
			"Using Default packet size %ld bytes\n",
			g_packet_size);
	}

	core_count = rte_lcore_count();
	if (core_count < 2) {
		RTE_LOG(ERR, qdma_demo, "Insufficient cores %d < 2\n",
			core_count);
		valid = 0;
		goto out;
	}
	RTE_LOG(INFO, qdma_demo, "Stats core id - %d\n",
		rte_get_master_lcore());
out:
	return !valid;
}

int
main(int argc, char *argv[])
{
	int ret = 0;
	uint64_t freq;
	float ns_per_cyc;
	uint64_t start_cycles, end_cycles;
	uint64_t time_diff;

	/* catch ctrl-c so we can print on exit */
	signal(SIGINT, int_handler);

	rte_atomic32_init(&synchro);

	/* init EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");

	argc -= ret;
	argv += ret;

	ret = qdma_demo_parse_args(argc, argv);
	if (ret) {
		RTE_LOG(ERR, qdma_demo, "Arg parsing failed\n");
		goto out;
	}
	ret = qdma_demo_validate_args();
	if (ret) {
		RTE_LOG(ERR, qdma_demo, "Arguments are invalid\n");
		qdma_demo_usage();
		goto out;
	}

	if (g_test_path != MEM_TO_MEM) {
		if (g_pci_phy == RTE_BAD_IOVA) {
			RTE_LOG(ERR, qdma_demo,
				"No PCIe address set for %s(%d)!\n",
				g_test_path == MEM_TO_PCI ? "mem2pci" :
				g_test_path == PCI_TO_MEM ? "pci2mem" :
				g_test_path == PCI_TO_PCI ? "pci2pci" :
				"invalid path", g_test_path);

			return 0;
		}
		g_pci_size = pci_find_bar_available_size(g_pci_phy);
		if (!g_pci_size) {
			RTE_LOG(ERR, qdma_demo,
				"PCI address 0x%lx not found for %s(%d)!\n",
				g_pci_phy,
				g_test_path == MEM_TO_PCI ? "mem2pci" :
				g_test_path == PCI_TO_MEM ? "pci2mem" :
				g_test_path == PCI_TO_PCI ? "pci2pci" :
				"invalid path", g_test_path);

			return 0;
		}
		if (g_pci_phy % PAGE_SIZE) {
			RTE_LOG(ERR, qdma_demo,
				"PCI addr(%lx) not multiple of page size\n",
				g_pci_phy);
			return 0;
		}
		if (g_pci_size % PAGE_SIZE) {
			RTE_LOG(ERR, qdma_demo,
				"PCI size(%lx) not multiple of page size\n",
				g_pci_size);
			return 0;
		}
	}

	/*cycle correction */
	freq = get_tsc_freq_from_cpuinfo();

	ns_per_cyc = 1000 / (float)freq;
	start_cycles = rte_get_timer_cycles();
	rte_delay_ms(1000);
	end_cycles = rte_get_timer_cycles();
	time_diff = end_cycles - start_cycles;
	rate = 1000 / ((ns_per_cyc * time_diff) / (1000 * 1000));
	RTE_LOG(INFO, qdma_demo, "Rate:%.5f cpu freq:%ld MHz\n",
		rate, freq);

	start_cycles = rte_get_timer_cycles ();
	rte_delay_ms(2000);
	end_cycles = rte_get_timer_cycles();
	time_diff = end_cycles - start_cycles;

	RTE_LOG(INFO, qdma_demo, "Spend :%.3f ms\n",
		(ns_per_cyc * time_diff * rate) / (1000 * 1000));

	ret = launch_cores(core_count);
	if (ret < 0)
		goto out;
	RTE_LOG(INFO, qdma_demo, "qdma_demo Finished.. bye!\n");
	return 0;
out:
	RTE_LOG(ERR, qdma_demo, "qdma_demo Failed!\n");
	return 0;
}
