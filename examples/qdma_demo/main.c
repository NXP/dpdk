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

#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <fcntl.h>
#include "qdma_demo.h"
#include <fslmc_vfio.h>

static int qdma_dev_id;
static float rate;
static uint64_t freq;
static rte_atomic32_t synchro;
static uint64_t start_cycles, end_cycles;
static uint64_t time_diff;

static rte_atomic32_t dequeue_num;
static rte_atomic32_t dequeue_num_percore[16];

static int g_vqid[RTE_MAX_LCORE];
static char *g_buf;
static char *g_buf1;
static rte_iova_t g_iova;
static rte_iova_t g_iova1;

#define CPU_INFO_FREQ_FILE \
	"/sys/devices/system/cpu/cpufreq/policy0/cpuinfo_max_freq"

#define RTE_LOGTYPE_qdma_demo RTE_LOGTYPE_USER1

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

struct latency {
	double min;
	double max;
	double total;
	int count;
};

static struct latency latency_data[RTE_MAX_LCORE] = {0};

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
static uint8_t *g_pci_vir1;
static uint32_t g_burst = RTE_QDMA_BURST_NB_MAX;
static uint64_t g_pci_iova;
static uint64_t g_pci_iova1;

static uint64_t g_packet_size = 1024;
static uint64_t g_pci_size = TEST_PCI_DEFAULT_SIZE;
static uint32_t g_packet_num = (1 * 1024);
static uint32_t g_latency;
static uint32_t g_memcpy;
static uint32_t g_scatter_gather;

static struct rte_qdma_job *g_jobs[RTE_MAX_LCORE];
static uint8_t quit_signal;
uint32_t core_count;

static int TEST_DMA_INIT_FLAG;

#define START_ADDR(base, num) \
	((uint64_t)base + TEST_PACKET_SIZE * num)

static void *
pci_addr_mmap(void *start, size_t length, int prot,
	int flags, off_t offset)
{
	off_t newoff = 0;
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

	p = mmap(start, length, prot, flags, fd, newoff);
	if (p == MAP_FAILED)
		RTE_LOG(ERR, qdma_demo, "%lX-%lX ERROR\n", newoff, offset);

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

static void calculate_latency(unsigned int lcore_id,
	uint64_t cycle1,
	int pkt_cnt, int pkt_enqueued)
{
	uint64_t cycle2 = 0;
	uint64_t my_time_diff;
	struct latency *core_latency = &latency_data[lcore_id];

	float ns_per_cyc = (float) (1000 * rate) / ((float) freq);
	float time_us = 0.0;

	cycle2 = rte_get_timer_cycles();
	my_time_diff = cycle2 - cycle1;
	time_us = ns_per_cyc *	my_time_diff / 1000;

	if (time_us < core_latency->min)
		core_latency->min = time_us;
	if (time_us > core_latency->max)
		core_latency->max = time_us;
	core_latency->total += time_us;
	core_latency->count++;

	RTE_LOG(INFO, qdma_demo,
		"cpu=%d pkt_cnt:%d [%d], pkt_size %ld\n",
		lcore_id, pkt_cnt, pkt_enqueued,
		TEST_PACKET_SIZE);
	RTE_LOG(INFO, qdma_demo,
		"min %.1f, max %.1f, mean %.1f\n",
		core_latency->min, core_latency->max,
		core_latency->total / core_latency->count);
	rte_delay_ms(1000);
}

#define MAX_SG_JOB_NB_IN_QDMA 512

static int
lcore_qdma_process_loop(__attribute__((unused)) void *arg)
{
	uint32_t lcore_id;
	uint64_t cycle1 = 0;
	uint32_t pkt_cnt = 0;
	int ret = 0;

	uint32_t pkt_enquened = 0;
	int in_dma = 0;
	uint32_t burst_nb = g_scatter_gather ? 32 : g_burst;

	lcore_id = rte_lcore_id();

	/* wait synchro for slaves */
	do {
		ret = rte_atomic32_read(&synchro);
	} while (!ret);
	RTE_LOG(INFO, qdma_demo, "Processing coreid: %d ready, now!\n",
		lcore_id);

	latency_data[lcore_id].min = 9999999.0;
	cycle1 = rte_get_timer_cycles();
	while (!quit_signal) {
		struct rte_qdma_job *job[g_burst];
		struct rte_qdma_job *job1[g_burst];
		struct rte_qdma_enqdeq e_context, de_context;
		int ret, j;
		int job_num = burst_nb;

		if (g_latency) {
			if (pkt_enquened >= TEST_PACKETS_NUM)
				goto dequeue;

			if ((pkt_enquened + g_burst) >= TEST_PACKETS_NUM)
				job_num = TEST_PACKETS_NUM - pkt_enquened;
		}

		if (in_dma > MAX_SG_JOB_NB_IN_QDMA && g_scatter_gather)
			goto dequeue;

		for (j = 0; j < job_num; j++) {
			job[j] = &g_jobs[lcore_id][(pkt_cnt + j) % TEST_PACKETS_NUM];
			job[j]->cnxt = ((pkt_cnt + j) % TEST_PACKETS_NUM);
			if (g_memcpy) {
				rte_memcpy((void *)job[j]->dest,
					(void *)job[j]->src,
					job[j]->len);
				pkt_cnt++;
				if (g_latency && (pkt_cnt >= TEST_PACKETS_NUM)) {
					calculate_latency(lcore_id, cycle1,
						pkt_cnt, pkt_enquened);
					pkt_cnt = 0;
					pkt_enquened = 0;
					cycle1 = rte_get_timer_cycles();
				}
			}
		}
		if (g_memcpy)
			goto performance_statistics;

		e_context.vq_id = g_vqid[lcore_id];
		e_context.job = job;

		/* Submit QDMA Jobs for processing */
		ret = rte_qdma_enqueue_buffers(qdma_dev_id, NULL,
				job_num, &e_context);
		if (unlikely(ret <= 0))
			goto dequeue;
		pkt_enquened += ret;
		in_dma += ret;
dequeue:
		/* Check for QDMA Job completion status */
		do {
			de_context.vq_id = g_vqid[lcore_id];
			de_context.job = job1;
			ret = rte_qdma_dequeue_buffers(qdma_dev_id, NULL,
					g_burst, &de_context);
			if (ret > 0)
				in_dma -= ret;
			for (j = 0; j < ret; j++) {
				if (job1[j]->status) {
					RTE_LOG(ERR, qdma_demo,
						"job[%d] err stat(%d)\n",
						j, job1[j]->status);
					rte_exit(EXIT_FAILURE,
						 "Job Processing Error\n");
				}
				pkt_cnt++;

				if (g_latency && (pkt_cnt >= TEST_PACKETS_NUM)) {
					calculate_latency(lcore_id, cycle1,
						pkt_cnt, pkt_enquened);
					pkt_cnt = 0;
					pkt_enquened = 0;
					cycle1 = rte_get_timer_cycles();
				}
			}
		} while (ret > 0);

performance_statistics:
		if (pkt_cnt > (64 * 1024)) {
			rte_atomic32_add(&dequeue_num, (64 * 1024));
			rte_atomic32_add(&dequeue_num_percore[lcore_id],
				(64 * 1024));
			pkt_cnt = 0;
		}
	}
	RTE_LOG(INFO, qdma_demo, "exit core %d\n", lcore_id);

	return 0;
}

static int
lcore_qdma_control_loop(__attribute__((unused)) void *arg)
{
	uint32_t lcore_id, i, j;
	struct rte_qdma_queue_config q_config;
	float ns_per_cyc = (float) (1000 * rate) / ((float) freq);
	uint64_t cycle1 = 0, cycle2 = 0, total_size;
	float speed;
	int ret, offset, len;
	const struct rte_memzone *mz0, *mz1;
	char src_name[16], dst_name[16];
	char perf_buf[1024];

	lcore_id = rte_lcore_id();
	total_size = TEST_PACKETS_NUM * TEST_PACKET_SIZE;

	/* wait synchro for slaves */
	if (!g_memcpy)
		test_dma_init();
	/* Memory map the PCI addresses */
	if (g_test_path != MEM_TO_MEM) {
		if (g_frame_format == RTE_QDMA_ULTRASHORT_FORMAT) {
			RTE_LOG(ERR, qdma_demo, "Long format only for PCI\n");
			return -EINVAL;
		}
		if (g_pci_size < total_size) {
			RTE_LOG(ERR, qdma_demo,
				"%s: PCI space(%lx) < size(%ld)*(%d)\n",
				g_test_path == MEM_TO_PCI ?
				"MEM2PCI" : "PCI2MEM",
				g_pci_size, TEST_PACKET_SIZE,
				TEST_PACKETS_NUM);
			return -ENOMEM;
		} else if ((g_pci_size / 2) < total_size &&
			g_test_path == PCI_TO_PCI) {
			RTE_LOG(ERR, qdma_demo,
				"%s: PCI space(%lx) < size(%ld)*(%d)\n",
				"PCI2PCI",
				g_pci_size / 2, TEST_PACKET_SIZE,
				TEST_PACKETS_NUM);
			return -ENOMEM;
		}
		g_pci_vir = pci_addr_mmap(NULL, g_pci_size,
					PROT_READ | PROT_WRITE, MAP_SHARED,
					g_pci_phy);
		if (!g_pci_vir) {
			RTE_LOG(ERR, qdma_demo, "Failed to mmap PCI addr %lx\n",
				g_pci_phy);
			return -ENOMEM;
		}
		if (rte_eal_iova_mode() == RTE_IOVA_PA)
			g_pci_iova = g_pci_phy;
		else
			g_pci_iova = (uint64_t)g_pci_vir;
		/* configure pci virtual address in SMMU via VFIO */
		ret = rte_fslmc_vfio_mem_dmamap((uint64_t)g_pci_vir,
			g_pci_iova, g_pci_size);
		if (ret)
			return ret;
		g_pci_vir1 = g_pci_vir + g_pci_size / 2;
		g_pci_iova1 = g_pci_iova + g_pci_size / 2;
		snprintf(src_name, 16, "src_n-%d", 1);
		snprintf(dst_name, 16, "dst_n-%d", 1);
		mz0 = rte_memzone_reserve_aligned(src_name, g_pci_size, 0,
				RTE_MEMZONE_IOVA_CONTIG, 4096);
		if (!mz0) {
			RTE_LOG(ERR, qdma_demo,
				"Memzone %s reserve failed\n",
				src_name);
			return -ENOMEM;
		}
		g_buf = mz0->addr;
		mz1 = rte_memzone_reserve_aligned(dst_name, g_pci_size, 0,
				RTE_MEMZONE_IOVA_CONTIG, 4096);
		if (!mz1) {
			RTE_LOG(ERR, qdma_demo,
				"Memzone %s reserve failed\n",
				dst_name);
			return -ENOMEM;
		}
		g_buf1 = mz1->addr;
		RTE_LOG(INFO, qdma_demo,
			"Local bufs, g_buf %p, g_buf1 %p\n",
			g_buf, g_buf1);
		g_iova = mz0->iova;
		g_iova1 = mz1->iova;
	}

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

	/* Adavance prepare the jobs for the test */
	for (j = 0; j < RTE_MAX_LCORE; j++) {
		if (!rte_lcore_is_enabled(j) || j == rte_get_master_lcore())
			continue;

		if (g_test_path == MEM_TO_MEM) {
			snprintf(src_name, 16, "src_p-%d", j + 1);
			snprintf(dst_name, 16, "dst_p-%d", j + 1);
			mz0 = rte_memzone_reserve_aligned(src_name,
					total_size, 0, RTE_MEMZONE_IOVA_CONTIG,
					4096);
			if (!mz0) {
				RTE_LOG(ERR, qdma_demo,
					"Memzone %s reserve failed\n",
					src_name);
				return -ENOMEM;
			}
			g_buf = mz0->addr;
			mz1 = rte_memzone_reserve_aligned(dst_name,
					total_size, 0, RTE_MEMZONE_IOVA_CONTIG,
					4096);
			if (!mz1) {
				RTE_LOG(ERR, qdma_demo,
					"Memzone %s reserve failed\n",
					dst_name);
				return -ENOMEM;
			}
			g_buf1 = mz1->addr;
			RTE_LOG(INFO, qdma_demo,
				"Local bufs, g_buf %p, g_buf1 %p\n",
				g_buf, g_buf1);
			g_iova = mz0->iova;
			g_iova1 = mz1->iova;
		}

		g_jobs[j] = rte_zmalloc("test qdma",
					  TEST_PACKETS_NUM *
					  sizeof(struct rte_qdma_job), 4096);
		RTE_LOG(INFO, qdma_demo, "[%d] job ptr %p\n", j, g_jobs[j]);

		/* Prepare the QDMA jobs in advance */
		for (i = 0; i < TEST_PACKETS_NUM; i++) {
			struct rte_qdma_job *job = g_jobs[j];

			job += i;
			job->len = TEST_PACKET_SIZE;
			job->cnxt = i;
			memset(g_buf + i * TEST_PACKET_SIZE, i + 1,
				TEST_PACKET_SIZE);
			memset(g_buf1 + i * TEST_PACKET_SIZE, 0xff,
				TEST_PACKET_SIZE);

			if (g_test_path == MEM_TO_PCI) {
				if (g_memcpy) {
					job->src = START_ADDR(g_buf, i);
					job->dest = START_ADDR(g_pci_vir, i);
				} else {
					job->src = START_ADDR(g_iova, i);
					job->dest = START_ADDR(g_pci_iova, i);
				}
			} else if (g_test_path == MEM_TO_MEM) {
				if (g_memcpy) {
					job->src = START_ADDR(g_buf, i);
					job->dest = START_ADDR(g_buf1, i);
				} else {
					job->src = START_ADDR(g_iova, i);
					job->dest = START_ADDR(g_iova1, i);
				}
			} else if (g_test_path == PCI_TO_PCI) {
				if (g_memcpy) {
					job->src = START_ADDR(g_pci_vir, i);
					job->dest = START_ADDR(g_pci_vir1, i);
				} else {
					job->src = START_ADDR(g_pci_iova, i);
					job->dest = START_ADDR(g_pci_iova1, i);
				}
			} else if (g_test_path == PCI_TO_MEM) {
				if (g_memcpy) {
					job->src = START_ADDR(g_pci_vir, i);
					job->dest = START_ADDR(g_buf, i);
				} else {
					job->src = START_ADDR(g_pci_iova, i);
					job->dest = START_ADDR(g_iova, i);
				}
			}
		}
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

		rte_atomic32_clear(&dequeue_num);
		RTE_LCORE_FOREACH_SLAVE(lcore_id) {
			rte_atomic32_clear(&dequeue_num_percore[lcore_id]);
		}
		cycle1 = rte_get_timer_cycles();
		rte_delay_ms(4000);

		if (g_latency)
			goto skip_print;

		cycle2 = rte_get_timer_cycles();
		time_diff = cycle2 - cycle1;
		speed = (float)rte_atomic32_read(&dequeue_num) /
			(ns_per_cyc * time_diff / (1000 * 1000 * 1000));
		speed = speed * TEST_PACKET_SIZE;

		offset = 0;

		len = sprintf(&perf_buf[offset], "Statistics:\n");
		offset += len;

		len = sprintf(&perf_buf[offset],
			"Time Spend :%.3f ms rcvd cnt:%d\n",
			(ns_per_cyc * time_diff) / (1000 * 1000),
			dequeue_num.cnt);
		offset += len;

		len = sprintf(&perf_buf[offset],
			"Rate: %.3f Mbps OR %.3f Kpps\n",
			8 * speed / (1000 * 1000),
			speed / (TEST_PACKET_SIZE * 1000));
		offset += len;

		RTE_LCORE_FOREACH_SLAVE(lcore_id) {
			len = sprintf(&perf_buf[offset],
				"processed on core %d pkt cnt: %d\n",
				lcore_id, dequeue_num_percore[lcore_id].cnt);
			offset += len;
		}
		len = sprintf(&perf_buf[offset], "\n");
		offset += len;
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
	j = sprintf(&buf[pos], "	: --pci_size <bytes>\n");
	pos += j;
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
	case ARG_PCI_SIZE:
		ret = sscanf(optarg, "%lx", &g_pci_size);
		if (ret == EOF) {
			RTE_LOG(ERR, qdma_demo, "Invalid PCI size");
			ret = -EINVAL;
			goto out;
		}
		ret = 0;
		RTE_LOG(INFO, qdma_demo, "PCI size 0x%lx\n", g_pci_size);
		break;
	case ARG_MEMCPY:
		if (g_scatter_gather) {
			RTE_LOG(WARNING, qdma_demo,
				"scatter gather not effective for memcpy\n");
		}
		g_memcpy = 1;
		break;
	case ARG_SCATTER_GATHER:
		g_frame_format = RTE_QDMA_LONG_FORMAT;
		g_scatter_gather = 1;
		if (g_memcpy) {
			RTE_LOG(WARNING, qdma_demo,
				"scatter gather not effective for memcpy\n");
		}
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
	 {"pci_size", optional_argument, &flg, ARG_PCI_SIZE},
	 {"memcpy", optional_argument, &flg, ARG_MEMCPY},
	 {"scatter_gather", optional_argument, &flg, ARG_SCATTER_GATHER},
	 {"burst", optional_argument, &flg, ARG_BURST},
	 {"packet_num", optional_argument, &flg, ARG_NUM},
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
		if (!g_pci_size) {
			RTE_LOG(ERR, qdma_demo,
				"No PCIe size set for %s(%d)!\n",
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
