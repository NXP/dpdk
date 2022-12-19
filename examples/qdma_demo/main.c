/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018-2022 NXP
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
#include <rte_dmadev.h>
#include <rte_dmadev_pmd.h>

#include <rte_interrupts.h>
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

#include <rte_pmd_dpaa2_qdma.h>
#include "qdma_demo.h"

static int qdma_dev_id[RTE_MAX_LCORE];
float rate;
uint64_t freq;
static rte_atomic32_t synchro;
uint64_t start_cycles, end_cycles;
uint64_t time_diff;
extern int rte_fslmc_vfio_mem_dmamap(uint64_t vaddr,
	uint64_t iova, uint64_t size);

#ifndef RTE_LIBRTE_DPAA2_USE_PHYS_IOVA
extern uint32_t dpaa2_svr_family;
#ifndef SVR_LX2160A
#define SVR_LX2160A    0x87360000
#endif
#endif

#if !TEST_PCIE_32B_WR
static rte_atomic32_t dequeue_num;
static rte_atomic32_t dequeue_num_percore[16];
#endif
static int g_vqid[RTE_MAX_LCORE];
static char *g_buf;
static char *g_buf1;
static rte_iova_t g_iova;
static rte_iova_t g_iova1;
static uint16_t num_dma_devs;

struct latency {
	double min;
	double max;
	double total;
	int count;
};
static struct latency latency_data[RTE_MAX_LCORE] = {0};

struct addr_t {
	uint64_t *src;
	uint64_t *dest;
};

static struct qdma_test_case test_case[] = {
	{"mem_to_mem", "Host mem to Host mem done, pci_addr not needed",
		 MEM_TO_MEM},
	{"mem_to_pci", "Host mem to EP mem done from host", MEM_TO_PCI},
	{"pci_to_mem", "EP me to host mem done from host", PCI_TO_MEM},
	{"pci_to_pci", "EP mem to EP mem done from host", PCI_TO_PCI},
};
static int test_case_array_size = sizeof(test_case) / sizeof(test_case[0]);

/*Configurable options*/
static int g_frame_format = LONG_FMT;
static int g_userbp = NO_RBP;
static int g_rbp_testcase = MEM_TO_PCI;
static uint32_t g_arg_mask;
static uint64_t g_target_pci_addr = TEST_PCICPU_BASE_ADDR;
static uint32_t g_burst = BURST_NB_MAX;
static uint64_t g_target_pci_iova;
static uint64_t g_target_pci_vaddr;
static int g_packet_size = 1024;
static uint64_t g_pci_size = TEST_PCI_SIZE_LIMIT;
static int g_packet_num = (1 * 1024);
static int g_latency;
static int g_validate;
static int g_memcpy;
static int g_scatter_gather;

static struct dma_job *g_jobs[RTE_MAX_LCORE];
static volatile uint8_t quit_signal;
#if TEST_PCIE_32B_WR
static int32_t total_cores;
#endif
static unsigned int core_count, stats_core_id;

static int TEST_DMA_INIT_FLAG;

static int
test_dma_init(void)
{
	struct rte_dma_conf dma_config;
	struct rte_dma_info dma_info;
	int ret, i;

	if (TEST_DMA_INIT_FLAG)
		return 0;

	num_dma_devs = rte_dma_count_avail();

	if (num_dma_devs >= RTE_MAX_LCORE) {
		for (i = 0; i < RTE_MAX_LCORE; i++) {
			qdma_dev_id[i] = i;
			g_vqid[i] = 0;
			ret = rte_dma_info_get(qdma_dev_id[i], &dma_info);
			if (ret) {
				RTE_LOG(ERR, PMD, "Failed to get DMA info\n");
				return -EINVAL;
			}
			dma_config.nb_vchans = 1;
			dma_config.enable_silent = 0;

			ret = rte_dma_configure(qdma_dev_id[i], &dma_config);
			if (ret) {
				RTE_LOG(ERR, PMD, "Failed to configure DMA\n");
				return -EINVAL;
			}
		}
	} else {
		for (i = 0; i < RTE_MAX_LCORE; i++) {
			qdma_dev_id[i] = 0;
			g_vqid[i] = i;
		}

		ret = rte_dma_info_get(qdma_dev_id[0], &dma_info);
		if (ret) {
			RTE_LOG(ERR, PMD, "Failed to get DMA info\n");
			return -EINVAL;
		}
		dma_config.nb_vchans = dma_info.max_vchans;
		dma_config.enable_silent = 0;

		ret = rte_dma_configure(qdma_dev_id[0], &dma_config);
		if (ret) {
			RTE_LOG(ERR, PMD, "Failed to configure DMA\n");
			return -EINVAL;
		}
	}

	TEST_DMA_INIT_FLAG = 1;

	return 0;
}
static void *pci_addr_mmap(void *start, size_t length, int prot,
		int flags, off_t offset, void **map_addr,
		int *retfd)
{
	off_t newoff = 0;
	off_t diff = 0;
	off_t mask = PAGE_MASK;
	void *p = NULL;
	int fd = 0;

	fd = open("/dev/mem", O_RDWR|O_SYNC);
	if (fd == -1) {
		printf("Error in opening /dev/mem\n");
		return NULL;
	}

	newoff = offset & mask;
	if (newoff != offset)
		diff = offset - newoff;

	p = mmap(start, length, prot, flags, fd, newoff);
	if (p == NULL) {
		printf("%s %lX-%lX ERROR\n", __func__, newoff, offset);
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

#if TEST_PCIE_32B_WR
static int
lcore_qdma_pcie32b_loop(__attribute__((unused)) void *arg)
{
	unsigned int lcore_id;
	size_t len;
	int32_t ret = 0;
	float time_us = 0.0;
	int fd;
	void *tmp;
	uint64_t start;
	volatile uint64_t value = 0x1234567890abcdef;
	volatile uint32_t value32 = 0x12345678;

	lcore_id = rte_lcore_id();

	total_cores++;

	fd = open("/dev/mem", O_RDWR);
	if (fd < 0) {
		RTE_LOG(ERR, PMD, "Fail to open /dev/mem\n");
		return 0;
	}
	start = g_target_pci_addr;
	len = g_pci_size;
	tmp = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, start);
	printf("PCI addr %lx, virt %p\n", start, tmp);
	if (lcore_id != rte_get_main_lcore())
		do {
			ret = rte_atomic32_read(&synchro);
		} while (!ret);
	else
		start_cycles = end_cycles = 0;

	rte_atomic32_set(&synchro, 1);

	if (lcore_id == rte_get_main_lcore())
		start_cycles = rte_get_timer_cycles();

	if (!quit_signal) {
		if (TEST_PCIE_32B) {
		  for (int i = 0; i < TEST_PCIE_READ_TIMES; i++) {
		      if (TEST_PCIE_READ)
			value32 = *((uint32_t *) ((uint64_t) tmp));
		      else
			*((uint32_t *) ((uint64_t) tmp + (i % g_pci_size))) =
			  value32;
		    }
		} else {
		  for (int i = 0; i < TEST_PCIE_READ_TIMES; i++) {
		      if (TEST_PCIE_READ)
			value =
			  *((uint64_t *) ((uint64_t) tmp + (16 * i) % TEST_M_SIZE));
		      else
			*((uint64_t *) ((uint64_t) tmp + (16 * i) % TEST_M_SIZE)) =
			  value;
		    }
		}
	}
	close(fd);

	return 0;
}

/* launch all the per-lcore test, and display the result */
static int
launch_pcie32b_cores(unsigned int cores)
{
	unsigned int lcore_id;
	int ret;
	unsigned int cores_save = cores;

	rte_atomic32_set(&synchro, 0);

	RTE_LCORE_FOREACH_WORKER(lcore_id)
	{
		if (cores == 1)
			break;
		cores--;
		rte_eal_remote_launch(lcore_qdma_pcie32b_loop, NULL, lcore_id);
	}

	/* start synchro and launch test on master */
	ret = lcore_qdma_pcie32b_loop(NULL);
	cores = cores_save;
	RTE_LCORE_FOREACH_WORKER(lcore_id)
	{
		if (cores == 1)
			break;
		cores--;

		if (rte_eal_wait_lcore(lcore_id) < 0)
			ret = -1;
	}

	if (ret < 0) {
		printf("per-lcore test returned -1\n");
		return -1;
	}

	float nsPerCycle = (float)(1000 * rate) / ((float)freq);
	float speed;

	end_cycles = rte_get_timer_cycles();
	time_diff = end_cycles - start_cycles;

	speed =
	(float)(total_cores * TEST_PCIE_READ_TIMES) / (float)(nsPerCycle *
							    time_diff /
							    (float)(1000 *
								     1000 *
								     1000));
	if (TEST_PCIE_READ)
		printf("TEST PCIE Read - ");
	else
		printf("TEST PCIE Write- ");
	if (TEST_PCIE_32B)
		printf("%d cores Spend : %.3f ms speed: %.3f M%ldbytes-ps %.3f Mbps\n",
	    total_cores,
	    (float)(nsPerCycle * time_diff) / (float)(1000 * 1000),
	    speed / ((float)(1000 * 1000)), sizeof(uint32_t),
	    (speed * 32) / ((float)(1000 * 1000)));
	else
		printf("%d cores Spend : %.3f ms speed: %.3f M%ldbytes-ps %.3f Mbps\n",
	    total_cores,
	    (float)(nsPerCycle * time_diff) / (float)(1000 * 1000),
	    speed / ((float)(1000 * 1000)), sizeof(uint64_t),
	    (speed * 64) / ((float)(1000 * 1000)));

	return 0;
}
#endif

static void calculate_latency(unsigned int lcore_id,
	uint64_t cycle1,
	int pkt_cnt, int pkt_enqueued,
	int poll_miss)
{
	uint64_t cycle2 = 0;
	uint64_t my_time_diff;

	float nsPerCycle = (float) (1000 * rate) / ((float) freq);
	float time_us = 0.0;

	cycle2 = rte_get_timer_cycles();
	my_time_diff = cycle2 - cycle1;
	time_us = nsPerCycle *	my_time_diff / 1000;

	if (time_us < latency_data[lcore_id].min)
		latency_data[lcore_id].min = time_us;
	if (time_us > latency_data[lcore_id].max)
		latency_data[lcore_id].max = time_us;
	latency_data[lcore_id].total += time_us;
	latency_data[lcore_id].count++;

	printf("cpu=%d pkt_cnt:%d [%d], pkt_size %d,"
		"time used (%.1f)us [min %.1f, max %.1f"
		", mean %.1f] poll_miss:%d\n",
		lcore_id, pkt_cnt, pkt_enqueued,
		TEST_PACKET_SIZE, time_us,
		latency_data[lcore_id].min, latency_data[lcore_id].max,
		latency_data[lcore_id].total/latency_data[lcore_id].count, poll_miss);
	rte_delay_ms(1000);
}

static struct addr_t qdma_mem_iova2virt(uint64_t src, uint64_t dest)
{
	uint64_t off_s, off_d;
	struct addr_t addr = {0};

	switch (g_rbp_testcase) {
	case PCI_TO_MEM:
		off_s = src - g_target_pci_iova;
		addr.src = (uint64_t *) (g_target_pci_vaddr + off_s);
		addr.dest = rte_mem_iova2virt(dest);
		break;
	case MEM_TO_PCI:
		off_d = dest - g_target_pci_iova;
		addr.src = rte_mem_iova2virt(src);
		addr.dest = (uint64_t *) (g_target_pci_vaddr + off_d);
		break;
	case MEM_TO_MEM:
		addr.src = rte_mem_iova2virt(src);
		addr.dest = rte_mem_iova2virt(dest);
		break;
	case PCI_TO_PCI:
		off_s = src - g_target_pci_iova;
		off_d = dest - g_target_pci_iova;
		addr.src = (uint64_t *) (g_target_pci_vaddr + off_s);
		addr.dest = (uint64_t *) (g_target_pci_vaddr + off_d);
		break;
	}
	return addr;
}

#define MAX_SG_JOB_NB_IN_QDMA 512

static int
lcore_qdma_process_loop(__attribute__((unused)) void *arg)
{
	unsigned int lcore_id;
	uint64_t cycle1 = 0;
	int pkt_cnt = 0;
	int poll_miss = 0;
	int32_t ret = 0;
	int err;

	int pkt_enquened = 0;
	int in_dma = 0;
	int burst_nb = g_scatter_gather ? 32 : g_burst;

	lcore_id = rte_lcore_id();

	/* wait synchro for slaves */
	do {
		ret = rte_atomic32_read(&synchro);
	} while (!ret);
	printf("Processing coreid: %d ready, now!\n", lcore_id);

	latency_data[lcore_id].min = 9999999.0;
	cycle1 = rte_get_timer_cycles();
	while (!quit_signal) {
		struct dma_job *job[g_burst];
		struct rte_dma_sge src_sge[g_burst];
		struct rte_dma_sge dst_sge[g_burst];
		struct addr_t addr;
		int ret, j;
		int job_num = burst_nb;
		uint64_t *src1, *dest1;
		uint8_t r_num;
		uint32_t k;
		bool error;

		if (num_dma_devs == 1)
			job_num = 1;

		if (g_latency) {
			if (pkt_enquened >= TEST_PACKETS_NUM) {
				poll_miss++;
				goto dequeue;
			}
			if (pkt_enquened >=
				(int)(TEST_PACKETS_NUM - g_burst))
				job_num = TEST_PACKETS_NUM - pkt_enquened;
			if (job_num < 0)
				job_num = burst_nb;
		}

		if (in_dma > MAX_SG_JOB_NB_IN_QDMA && g_scatter_gather)
			goto dequeue;

		for (j = 0; j < job_num; j++) {
			job[j] = &g_jobs[lcore_id][(pkt_cnt + j) % TEST_PACKETS_NUM];

			if (g_memcpy) {
				if (g_validate) {
					/* Setting random value in the
					 * job[j]->len bits at job[j]->src
					 * and 0 at job[j]->dest to check data
					 * validity of entire job[j]->len bits
					 * of dest, after DMA operation is
					 * performed from src.
					 */
					r_num = rand() + 1;

					for (k = 0; k < job[j]->len; k++) {
						*((uint8_t *)(job[j]->src) + k)
							= r_num;
						*((uint8_t *)(job[j]->dest) + k)
							= 0;
					}
				}

				rte_memcpy((void *)job[j]->dest,
					(void *)job[j]->src,
					job[j]->len);

				if (g_validate) {
					err = memcmp((void *)job[j]->src,
						(void *)job[j]->dest,
						job[j]->len);

					if (err) {
						printf("ERROR: DATA VALIDATION FAILED\n");
						quit_signal = 1;
						return -1;
					}
				}

				pkt_cnt++;
				if (g_latency && (pkt_cnt >= TEST_PACKETS_NUM)) {
					calculate_latency(lcore_id, cycle1,
						pkt_cnt,
						pkt_enquened, poll_miss);
					pkt_cnt = 0;
					pkt_enquened = 0;
					cycle1 = rte_get_timer_cycles();
				}
			} else {
				if (g_validate) {
					addr = qdma_mem_iova2virt(job[j]->src, job[j]->dest);
					src1 = addr.src;
					dest1 = addr.dest;

					/* Setting random value in the  job[i]->len bits
					 * at src1 and 0 at dest1 to check data validity
					 * of entire job[i]->len bits of dest1, after
					 * DMA operation is performed from src1.
					 */
					r_num = rand() + 1;
					for (k = 0; k < job[j]->len; k++) {
						*((uint8_t *)(src1) + k) = r_num;
						*((uint8_t *)(dest1) + k) = 0;
					}
				}

				if (g_scatter_gather) {
					src_sge[j].addr = job[j]->src;
					src_sge[j].length = job[j]->len;

					dst_sge[j].addr = job[j]->dest;
					dst_sge[j].length = job[j]->len;
					continue;
				}

				if (j == job_num - 1) {
					/* Submit QDMA Jobs for processing */
					ret = rte_dma_copy(qdma_dev_id[lcore_id], g_vqid[lcore_id],
							job[j]->src, job[j]->dest, job[j]->len,
							job[j]->flags | RTE_DMA_OP_FLAG_SUBMIT);
					if (unlikely(ret < 0))
						goto dequeue;
				} else {
					/* Submit QDMA Jobs for processing */
					ret = rte_dma_copy(qdma_dev_id[lcore_id], g_vqid[lcore_id],
							job[j]->src, job[j]->dest, job[j]->len,
							job[j]->flags);
					if (unlikely(ret < 0)) {
						if (likely(j > 0))
							rte_dma_submit(qdma_dev_id[lcore_id],
								g_vqid[lcore_id]);
						goto dequeue;
					}
				}
				pkt_enquened++;
				in_dma++;
			}
		}

		if (g_scatter_gather) {
			ret = rte_dma_copy_sg(qdma_dev_id[lcore_id], g_vqid[lcore_id],
				src_sge, dst_sge, job_num, job_num, RTE_DMA_OP_FLAG_SUBMIT);
			if (likely(!ret)) {
				pkt_enquened += job_num;
				in_dma += job_num;
			}
		}
dequeue:
		do {
			/* Check for QDMA Job completion status */
			error = false;
			ret = rte_dma_completed(qdma_dev_id[lcore_id],
				g_vqid[lcore_id], 1, NULL, &error);

			in_dma -= ret;
			if (error) {
				printf("Error(%x) occurred for a job\n", error);
				rte_exit(EXIT_FAILURE, "Job Processing Error\n");
			}
			pkt_cnt += ret;

			if (g_validate) {
				for (j = 0; j < ret; j++) {
					addr = qdma_mem_iova2virt(job[j]->src, job[j]->dest);
					src1 = addr.src;
					dest1 = addr.dest;

					err = memcmp((void *)src1, (void *)dest1, job[j]->len);
					if (err) {
						printf("ERROR: DATA VALIDATION FAILED\n");
						quit_signal = 1;
						return -1;
					}
				}
			}

			if (g_latency && (pkt_cnt >= TEST_PACKETS_NUM)) {
				calculate_latency(lcore_id, cycle1,
					pkt_cnt,
					pkt_enquened, poll_miss);
				pkt_cnt = 0;
				pkt_enquened = 0;
				cycle1 = rte_get_timer_cycles();
			}
		} while ((g_validate && in_dma) || (!g_validate && ret));

		if (pkt_cnt > (64 * 1024)) {
			rte_atomic32_add(&dequeue_num, (64 * 1024));
			rte_atomic32_add(&dequeue_num_percore[lcore_id],
				(64 * 1024));
			pkt_cnt = 0;
			poll_miss = 0;
		}
	}
	printf("exit core %d\n", lcore_id);

	return 0;
}

static int
lcore_qdma_control_loop(__attribute__((unused)) void *arg)
{
	unsigned int lcore_id;
	struct rte_dma_vchan_conf conf;
	struct rte_dma_info info;
	uint64_t pci_vaddr, pci_phys, len;
	float nsPerCycle = (float) (1000 * rate) / ((float) freq);
	uint64_t cycle1 = 0, cycle2 = 0;
	float speed;
	int32_t i, ret;
	unsigned int j;
	const struct rte_memzone *mz0, *mz1;
	char src_name[16], dst_name[16];

	lcore_id = rte_lcore_id();

	/* wait synchro for slaves */
	if (!g_memcpy)
		test_dma_init();
	/* Memory map the PCI addresses */
	if (g_rbp_testcase != MEM_TO_MEM) {
		pci_phys = g_target_pci_addr;
		len = g_pci_size;
		pci_vaddr = (uint64_t)pci_addr_mmap(NULL, len,
			PROT_READ | PROT_WRITE, MAP_SHARED,
			pci_phys, NULL, NULL);
		if (!pci_vaddr) {
			printf("Failed to mmap PCI addr %lx\n",
				pci_phys);
			return 0;
		}
		g_target_pci_iova = pci_phys;
		g_target_pci_vaddr = pci_vaddr;
		/* configure pci virtual address in SMMU via VFIO */
		rte_fslmc_vfio_mem_dmamap(pci_vaddr,
					  g_target_pci_iova, len);
		snprintf(src_name, 16, "src_n-%d", 1);
		snprintf(dst_name, 16, "dst_n-%d", 1);
		mz0 = rte_memzone_reserve_aligned(src_name, g_pci_size, 0,
				RTE_MEMZONE_IOVA_CONTIG, 4096);
		if (!mz0) {
			printf("Memzone %s reserve failed\n", src_name);
			return -1;
		}
		g_buf = mz0->addr;
		mz1 = rte_memzone_reserve_aligned(dst_name, g_pci_size, 0,
				RTE_MEMZONE_IOVA_CONTIG, 4096);
		if (!mz1) {
			printf("Memzone %s reserve failed\n", dst_name);
			return -1;
		}
		g_buf1 = mz1->addr;
		printf("Local bufs, g_buf %p, g_buf1 %p\n",
			g_buf, g_buf1);
		g_iova = mz0->iova;
		g_iova1 = mz1->iova;
	}

	/* setup QDMA queues */
	for (i = 0; (!g_memcpy) && i < RTE_MAX_LCORE; i++) {
		if (!rte_lcore_is_enabled(i))
			continue;

		ret = rte_dma_info_get(qdma_dev_id[i], &info);
		if (ret != 0)
			return -1;

		conf.direction = 0;
		conf.nb_desc = info.max_desc;
		conf.src_port.port_type = RTE_DMA_PORT_NONE;
		conf.dst_port.port_type = RTE_DMA_PORT_NONE;
		ret = rte_dma_vchan_setup(qdma_dev_id[i], g_vqid[i], &conf);
		if (ret) {
			printf("ERR, vchan setup failed\n");
			return -1;
		}
	}

	if (num_dma_devs >= RTE_MAX_LCORE) {
		for (i = 0; i < RTE_MAX_LCORE; i++) {
			ret = rte_dma_start(qdma_dev_id[i]);
			if (ret) {
				RTE_LOG(ERR, PMD, "Failed to start DMA\n");
				return -EINVAL;
			}
		}
	} else {
		ret = rte_dma_start(qdma_dev_id[0]);
		if (ret) {
			RTE_LOG(ERR, PMD, "Failed to start DMA\n");
			return -EINVAL;
		}
	}

	/* Adavance prepare the jobs for the test */
	for (j = 0; j < RTE_MAX_LCORE; j++) {
		if (!rte_lcore_is_enabled(j) || j == rte_get_main_lcore())
			continue;

		if (g_rbp_testcase == MEM_TO_MEM) {
			snprintf(src_name, 16, "src_p-%d", j+1);
			snprintf(dst_name, 16, "dst_p-%d", j+1);
			mz0 = rte_memzone_reserve_aligned(src_name,
					TEST_PACKETS_NUM*TEST_PACKET_SIZE, 0,
					RTE_MEMZONE_IOVA_CONTIG, 4096);
			if (!mz0) {
				printf("Memzone %s reserve failed\n", src_name);
				return -1;
			}
			g_buf = mz0->addr;
			mz1 = rte_memzone_reserve_aligned(dst_name,
					TEST_PACKETS_NUM*TEST_PACKET_SIZE, 0,
					RTE_MEMZONE_IOVA_CONTIG, 4096);
			if (!mz1) {
				printf("Memzone %s reserve failed\n", dst_name);
				return -1;
			}
			g_buf1 = mz1->addr;
			printf("Local bufs, g_buf %p, g_buf1 %p\n",
				g_buf, g_buf1);
			g_iova = mz0->iova;
			g_iova1 = mz1->iova;
		}

		g_jobs[j] = rte_zmalloc("test qdma",
					  TEST_PACKETS_NUM *
					  sizeof(struct dma_job), 4096);
		printf("[%d] job ptr %p\n", j, g_jobs[j]);

	/* Prepare the QDMA jobs in advance */
	for (i = 0; i < TEST_PACKETS_NUM; i++) {
		struct dma_job *job = g_jobs[j];

		job += i;
		job->len = TEST_PACKET_SIZE;
		memset(g_buf + (i * TEST_PACKET_SIZE), (char) i + 1,
			TEST_PACKET_SIZE);
		memset(g_buf1 + (i * TEST_PACKET_SIZE), 0xff,
			TEST_PACKET_SIZE);

		if (g_rbp_testcase == MEM_TO_PCI) {
			if (g_memcpy)
				job->src = ((long)g_buf + (long) (i * TEST_PACKET_SIZE));
			else
				job->src = ((long)g_iova + (long) (i * TEST_PACKET_SIZE));
			if (g_userbp) {
				job->dest =
				(TEST_PCIBUS_BASE_ADDR + (long) (i * TEST_PACKET_SIZE));
			} else {
				job->dest =
				(g_target_pci_iova + (long) (i * TEST_PACKET_SIZE));
			}
		} else if (g_rbp_testcase == MEM_TO_MEM) {
			if (g_memcpy) {
				job->src = ((long)g_buf + (long) (i * TEST_PACKET_SIZE));
				job->dest =
					((long)g_buf1 + (long) (i * TEST_PACKET_SIZE));
			} else {
				job->src = ((long)g_iova +
					   (long) (i * TEST_PACKET_SIZE));
				job->dest =
					((long) g_iova1 +
					(long) (i * TEST_PACKET_SIZE));
			}
		} else if (g_rbp_testcase == PCI_TO_PCI) {
			if (g_userbp) {
				job->dest = (TEST_PCIBUS_BASE_ADDR +
					g_pci_size +
					(long) (i * TEST_PACKET_SIZE));
				job->src = (TEST_PCIBUS_BASE_ADDR +
					(long) ((i * TEST_PACKET_SIZE)));
			} else {
				job->dest = (g_target_pci_iova + g_pci_size +
					(long) (i * TEST_PACKET_SIZE));
				job->src = (g_target_pci_iova +
					(long) ((i * TEST_PACKET_SIZE)));
			}
		} else if (g_rbp_testcase == PCI_TO_MEM) {
			if (g_userbp) {
				job->src = (TEST_PCIBUS_BASE_ADDR +
					(long) ((i * TEST_PACKET_SIZE)));
			} else {
				job->src = (g_target_pci_iova +
					(long) ((i * TEST_PACKET_SIZE)));
			}
			if (g_memcpy)
				job->dest = ((long)g_buf + (long) (i * TEST_PACKET_SIZE));
			else
				job->dest = ((long)g_iova + (long) (i * TEST_PACKET_SIZE));
		}
	}
	}
	printf("test memory size: 0x%lx packets number:%d packet size: %d\n",
	      g_pci_size, TEST_PACKETS_NUM, TEST_PACKET_SIZE);
	printf("Local mem phy addr: %lx addr1: %lx g_jobs[0]:%p\n",
	      g_iova, g_iova1, g_jobs[0]);

	if (g_frame_format == ULTRA_SHORT_FMT)
		printf("\n\nUsing ultra short format to test: packet size %d Bytes, ",
			TEST_PACKET_SIZE);
	else
		printf("\n\nUsing long format to test: packet size %d Bytes, ",
			TEST_PACKET_SIZE);

	switch (g_rbp_testcase) {
	case PCI_TO_MEM:
		printf("PCI_TO_MEM\n");
		break;
	case MEM_TO_PCI:
		printf("MEM_TO_PCI\n");
		break;
	case MEM_TO_MEM:
		printf("MEM_TO_MEM\n");
		break;
	case PCI_TO_PCI:
		printf("PCI_TO_PCI\n");
		break;
	default:
		printf("unknown test case!\n");
	}
	printf("Master coreid: %d ready, now!\n", lcore_id);

	rte_atomic32_set(&synchro, 1);

	while (!quit_signal) {

		rte_atomic32_clear(&dequeue_num);
		RTE_LCORE_FOREACH_WORKER(lcore_id) {
			rte_atomic32_clear(&dequeue_num_percore[lcore_id]);
		}
		cycle1 = rte_get_timer_cycles();
		rte_delay_ms(4000);

		if (g_latency)
			goto skip_print;

		cycle2 = rte_get_timer_cycles();
		time_diff = cycle2 - cycle1;
		speed =
			(float) (rte_atomic32_read(&dequeue_num))
				/ (float) (nsPerCycle * time_diff /
				(float) (1000 * 1000 * 1000));
		speed = speed * TEST_PACKET_SIZE;

		printf("\n=>Time Spend :%.3f ms ",
			(nsPerCycle * time_diff) / (float) (1000 * 1000));

		printf("rcvd cnt:%d\n", dequeue_num.cnt);
		printf("Rate: %.3f Mbps OR %.3f Kpps\n",
				8 * speed / ((float) (1000 * 1000)),
				speed / ((float) (TEST_PACKET_SIZE * 1000)));

		RTE_LCORE_FOREACH_WORKER(lcore_id) {
			printf("processed on core %d pkt cnt: %d\n",
			lcore_id, dequeue_num_percore[lcore_id].cnt);
		}

skip_print:
		cycle1 = cycle2 = 0;
	}
	printf("exit core %d\n", rte_lcore_id());

	return 0;
}


/* launch all the per-lcore test, and display the result */
static int
launch_cores(unsigned int cores)
{
	unsigned lcore_id;
	int ret;
	unsigned cores_save = cores;

	rte_atomic32_set(&synchro, 0);

	RTE_LCORE_FOREACH_WORKER(lcore_id)
	{
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
	RTE_LCORE_FOREACH_WORKER(lcore_id)
	{
		if (cores == 1)
			break;
		cores--;

		if (rte_eal_wait_lcore(lcore_id) < 0)
			ret = -1;
	}

	if (ret < 0) {
		printf ("per-lcore test returned -1\n");
		return -1;
	}

	return 0;
}

static void
int_handler(int sig_num)
{
	printf("Exiting on signal %d\n", sig_num);
	/* set quit flag for rx thread to exit */
	quit_signal = 1;
}

static uint64_t
get_tsc_freq_from_cpuinfo(void)
{
	char line[256];
	FILE *stream;
	double dmhz;

	stream =
	fopen("/sys/devices/system/cpu/cpufreq/policy0/cpuinfo_max_freq", "r");
	if (!stream) {
		RTE_LOG(WARNING, EAL, "WARNING: Unable to open /proc/cpuinfo\n");
		return 0;
	}

	while (fgets(line, sizeof line, stream)) {
		if (sscanf(line, "%lf", &dmhz) == 1) {
			  freq = (uint64_t) (dmhz / 1000);
			  break;
		}
	}

	fclose(stream);
	return freq;
}

static void qdma_demo_usage(void)
{
	int i;
	printf("./qdma_demo [EAL options] -- -option --<args>=<value>\n");
	printf("options	:\n");
	printf("	: -c <hex core mask>\n");
	printf("	: -h print usage\n");
	printf("Args	:\n");
	printf("	: --pci_addr <target_pci_addr>\n");
	printf("	: --packet_size <bytes>\n");
	printf("	: --test_case <test_case_name>\n");
	for (i = 0; i < test_case_array_size; i++)
		printf("		%s - %s\n", test_case[i].name,
				test_case[i].help);
	printf("	: --pci_size <bytes>\n");
	printf("	: --latency_test\n");
	printf("	: --memcpy\n");
	printf("	: --scatter_gather\n");
	printf("	: --burst\n");
	printf("	: --packet_num (valid only for mem_to_mem)\n");
	printf("        : --validate\n");
}

static int qdma_parse_long_arg(char *optarg, struct option *lopt)
{
	int ret = 0, i;

	switch (lopt->val) {
	case ARG_PCI_ADDR:
		ret = sscanf(optarg, "%lx", &g_target_pci_addr);
		if (ret == EOF) {
			printf("Invalid PCI address\n");
			ret = -EINVAL;
			goto out;
		}
		ret = 0;
		printf("%s: PCI addr %lx\n", __func__, g_target_pci_addr);
		break;
	case ARG_SIZE:
		ret = sscanf(optarg, "%d", &g_packet_size);
		if (ret == EOF) {
			printf("Invalid Packet size\n");
			ret = -EINVAL;
			goto out;
		}
		ret = 0;
		printf("%s: Pkt size %d\n", __func__, g_packet_size);
		break;
	case ARG_TEST_ID:
		for (i = 0; i < test_case_array_size; i++) {
			ret = strncmp(test_case[i].name, optarg,
				TEST_CASE_NAME_SIZE);
			if (!ret) {
				g_rbp_testcase = test_case[i].id;
				break;
			}
		}
		if (i == test_case_array_size) {
			printf("Invalid test case\n");
			ret = -EINVAL;
			goto out;
		}
		ret = 0;
		printf("%s:test case %s\n", __func__,
				test_case[i].name);
		break;
	case ARG_LATENCY:
		g_latency = 1;
		break;
	case ARG_PCI_SIZE:
		ret = sscanf(optarg, "%lu", &g_pci_size);
		if (ret == EOF) {
			printf("Invalid PCI size\n");
			ret = -EINVAL;
			goto out;
		}
		ret = 0;
		printf("%s: PCI size %lu\n", __func__, g_pci_size);
		break;
	case ARG_MEMCPY:
		if (g_scatter_gather) {
			printf("memcpy conflicts with scatter gather\n");
			ret = -EINVAL;
			goto out;
		}
		g_memcpy = 1;
		break;
	case ARG_SCATTER_GATHER:
#ifndef RTE_LIBRTE_DPAA2_USE_PHYS_IOVA
		if (dpaa2_svr_family == SVR_LX2160A) {
			printf("qDMA demo is NOT supported on LX with IOVA on\n");
			ret = -EINVAL;
			goto out;
		}
#endif
		if (g_memcpy) {
			printf("scatter gather conflicts with memcpy\n");
			ret = -EINVAL;
			goto out;
		}
		g_frame_format = LONG_FMT;
		g_scatter_gather = 1;
		break;
	case ARG_BURST:
		ret = sscanf(optarg, "%u", &g_burst);
		if (ret == EOF) {
			printf("Invalid burst size\n");
			ret = -EINVAL;
			goto out;
		}
		ret = 0;
		if (g_burst > BURST_NB_MAX || g_burst < 1)
			g_burst = BURST_NB_MAX;

		printf("%s: burst size %u\n", __func__, g_burst);
		break;
	case ARG_NUM:
		ret = sscanf(optarg, "%d", &g_packet_num);
		if (ret == EOF) {
			printf("Invalid Packet number\n");
			ret = -EINVAL;
			goto out;
		}
		ret = 0;
		printf("%s: Pkt num %d\n", __func__, g_packet_num);
		break;
	case ARG_VALIDATE:
		g_validate = 1;
		break;
	default:
		printf("Unknown Argument\n");
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

	if (g_rbp_testcase != MEM_TO_MEM) {
		valid = !!(g_arg_mask & ARG_PCI_ADDR);
	} else {
		/* Total buffers should be more than 3 * burst */
		if (g_packet_num < (int)(3 * g_burst)) {
			printf("Not sufficient buffers = %d\n", g_packet_num);
			valid = 0;
			goto out;
		}
	}

	if ((g_rbp_testcase != MEM_TO_MEM)
		&& (g_memcpy)) {
		printf("Memcpy not supported with PCI\n");
		valid = 0;
		goto out;
	}

	if (!(g_arg_mask & ARG_SIZE)) {
		printf("Using Default packet size %d bytes\n",
			g_packet_size);
	}

	core_count = rte_lcore_count();
	if (core_count < 2) {
		printf("Insufficient cores %d, need at least 2\n",
			core_count);
		valid = 0;
		goto out;
	}
	stats_core_id = rte_get_main_lcore();
	printf("%s: Stats core id - %d\n", __func__, stats_core_id);
out:
	return !valid;
}

int
main(int argc, char *argv[])
{
	int ret = 0;

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
		printf("Arg parsing failed\n");
		goto out;
	}
	ret = qdma_demo_validate_args();
	if (ret) {
		printf("Arguments are invalid\n");
		qdma_demo_usage();
		goto out;
	}

	if ((g_target_pci_addr % PAGE_SIZE) != 0 ||
	    (g_pci_size % PAGE_SIZE) != 0) {
		printf("PCI addr or len not multiple of page size\n");
		return 0;
	}

	if (g_rbp_testcase != MEM_TO_MEM) {
		g_packet_num = g_pci_size / (TEST_PACKET_SIZE);
		printf("test packet count %d\n", g_packet_num);
		if (g_pci_size < (unsigned int)(TEST_PACKETS_NUM * TEST_PACKET_SIZE)) {
			printf("Need to increase host pcie memory space!\n");
			return 0;
		}
	}

	/*cycle correction */
	uint64_t freq = get_tsc_freq_from_cpuinfo();

	float nsPerCycle = (float) 1000 / ((float) freq);
	start_cycles = rte_get_timer_cycles();
	rte_delay_ms(1000);
	end_cycles = rte_get_timer_cycles();
	time_diff = end_cycles - start_cycles;
	rate = (float) (1000) / ((nsPerCycle * time_diff) / (1000 * 1000));
	printf("Rate:%.5f cpu freq:%ld MHz\n", rate, freq);

	start_cycles = rte_get_timer_cycles ();
	rte_delay_ms(2000);
	end_cycles = rte_get_timer_cycles();
	time_diff = end_cycles - start_cycles;

	printf("Spend :%.3f ms\n",
	      (nsPerCycle * time_diff * rate) / (float) (1000 * 1000));

#if TEST_PCIE_32B_WR
	ret = launch_pcie32b_cores(core_count);
#else
	ret = launch_cores(core_count);
#endif
	if (ret < 0)
		goto out;
	printf("qdma_demo Finished.. bye!\n");
	return 0;
out:
	printf("qdma_demo Failed!\n");
	return 0;
}
