/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018-2019 NXP
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
#include <rte_dpaa2_mempool.h>
#include <rte_bus_vdev.h>
#include <rte_rawdev.h>

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

/* Determines H/W or virtual mode */
uint8_t qdma_mode = RTE_QDMA_MODE_HW;
float rate;
uint64_t freq;
static rte_atomic32_t synchro;
uint64_t start_cycles, end_cycles;
uint64_t time_diff;
extern int rte_fslmc_vfio_mem_dmamap(uint64_t vaddr,
	uint64_t iova, uint64_t size);

#if !TEST_PCIE_32B_WR
static rte_atomic32_t dequeue_num;
static rte_atomic32_t dequeue_num_percore[16];
#endif
int g_vqid[32];
char *g_buf;
char *g_buf1;
rte_iova_t g_iova;
rte_iova_t g_iova1;

struct qdma_test_case test_case[] = {
	{"pci_to_pci", "EP mem to EP mem qdma from host", PCI_TO_PCI},
	{"mem_to_pci", "Host mem to EP mem qdma from host", MEM_TO_PCI},
	{"pci_to_mem", "EP me to host mem qdma from host", PCI_TO_MEM},
	{"mem_to_mem", "Host mem to Host mem qdma, pci_addr not needed",
		 MEM_TO_MEM},
};
int test_case_array_size = sizeof(test_case) / sizeof(test_case[0]);

/*Configurable options*/
int g_frame_format = LONG_FMT;
int g_userbp = NO_RBP;
int g_rbp_testcase = MEM_TO_PCI;
uint32_t g_arg_mask;
uint64_t g_target_pci_addr = TEST_PCICPU_BASE_ADDR;
int g_packet_size = 1024;
uint64_t g_pci_size = TEST_PCI_SIZE_LIMIT;
int g_packet_num = (54 * 1024);
int g_latency;

rte_spinlock_t test_lock;
struct rte_qdma_job *g_jobs[16];
volatile uint8_t quit_signal;
int32_t total_cores;
unsigned int core_count, stats_core_id;

static int TEST_DMA_INIT_FLAG;
static int test_dma_init(void);
static void qdma_demo_usage(void);
static int qdma_parse_long_arg(char *optarg, struct option *lopt);
static int qdma_demo_validate_args(void);

static void *pci_addr_mmap(void *start, size_t length,
		int prot, int flags, off_t offset,
		void **map_addr, int *retfd);
int
test_dma_init(void)
{
	struct rte_qdma_config qdma_config;
	int ret;

	if (TEST_DMA_INIT_FLAG)
		return 0;

	qdma_config.max_hw_queues_per_core = LSINIC_QDMA_MAX_HW_QUEUES_PER_CORE;
	qdma_config.mode = RTE_QDMA_MODE_HW;
	qdma_config.fle_pool_count = LSINIC_QDMA_FLE_POOL_COUNT;
	qdma_config.max_vqs = LSINIC_QDMA_MAX_VQS;

	ret = rte_qdma_init();
	if (ret) {
		RTE_LOG(ERR, PMD, "Failed to initialize dma\n");
		return -EINVAL;
	}

	ret = rte_qdma_configure(&qdma_config);
	if (ret) {
		RTE_LOG(ERR, PMD, "Failed to configure DMA\n");
		return -EINVAL;
	}

	ret = rte_qdma_start();
	if (ret) {
		RTE_LOG(ERR, PMD, "Failed to start DMA\n");
		return -EINVAL;
	}

	TEST_DMA_INIT_FLAG = 1;

	return 0;
}
void *pci_addr_mmap(void *start, size_t length, int prot,
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
		return NULL;
	}

	if (map_addr)
		*map_addr = (void *)((uint64_t)p + diff);

	if (retfd)
		*retfd = fd;

	return p;
}

static int
lcore_qdma_process_loop(__attribute__((unused))
	     void *arg)
{
	unsigned int lcore_id;
	uint64_t pci_vaddr, pci_phys, len;
#if !TEST_PCIE_32B_WR
	float nsPerCycle = (float) (1000 * rate) / ((float) freq);
	uint64_t cycle1 = 0, cycle2 = 0;
	float speed;
	int pkt_cnt = 0;
#endif
	lcore_id = rte_lcore_id();
	int32_t ret = 0;

	float time_us = 0.0;
	float time_us_min = 9999999.0;
	float time_us_max = 0.0;
	double time_us_toal = 0.0;
	int time_count = 0;
	int pkt_enquened = 0;

#if TEST_PCIE_32B_WR
	int fd;
	void *tmp;
	uint64_t start;
	size_t len;
	volatile uint64_t value = 0x1234567890abcdef;
	volatile uint32_t value32 = 0x12345678;

	total_cores++;

	fd = open("/dev/mem", O_RDWR);
	if (fd < 0) {
		RTE_LOG(ERR, PMD, "Fail to open /dev/mem\n");
		return 0;
	}
	start = (g_target_pci_addr) & PAGE_MASK;
	len = g_pci_size & PAGE_MASK;
	if (len < (size_t) PAGE_SIZE)
		len = PAGE_SIZE;
	tmp = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, start);
	printf("PCI addr %lx, virt %p\n", start, tmp);
	if (lcore_id != rte_get_master_lcore())
		do {
			ret = rte_atomic32_read(&synchro);
		} while (!ret);
	else
		start_cycles = end_cycles = 0;

	rte_atomic32_set(&synchro, 1);

	if (lcore_id == rte_get_master_lcore())
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
#else
	/* wait synchro for slaves */
	if (lcore_id != rte_get_master_lcore()) {
		do {
			ret = rte_atomic32_read(&synchro);
		} while (!ret);
		printf("Processing coreid: %d ready, now!\n", lcore_id);
	} else {
		test_dma_init();
		if (g_rbp_testcase != MEM_TO_MEM) {
			pci_phys = (g_target_pci_addr) & PAGE_MASK;
			len = g_pci_size & PAGE_MASK;
			if (len < (size_t) PAGE_SIZE)
				len = PAGE_SIZE;
			pci_vaddr = (uint64_t) pci_addr_mmap(NULL, len,
				PROT_READ | PROT_WRITE, MAP_SHARED,
				pci_phys, NULL, NULL);
			if (!pci_vaddr) {
				printf("Failed to mmap PCI addr %lx\n",
					pci_phys);
				return 0;
			}
			rte_fslmc_vfio_mem_dmamap(pci_vaddr, pci_phys, len);
		}

		g_buf = rte_malloc("test qdma", g_pci_size, 4096);
		g_buf1 = rte_malloc("test qdma", g_pci_size, 4096);
		printf("Local bufs, g_buf %p, g_buf1 %p\n", g_buf, g_buf1);
		for (int j = 0; j < MAX_CORE_COUNT; j++) {
			if (!rte_lcore_is_enabled(j))
				continue;
		  g_jobs[j] = rte_zmalloc("test qdma",
					  TEST_PACKETS_NUM *
					  sizeof(struct rte_qdma_job), 4096);
		  printf("[%d] job ptr %p\n", j, g_jobs[j]);
		  for (int i = 0; i < TEST_PACKETS_NUM; i++) {
		      struct rte_qdma_job *job = g_jobs[j];
		      job += i;
		      job->len = TEST_PACKET_SIZE;
		      job->cnxt = i;
		      memset(g_buf + (i * TEST_PACKET_SIZE), (char) i + 1,
			      TEST_PACKET_SIZE);
		      memset(g_buf1 + (i * TEST_PACKET_SIZE), 0xff,
			      TEST_PACKET_SIZE);
			if (g_rbp_testcase == MEM_TO_PCI) {
				job->src = ((long) g_buf + (long) (i * TEST_PACKET_SIZE));
				if (g_userbp) {
					job->dest =
					(TEST_PCIBUS_BASE_ADDR + (long) (i * TEST_PACKET_SIZE));
					job->flags = RTE_QDMA_JOB_DEST_PHY;
				} else {
					job->dest =
					(g_target_pci_addr + (long) (i * TEST_PACKET_SIZE));
				}
			}
		      else if (g_rbp_testcase == MEM_TO_MEM) {
			  job->src = ((long) g_buf + (long) (i * TEST_PACKET_SIZE));
			  job->dest =
			    ((long) g_buf1 + (long) (i * TEST_PACKET_SIZE));
			}
		      else if (g_rbp_testcase == PCI_TO_PCI) {
			  if (g_userbp) {
			      job->dest =
				(TEST_PCIBUS_BASE_ADDR + g_pci_size +
				 (long) (i * TEST_PACKET_SIZE));
			      job->src =
				(TEST_PCIBUS_BASE_ADDR +
				 (long) ((i * TEST_PACKET_SIZE)));
			      job->flags = RTE_QDMA_JOB_SRC_PHY | RTE_QDMA_JOB_DEST_PHY;
			    }
			  else {
			      job->dest =
				(g_target_pci_addr + g_pci_size +
				 (long) (i * TEST_PACKET_SIZE));
			      job->src =
				(g_target_pci_addr+
				 (long) ((i * TEST_PACKET_SIZE)));
			    }
			}
		      else if (g_rbp_testcase == PCI_TO_MEM) {
			  if (g_userbp) {
			      job->src =
				(TEST_PCIBUS_BASE_ADDR +
				 (long) ((i * TEST_PACKET_SIZE)));
			      job->flags = RTE_QDMA_JOB_SRC_PHY;
			    }
			  else {
			      job->src =
				(g_target_pci_addr+
				 (long) ((i * TEST_PACKET_SIZE)));
			    }
			  job->dest = ((long) g_buf + (long) (i * TEST_PACKET_SIZE));
			}
		    }
		}

		for (int i = 0; i < MAX_CORE_COUNT; i++) {
			if (!rte_lcore_is_enabled(i))
				continue;
		  g_vqid[i] = rte_qdma_vq_create(i, 0);
		  g_vqid[i + 16] = rte_qdma_vq_create(i, 0);
		  printf("core id:%d g_vqid[%d]:%d g_vqid[%d]:%d\n", i, i,
			  g_vqid[i], i + 16, g_vqid[i + 16]);
		}

		printf("test memory size: 0x%lx packets number:%d packet size: %d\n",
		      g_pci_size, TEST_PACKETS_NUM, TEST_PACKET_SIZE);
		printf("Local mem phy addr: %lx addr1: %lx g_jobs[0]:%p\n",
		      g_iova, g_iova1, g_jobs[0]);

		if (g_frame_format == ULTRA_SHORT_FMT)
			printf("\n\nUsing ultra short format to test: packet size %d Bytes, ", TEST_PACKET_SIZE);
		else
			printf("\n\nUsing long format to test: packet size %d Bytes, ", TEST_PACKET_SIZE);

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
	}

	rte_atomic32_set(&synchro, 1);

	if (lcore_id != stats_core_id) {

		 cycle1 = rte_get_timer_cycles();
		while (!quit_signal) {
		  struct rte_qdma_job *job[256], *job1[16];
		  int ret, j;
		int job_num = 256;

		for (j = 0; j < job_num; j++) {
		      job[j] = &g_jobs[lcore_id][(pkt_cnt + j) % TEST_PACKETS_NUM];
		      job[j]->cnxt = ((pkt_cnt + j) % TEST_PACKETS_NUM);
		  }

		if (g_latency) {
			if (pkt_enquened >= TEST_PACKETS_NUM)
				goto dequeue;
			if (pkt_enquened >= (TEST_PACKETS_NUM - 256))
				job_num = TEST_PACKETS_NUM - pkt_enquened;
			if (job_num < 0)
				job_num = 256;
		}
		  ret = rte_qdma_vq_enqueue_multi(g_vqid[lcore_id], job, job_num);
		  if (unlikely(ret <= 0))
		      goto dequeue;

		 pkt_enquened += ret;

dequeue:
		  do {
		      ret = rte_qdma_vq_dequeue_multi(g_vqid[lcore_id], job1, 16);
		      for (j = 0; j < ret; j++) {
			  if (!job1[j]->status)
			      pkt_cnt++;
			if (g_latency && (pkt_cnt >= TEST_PACKETS_NUM)) {
				cycle2 = rte_get_timer_cycles();
				time_diff = cycle2 - cycle1;
				time_us = nsPerCycle *  time_diff / 1000;

				if (time_us < time_us_min)
					time_us_min = time_us;
				if (time_us > time_us_max)
					time_us_max = time_us;
				time_us_toal += time_us;
				time_count++;


				printf("cpu=%d pkt_cnt:%d [%d], pkt_size %d,"
					"time used (%.1f)us [min %.1f, max %.1f"
					", mean %.1f]\n",
					lcore_id, pkt_cnt, pkt_enquened,
					TEST_PACKET_SIZE, time_us,
					time_us_min, time_us_max,
					time_us_toal/time_count);
				rte_delay_ms(1000);
				pkt_cnt = 0;
				pkt_enquened = 0;
				cycle1 = rte_get_timer_cycles();
			}
		      }
		  } while (ret);

		  if (pkt_cnt > (64 * 1024)) {
			rte_atomic32_add(&dequeue_num, (64 * 1024));
			rte_atomic32_add(&dequeue_num_percore[lcore_id],
				(64 * 1024));
			pkt_cnt = 0;
		  }

		}
		printf("exit core %d\n", lcore_id);
	} else {
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
		  speed =
		    (float) (rte_atomic32_read(&dequeue_num)) / (float) (nsPerCycle *
									  time_diff /
									  (float)
									  (1000 *
									   1000 *
									   1000));
		  speed = speed * TEST_PACKET_SIZE;

		  printf("\n=>Time Spend :%.3f ms ",
			  (nsPerCycle * time_diff) / (float) (1000 * 1000));
		  printf("rcvd cnt:%d pkt_cnt:%d\n", dequeue_num.cnt, pkt_cnt);
		  printf("Rate: %.3f Mbps OR %.3f Kpps\n",
			  8 * speed / ((float) (1000 * 1000)),
			  speed / ((float) (TEST_PACKET_SIZE * 1000)));

		RTE_LCORE_FOREACH_SLAVE(lcore_id) {
			printf("processed on core %d pkt cnt: %d\n",
				lcore_id, dequeue_num_percore[lcore_id].cnt);
		}

skip_print:
		  cycle1 = cycle2 = 0;
		  pkt_cnt = 0;
		}
		printf("exit core %d\n", rte_lcore_id());

	}
#endif

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

	RTE_LCORE_FOREACH_SLAVE(lcore_id)
	{
		if (cores == 1)
			break;
		cores--;

		rte_eal_remote_launch(lcore_qdma_process_loop, NULL, lcore_id);
	}

	/* start synchro and launch test on master */

	ret = lcore_qdma_process_loop(NULL);

	cores = cores_save;
	RTE_LCORE_FOREACH_SLAVE(lcore_id)
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

#if TEST_PCIE_32B_WR
	float nsPerCycle = (float) (1000 * rate) / ((float) freq);
	float speed;

	end_cycles = rte_get_timer_cycles();
	time_diff = end_cycles - start_cycles;

	speed =
	(float) (total_cores * TEST_PCIE_READ_TIMES) / (float) (nsPerCycle *
							    time_diff /
							    (float) (1000 *
								     1000 *
								     1000));
	if (TEST_PCIE_READ)
		printf("TEST PCIE Read - ");
	else
		printf("TEST PCIE Write- ");
	if (TEST_PCIE_32B)
		printf("%d cores Spend : %.3f ms speed: %.3f M%ldbytes-ps %.3f Mbps\n",
	    total_cores,
	    (float) (nsPerCycle * time_diff) / (float) (1000 * 1000),
	    speed / ((float) (1000 * 1000)), sizeof (uint32_t),
	    (speed * 32) / ((float) (1000 * 1000)));
	else
		printf("%d cores Spend : %.3f ms speed: %.3f M%ldbytes-ps %.3f Mbps\n",
	    total_cores,
	    (float) (nsPerCycle * time_diff) / (float) (1000 * 1000),
	    speed / ((float) (1000 * 1000)), sizeof (uint64_t),
	    (speed * 64) / ((float) (1000 * 1000)));

#endif

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


void qdma_demo_usage(void)
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
	printf("	: --pci_size <bytes>\n");
	printf("	: --latency_test\n");
	for (i = 0; i < test_case_array_size; i++)
		printf("		%s - %s\n", test_case[i].name,
				test_case[i].help);
}

int qdma_parse_long_arg(char *optarg, struct option *lopt)
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
int qdma_demo_validate_args(void)
{
	int valid = 1;

	if (g_rbp_testcase == MEM_TO_PCI)
		valid = !!(g_arg_mask & ARG_PCI_ADDR);

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
	stats_core_id = rte_get_master_lcore();
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

	g_packet_num = g_pci_size / (TEST_PACKET_SIZE);
	printf("test packet count %d\n", g_packet_num);
	if (g_pci_size < (unsigned int)(TEST_PACKETS_NUM * TEST_PACKET_SIZE)) {
		printf("Need to increase host pcie memory space!\n");
		return 0;
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

	launch_cores(core_count);

	printf("qdma_demo Finished.. bye!\n");
	return 0;
out:
	printf("qdma_demo Failed!\n");
	return 0;
}
