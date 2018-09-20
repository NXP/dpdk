/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018 NXP
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
#include <fsl_qbman_base.h>
#include <mc/fsl_mc_sys.h>
#include <mc/fsl_dpdmai.h>
#include <dpaa2_hw_pvt.h>
#include <dpaa2_qdma.h>
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

#if !TEST_PCIE_32B_WR
static rte_atomic32_t dequeue_num;
static rte_atomic32_t dequeue_num_percore[16];
#endif
int g_vqid[32];
char *g_buf;
char *g_buf1;
rte_iova_t g_iova;
rte_iova_t g_iova1;


int g_frame_format = LONG_FMT;
int g_userbp = NO_RBP;

int g_rbp_testcase = MEM_TO_PCI;
struct rte_qdma_job *g_jobs[16];

volatile uint8_t quit_signal;

int32_t total_cores;
int g_packet_size = 1024;
int g_packet_num = (54 * 1024);
rte_spinlock_t test_lock;

static int TEST_DMA_INIT_FLAG;
static int test_dma_init(void);

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

static int
lcore_hello(__attribute__((unused))
	     void *arg)
{
	unsigned int lcore_id;

#if !TEST_PCIE_32B_WR
	float nsPerCycle = (float) (1000 * rate) / ((float) freq);
	uint64_t cycle1 = 0, cycle2 = 0;
	float speed;
	int pkt_cnt = 0;
#endif
	lcore_id = rte_lcore_id ();
	int32_t ret = 0;

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
	start = (TEST_PCICPU_BASE_ADDR) & PAGE_MASK;
	len = TEST_PCI_SIZE_LIMIT & PAGE_MASK;
	if (len < (size_t) PAGE_SIZE)
		len = PAGE_SIZE;
	tmp = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, start);
	printf("PCI addr %lx, virt %p\n", start, tmp);
	if (lcore_id != rte_get_master_lcore ())
		do {
		ret = rte_atomic32_read(&synchro);
		} while (!ret);
	else
		start_cycles = end_cycles = 0;

	rte_atomic32_set(&synchro, 1);

	if (lcore_id == 0)
		start_cycles = rte_get_timer_cycles();

	if (!quit_signal) {
		if (TEST_PCIE_32B) {
		  for (int i = 0; i < TEST_PCIE_READ_TIMES; i++) {
		      if (TEST_PCIE_READ)
			value32 = *((uint32_t *) ((uint64_t) tmp));
		      else
			*((uint32_t *) ((uint64_t) tmp + (i % TEST_PCI_SIZE_LIMIT))) =
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
	close (fd);
#else
	/* wait synchro for slaves */
	if (lcore_id != rte_get_master_lcore())
		do {
			ret = rte_atomic32_read(&synchro);
		} while (!ret);
	else {
		test_dma_init();
		g_buf = rte_malloc("test qdma", TEST_PCI_SIZE_LIMIT, 4096);
		g_buf1 = rte_malloc("test qdma", TEST_PCI_SIZE_LIMIT, 4096);
		g_iova = rte_malloc_virt2iova(g_buf);
		g_iova1 = rte_malloc_virt2iova(g_buf1);

		for (int j = 0; j < 16; j++) {
		  g_jobs[j] = rte_malloc("test qdma",
					  TEST_PACKETS_NUM *
					  sizeof (struct rte_qdma_job), 4096);
		  printf("[%d] job ptr %p\n", j, g_jobs[j]);
		  for (int i = 0; i < TEST_PACKETS_NUM; i++) {
		      struct rte_qdma_job *job = g_jobs[j];
		      job += i;
		      job->flags = 3;
		      job->len = TEST_PACKET_SIZE;
		      job->cnxt = i;
		      memset(g_buf + (i * TEST_PACKET_SIZE), (char) i + 1,
			      TEST_PACKET_SIZE);
		      memset(g_buf1 + (i * TEST_PACKET_SIZE), 0xff,
			      TEST_PACKET_SIZE);

			if (g_rbp_testcase == MEM_TO_PCI) {
				job->src = ((long) g_iova + (long) (i * TEST_PACKET_SIZE));
				if (g_userbp)
					job->dest =
					(TEST_PCIBUS_BASE_ADDR + (long) (i * TEST_PACKET_SIZE));
				else
					job->dest =
					(TEST_PCICPU_BASE_ADDR + (long) (i * TEST_PACKET_SIZE));

			}
		      else if (g_rbp_testcase == MEM_TO_MEM) {
			  job->src = ((long) g_iova + (long) (i * TEST_PACKET_SIZE));
			  job->dest =
			    ((long) g_iova1 + (long) (i * TEST_PACKET_SIZE));
			}
		      else if (g_rbp_testcase == PCI_TO_PCI) {
			  if (g_userbp) {
			      job->dest =
				(TEST_PCIBUS_BASE_ADDR + TEST_PCI_SIZE_LIMIT +
				 (long) (i * TEST_PACKET_SIZE));
			      job->src =
				(TEST_PCIBUS_BASE_ADDR +
				 (long) ((i * TEST_PACKET_SIZE)));
			    }
			  else {
			      job->dest =
				(TEST_PCICPU_BASE_ADDR + TEST_PCI_SIZE_LIMIT +
				 (long) (i * TEST_PACKET_SIZE));
			      job->src =
				(TEST_PCICPU_BASE_ADDR +
				 (long) ((i * TEST_PACKET_SIZE)));
			    }
			}
		      else if (g_rbp_testcase == PCI_TO_MEM) {
			  if (g_userbp) {
			      job->src =
				(TEST_PCIBUS_BASE_ADDR +
				 (long) ((i * TEST_PACKET_SIZE)));
			    }
			  else {
			      job->src =
				(TEST_PCICPU_BASE_ADDR +
				 (long) ((i * TEST_PACKET_SIZE)));
			    }
			  job->dest = ((long) g_iova + (long) (i * TEST_PACKET_SIZE));
			}
		    }
		}


		for (int i = 0; i < 16; i++) {
		  g_vqid[i] = rte_qdma_vq_create(i, 0);
		  g_vqid[i + 16] = rte_qdma_vq_create(i, 0);
		  printf("core id:%d g_vqid[%d]:%d g_vqid[%d]:%d\n", i, i,
			  g_vqid[i], i + 16, g_vqid[i + 16]);
		}

		printf("cores:%d packet count:%d\n\n", total_cores, dequeue_num.cnt);
		printf("test memory size: 0x%x packets number:%d packet size: %d\n",
		      TEST_PCI_SIZE_LIMIT, TEST_PACKETS_NUM, TEST_PACKET_SIZE);
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

	}
	printf("coreid: %d ready, now!\n", lcore_id);

	rte_atomic32_set(&synchro, 1);

	switch (lcore_id) {
	case 0:
	case 1:
	case 2:
	case 3:
	case 4:
	case 5:
	case 6:
	case 7:
	case 8:
	case 9:
	case 10:
	case 11:
	case 12:
	case 13:
	case 14:
	while (!quit_signal) {
	  struct rte_qdma_job *job;

	  int ret;

	  for (int j = 0; j < 256; j++) {
	      job = &g_jobs[lcore_id][(pkt_cnt + j) % TEST_PACKETS_NUM];
	      job->cnxt = ((pkt_cnt + j) % TEST_PACKETS_NUM);

	      ret = rte_qdma_vq_enqueue(g_vqid[lcore_id], job);
	      if (ret < 0) {
		  for (int i = 0; i < 256; i++) {
		      struct rte_qdma_job *job1 = 0;
		      job1 = rte_qdma_vq_dequeue (g_vqid[lcore_id]);

		      if (job1) {
			  if (!job1->status) {
			      pkt_cnt++;
			    }
			}
		      else {
			  break;
			}
		    }
		}
	    }

	  for (int j = 0; j < 256; j++) {
	      struct rte_qdma_job *job1 = 0;
	      job1 = rte_qdma_vq_dequeue(g_vqid[lcore_id]);

	      if (job1) {
		  if (!job1->status) {
		      pkt_cnt++;
		    }
		}
	      else {
		  break;
		}
	    }
	  if (pkt_cnt > (64 * 1024)) {
	      rte_atomic32_add(&dequeue_num, (64 * 1024));
	      rte_atomic32_add(&dequeue_num_percore[lcore_id], (64 * 1024));
	      pkt_cnt = 0;
	    }

	}
	printf("exit core %d\n", lcore_id);
	break;
	case 15:
	while (!quit_signal) {
	  rte_atomic32_clear(&dequeue_num);
	  for (int i = 0; i < 16; i++) {
	      rte_atomic32_clear(&dequeue_num_percore[i]);
	    }
	  cycle1 = rte_get_timer_cycles();
	  rte_delay_ms(4000);
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

	  printf("Spend :%.3f ms ",
		  (nsPerCycle * time_diff) / (float) (1000 * 1000));
	  printf("cnt:%d pkt_cnt:%d\n", dequeue_num.cnt, pkt_cnt);
	  printf("	Speed: %.3f Mbps %.3f Kpps\n\n",
		  8 * speed / ((float) (1000 * 1000)),
		  speed / ((float) (TEST_PACKET_SIZE * 1000)));
	  for (int i = 0; i < 16; i += 4) {
	      printf(" pkt cnt: %d %d %d %d\n", dequeue_num_percore[i].cnt,
		      dequeue_num_percore[i + 1].cnt,
		      dequeue_num_percore[i + 2].cnt,
		      dequeue_num_percore[i + 3].cnt);
	    }

	  cycle1 = cycle2 = 0;
	  pkt_cnt = 0;
	}
	printf("exit core %d\n", lcore_id);

	break;
	default:
	return -EINVAL;
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
		rte_eal_remote_launch(lcore_hello, NULL, lcore_id);
	}

	/* start synchro and launch test on master */

	ret = lcore_hello(NULL);

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

extern uint64_t *g_pf0_bar0_virt;

int
main(int argc, char *argv[])
{
	int ret = 0;
	unsigned lcore_id;

	/* catch ctrl-c so we can print on exit */
	signal(SIGINT, int_handler);

	g_packet_num = TEST_PCI_SIZE_LIMIT / (TEST_PACKET_SIZE);
	rte_atomic32_init(&synchro);


	if (TEST_PCI_SIZE_LIMIT < (TEST_PACKETS_NUM * TEST_PACKET_SIZE)) {
		printf("Need to increase host pcie memory space!\n");
		return 0;
	}

	/* init EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
	/*cycle correction */
	lcore_id = rte_lcore_id();
	if (lcore_id == 0) {
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
	}

	launch_cores(16);

	printf("Main Finished.. bye!\n");
	return 0;
}
