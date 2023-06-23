/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018-2023 NXP
 */
#ifndef __QDMA_DEMO_H__
#define __QDMA_DEMO_H__

#define PAGE_SIZE	(sysconf(_SC_PAGESIZE))
#define PAGE_MASK	(~(PAGE_SIZE - 1))

#define PCI_TO_PCI 1
#define MEM_TO_PCI 2
#define PCI_TO_MEM 3
#define MEM_TO_MEM 4

#define TEST_PACKETS_NUM (g_packet_num)
#define TEST_PCI_DEFAULT_SIZE (32 * 1024)
#define TEST_PACKET_SIZE (g_packet_size)

#define QDMA_DEMO_MAX_VQS 2048

struct qdma_test_case {
	const char *name;
	const char *help;
	int id;
};
#define TEST_CASE_NAME_SIZE 30
#define ARG_PCI_ADDR (1 << 0)
#define ARG_SIZE (1 << 1)
#define ARG_TEST_ID (1 << 2)
#define ARG_LATENCY (1 << 3)
#define ARG_MEMCPY (1 << 4)
#define ARG_SCATTER_GATHER (1 << 5)
#define ARG_BURST (1 << 6)
#define ARG_NUM (1 << 7)
#define ARG_VALIDATE (1 << 8)
#define ARG_SEG_IOVA (1 << 9)

#endif
