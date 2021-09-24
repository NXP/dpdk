/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2021 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/types.h>
#include <errno.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_spinlock.h>
#include <rte_lsx_pciep_bus.h>

#include "lsxinic_ep_dma.h"
#include "lsxinic_ep_tool.h"

#define LSINIC_QDMA_MAX_HW_QUEUES_PER_CORE	2
#define LSINIC_QDMA_FLE_POOL_QUEUE_COUNT	2048
#define LSINIC_QDMA_MAX_VQS			2048

static int LSINIC_DMA_INIT_FLAG;
static rte_spinlock_t lsinic_dma_init_lock = RTE_SPINLOCK_INITIALIZER;
static int qdma_dev_id;

int
lsinic_dma_write_reg(uint64_t addr, uint32_t val)
{
	int retfd = 0;
	void *ret_addr = 0;
	void *map_addr = NULL;

	ret_addr = lsinic_mmap(NULL, QDMA_MAP_SIZE,
		PROT_WRITE, MAP_SHARED,
		addr, &map_addr, &retfd);
	if (!ret_addr) {
		RTE_LOG(ERR, PMD, "%s mmap error!\n", __func__);
		return -1;
	}

	*(uint32_t *)map_addr = val;

	munmap(ret_addr, QDMA_MAP_SIZE);
	close(retfd);

	return 0;
}

uint32_t
lsinic_dma_read_reg(uint64_t addr)
{
	int retfd = 0;
	uint32_t val = 0;
	void *ret_addr = 0;
	void *map_addr = NULL;

	ret_addr = lsinic_mmap(NULL, QDMA_MAP_SIZE,
		PROT_READ, MAP_SHARED,
		addr, &map_addr, &retfd);
	if (!ret_addr) {
		RTE_LOG(ERR, PMD, "%s mmap error!\n", __func__);
		return 0;
	}

	val = *(uint32_t *)map_addr;

	munmap(ret_addr, QDMA_MAP_SIZE);
	close(retfd);

	return val;
}

int
lsinic_dma_reg_init(void)
{
	lsinic_dma_write_reg(REG_DMR, 0x11000);
	lsinic_dma_write_reg(REG_DWQBWCR0, 0x11111111);
	lsinic_dma_write_reg(REG_DWQBWCR1, 0x11111110);

	return 0;
}

int
lsinic_dma_init(void)
{
	struct rte_qdma_config qdma_config;
	struct rte_qdma_info dev_conf;
	int ret;

	rte_spinlock_lock(&lsinic_dma_init_lock);
	if (LSINIC_DMA_INIT_FLAG) {
		rte_spinlock_unlock(&lsinic_dma_init_lock);
		return qdma_dev_id;
	}

	/* Configure QDMA to use HW resource - no virtual queues */
	qdma_config.max_hw_queues_per_core = LSINIC_QDMA_MAX_HW_QUEUES_PER_CORE;
	qdma_config.fle_queue_pool_cnt = LSINIC_QDMA_FLE_POOL_QUEUE_COUNT;
	qdma_config.max_vqs = LSINIC_QDMA_MAX_VQS;

	dev_conf.dev_private = (void *)&qdma_config;
	ret = rte_qdma_configure(qdma_dev_id, &dev_conf);
	if (ret) {
		RTE_LOG(ERR, PMD, "Failed to configure DMA\n");
		rte_spinlock_unlock(&lsinic_dma_init_lock);
		return -EINVAL;
	}

	ret = rte_qdma_start(qdma_dev_id);
	if (ret) {
		RTE_LOG(ERR, PMD, "Failed to start DMA\n");
		rte_spinlock_unlock(&lsinic_dma_init_lock);
		return -EINVAL;
	}

	lsinic_dma_reg_init();

	LSINIC_DMA_INIT_FLAG = 1;
	rte_spinlock_unlock(&lsinic_dma_init_lock);

	return qdma_dev_id;
}

int
lsinic_dma_uninit(void)
{
	if (LSINIC_DMA_INIT_FLAG == 0)
		return 0;

	rte_rawdev_stop(qdma_dev_id);
	rte_rawdev_close(qdma_dev_id);

	LSINIC_DMA_INIT_FLAG = 0;

	return 0;
}
