/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2022 NXP
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

#include "lsxinic_ep_rawdev_dma.h"
#include "lsxinic_ep_tool.h"
#include "lsxinic_common_logs.h"

#define LSINIC_QDMA_MAX_VQS 2048

#define QDMA_MAP_SIZE (4096)
#define QDMA_REG_BASE (0x8380000)

#define REG_DMR (QDMA_REG_BASE + 0x00)
#define REG_DSRP (QDMA_REG_BASE + 0x04)
#define REG_DEWQAR0 (QDMA_REG_BASE + 0x60)
#define REG_DWQBWCR0 (QDMA_REG_BASE + 0x70)
#define REG_DWQBWCR1 (QDMA_REG_BASE + 0x74)
#define REG_DPWQAR (QDMA_REG_BASE + 0x78)
#define REG_DSRM (QDMA_REG_BASE + 0x10004)
#define REG_DGBTR (QDMA_REG_BASE + 0x10040)

static int LSINIC_DMA_INIT_FLAG;
static rte_spinlock_t lsinic_dma_init_lock = RTE_SPINLOCK_INITIALIZER;
static int qdma_dev_id;

static int
lsinic_dma_write_reg(uint64_t addr, uint32_t val)
{
	int retfd = 0;
	void *ret_addr = 0;
	void *map_addr = NULL;

	ret_addr = lsinic_mmap(NULL, QDMA_MAP_SIZE,
		PROT_WRITE, MAP_SHARED,
		addr, &map_addr, &retfd);
	if (!ret_addr) {
		LSXINIC_PMD_ERR("%s mmap error!\n", __func__);
		return -EIO;
	}

	*(uint32_t *)map_addr = val;

	munmap(ret_addr, QDMA_MAP_SIZE);
	close(retfd);

	return 0;
}

static int
lsinic_dma_reg_init(void)
{
	int ret;

	ret = lsinic_dma_write_reg(REG_DMR, 0x11000);
	if (ret)
		return ret;
	ret = lsinic_dma_write_reg(REG_DWQBWCR0, 0x11111111);
	if (ret)
		return ret;
	ret = lsinic_dma_write_reg(REG_DWQBWCR1, 0x11111110);

	return ret;
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

	qdma_config.max_vqs = LSINIC_QDMA_MAX_VQS;

	dev_conf.dev_private = &qdma_config;
	ret = rte_qdma_configure(qdma_dev_id, &dev_conf);
	if (ret) {
		LSXINIC_PMD_ERR("Configure DMA%d error(%d)",
			qdma_dev_id, ret);
		rte_spinlock_unlock(&lsinic_dma_init_lock);
		return -EINVAL;
	}

	ret = rte_qdma_start(qdma_dev_id);
	if (ret) {
		LSXINIC_PMD_ERR("Start DMA%d error(%d)",
			qdma_dev_id, ret);
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
