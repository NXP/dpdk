/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2023 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_spinlock.h>
#include <rte_lsx_pciep_bus.h>

#include "lsxinic_ep_rawdev_dma.h"
#include "lsxinic_ep_tool.h"
#include "lsxinic_common_logs.h"

#define LSINIC_RAWDMA_MP "lsinic_rawdma_mp_sync"

#define LSINIC_DMA_REQ_ID 1
struct lsinic_dma_mp_param {
	int req;
	int dma_dev_id;
};

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
static int mp_qdma_dev_id = 1;
static int mp_qdma_raw_sync_setup;

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

static int
lsinic_dma_mp_primary(const struct rte_mp_msg *msg,
	const void *peer)
{
	int ret;
	struct rte_mp_msg reply;
	struct lsinic_dma_mp_param *r = (void *)reply.param;
	const struct lsinic_dma_mp_param *m = (const void *)msg->param;

	if (msg->len_param != sizeof(*m)) {
		LSXINIC_PMD_ERR("msg len(%d) != sizeof(*m)(%d)",
			msg->len_param, (int)sizeof(*m));
		return -EINVAL;
	}

	memset(&reply, 0, sizeof(reply));

	switch (m->req) {
	case LSINIC_DMA_REQ_ID:
		r->req = LSINIC_DMA_REQ_ID;
		r->dma_dev_id = mp_qdma_dev_id;
		mp_qdma_dev_id++;
		break;
	default:
		LSXINIC_PMD_ERR("%s: Received invalid message!(%d)",
			__func__, m->req);
		return -ENOTSUP;
	}

	strcpy(reply.name, LSINIC_RAWDMA_MP);
	reply.len_param = sizeof(*r);
	ret = rte_mp_reply(&reply, peer);

	return ret;
}

int
lsinic_dma_mp_sync_setup(void)
{
	int ret;

	if (mp_qdma_raw_sync_setup)
		return 0;

	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
		ret = rte_mp_action_register(LSINIC_RAWDMA_MP,
			lsinic_dma_mp_primary);
		if (ret && rte_errno != ENOTSUP)
			return ret;
	}
	mp_qdma_raw_sync_setup = 1;

	return 0;
}

static int
lsinic_dma_mp_request_id(void)
{
	int ret;
	struct rte_mp_msg mp_req, *mp_rep;
	struct rte_mp_reply mp_reply = {0};
	struct timespec ts = {.tv_sec = 5, .tv_nsec = 0};
	struct lsinic_dma_mp_param *p = (void *)mp_req.param;

	p->req = LSINIC_DMA_REQ_ID;
	strcpy(mp_req.name, LSINIC_RAWDMA_MP);
	mp_req.len_param = sizeof(*p);
	mp_req.num_fds = 0;

	ret = rte_mp_request_sync(&mp_req, &mp_reply, &ts);
	if (ret)
		goto err_exit;

	if (mp_reply.nb_received != 1) {
		ret = -EIO;
		goto err_exit;
	}

	mp_rep = &mp_reply.msgs[0];
	p = (void *)mp_rep->param;
	ret = p->dma_dev_id;
	free(mp_reply.msgs);

	return ret;

err_exit:
	if (mp_reply.msgs)
		free(mp_reply.msgs);
	LSXINIC_PMD_ERR("Cannot request DMA ID err(%d)", ret);

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
		LSINIC_DMA_INIT_FLAG++;
		rte_spinlock_unlock(&lsinic_dma_init_lock);
		return qdma_dev_id;
	}

	if (rte_eal_process_type() == RTE_PROC_PRIMARY)
		qdma_dev_id = 0;
	else
		qdma_dev_id = lsinic_dma_mp_request_id();

	qdma_config.max_vqs = LSINIC_QDMA_MAX_VQS;

	dev_conf.dev_private = &qdma_config;
	ret = rte_qdma_configure(qdma_dev_id, &dev_conf);
	if (ret) {
		LSXINIC_PMD_ERR("Configure DMA%d error(%d)",
			qdma_dev_id, ret);
		rte_spinlock_unlock(&lsinic_dma_init_lock);
		return ret;
	}

	ret = rte_qdma_start(qdma_dev_id);
	if (ret) {
		LSXINIC_PMD_ERR("Start DMA%d error(%d)",
			qdma_dev_id, ret);
		rte_spinlock_unlock(&lsinic_dma_init_lock);
		return ret;
	}

	lsinic_dma_reg_init();

	LSINIC_DMA_INIT_FLAG++;
	rte_spinlock_unlock(&lsinic_dma_init_lock);

	return qdma_dev_id;
}

int
lsinic_dma_uninit(void)
{
	int ret;

	LSINIC_DMA_INIT_FLAG--;
	if (LSINIC_DMA_INIT_FLAG < 0) {
		LSXINIC_PMD_ERR("DMA uninit too many times(%d)",
			LSINIC_DMA_INIT_FLAG);
		return -EINVAL;
	}

	if (!LSINIC_DMA_INIT_FLAG) {
		rte_rawdev_stop(qdma_dev_id);
		ret = rte_rawdev_close(qdma_dev_id);
		if (ret) {
			LSXINIC_PMD_ERR("DMA%d close failed(%d)",
				qdma_dev_id, ret);
		}
	}

	return 0;
}
