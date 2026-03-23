/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2026 NXP
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
#include "lsxinic_common_logs.h"

static int s_lsinic_dma_idx;

static rte_spinlock_t s_lsinic_dma_sl = RTE_SPINLOCK_INITIALIZER;

struct lsinic_dma_dir_cap_map {
	enum lsinic_dma_direction dir;
	uint64_t cap_flag;
	const char *str;
};

int
lsinic_dma_acquire(int silent, uint16_t nb_vchans,
	uint16_t nb_desc, enum lsinic_dma_direction dir,
	int *dma_id_acquired)
{
	struct rte_dma_info dev_info;
	struct rte_dma_conf dev_conf;
	int ret = 0, dma_idx;
	uint32_t i;
	const struct lsinic_dma_dir_cap_map dir_cap[] = {
		{
			LSINIC_DMA_MEM_TO_PCIE,
			RTE_DMA_CAPA_MEM_TO_DEV,
			"mem2dev"
		},
		{
			LSINIC_DMA_PCIE_TO_MEM,
			RTE_DMA_CAPA_DEV_TO_MEM,
			"dev2mem"
		},
		{
			LSINIC_DMA_MEM_TO_MEM,
			RTE_DMA_CAPA_MEM_TO_MEM,
			"mem2mem"
		},
		{
			LSINIC_DMA_PCIE_TO_PCIE,
			RTE_DMA_CAPA_DEV_TO_DEV,
			"dev2dev"
		}
	};

	memset(&dev_conf, 0, sizeof(struct rte_dma_conf));

	rte_spinlock_lock(&s_lsinic_dma_sl);

acquire_again:
	dma_idx = rte_dma_next_dev(s_lsinic_dma_idx);
	if (dma_idx < 0) {
		LSXINIC_PMD_ERR("No DMA available from DMA%d",
			s_lsinic_dma_idx);
		ret = -EINVAL;
		goto err_quit;
	}
	s_lsinic_dma_idx = dma_idx + 1;

	ret = rte_dma_info_get(dma_idx, &dev_info);
	if (ret) {
		LSXINIC_PMD_ERR("Failed(%d) to get info from DMA%d",
			ret, s_lsinic_dma_idx);
		goto err_quit;
	}

	if (dev_info.nb_vchans) {
		LSXINIC_PMD_INFO("DMA%d may be configured in another process",
			dma_idx);
		goto acquire_again;
	}

	if (nb_vchans > dev_info.max_vchans) {
		LSXINIC_PMD_ERR("acquire chan(%d) > dma[%d] max chan(%d)",
			nb_vchans, dma_idx, dev_info.max_vchans);
		ret = -ENOTSUP;
		goto err_quit;
	}

	if (nb_desc > dev_info.max_desc) {
		LSXINIC_PMD_ERR("acquire desc(%d) > dma[%d] max desc(%d)",
			nb_desc, dma_idx, dev_info.max_desc);
		ret = -ENOTSUP;
		goto err_quit;
	}

	if (silent && !(dev_info.dev_capa & RTE_DMA_CAPA_SILENT)) {
		LSXINIC_PMD_ERR("dma[%d] not support silent mode", dma_idx);
		ret = -ENOTSUP;
		goto err_quit;
	}

	for (i = 0; i < RTE_DIM(dir_cap); i++) {
		if (dir != dir_cap[i].dir)
			continue;
		if (!(dev_info.dev_capa & dir_cap[i].cap_flag)) {
			LSXINIC_PMD_ERR("dma[%d] not support %s",
				dma_idx, dir_cap[i].str);
			ret = -ENOTSUP;
			goto err_quit;
		}
		break;
	}
	if (i == RTE_DIM(dir_cap)) {
		LSXINIC_PMD_ERR("Invalid DMA direction(%d)", dir);
		ret = -EINVAL;
		goto err_quit;
	}

	dev_conf.nb_vchans = nb_vchans;
	if (silent)
		dev_conf.flags |= RTE_DMA_CFG_FLAG_SILENT;
	ret = rte_dma_configure(dma_idx, &dev_conf);
	if (ret) {
		LSXINIC_PMD_ERR("dma[%d] configure failed(%d)", dma_idx, ret);
		goto err_quit;
	}

	if (dma_id_acquired)
		*dma_id_acquired = dma_idx;

err_quit:
	rte_spinlock_unlock(&s_lsinic_dma_sl);

	return ret;
}

int
lsinic_dma_release(int dma_idx)
{
	int ret;

	ret = rte_dma_stop(dma_idx);
	if (ret)
		return ret;
	ret = rte_dma_close(dma_idx);
	if (ret)
		return ret;

	return 0;
}
