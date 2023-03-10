/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020-2023 NXP
 */

#include <unistd.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#include <rte_log.h>
#include <rte_bus.h>
#include <rte_malloc.h>
#include <rte_devargs.h>
#include <rte_memcpy.h>
#include <rte_io.h>
#include <rte_spinlock.h>
#include <linux/pci_regs.h>

#include "lsx_pciep_ctrl.h"

#define LSX_PCIE_DW_OB_WINS_NUM        (256)
#define LSX_PCIE_DW_IB_WINS_NUM        (24)

#ifndef __packed
#define __packed	__rte_packed
#endif

#define LSX_PCIE_DW_PF_BAR_SIZE_MASK_OFFSET 0x1000

#define LSX_PCIE_DW_VF_BAR_SIZE_MASK_OFFSET \
	(LSX_PCIE_DW_PF_BAR_SIZE_MASK_OFFSET + 0x18c)

#define LSX_PCIEP_DW_WIN_MASK 0xfff

#define LSX_PCIE_DW_IATU_REGION_OFFSET 0x900

enum {
	ADDR_LOW,
	ADDR_UP,
	ADDR_NUM
};

#define PCIE_DW_ATU_VP_REGION_INBOUND		(0x1 << 31)
#define PCIE_DW_ATU_VP_REGION_OUTBOUND	(0x0 << 31)

#define PCIE_DW_ATU_CTL1_FUNC_SHIFT		(20)
#define PCIE_DW_ATU_CTL1_TYPE_MEM			(0x0 << 0)

#define PCIE_DW_ATU_CTL2_EN				(0x1 << 31)
#define PCIE_DW_ATU_CTL2_BAR_MODE_EN	(0x1 << 30)
#define PCIE_DW_ATU_CTL2_FUNC_NUM_MATCH_EN		(0x00080000)
#define PCIE_DW_ATU_CTL2_VFBAR_MATCH_MODE_EN	(0x04000000)
#define PCIE_DW_ATU_CTL2_VF_MATCH_MODE_EN	(0x00100000)
#define PCIE_DW_ATU_CTL2_BAR_NUM(bar)		((bar) << 8)

#define PCIE_DW_ATU_CTL3_VF_ACTIVE_EN		(0x1 << 31)

struct pcie_dw_iatu_region {
	uint32_t view_port;
	union {
		uint32_t ctl1_ib;
		uint32_t ctl1_ob;
	};
	union {
		uint32_t ctl2_ib;
		uint32_t ctl2_ob;
	};
	uint32_t base_addr[ADDR_NUM];
	uint32_t base_limit;
	uint32_t bus_addr[ADDR_NUM];
	union {
		uint32_t ctl3_ib;
		uint32_t ctl3_ob;
	};
} __packed;

#define PCIE_DW_DBI_WR_DIS 0
#define PCIE_DW_DBI_WR_ENA 1
#define PCIE_DW_MISC_CONTROL_1_OFF_OFFSET 0x8bc

#define PCIE_DW_MSIX_DOORBELL_REG 0x948
#define PCIE_DW_MSIX_DOORBELL_PF_SHIFT 24
#define PCIE_DW_MSIX_DOORBELL_VF_SHIFT 16
#define PCIE_DW_MSIX_DOORBELL_VF_ACTIVE 0x8000

enum dw_win_type {
	DW_OUTBOUND_WIN,
	DW_INBOUND_WIN
};

const uint8_t s_dw_32b_bar_support_id[] = {0, 1, 2, 4};

const uint8_t s_dw_32b_bar_id[] = {0, 1};

#define DW_ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define PCIEP_DW_GLOBE_INFO_F "/tmp/pciep_dw_globe_info"
static rte_spinlock_t s_f_lock = RTE_SPINLOCK_INITIALIZER;
static int s_f_create;

struct pciep_dw_shared_ob_win {
	uint64_t bus_start;
	uint64_t bus_end;
	uint64_t offset;
	int ref_count;
};

struct pciep_dw_priv_ob_win {
	uint64_t phy_start;
	uint64_t phy_size;
	int using;
};

struct pciep_dw_info {
	uint64_t dbi_phy[LSX_MAX_PCIE_NB];
	int ob_win_used[LSX_MAX_PCIE_NB][LSX_PCIE_DW_OB_WINS_NUM];
	int ib_win_used[LSX_MAX_PCIE_NB][LSX_PCIE_DW_IB_WINS_NUM];
	uint64_t ob_base[LSX_MAX_PCIE_NB];
	uint64_t ob_offset[LSX_MAX_PCIE_NB];
	struct pciep_dw_priv_ob_win
		priv_ob_win[LSX_MAX_PCIE_NB][LSX_PCIE_DW_OB_WINS_NUM];
	struct pciep_dw_shared_ob_win
		shared_ob_win[LSX_MAX_PCIE_NB][LSX_PCIE_DW_OB_WINS_NUM];
	uint64_t ob_max_size;
	uint64_t ob_win_max_size;
	uint64_t win_mask;
	int shared_ob;
};

struct pciep_dw_proc_info {
	uint64_t ob_start[LSX_PCIE_DW_OB_WINS_NUM];
	int ob_idx[LSX_PCIE_DW_OB_WINS_NUM];
	int ob_nb;

	int ob_shared_idx[LSX_PCIE_DW_OB_WINS_NUM];
	int ob_shared_nb;

	int ib_idx[LSX_PCIE_DW_OB_WINS_NUM];
	int ib_nb;
};

static struct pciep_dw_proc_info g_dw_proc_info[LSX_MAX_PCIE_NB];

#define DWC_OB_PF_INFO_DUMP_FORMAT(pci, pf, \
		phy, bus, size, win) \
		"DWC OB PEX%d PF%d:" \
		"  MEM:0x%" PRIx64 \
		"  PCI:0x%" PRIx64 \
		"  SIZE:0x%" PRIx64 \
		"  WIN:%d", \
		pci, pf, \
		(unsigned long)phy, \
		(unsigned long)bus, \
		(unsigned long)size, \
		win

#define DWC_OB_VF_INFO_DUMP_FORMAT(pci, pf, vf, \
		phy, bus, size, win) \
		"DWC OB PEX%d PF%d-VF%d:" \
		"  MEM:0x%" PRIx64 \
		"  PCI:0x%" PRIx64 \
		"  SIZE:0x%" PRIx64 \
		"  WIN:%d", \
		pci, pf, vf, \
		(unsigned long)phy, \
		(unsigned long)bus, \
		(unsigned long)size, \
		win

#define DWC_IB_PF_INFO_DUMP_FORMAT(pci, pf, \
		phy, bar, size, win) \
		"DWC IB PEX%d PF%d:" \
		"  MEM:0x%" PRIx64 \
		"  bar:%d" \
		"  SIZE:0x%" PRIx64 \
		"  WIN:%d", \
		pci, pf, \
		(unsigned long)phy, \
		bar, \
		(unsigned long)size, \
		win

#define DWC_IB_VF_INFO_DUMP_FORMAT(pci, pf, vf, \
		phy, bar, size, win) \
		"DWC IB PEX%d PF%d-VF%d:" \
		"  MEM:0x%" PRIx64 \
		"  bar:%d" \
		"  SIZE:0x%" PRIx64 \
		"  WIN:%d", \
		pci, pf, vf, \
		(unsigned long)phy, \
		bar, \
		(unsigned long)size, \
		win

static inline int
pcie_dw_32b_bar_support(uint8_t bar)
{
	size_t i;

	for (i = 0; i < DW_ARRAY_SIZE(s_dw_32b_bar_support_id); i++) {
		if (bar == s_dw_32b_bar_support_id[i])
			return 1;
	}

	return 0;
}

static inline int
pcie_dw_using_32b_bar(uint8_t bar)
{
	size_t i;

	for (i = 0; i < DW_ARRAY_SIZE(s_dw_32b_bar_id); i++) {
		if (bar == s_dw_32b_bar_id[i])
			return 1;
	}

	return 0;
}

static inline uint32_t
pcie_dw_route_fun_id(uint8_t *pf_base,
	int pf, int is_vf, int vf)
{
	struct pcie_ctrl_cfg *cfg;
	uint16_t pos, stride;

	if (is_vf) {
		cfg = (void *)pf_base;
		lsx_pciep_read_config(&cfg->first_vf_pos,
			&pos, sizeof(uint16_t), 0);
		lsx_pciep_read_config(&cfg->vf_stride,
			&stride, sizeof(uint16_t), 0);

		return pf + pos + vf * stride;
	} else {
		return pf;
	}
}

static int
pcie_dw_alloc_win_idx(int pcie_id, enum dw_win_type win_type)
{
	int i, max_nb;
	int *pwin;
	FILE *f_dw_cfg;
	size_t f_ret;
	struct pciep_dw_info *info;

	if (pcie_id >= LSX_MAX_PCIE_NB)
		return -EINVAL;

	rte_spinlock_lock(&s_f_lock);
	f_dw_cfg = fopen(PCIEP_DW_GLOBE_INFO_F, "rb");
	if (!f_dw_cfg) {
		LSX_PCIEP_BUS_ERR("%s: %s read open failed",
			__func__, PCIEP_DW_GLOBE_INFO_F);
		rte_spinlock_unlock(&s_f_lock);
		return -ENODEV;
	}

	info = malloc(sizeof(struct pciep_dw_info));
	if (!info) {
		LSX_PCIEP_BUS_ERR("%s prepare buf for read %s failed",
			__func__,
			PCIEP_DW_GLOBE_INFO_F);
		fclose(f_dw_cfg);
		rte_spinlock_unlock(&s_f_lock);
		return -ENOMEM;
	}

	memset(info, 0, sizeof(struct pciep_dw_info));

	f_ret = fread(info, sizeof(struct pciep_dw_info),
			1, f_dw_cfg);
	fclose(f_dw_cfg);
	if (f_ret != 1) {
		LSX_PCIEP_BUS_ERR("%s: %s read (%ldB) failed (%ld)",
			__func__, PCIEP_DW_GLOBE_INFO_F,
			sizeof(struct pciep_dw_info), f_ret);
		free(info);
		rte_spinlock_unlock(&s_f_lock);
		return -EIO;
	}

	f_dw_cfg = fopen(PCIEP_DW_GLOBE_INFO_F, "wb");
	if (!f_dw_cfg) {
		LSX_PCIEP_BUS_ERR("%s: %s write open failed",
			__func__, PCIEP_DW_GLOBE_INFO_F);
		free(info);
		rte_spinlock_unlock(&s_f_lock);
		return -ENODEV;
	}

	if (win_type == DW_OUTBOUND_WIN) {
		max_nb = LSX_PCIE_DW_OB_WINS_NUM;
		pwin = &info->ob_win_used[pcie_id][0];
	} else {
		max_nb = LSX_PCIE_DW_IB_WINS_NUM;
		pwin = &info->ib_win_used[pcie_id][0];
	}

	for (i = 0; i < max_nb; i++) {
		if (!pwin[i]) {
			pwin[i] = 1;
			break;
		}
	}

	if (i == max_nb) {
		LSX_PCIEP_BUS_ERR("alloc win index failed");
		fclose(f_dw_cfg);
		free(info);
		rte_spinlock_unlock(&s_f_lock);
		return -ENODEV;
	}
	f_ret = fwrite(info, sizeof(struct pciep_dw_info),
		1, f_dw_cfg);
	if (f_ret != 1) {
		LSX_PCIEP_BUS_ERR("%s write failed",
			PCIEP_DW_GLOBE_INFO_F);
		fclose(f_dw_cfg);
		free(info);
		rte_spinlock_unlock(&s_f_lock);
		return -ENODEV;
	}
	fclose(f_dw_cfg);
	free(info);
	rte_spinlock_unlock(&s_f_lock);

	return i;
}

static uint64_t
pcie_dw_alloc_from_priv_ob(struct pciep_dw_info *info,
	int pcie_id, uint64_t size, int idx)
{
	struct pciep_dw_priv_ob_win *ob_win;
	uint64_t *ob_offset = &info->ob_offset[pcie_id];
	const uint64_t ob_base = info->ob_base[pcie_id];
	const uint64_t ob_max_size = info->ob_max_size;

	ob_win = &info->priv_ob_win[pcie_id][idx];
	if (ob_win->using)
		return 0;

	if (ob_win->phy_size && size <= ob_win->phy_size) {
		ob_win->using = 1;
	} else if (!ob_win->phy_size) {
		if (*ob_offset + size > ob_max_size)
			return 0;

		if (idx > 0) {
			ob_win->phy_size = size;
		} else {
			ob_win->phy_start = ob_base;
			ob_win->phy_size = size;
		}
		*ob_offset += size;
		if (idx < LSX_PCIE_DW_OB_WINS_NUM &&
			(*ob_offset < ob_max_size)) {
			ob_win[1].phy_start =
			ob_win[0].phy_start + size;
		}
		ob_win->using = 1;
	}
	return ob_win->phy_start;
}

static uint64_t
pcie_dw_alloc_ob_space(int pcie_id,
	uint64_t size)
{
	FILE *f_dw_cfg;
	struct pciep_dw_info *info;
	size_t f_ret;
	uint64_t cpu_addr = 0;
	int i;
	char err_str[128];

	rte_spinlock_lock(&s_f_lock);
	f_dw_cfg = fopen(PCIEP_DW_GLOBE_INFO_F, "rb");
	if (!f_dw_cfg) {
		LSX_PCIEP_BUS_ERR("%s: %s read open failed",
			__func__, PCIEP_DW_GLOBE_INFO_F);
		rte_spinlock_unlock(&s_f_lock);
		return 0;
	}

	info = malloc(sizeof(struct pciep_dw_info));
	if (!info) {
		LSX_PCIEP_BUS_ERR("%s prepare buf for read %s failed",
			__func__,
			PCIEP_DW_GLOBE_INFO_F);
		fclose(f_dw_cfg);
		rte_spinlock_unlock(&s_f_lock);
		return 0;
	}

	memset(info, 0, sizeof(struct pciep_dw_info));

	f_ret = fread(info, sizeof(struct pciep_dw_info),
			1, f_dw_cfg);
	fclose(f_dw_cfg);
	if (f_ret != 1) {
		LSX_PCIEP_BUS_ERR("%s: %s read failed",
			__func__, PCIEP_DW_GLOBE_INFO_F);
		free(info);
		rte_spinlock_unlock(&s_f_lock);
		return 0;
	}

	f_dw_cfg = fopen(PCIEP_DW_GLOBE_INFO_F, "wb");
	if (!f_dw_cfg) {
		LSX_PCIEP_BUS_ERR("%s: %s write open failed",
			__func__, PCIEP_DW_GLOBE_INFO_F);
		free(info);
		rte_spinlock_unlock(&s_f_lock);
		return 0;
	}

	if (info->ob_offset[pcie_id] + size > info->ob_max_size)
		goto no_space_available;

	for (i = 0; i < LSX_PCIE_DW_OB_WINS_NUM; i++) {
		cpu_addr = pcie_dw_alloc_from_priv_ob(info,
					pcie_id, size, i);
		if (cpu_addr)
			break;
	}
	if (!cpu_addr)
		goto no_space_available;

	f_ret = fwrite(info, sizeof(struct pciep_dw_info),
		1, f_dw_cfg);
	if (f_ret != 1) {
		LSX_PCIEP_BUS_ERR("%s write failed",
			PCIEP_DW_GLOBE_INFO_F);
		cpu_addr = 0;
	}
	fclose(f_dw_cfg);
	free(info);
	rte_spinlock_unlock(&s_f_lock);

	return cpu_addr;

no_space_available:
	sprintf(err_str, "offset(0x%lx) + size(0x%lx) > max(0x%lx)",
		info->ob_offset[pcie_id], size,
		info->ob_max_size);
	LSX_PCIEP_BUS_ERR("map failed: %s", err_str);
	fclose(f_dw_cfg);
	free(info);
	rte_spinlock_unlock(&s_f_lock);

	return 0;
}

static uint64_t
pcie_dw_find_shared_ob_space(int pcie_id,
	uint64_t pci_addr, uint64_t size)
{
	FILE *f_dw_cfg;
	size_t f_ret;
	int i;
	int *shared_nb = &g_dw_proc_info[pcie_id].ob_shared_nb;
	struct pciep_dw_info *info;
	struct pciep_dw_shared_ob_win *ob_shared_win;
	uint64_t ob_base, ob_addr = 0;

	rte_spinlock_lock(&s_f_lock);
	f_dw_cfg = fopen(PCIEP_DW_GLOBE_INFO_F, "rb");
	if (!f_dw_cfg) {
		LSX_PCIEP_BUS_ERR("%s: %s read open failed",
			__func__, PCIEP_DW_GLOBE_INFO_F);
		rte_spinlock_unlock(&s_f_lock);
		return 0;
	}

	info = malloc(sizeof(struct pciep_dw_info));
	if (!info) {
		LSX_PCIEP_BUS_ERR("%s prepare buf for read %s failed",
			__func__,
			PCIEP_DW_GLOBE_INFO_F);
		fclose(f_dw_cfg);
		rte_spinlock_unlock(&s_f_lock);
		return 0;
	}

	memset(info, 0, sizeof(struct pciep_dw_info));

	f_ret = fread(info, sizeof(struct pciep_dw_info),
			1, f_dw_cfg);
	fclose(f_dw_cfg);
	if (f_ret != 1) {
		LSX_PCIEP_BUS_ERR("%s: %s read failed",
			__func__, PCIEP_DW_GLOBE_INFO_F);
		free(info);
		rte_spinlock_unlock(&s_f_lock);
		return 0;
	}

	ob_shared_win = &info->shared_ob_win[pcie_id][0];
	ob_base = info->ob_base[pcie_id];

	for (i = 0; i < LSX_PCIE_DW_OB_WINS_NUM; i++) {
		if (pci_addr >= ob_shared_win->bus_start &&
			(pci_addr + size) <= ob_shared_win->bus_end) {
			ob_shared_win->ref_count++;
			ob_addr = ob_base + ob_shared_win->offset;
			break;
		}
		ob_shared_win++;
	}

	if (ob_addr) {
		f_dw_cfg = fopen(PCIEP_DW_GLOBE_INFO_F, "wb");
		if (!f_dw_cfg) {
			LSX_PCIEP_BUS_ERR("%s: %s write open failed",
				__func__, PCIEP_DW_GLOBE_INFO_F);
			free(info);
			rte_spinlock_unlock(&s_f_lock);
			return 0;
		}
		f_ret = fwrite(info, sizeof(struct pciep_dw_info),
			1, f_dw_cfg);
		if (f_ret != 1) {
			LSX_PCIEP_BUS_ERR("%s write failed",
				PCIEP_DW_GLOBE_INFO_F);
			free(info);
			fclose(f_dw_cfg);
			rte_spinlock_unlock(&s_f_lock);
			return 0;
		}
		fclose(f_dw_cfg);
		g_dw_proc_info[pcie_id].ob_shared_idx[*shared_nb] = i;
		(*shared_nb)++;
	}

	free(info);
	rte_spinlock_unlock(&s_f_lock);

	return ob_addr;
}

static int
pcie_dw_add_shared_ob_space(int pcie_id,
	uint64_t pci_addr, uint64_t size, uint64_t cpu_addr,
	int win_id)
{
	FILE *f_dw_cfg;
	size_t f_ret;
	struct pciep_dw_info *info;
	struct pciep_dw_shared_ob_win *ob_shared_win;
	uint64_t ob_base;
	int *shared_nb = &g_dw_proc_info[pcie_id].ob_shared_nb;

	rte_spinlock_lock(&s_f_lock);
	f_dw_cfg = fopen(PCIEP_DW_GLOBE_INFO_F, "rb");
	if (!f_dw_cfg) {
		LSX_PCIEP_BUS_ERR("%s: %s read open failed",
			__func__, PCIEP_DW_GLOBE_INFO_F);
		rte_spinlock_unlock(&s_f_lock);
		return -ENODEV;
	}

	info = malloc(sizeof(struct pciep_dw_info));
	if (!info) {
		LSX_PCIEP_BUS_ERR("%s prepare buf for read %s failed",
			__func__,
			PCIEP_DW_GLOBE_INFO_F);
		fclose(f_dw_cfg);
		rte_spinlock_unlock(&s_f_lock);
		return -ENOMEM;
	}

	memset(info, 0, sizeof(struct pciep_dw_info));

	f_ret = fread(info, sizeof(struct pciep_dw_info),
			1, f_dw_cfg);
	fclose(f_dw_cfg);
	if (f_ret != 1) {
		LSX_PCIEP_BUS_ERR("%s: %s read failed",
			__func__, PCIEP_DW_GLOBE_INFO_F);
		free(info);
		rte_spinlock_unlock(&s_f_lock);
		return -EIO;
	}

	ob_shared_win = &info->shared_ob_win[pcie_id][win_id];
	ob_base = info->ob_base[pcie_id];

	ob_shared_win->bus_start = pci_addr;
	ob_shared_win->bus_end = pci_addr + size;
	ob_shared_win->offset = cpu_addr - ob_base;
	ob_shared_win->ref_count++;

	f_dw_cfg = fopen(PCIEP_DW_GLOBE_INFO_F, "wb");
	if (!f_dw_cfg) {
		LSX_PCIEP_BUS_ERR("%s: %s write open failed",
			__func__, PCIEP_DW_GLOBE_INFO_F);
		rte_spinlock_unlock(&s_f_lock);
		return -ENODEV;
	}

	f_ret = fwrite(info, sizeof(struct pciep_dw_info),
		1, f_dw_cfg);
	if (f_ret != 1) {
		LSX_PCIEP_BUS_ERR("%s write failed",
			PCIEP_DW_GLOBE_INFO_F);
		fclose(f_dw_cfg);
		rte_spinlock_unlock(&s_f_lock);
		return -EIO;
	}
	fclose(f_dw_cfg);

	g_dw_proc_info[pcie_id].ob_shared_idx[*shared_nb] = win_id;
	(*shared_nb)++;
	rte_spinlock_unlock(&s_f_lock);

	return 0;
}

static void
pcie_dw_disable_ob_win(struct lsx_pciep_hw_low *hw,
	int idx)
{
	struct pcie_dw_iatu_region *iatu;
	int loop;

	iatu = (void *)(hw->dbi_vir + LSX_PCIE_DW_IATU_REGION_OFFSET);

	if (idx >= 0) {
		rte_write32(PCIE_DW_ATU_VP_REGION_OUTBOUND | idx,
			&iatu->view_port);
		rte_write32(0, &iatu->base_addr[ADDR_LOW]);
		rte_write32(0, &iatu->base_addr[ADDR_UP]);
		rte_write32(0, &iatu->base_limit);
		rte_write32(0, &iatu->bus_addr[ADDR_LOW]);
		rte_write32(0, &iatu->bus_addr[ADDR_UP]);
		rte_write32(PCIE_DW_ATU_CTL1_TYPE_MEM, &iatu->ctl1_ob);
		rte_write32(0, &iatu->ctl3_ob);
		rte_write32(0, &iatu->ctl2_ob);
	} else {
		for (loop = 0; loop < LSX_PCIE_DW_OB_WINS_NUM; loop++) {
			rte_write32(PCIE_DW_ATU_VP_REGION_OUTBOUND | loop,
				&iatu->view_port);
			rte_write32(0, &iatu->base_addr[ADDR_LOW]);
			rte_write32(0, &iatu->base_addr[ADDR_UP]);
			rte_write32(0, &iatu->base_limit);
			rte_write32(0, &iatu->bus_addr[ADDR_LOW]);
			rte_write32(0, &iatu->bus_addr[ADDR_UP]);
			rte_write32(PCIE_DW_ATU_CTL1_TYPE_MEM, &iatu->ctl1_ob);
			rte_write32(0, &iatu->ctl3_ob);
			rte_write32(0, &iatu->ctl2_ob);
		}
	}
}

static uint64_t
pcie_dw_map_ob_win(struct lsx_pciep_hw_low *hw,
	int pf, int is_vf, int vf,
	uint64_t pci_addr,
	uint64_t size, int shared)
{
	struct pcie_dw_iatu_region *iatu;
	int win_id, ob_nb;
	uint64_t cpu_addr;
	uint64_t pcie_id = hw->index;
	uint32_t ctrl1, ctrl2, ctrl3 = 0;
	struct pciep_dw_proc_info *proc_info;

	if (!hw->is_sriov && (pf > PF0_IDX || is_vf)) {
		LSX_PCIEP_BUS_ERR("%s: PCIe%d is NONE-SRIOV",
			__func__, hw->index);
		return 0;
	}

	if (shared) {
		cpu_addr = pcie_dw_find_shared_ob_space(pcie_id,
			pci_addr, size);
		if (cpu_addr)
			return cpu_addr;
	}

	win_id = pcie_dw_alloc_win_idx(pcie_id, DW_OUTBOUND_WIN);
	if (win_id < 0)
		return 0;

	cpu_addr = pcie_dw_alloc_ob_space(pcie_id, size);

	ctrl1 = PCIE_DW_ATU_CTL1_TYPE_MEM | (pf << PCIE_DW_ATU_CTL1_FUNC_SHIFT);
	ctrl2 = PCIE_DW_ATU_CTL2_EN;
	if (is_vf)
		ctrl3 = PCIE_DW_ATU_CTL3_VF_ACTIVE_EN | vf;

	if (shared) {
		if (pcie_dw_add_shared_ob_space(pcie_id,
			pci_addr, size, cpu_addr, win_id)) {
			return 0;
		}
	}

	iatu = (void *)(hw->dbi_vir + LSX_PCIE_DW_IATU_REGION_OFFSET);

	rte_write32(PCIE_DW_ATU_VP_REGION_OUTBOUND | win_id,
		&iatu->view_port);

	rte_write32(lower_32_bits(cpu_addr), &iatu->base_addr[ADDR_LOW]);
	rte_write32(upper_32_bits(cpu_addr), &iatu->base_addr[ADDR_UP]);

	rte_write32(lower_32_bits(cpu_addr + size - 1),
		&iatu->base_limit);

	rte_write32(lower_32_bits(pci_addr), &iatu->bus_addr[ADDR_LOW]);
	rte_write32(upper_32_bits(pci_addr), &iatu->bus_addr[ADDR_UP]);

	rte_write32(ctrl1, &iatu->ctl1_ob);
	if (ctrl3) {
		/* Don't program ctl3 for PF, otherwise,
		 * qdma-PCIe perf drops???
		 */
		rte_write32(ctrl3, &iatu->ctl3_ob);
	}
	rte_write32(ctrl2, &iatu->ctl2_ob);

	if (!is_vf) {
		LSX_PCIEP_BUS_INFO(DWC_OB_PF_INFO_DUMP_FORMAT(hw->index,
			pf, cpu_addr, pci_addr, size, win_id));
	} else {
		LSX_PCIEP_BUS_INFO(DWC_OB_VF_INFO_DUMP_FORMAT(hw->index,
			pf, vf, cpu_addr, pci_addr, size, win_id));
	}

	proc_info = &g_dw_proc_info[hw->index];

	ob_nb = proc_info->ob_nb;

	proc_info->ob_start[ob_nb] = cpu_addr;
	proc_info->ob_idx[ob_nb] = win_id;
	proc_info->ob_nb++;

	return cpu_addr;
}

static int
pcie_dw_set_ob_win(struct lsx_pciep_hw_low *hw,
	int idx, int pf, int is_vf, int vf,
	uint64_t cpu_addr, uint64_t pci_addr,
	uint64_t size)
{
	uint32_t ctrl1, ctrl2, ctrl3 = 0;
	struct pcie_dw_iatu_region *iatu;

	if (!hw->is_sriov && (pf > PF0_IDX || is_vf)) {
		LSX_PCIEP_BUS_ERR("%s: PCIe%d is NONE-SRIOV",
			__func__, hw->index);
		return -EIO;
	}

	ctrl1 = PCIE_DW_ATU_CTL1_TYPE_MEM | (pf << PCIE_DW_ATU_CTL1_FUNC_SHIFT);
	ctrl2 = PCIE_DW_ATU_CTL2_EN;
	if (is_vf)
		ctrl3 = PCIE_DW_ATU_CTL3_VF_ACTIVE_EN | vf;

	iatu = (void *)(hw->dbi_vir + LSX_PCIE_DW_IATU_REGION_OFFSET);

	rte_write32(PCIE_DW_ATU_VP_REGION_OUTBOUND | idx, &iatu->view_port);

	rte_write32(lower_32_bits(cpu_addr), &iatu->base_addr[ADDR_LOW]);
	rte_write32(upper_32_bits(cpu_addr), &iatu->base_addr[ADDR_UP]);

	rte_write32(lower_32_bits(cpu_addr + size - 1),
		&iatu->base_limit);

	rte_write32(lower_32_bits(pci_addr), &iatu->bus_addr[ADDR_LOW]);
	rte_write32(upper_32_bits(pci_addr), &iatu->bus_addr[ADDR_UP]);

	rte_write32(ctrl1, &iatu->ctl1_ob);
	rte_write32(ctrl3, &iatu->ctl3_ob);
	rte_write32(ctrl2, &iatu->ctl2_ob);

	if (!is_vf) {
		LSX_PCIEP_BUS_INFO(DWC_OB_PF_INFO_DUMP_FORMAT(hw->index,
			pf, cpu_addr, pci_addr, size, idx));
	} else {
		LSX_PCIEP_BUS_INFO(DWC_OB_VF_INFO_DUMP_FORMAT(hw->index,
			pf, vf, cpu_addr, pci_addr, size, idx));
	}

	return 0;
}

static int
pcie_dw_set_bar(uint8_t *pf_base, int id, uint64_t size,
	int is_vf, int is_64b, int pref, int is_io)
{
	uint64_t mask, offset;
	uint32_t bar, mask_lo, mask_hi;
	struct pcie_ctrl_bar_size_mask *size_mask;
	struct pcie_ctrl_cfg *cfg;
	int ret = 0;
	uint32_t *bar_cfg;

	if (is_io) {
		if (is_64b) {
			LSX_PCIEP_BUS_ERR("IO bar must be a 32b bar");
			return -EINVAL;
		}
		if (pref) {
			LSX_PCIEP_BUS_ERR("IO bar cannot be prefetchable");
			return -EINVAL;
		}
	}

	if (is_64b && !lsx_pciep_valid_64b_bar_id(id)) {
		LSX_PCIEP_BUS_ERR("Invalid bar pair ID(%d)", id);
		return -EINVAL;
	}
	if (!is_64b && !pcie_dw_32b_bar_support(id)) {
		LSX_PCIEP_BUS_ERR("Invalid bar ID(%d)", id);
		return -EINVAL;
	}
	/* The least inbound window is 4KiB */
	if (size < (LSX_PCIEP_DW_WIN_MASK + 1)) {
		LSX_PCIEP_BUS_ERR("Too small bar size(0x%lx)", size);
		return -EINVAL;
	}

	if (!rte_is_power_of_2(size)) {
		LSX_PCIEP_BUS_ERR("Size(0x%lx) not power of 2", size);
		return -EINVAL;
	}

	mask = size - 1;
	mask_lo = (uint32_t)mask;
	mask_hi = (uint32_t)(mask >> 32);
	cfg = (void *)pf_base;

	if (is_vf)
		offset = LSX_PCIE_DW_VF_BAR_SIZE_MASK_OFFSET;
	else
		offset = LSX_PCIE_DW_PF_BAR_SIZE_MASK_OFFSET;

	size_mask = (void *)(pf_base + offset);

	if (is_64b)
		goto bar_64b_config;

	lsx_pciep_write_config(&size_mask->bar_mask[id],
		&mask_lo, sizeof(uint32_t), 0);
	if (is_vf)
		bar_cfg = &cfg->vfbar[id];
	else
		bar_cfg = &cfg->pfbar[id];
	lsx_pciep_read_config(bar_cfg, &bar, sizeof(uint32_t), 0);
	PCIE_BAR_SET_32B_WIDTH(bar);
	if (is_io) {
		PCIE_BAR_SET_IO_SPACE_IND(bar);
		PCIE_BAR_DISABLE_PREFETCH(bar);
	} else {
		PCIE_BAR_SET_MEM_SPACE_IND(bar);
		if (pref)
			PCIE_BAR_ENABLE_PREFETCH(bar);
		else
			PCIE_BAR_DISABLE_PREFETCH(bar);
	}
	lsx_pciep_write_config(bar_cfg,	&bar, sizeof(uint32_t), 0);

	return ret;

bar_64b_config:

	id = lsx_pciep_64bar_to_32bar(id);
	if (id < 0)
		return id;

	lsx_pciep_write_config(&size_mask->bar_mask[id],
		&mask_lo, sizeof(uint32_t), 0);
	lsx_pciep_write_config(&size_mask->bar_mask[id + 1],
		&mask_hi, sizeof(uint32_t), 0);
	lsx_pciep_read_config(&cfg->pfbar[id],
		&bar, sizeof(uint32_t), 0);
	PCIE_BAR_SET_64B_WIDTH(bar);
	if (pref)
		PCIE_BAR_ENABLE_PREFETCH(bar);
	else
		PCIE_BAR_DISABLE_PREFETCH(bar);
	lsx_pciep_write_config(&cfg->pfbar[id],
		&bar, sizeof(uint32_t), 0);

	return ret;
}

static int
pcie_dw_set_ib_win(struct lsx_pciep_hw_low *hw,
	int pf, int is_vf, int vf, int bar,
	uint64_t phys, uint64_t size, int resize)
{
	uint32_t ctrl1, ctrl2, ctrl3 = 0, tmp;
	int idx, ib_nb, ret, bar_64b;
	struct pciep_dw_proc_info *proc_info;
	struct pcie_dw_iatu_region *iatu;
	void *pf_base;

	if (!hw->is_sriov && (pf > PF0_IDX || is_vf)) {
		LSX_PCIEP_BUS_ERR("%s: PCIe%d is NONE-SRIOV",
			__func__, hw->index);
		return -EIO;
	}

	if (bar >= PCI_MAX_RESOURCE) {
		LSX_PCIEP_BUS_ERR("Invalid bar(%d)", bar);

		return -EIO;
	}

	if (resize) {
		pf_base = hw->dbi_vir + pf * hw->dbi_pf_size;
		tmp = PCIE_DW_DBI_WR_ENA;
		lsx_pciep_write_config(hw->dbi_vir, &tmp, sizeof(uint32_t),
			PCIE_DW_MISC_CONTROL_1_OFF_OFFSET);
		if (pcie_dw_using_32b_bar(bar)) {
			ret = pcie_dw_set_bar(pf_base, bar, size,
				is_vf, 0, 0, 0);
		} else {
			bar_64b = lsx_pciep_32bar_to_64bar(bar);
			if (bar_64b < 0) {
				ret = bar_64b;
			} else {
				ret = pcie_dw_set_bar(pf_base, bar_64b, size,
					is_vf, 1, 1, 0);
			}
		}
		tmp = PCIE_DW_DBI_WR_DIS;
		lsx_pciep_write_config(hw->dbi_vir, &tmp, sizeof(uint32_t),
			PCIE_DW_MISC_CONTROL_1_OFF_OFFSET);
		if (ret) {
			LSX_PCIEP_BUS_ERR("Set IB[%d] size(0x%lx) failed(%d)",
				bar, size, ret);

			return ret;
		}
	}

	idx = pcie_dw_alloc_win_idx(hw->index,
		DW_INBOUND_WIN);
	if (idx < 0) {
		LSX_PCIEP_BUS_ERR("Inbound window alloc failed");

		return -ENOMEM;
	}

	ctrl1 = PCIE_DW_ATU_CTL1_TYPE_MEM | (pf << PCIE_DW_ATU_CTL1_FUNC_SHIFT);

	ctrl2 = PCIE_DW_ATU_CTL2_EN |
		PCIE_DW_ATU_CTL2_BAR_MODE_EN |
		PCIE_DW_ATU_CTL2_BAR_NUM(bar) |
		PCIE_DW_ATU_CTL2_FUNC_NUM_MATCH_EN;
	if (is_vf) {
		ctrl2 |= PCIE_DW_ATU_CTL2_VF_MATCH_MODE_EN;
		ctrl3 = PCIE_DW_ATU_CTL3_VF_ACTIVE_EN | vf;
	}

	iatu = (void *)(hw->dbi_vir + LSX_PCIE_DW_IATU_REGION_OFFSET);

	rte_write32(PCIE_DW_ATU_VP_REGION_INBOUND | idx,
		&iatu->view_port);

	rte_write32(lower_32_bits(phys), &iatu->bus_addr[ADDR_LOW]);
	rte_write32(upper_32_bits(phys), &iatu->bus_addr[ADDR_UP]);

	rte_write32(ctrl1, &iatu->ctl1_ib);
	rte_write32(ctrl3, &iatu->ctl3_ib);
	rte_write32(ctrl2, &iatu->ctl2_ib);

	if (!is_vf) {
		LSX_PCIEP_BUS_INFO(DWC_IB_PF_INFO_DUMP_FORMAT(hw->index,
			pf, phys, bar, size, idx));
	} else {
		LSX_PCIEP_BUS_INFO(DWC_IB_VF_INFO_DUMP_FORMAT(hw->index,
			pf, vf, phys, bar, size, idx));
	}

	proc_info = &g_dw_proc_info[hw->index];

	ib_nb = proc_info->ib_nb;

	proc_info->ib_idx[ib_nb] = idx;
	proc_info->ib_nb++;

	return 0;
}

static void
pcie_dw_disable_ib_win(struct lsx_pciep_hw_low *hw, int idx)
{
	struct pcie_dw_iatu_region *iatu;
	int loop;

	iatu = (void *)(hw->dbi_vir + LSX_PCIE_DW_IATU_REGION_OFFSET);
	if (idx >= 0) {
		rte_write32(PCIE_DW_ATU_VP_REGION_INBOUND | idx,
			&iatu->view_port);
		rte_write32(0, &iatu->bus_addr[ADDR_LOW]);
		rte_write32(0, &iatu->bus_addr[ADDR_UP]);
		rte_write32(PCIE_DW_ATU_CTL1_TYPE_MEM, &iatu->ctl1_ib);
		rte_write32(0, &iatu->ctl3_ib);
		rte_write32(0, &iatu->ctl2_ib);
	} else {
		for (loop = 0; loop < LSX_PCIE_DW_IB_WINS_NUM; loop++) {
			rte_write32(PCIE_DW_ATU_VP_REGION_INBOUND | loop,
				&iatu->view_port);
			rte_write32(0, &iatu->bus_addr[ADDR_LOW]);
			rte_write32(0, &iatu->bus_addr[ADDR_UP]);
			rte_write32(PCIE_DW_ATU_CTL1_TYPE_MEM, &iatu->ctl1_ib);
			rte_write32(0, &iatu->ctl3_ib);
			rte_write32(0, &iatu->ctl2_ib);
		}
	}
}

static int
pcie_dw_msix_init(struct lsx_pciep_hw_low *hw,
	int pf, int is_vf, int vf,
	uint64_t msg_addr[], uint32_t msg_data[],
	int vector_total)
{
	struct pcie_ctrl_cfg *cfg;
	uint64_t maddr, phy_addr, doorbell_addr;
	uint32_t maddr_32;
	uint16_t mdata;
	int vector;

	if (hw->msi_flag == LSX_PCIEP_DONT_INT)
		return 0;

	if (!hw->is_sriov && (pf > PF0_IDX || is_vf)) {
		LSX_PCIEP_BUS_ERR("%s: PCIe%d is NONE-SRIOV",
			__func__, hw->index);
		return 0;
	}

	doorbell_addr = hw->dbi_phy + PCIE_DW_MSIX_DOORBELL_REG;

	if (hw->msi_flag == LSX_PCIEP_MSIX_INT) {
		if (!hw->is_sriov) {
			LSX_PCIEP_BUS_ERR("PCIe%d (NONE-SRIOV) %s",
				hw->index,
				"does not support MSI-X");
			return 0;
		}
		if (is_vf) {
			mdata = pf << PCIE_DW_MSIX_DOORBELL_PF_SHIFT |
				vf << PCIE_DW_MSIX_DOORBELL_VF_SHIFT |
				PCIE_DW_MSIX_DOORBELL_VF_ACTIVE;
		} else {
			mdata = pf << PCIE_DW_MSIX_DOORBELL_PF_SHIFT;
		}
		for (vector = 0; vector < vector_total; vector++) {
			msg_addr[vector] = doorbell_addr;
			msg_data[vector] = mdata | vector;
		}
	} else if (hw->msi_flag == LSX_PCIEP_MMSI_INT) {
		cfg = (void *)(hw->dbi_vir + pf * hw->dbi_pf_size);
		lsx_pciep_read_config(&cfg->msi_addr_high,
			&maddr_32, sizeof(uint32_t), 0);
		maddr = maddr_32;
		maddr = maddr << 32;
		lsx_pciep_read_config(&cfg->msi_addr_low,
			&maddr_32, sizeof(uint32_t), 0);
		maddr |= maddr_32;
		lsx_pciep_read_config(&cfg->msi_data,
			&mdata, sizeof(uint16_t), 0);

		if (hw->ob_policy != LSX_PCIEP_OB_SHARE) {
			phy_addr = pcie_dw_map_ob_win(hw, pf, is_vf, vf,
				maddr, CFG_MSIX_OB_SIZE, 0);
		} else {
			phy_addr = hw->out_base + maddr;
		}
		for (vector = 0; vector < vector_total; vector++) {
			msg_addr[vector] = phy_addr;
			msg_data[vector] = mdata + vector;
		}
	}

	return vector_total;
}

static int
pcie_dw_fun_init(struct lsx_pciep_hw_low *hw,
	int pf, int is_vf, uint16_t vendor_id,
	uint16_t device_id, uint16_t class_id)
{
	struct pcie_ctrl_cfg *cfg;
	uint32_t tmp;

	if (!hw->is_sriov && (pf > PF0_IDX || is_vf)) {
		LSX_PCIEP_BUS_ERR("%s: PCIe%d is NONE-SRIOV",
			__func__, hw->index);
		return -EIO;
	}

	tmp = PCIE_DW_DBI_WR_ENA;
	lsx_pciep_write_config(hw->dbi_vir, &tmp,
		sizeof(uint32_t),
		PCIE_DW_MISC_CONTROL_1_OFF_OFFSET);

	cfg = (void *)(hw->dbi_vir + pf * hw->dbi_pf_size);
	if (!is_vf) {
		lsx_pciep_write_config(&cfg->vendor_id,
			&vendor_id, sizeof(uint16_t), 0);
		lsx_pciep_write_config(&cfg->device_id,
			&device_id, sizeof(uint16_t), 0);
		lsx_pciep_write_config(&cfg->class_id,
			&class_id, sizeof(uint16_t), 0);
	} else {
		lsx_pciep_write_config(&cfg->vf_dev_id,
			&device_id, sizeof(uint16_t), 0);
	}

	tmp = PCIE_DW_DBI_WR_DIS;
	lsx_pciep_write_config(hw->dbi_vir, &tmp,
		sizeof(uint32_t),
		PCIE_DW_MISC_CONTROL_1_OFF_OFFSET);

	return 0;
}

static int
pcie_dw_fun_init_ext(struct lsx_pciep_hw_low *hw,
	int pf, uint16_t sub_vendor_id, uint16_t sub_device_id)
{
	struct pcie_ctrl_cfg *cfg;
	uint32_t tmp;

	if (!hw->is_sriov && pf > PF0_IDX) {
		LSX_PCIEP_BUS_ERR("%s: PCIe%d is NONE-SRIOV",
			__func__, hw->index);
		return -EIO;
	}

	if (pf != PF0_IDX && pf != PF1_IDX) {
		LSX_PCIEP_BUS_ERR("%s: Invalid PF ID(%d)",
			__func__, pf);
		return -EIO;
	}

	tmp = PCIE_DW_DBI_WR_ENA;
	lsx_pciep_write_config(hw->dbi_vir, &tmp,
		sizeof(uint32_t),
		PCIE_DW_MISC_CONTROL_1_OFF_OFFSET);

	cfg = (void *)(hw->dbi_vir + pf * hw->dbi_pf_size);
	if (sub_vendor_id && sub_vendor_id != RTE_PCI_ANY_ID) {
		lsx_pciep_write_config(&cfg->sub_vendor_id,
			&sub_vendor_id, sizeof(uint16_t), 0);
	}
	if (sub_device_id && sub_device_id != RTE_PCI_ANY_ID) {
		lsx_pciep_write_config(&cfg->sub_device_id,
			&sub_device_id, sizeof(uint16_t), 0);
	}

	tmp = PCIE_DW_DBI_WR_DIS;
	lsx_pciep_write_config(hw->dbi_vir, &tmp,
		sizeof(uint32_t),
		PCIE_DW_MISC_CONTROL_1_OFF_OFFSET);

	return 0;
}

static uint64_t
pcie_dw_ob_unmapped(struct lsx_pciep_hw_low *hw)
{
	FILE *f_dw_cfg;
	size_t f_ret;
	uint64_t offset, cpu_addr;
	struct pciep_dw_info *info;

	rte_spinlock_lock(&s_f_lock);
	f_dw_cfg = fopen(PCIEP_DW_GLOBE_INFO_F, "rb");
	if (!f_dw_cfg) {
		LSX_PCIEP_BUS_ERR("%s: %s read open failed",
			__func__, PCIEP_DW_GLOBE_INFO_F);
		rte_spinlock_unlock(&s_f_lock);
		return 0;
	}

	info = malloc(sizeof(struct pciep_dw_info));
	if (!info) {
		LSX_PCIEP_BUS_ERR("%s prepare buf for read %s failed",
			__func__,
			PCIEP_DW_GLOBE_INFO_F);
		fclose(f_dw_cfg);
		rte_spinlock_unlock(&s_f_lock);
		return 0;
	}

	memset(info, 0, sizeof(struct pciep_dw_info));

	f_ret = fread(info, sizeof(struct pciep_dw_info),
			1, f_dw_cfg);
	fclose(f_dw_cfg);
	if (f_ret != 1) {
		LSX_PCIEP_BUS_ERR("%s: %s read failed",
			__func__, PCIEP_DW_GLOBE_INFO_F);
		free(info);
		rte_spinlock_unlock(&s_f_lock);
		return 0;
	}

	cpu_addr = info->ob_base[hw->index];
	offset = info->ob_offset[hw->index];

	free(info);
	rte_spinlock_unlock(&s_f_lock);

	return cpu_addr + offset;
}

static void
pcie_dw_config(struct lsx_pciep_hw_low *hw)
{
	FILE *f_dw_cfg;
	size_t f_ret;
	uint8_t pcie_id = hw->index;
	struct pciep_dw_info *info;

	info = malloc(sizeof(struct pciep_dw_info));
	if (!info) {
		LSX_PCIEP_BUS_ERR("%s prepare buf for read %s failed",
			__func__,
			PCIEP_DW_GLOBE_INFO_F);
		return;
	}

	memset(info, 0, sizeof(struct pciep_dw_info));

	rte_spinlock_lock(&s_f_lock);
	f_dw_cfg = fopen(PCIEP_DW_GLOBE_INFO_F, "rb");
	if (f_dw_cfg) {
		f_ret = fread(info, sizeof(struct pciep_dw_info),
			1, f_dw_cfg);
		if (f_ret != 1) {
			LSX_PCIEP_BUS_ERR("%s: %s read failed",
				__func__, PCIEP_DW_GLOBE_INFO_F);
			fclose(f_dw_cfg);
			rte_spinlock_unlock(&s_f_lock);
			return;
		}
		fclose(f_dw_cfg);
	} else {
		info->dbi_phy[pcie_id] = hw->dbi_phy;
		info->ob_base[pcie_id] = hw->out_base;
		info->ob_max_size = CFG_32G_SIZE;
		info->ob_win_max_size = CFG_4G_SIZE;
		info->win_mask = LSX_PCIEP_DW_WIN_MASK;
		s_f_create = 1;
	}

	hw->dbi_phy = info->dbi_phy[pcie_id];
	hw->out_base = info->ob_base[pcie_id];
	hw->out_size = info->ob_max_size;
	hw->out_win_max_size = info->ob_win_max_size;
	hw->win_mask = info->win_mask;

	f_dw_cfg = fopen(PCIEP_DW_GLOBE_INFO_F, "wb");
	f_ret = fwrite(info, sizeof(struct pciep_dw_info),
		1, f_dw_cfg);
	if (f_ret != 1) {
		LSX_PCIEP_BUS_ERR("%s: %s write failed",
			__func__, PCIEP_DW_GLOBE_INFO_F);
	}
	fclose(f_dw_cfg);
	rte_spinlock_unlock(&s_f_lock);
}

static int
pcie_dw_info_empty(struct pciep_dw_info *info)
{
	int i, j;
	int empty = 1;

	for (i = 0; i < LSX_MAX_PCIE_NB; i++) {
		for (j = 0; j < LSX_PCIE_DW_OB_WINS_NUM; j++) {
			if (info->ob_win_used[i][j]) {
				empty = 0;
				goto finish_check;
			}
			if (info->priv_ob_win[i][j].using) {
				empty = 0;
				goto finish_check;
			}
			if (info->shared_ob_win[i][j].ref_count) {
				empty = 0;
				goto finish_check;
			}
		}
		for (j = 0; j < LSX_PCIE_DW_IB_WINS_NUM; j++) {
			if (info->ib_win_used[i][j]) {
				empty = 0;
				goto finish_check;
			}
		}
	}

finish_check:
	return empty;
}

static int
pcie_dw_proc_info_empty(struct lsx_pciep_hw_low *hw)
{
	struct pciep_dw_proc_info *proc_info;

	proc_info = &g_dw_proc_info[hw->index];
	if (!proc_info->ob_nb && !proc_info->ob_shared_nb &&
		!proc_info->ib_nb)
		return 1;

	return 0;
}

static void
pcie_dw_deconfig(struct lsx_pciep_hw_low *hw)
{
	int i, idx, j, ret;
	size_t f_ret;
	FILE *f_dw_cfg;
	struct pciep_dw_proc_info *proc_info;
	struct pciep_dw_info *info;
	uint64_t phy_start;

	rte_spinlock_lock(&s_f_lock);
	if (pcie_dw_proc_info_empty(hw)) {
		if (!s_f_create) {
			rte_spinlock_unlock(&s_f_lock);
			return;
		}
	}

	f_dw_cfg = fopen(PCIEP_DW_GLOBE_INFO_F, "rb");
	if (!f_dw_cfg) {
		if (pcie_dw_proc_info_empty(hw))
			return;
		LSX_PCIEP_BUS_ERR("%s: %s read open failed",
			__func__, PCIEP_DW_GLOBE_INFO_F);
		rte_spinlock_unlock(&s_f_lock);
		return;
	}

	info = malloc(sizeof(struct pciep_dw_info));
	if (!info) {
		LSX_PCIEP_BUS_ERR("%s prepare buf for read %s failed",
			__func__,
			PCIEP_DW_GLOBE_INFO_F);
		fclose(f_dw_cfg);
		rte_spinlock_unlock(&s_f_lock);
		return;
	}

	memset(info, 0, sizeof(struct pciep_dw_info));

	f_ret = fread(info, sizeof(struct pciep_dw_info),
			1, f_dw_cfg);
	fclose(f_dw_cfg);
	if (f_ret != 1) {
		LSX_PCIEP_BUS_ERR("%s: %s read (%ldB) failed (%ld)",
			__func__, PCIEP_DW_GLOBE_INFO_F,
			sizeof(struct pciep_dw_info), f_ret);
		free(info);
		rte_spinlock_unlock(&s_f_lock);
		return;
	}

	proc_info = &g_dw_proc_info[hw->index];
	for (i = 0; i < proc_info->ob_nb; i++) {
		idx = proc_info->ob_idx[i];
		phy_start = proc_info->ob_start[i];
		info->ob_win_used[hw->index][idx] = 0;
		for (j = 0; j < LSX_PCIE_DW_OB_WINS_NUM; j++) {
			if (info->priv_ob_win[hw->index][j].using &&
				info->priv_ob_win[hw->index][j].phy_start ==
				phy_start) {
				info->priv_ob_win[hw->index][j].using = 0;
			}
		}
	}
	for (i = 0; i < proc_info->ib_nb; i++) {
		idx = proc_info->ib_idx[i];
		info->ib_win_used[hw->index][idx] = 0;
	}

	for (i = 0; i < proc_info->ob_shared_nb; i++) {
		idx = proc_info->ob_shared_idx[i];
		info->shared_ob_win[hw->index][idx].ref_count--;
	}

	memset(proc_info, 0, sizeof(struct pciep_dw_proc_info));
	if (pcie_dw_info_empty(info)) {
		if (access(PCIEP_DW_GLOBE_INFO_F, F_OK) != -1) {
			ret = remove(PCIEP_DW_GLOBE_INFO_F);
			if (ret) {
				LSX_PCIEP_BUS_ERR("%s removed failed",
					PCIEP_DW_GLOBE_INFO_F);
			}
		}
		free(info);
		rte_spinlock_unlock(&s_f_lock);
		return;
	}

	f_dw_cfg = fopen(PCIEP_DW_GLOBE_INFO_F, "wb");
	if (!f_dw_cfg) {
		LSX_PCIEP_BUS_ERR("%s: %s write open failed",
			__func__, PCIEP_DW_GLOBE_INFO_F);
		free(info);
		rte_spinlock_unlock(&s_f_lock);
		return;
	}

	f_ret = fwrite(info, sizeof(struct pciep_dw_info),
		1, f_dw_cfg);
	if (f_ret != 1) {
		LSX_PCIEP_BUS_ERR("%s write failed",
			PCIEP_DW_GLOBE_INFO_F);
	}
	fclose(f_dw_cfg);
	free(info);
	rte_spinlock_unlock(&s_f_lock);
}

static int
pcie_dw_is_sriov(struct lsx_pciep_hw_low *hw)
{
	struct pcie_ctrl_cfg *cfg;
	uint32_t dev_cap_reg = 0;

	cfg = (void *)hw->dbi_vir;
	lsx_pciep_read_config(&cfg->dev_cap,
		&dev_cap_reg, sizeof(uint32_t), 0);
	if (dev_cap_reg & PCIE_FUN_RESET_SRIOV_CAP)
		hw->is_sriov = 1;
	else
		hw->is_sriov = 0;
	LSX_PCIEP_BUS_INFO("PCIe%d is %s controller",
		hw->index,
		hw->is_sriov ? "SRIOV" : "NONE SRIOV");

	return hw->is_sriov;
}

static struct lsx_pciep_ops pcie_dw_ops = {
	.pcie_config = pcie_dw_config,
	.pcie_deconfig = pcie_dw_deconfig,
	.pcie_fun_init = pcie_dw_fun_init,
	.pcie_fun_init_ext = pcie_dw_fun_init_ext,
	.pcie_disable_ob_win = pcie_dw_disable_ob_win,
	.pcie_disable_ib_win = pcie_dw_disable_ib_win,
	.pcie_map_ob_win = pcie_dw_map_ob_win,
	.pcie_cfg_ob_win = pcie_dw_set_ob_win,
	.pcie_cfg_ib_win = pcie_dw_set_ib_win,
	.pcie_msix_cfg = pcie_dw_msix_init,
	.pcie_get_ob_unmapped = pcie_dw_ob_unmapped,
	.pcie_is_sriov = pcie_dw_is_sriov,
};

struct lsx_pciep_ops *lsx_pciep_get_dw_ops(void)
{
	return &pcie_dw_ops;
}
