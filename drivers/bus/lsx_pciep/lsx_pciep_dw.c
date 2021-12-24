/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020-2021 NXP
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
#include <rte_ethdev.h>
#include <rte_io.h>
#include <linux/pci_regs.h>

#include "lsx_pciep_ctrl.h"

#define PCIE_PF1_LS2_DBI_OFF		0x20000
#define PCIE_PF1_LX2_DBI_OFF		0x8000

#define PCIE_DBI_RO_WR_EN       (0x8bc)
#define PCIE_CFG_OFFSET		(0x8000)

#define PCIE_DW_OB_WINS_NUM	(256)
#define PCIE_DW_IB_WINS_NUM	(24)

#define PCIE_DW_IB_FUN_IDX(pf, is_vf) \
	(((uint8_t)pf) << 1 | (uint8_t)is_vf)

#define PCIE_MSI_MSG_LADDR_OFF		0x54
#define PCIE_MSI_MSG_HADDR_OFF		0x58
#define PCIE_MSI_MSG_DATA_OFF		0x5c

#ifndef __packed
#define __packed	__rte_packed
#endif

#define PCIE_PF_SIZE_OFF 0x1000

#define PCIE_VF_SIZE_OFF (PCIE_PF_SIZE_OFF + 0x18c)

struct pcie_dw_bar_size_mask {
	uint32_t rsv[4];
	uint32_t bar0_mask;
	uint32_t bar1_mask;
	uint32_t bar2_mask;
	uint32_t bar3_mask;
	uint32_t bar4_mask;
	uint32_t bar5_mask;
} __packed;

struct pcie_dw_cap {
	uint16_t vendor_id;
	uint16_t device_id;
	uint16_t control_reg;
	uint16_t status_reg;
	uint8_t rev_id;
	uint8_t prog;
	uint16_t class_id;
	uint8_t cache_line;
	uint8_t latency_timer;
	uint8_t header_type;
	uint8_t rsv0;
	uint32_t pfbar0;
	uint32_t pfbar1;
	uint32_t pfbar2;
	uint32_t pfbar3;
	uint32_t pfbar4;
	uint32_t pfbar5;
} __packed;

#define PCIE_DW_EXT_CAP_OFFSET 0x178

struct pcie_dw_ext_cap {
	uint32_t extend_cap_header;
	uint32_t cap_reg;
	uint16_t control_reg;
	uint16_t status_reg;
	uint16_t init_vf;
	uint16_t total_vf;
	uint16_t number_vf;
	uint8_t link_reg;
	uint8_t rsv0;
	uint16_t first_vf_off;
	uint16_t vf_stride;
	uint16_t rsv1;
	uint16_t vf_dev_id;
	uint32_t sup_page_size;
	uint32_t sys_page_size;
	uint32_t vfbar0;
	uint32_t vfbar1;
	uint32_t vfbar2;
	uint32_t vfbar3;
	uint32_t vfbar4;
	uint32_t vfbar5;
} __packed;

#define PCIE_MISC_CONTROL_1_OFF		0x8bc

#define PCIE_ATU_VIEWPORT		0x900
#define PCIE_ATU_REGION_INBOUND		(0x1 << 31)
#define PCIE_ATU_REGION_OUTBOUND	(0x0 << 31)
#define PCIE_ATU_CR1			0x904
#define PCIE_ATU_CR2			0x908
#define PCIE_ATU_ENABLE			(0x1 << 31)
#define PCIE_ATU_BAR_MODE_ENABLE	(0x1 << 30)
#define PCIE_ATU_LOWER_BASE		0x90C
#define PCIE_ATU_UPPER_BASE		0x910
#define PCIE_ATU_LIMIT			0x914
#define PCIE_ATU_LOWER_TARGET		0x918
#define PCIE_ATU_UPPER_TARGET		0x91C
#define PCIE_FUNC_NUM_MATCH_EN		(0x00080000)
#define PCIE_VFBAR_MATCH_MODE_EN	(0x04000000)

#define PCIE_CTRL1_FUNC_SHIFT		(20)

#define PCIE_ATU_TYPE_MEM		(0x0 << 0)

#define PCIE_ATU_BAR_NUM(bar)		((bar) << 8)

#define MSIX_DOORBELL_REG		0x948
#define MSIX_DOORBELL_PF_SHIFT		24
#define MSIX_DOORBELL_VF_SHIFT		16
#define MSIX_DOORBELL_VF_ACTIVE		0x8000

enum dw_win_type {
	DW_OUTBOUND_WIN,
	DW_INBOUND_WIN
};

#define PCIEP_DW_GLOBE_INFO_F "/tmp/pciep_dw_globe_info"

struct pciep_dw_globe_info {
	uint64_t dbi_phy[LSX_MAX_PCIE_NB];
	int ob_win_used[LSX_MAX_PCIE_NB][PCIE_DW_OB_WINS_NUM];
	int ib_win_used[LSX_MAX_PCIE_NB][PCIE_DW_IB_WINS_NUM];
	uint64_t ob_base[LSX_MAX_PCIE_NB];
	uint64_t ob_offset[LSX_MAX_PCIE_NB];
	uint64_t ob_max_size;
	uint64_t ob_win_max_size;
};

struct pciep_dw_globe_info *g_dw_globe_info;

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

static inline uint32_t pcie_dw_route_fun_id(uint8_t *base,
	int pf, int is_vf, int vf)
{
	struct pcie_dw_ext_cap *ext_cap;
	uint16_t off, stride;

	if (is_vf) {
		ext_cap = (struct pcie_dw_ext_cap *)
			(base + PCIE_DW_EXT_CAP_OFFSET);
		off = rte_read16(&ext_cap->first_vf_off);
		stride = rte_read16(&ext_cap->vf_stride);

		return pf + off + vf * stride;
	} else {
		return pf;
	}
}

static int pcie_dw_alloc_win_idx(int pcie_id,
	enum dw_win_type win_type)
{
	int i, max_nb;
	int *pwin;
	FILE *f_dw_cfg;
	size_t f_ret;

	if (pcie_id >= LSX_MAX_PCIE_NB)
		return -EINVAL;

	f_dw_cfg = fopen(PCIEP_DW_GLOBE_INFO_F, "rb");
	if (!f_dw_cfg) {
		LSX_PCIEP_BUS_ERR("%s: %s read open failed",
			__func__, PCIEP_DW_GLOBE_INFO_F);
		return -ENODEV;
	}
	if (!g_dw_globe_info) {
		g_dw_globe_info = malloc(sizeof(struct pciep_dw_globe_info));
		memset(g_dw_globe_info, 0,
			sizeof(struct pciep_dw_globe_info));
	}

	f_ret = fread(g_dw_globe_info,
			sizeof(struct pciep_dw_globe_info),
			1, f_dw_cfg);
	fclose(f_dw_cfg);
	if (f_ret != 1) {
		LSX_PCIEP_BUS_ERR("%s: %s read (%ldB) failed (%ld)",
			__func__, PCIEP_DW_GLOBE_INFO_F,
			sizeof(struct pciep_dw_globe_info), f_ret);
		return -ENODEV;
	}

	f_dw_cfg = fopen(PCIEP_DW_GLOBE_INFO_F, "wb");
	if (!f_dw_cfg) {
		LSX_PCIEP_BUS_ERR("%s: %s write open failed",
			__func__, PCIEP_DW_GLOBE_INFO_F);
		return -ENODEV;
	}

	if (win_type == DW_OUTBOUND_WIN) {
		max_nb = PCIE_DW_OB_WINS_NUM;
		pwin = &g_dw_globe_info->ob_win_used[pcie_id][0];
	} else {
		max_nb = PCIE_DW_IB_WINS_NUM;
		pwin = &g_dw_globe_info->ib_win_used[pcie_id][0];
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
		return -ENODEV;
	}
	f_ret = fwrite(g_dw_globe_info,
		sizeof(struct pciep_dw_globe_info),
		1, f_dw_cfg);
	if (f_ret != 1) {
		LSX_PCIEP_BUS_ERR("%s write failed",
			PCIEP_DW_GLOBE_INFO_F);
		return -ENODEV;
	}
	fclose(f_dw_cfg);

	return i;
}

static uint64_t
pcie_dw_alloc_ob_space(int pcie_id,
	uint64_t size)
{
	FILE *f_dw_cfg;
	size_t f_ret;
	uint64_t max_size, offset, cpu_addr;

	f_dw_cfg = fopen(PCIEP_DW_GLOBE_INFO_F, "rb");
	if (!f_dw_cfg) {
		LSX_PCIEP_BUS_ERR("%s: %s read open failed",
			__func__, PCIEP_DW_GLOBE_INFO_F);
		return -ENODEV;
	}

	if (!g_dw_globe_info) {
		g_dw_globe_info = malloc(sizeof(struct pciep_dw_globe_info));
		memset(g_dw_globe_info, 0,
			sizeof(struct pciep_dw_globe_info));
	}

	f_ret = fread(g_dw_globe_info,
			sizeof(struct pciep_dw_globe_info),
			1, f_dw_cfg);
	fclose(f_dw_cfg);
	if (f_ret != 1) {
		LSX_PCIEP_BUS_ERR("%s: %s read failed",
			__func__, PCIEP_DW_GLOBE_INFO_F);
		return 0;
	}

	f_dw_cfg = fopen(PCIEP_DW_GLOBE_INFO_F, "wb");
	if (!f_dw_cfg) {
		LSX_PCIEP_BUS_ERR("%s: %s write open failed",
			__func__, PCIEP_DW_GLOBE_INFO_F);
		return -ENODEV;
	}

	max_size = g_dw_globe_info->ob_max_size;
	offset = g_dw_globe_info->ob_offset[pcie_id];
	if (offset + size > max_size) {
		char err_str[128];

		sprintf(err_str,
			"offset(0x%lx) + size(0x%lx) > max(0x%lx)",
			offset, size, max_size);
		LSX_PCIEP_BUS_ERR("map failed: %s",
			err_str);
		fclose(f_dw_cfg);
		return 0;
	}

	cpu_addr = g_dw_globe_info->ob_base[pcie_id] +
		g_dw_globe_info->ob_offset[pcie_id];

	g_dw_globe_info->ob_offset[pcie_id] += size;
	f_ret = fwrite(g_dw_globe_info,
		sizeof(struct pciep_dw_globe_info),
		1, f_dw_cfg);
	if (f_ret != 1) {
		LSX_PCIEP_BUS_ERR("%s write failed",
			PCIEP_DW_GLOBE_INFO_F);
	}
	fclose(f_dw_cfg);

	return cpu_addr;
}

static void
pcie_dw_disable_ob_win(struct lsx_pciep_hw_low *hw,
	int idx)
{
	int loop;

	if (idx >= 0) {
		rte_write32(PCIE_ATU_REGION_OUTBOUND | idx,
				    hw->dbi_vir + PCIE_ATU_VIEWPORT);
		rte_write32(0, hw->dbi_vir + PCIE_ATU_LOWER_BASE);
		rte_write32(0, hw->dbi_vir + PCIE_ATU_UPPER_BASE);
		rte_write32(0, hw->dbi_vir + PCIE_ATU_LIMIT);
		rte_write32(0, hw->dbi_vir + PCIE_ATU_LOWER_TARGET);
		rte_write32(0, hw->dbi_vir + PCIE_ATU_UPPER_TARGET);
		rte_write32(PCIE_ATU_TYPE_MEM,
			hw->dbi_vir + PCIE_ATU_CR1);
		rte_write32(0, hw->dbi_vir + PCIE_ATU_CR2);
	} else {
		for (loop = 0; loop < PCIE_DW_OB_WINS_NUM; loop++) {
			rte_write32(PCIE_ATU_REGION_OUTBOUND | loop,
				    hw->dbi_vir + PCIE_ATU_VIEWPORT);
			rte_write32(0, hw->dbi_vir + PCIE_ATU_LOWER_BASE);
			rte_write32(0, hw->dbi_vir + PCIE_ATU_UPPER_BASE);
			rte_write32(0, hw->dbi_vir + PCIE_ATU_LIMIT);
			rte_write32(0, hw->dbi_vir + PCIE_ATU_LOWER_TARGET);
			rte_write32(0, hw->dbi_vir + PCIE_ATU_UPPER_TARGET);
			rte_write32(PCIE_ATU_TYPE_MEM,
				hw->dbi_vir + PCIE_ATU_CR1);
			rte_write32(0, hw->dbi_vir + PCIE_ATU_CR2);
		}
	}
}

static uint64_t
pcie_dw_map_ob_win(struct lsx_pciep_hw_low *hw,
	int pf, int is_vf, int vf,
	uint64_t pci_addr,
	uint64_t size)
{
	int win_id;
	uint64_t cpu_addr;
	uint64_t pcie_id = hw->index;
	uint32_t route_id;

	win_id = pcie_dw_alloc_win_idx(pcie_id, DW_OUTBOUND_WIN);
	if (win_id < 0)
		return 0;

	cpu_addr = pcie_dw_alloc_ob_space(pcie_id, size);

	route_id = pcie_dw_route_fun_id(hw->dbi_vir, pf, is_vf, vf);

	rte_write32(PCIE_ATU_REGION_OUTBOUND | win_id,
		    hw->dbi_vir + PCIE_ATU_VIEWPORT);

	rte_write32(lower_32_bits(cpu_addr),
		    hw->dbi_vir + PCIE_ATU_LOWER_BASE);
	rte_write32(upper_32_bits(cpu_addr),
		    hw->dbi_vir + PCIE_ATU_UPPER_BASE);

	rte_write32(lower_32_bits(cpu_addr + size - 1),
		    hw->dbi_vir + PCIE_ATU_LIMIT);

	rte_write32(lower_32_bits(pci_addr),
		    hw->dbi_vir + PCIE_ATU_LOWER_TARGET);
	rte_write32(upper_32_bits(pci_addr),
		    hw->dbi_vir + PCIE_ATU_UPPER_TARGET);

	rte_write32(PCIE_ATU_TYPE_MEM |
		(route_id << PCIE_CTRL1_FUNC_SHIFT),
		hw->dbi_vir + PCIE_ATU_CR1);

	rte_write32(PCIE_ATU_ENABLE, hw->dbi_vir + PCIE_ATU_CR2);

	if (!is_vf) {
		LSX_PCIEP_BUS_INFO(DWC_OB_PF_INFO_DUMP_FORMAT(hw->index,
			pf, cpu_addr, pci_addr, size, win_id));
	} else {
		LSX_PCIEP_BUS_INFO(DWC_OB_VF_INFO_DUMP_FORMAT(hw->index,
			pf, vf, cpu_addr, pci_addr, size, win_id));
	}

	return cpu_addr;
}

static void
pcie_dw_set_ob_win(struct lsx_pciep_hw_low *hw,
	int idx, int pf, int is_vf, int vf,
	uint64_t cpu_addr, uint64_t pci_addr,
	uint64_t size)
{
	uint32_t route_id =
		pcie_dw_route_fun_id(hw->dbi_vir, pf, is_vf, vf);

	rte_write32(PCIE_ATU_REGION_OUTBOUND | idx,
		    hw->dbi_vir + PCIE_ATU_VIEWPORT);

	rte_write32(lower_32_bits(cpu_addr),
		    hw->dbi_vir + PCIE_ATU_LOWER_BASE);
	rte_write32(upper_32_bits(cpu_addr),
		    hw->dbi_vir + PCIE_ATU_UPPER_BASE);

	rte_write32(lower_32_bits(cpu_addr + size - 1),
		    hw->dbi_vir + PCIE_ATU_LIMIT);

	rte_write32(lower_32_bits(pci_addr),
		    hw->dbi_vir + PCIE_ATU_LOWER_TARGET);
	rte_write32(upper_32_bits(pci_addr),
		    hw->dbi_vir + PCIE_ATU_UPPER_TARGET);

	rte_write32(PCIE_ATU_TYPE_MEM |
		(route_id << PCIE_CTRL1_FUNC_SHIFT),
		hw->dbi_vir + PCIE_ATU_CR1);

	rte_write32(PCIE_ATU_ENABLE, hw->dbi_vir + PCIE_ATU_CR2);

	if (!is_vf) {
		LSX_PCIEP_BUS_INFO(DWC_OB_PF_INFO_DUMP_FORMAT(hw->index,
			pf, cpu_addr, pci_addr, size, idx));
	} else {
		LSX_PCIEP_BUS_INFO(DWC_OB_VF_INFO_DUMP_FORMAT(hw->index,
			pf, vf, cpu_addr, pci_addr, size, idx));
	}
}

static void pcie_dw_set_ib_size(uint8_t *base, int bar,
		uint64_t size, int pf, int is_vf)
{
	uint64_t mask;
	struct pcie_dw_bar_size_mask *size_mask;

	/* The least inbound window is 4KiB */
	if (size < (4 * 1024))
		mask = 0;
	else
		mask = size - 1;

	if (is_vf) {
		size_mask = (struct pcie_dw_bar_size_mask *)
			(base + PCIE_VF_SIZE_OFF +
			pf * PCIE_CFG_OFFSET);
	} else {
		size_mask = (struct pcie_dw_bar_size_mask *)
			(base + PCIE_PF_SIZE_OFF +
			pf * PCIE_CFG_OFFSET);
	}

	switch (bar) {
	case 0:
		rte_write32((uint32_t)mask,
			&size_mask->bar0_mask);
	break;
	case 1:
		rte_write32((uint32_t)mask,
			&size_mask->bar1_mask);
	break;
	case 2:
		rte_write32((uint32_t)mask,
			&size_mask->bar2_mask);
		rte_write32((uint32_t)(mask >> 32),
			&size_mask->bar3_mask);
	break;
	case 4:
		rte_write32((uint32_t)mask,
			&size_mask->bar4_mask);
		rte_write32((uint32_t)(mask >> 32),
			&size_mask->bar5_mask);
	break;
	default:
	break;
	}
}

static void
pcie_dw_set_ib_win(struct lsx_pciep_hw_low *hw,
	int pf, int is_vf, int vf, int bar,
	uint64_t phys, uint64_t size, int resize)
{
	uint32_t ctrl1, ctrl2;
	int idx;
	uint32_t route_id;

	if (bar >= PCI_MAX_RESOURCE) {
		LSX_PCIEP_BUS_ERR("Invalid bar(%d)", bar);

		return;
	}

	if (resize) {
		rte_write32(0, hw->dbi_vir + PCIE_MISC_CONTROL_1_OFF);
		pcie_dw_set_ib_size(hw->dbi_vir, bar, size, pf, is_vf);
	}

	idx = pcie_dw_alloc_win_idx(hw->index,
		DW_INBOUND_WIN);
	if (idx < 0) {
		LSX_PCIEP_BUS_ERR("Inbound window alloc failed");

		return;
	}

	route_id = pcie_dw_route_fun_id(hw->dbi_vir, pf, is_vf, vf);

	ctrl1 = PCIE_ATU_TYPE_MEM | (route_id << PCIE_CTRL1_FUNC_SHIFT);

	ctrl2 = PCIE_ATU_ENABLE |
		PCIE_ATU_BAR_MODE_ENABLE |
		PCIE_ATU_BAR_NUM(bar) |
		PCIE_FUNC_NUM_MATCH_EN;
	if (is_vf)
		ctrl2 |= PCIE_VFBAR_MATCH_MODE_EN;

	rte_write32(PCIE_ATU_REGION_INBOUND | idx,
		hw->dbi_vir + PCIE_ATU_VIEWPORT);

	rte_write32(lower_32_bits(phys),
		hw->dbi_vir + PCIE_ATU_LOWER_TARGET);
	rte_write32(upper_32_bits(phys),
		hw->dbi_vir + PCIE_ATU_UPPER_TARGET);

	rte_write32(ctrl1, hw->dbi_vir + PCIE_ATU_CR1);
	rte_write32(ctrl2, hw->dbi_vir + PCIE_ATU_CR2);

	if (!is_vf) {
		LSX_PCIEP_BUS_INFO(DWC_IB_PF_INFO_DUMP_FORMAT(hw->index,
			pf, phys, bar, size, idx));
	} else {
		LSX_PCIEP_BUS_INFO(DWC_IB_VF_INFO_DUMP_FORMAT(hw->index,
			pf, vf, phys, bar, size, idx));
	}
}

static void
pcie_dw_disable_ib_win(struct lsx_pciep_hw_low *hw, int idx)
{
	int loop;

	if (idx >= 0) {
		rte_write32(PCIE_ATU_REGION_INBOUND | idx,
				    hw->dbi_vir + PCIE_ATU_VIEWPORT);
		rte_write32(0, hw->dbi_vir + PCIE_ATU_LOWER_TARGET);
		rte_write32(0, hw->dbi_vir + PCIE_ATU_UPPER_TARGET);
		rte_write32(PCIE_ATU_TYPE_MEM,
			hw->dbi_vir + PCIE_ATU_CR1);
		rte_write32(0, hw->dbi_vir + PCIE_ATU_CR2);
	} else {
		for (loop = 0; loop < PCIE_DW_IB_WINS_NUM; loop++) {
			rte_write32(PCIE_ATU_REGION_INBOUND | loop,
				    hw->dbi_vir + PCIE_ATU_VIEWPORT);
			rte_write32(0, hw->dbi_vir + PCIE_ATU_LOWER_TARGET);
			rte_write32(0, hw->dbi_vir + PCIE_ATU_UPPER_TARGET);
			rte_write32(PCIE_ATU_TYPE_MEM,
				hw->dbi_vir + PCIE_ATU_CR1);
			rte_write32(0, hw->dbi_vir + PCIE_ATU_CR2);
		}
	}
}

static int
pcie_dw_msix_init(struct lsx_pciep_hw_low *hw,
	int pf, int is_vf, int vf,
	uint64_t msg_addr[], uint32_t msg_data[],
	int vector_total)
{
	uint64_t maddr, dbi_offset, phy_addr;
	uint32_t mdata;
	int vector;
	uint8_t *dbi;

	if (hw->msi_flag == LSX_PCIEP_MSIX_INT) {
		if (is_vf) {
			mdata = pf << MSIX_DOORBELL_PF_SHIFT |
				vf << MSIX_DOORBELL_VF_SHIFT |
				MSIX_DOORBELL_VF_ACTIVE;
		} else {
			mdata = pf << MSIX_DOORBELL_PF_SHIFT;
		}
		for (vector = 0; vector < vector_total; vector++) {
			msg_addr[vector] = hw->dbi_phy + MSIX_DOORBELL_REG;
			msg_data[vector] = mdata | vector;
		}
	} else if (hw->msi_flag == LSX_PCIEP_MMSI_INT) {
		dbi_offset = PCIE_PF1_LX2_DBI_OFF;

		dbi = hw->dbi_vir + pf * dbi_offset;

		maddr = rte_read32(dbi + PCIE_MSI_MSG_HADDR_OFF);
		maddr = ((maddr) << 32) |
			   rte_read32(dbi + PCIE_MSI_MSG_LADDR_OFF);
		mdata = rte_read32(dbi + PCIE_MSI_MSG_DATA_OFF);

		if (hw->ob_policy != LSX_PCIEP_OB_SHARE) {
			phy_addr = pcie_dw_map_ob_win(hw, pf, is_vf, vf,
				maddr, CFG_MSIX_OB_SIZE);
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

static void
pcie_dw_fun_init(struct lsx_pciep_hw_low *hw,
	int pf, int is_vf, uint16_t vendor_id,
	uint16_t device_id, uint16_t class_id)
{
	struct pcie_dw_cap *pf_cap;
	struct pcie_dw_ext_cap *ext_cap;

	rte_write16(1, hw->dbi_vir + PCIE_DBI_RO_WR_EN);

	if (pf == PF0_IDX && !is_vf) {
		pf_cap = (struct pcie_dw_cap *)hw->dbi_vir;
		rte_write16(vendor_id, &pf_cap->vendor_id);
		rte_write16(device_id, &pf_cap->device_id);
		rte_write16(class_id, &pf_cap->class_id);
	} else if (pf == PF1_IDX && !is_vf) {
		pf_cap = (struct pcie_dw_cap *)
			(hw->dbi_vir + PCIE_CFG_OFFSET);
		rte_write16(vendor_id, &pf_cap->vendor_id);
		rte_write16(device_id, &pf_cap->device_id);
		rte_write16(class_id, &pf_cap->class_id);
	} else if (pf == PF0_IDX && is_vf) {
		ext_cap = (struct pcie_dw_ext_cap *)
			(hw->dbi_vir + PCIE_DW_EXT_CAP_OFFSET);
		rte_write16(device_id, &ext_cap->vf_dev_id);
	} else if (pf == PF1_IDX && is_vf) {
		ext_cap = (struct pcie_dw_ext_cap *)
			(hw->dbi_vir + PCIE_CFG_OFFSET +
			PCIE_DW_EXT_CAP_OFFSET);
		rte_write16(device_id, &ext_cap->vf_dev_id);
	}

	rte_write16(0, hw->dbi_vir + PCIE_DBI_RO_WR_EN);
}

static uint64_t
pcie_dw_ob_unmapped(struct lsx_pciep_hw_low *hw)
{
	FILE *f_dw_cfg;
	size_t f_ret;
	uint64_t offset, cpu_addr;

	f_dw_cfg = fopen(PCIEP_DW_GLOBE_INFO_F, "rb");
	if (!f_dw_cfg) {
		LSX_PCIEP_BUS_ERR("%s: %s read open failed",
			__func__, PCIEP_DW_GLOBE_INFO_F);
		return -ENODEV;
	}

	if (!g_dw_globe_info) {
		g_dw_globe_info = malloc(sizeof(struct pciep_dw_globe_info));
		memset(g_dw_globe_info, 0,
			sizeof(struct pciep_dw_globe_info));
	}

	f_ret = fread(g_dw_globe_info,
			sizeof(struct pciep_dw_globe_info),
			1, f_dw_cfg);
	fclose(f_dw_cfg);
	if (f_ret != 1) {
		LSX_PCIEP_BUS_ERR("%s: %s read failed",
			__func__, PCIEP_DW_GLOBE_INFO_F);
		return 0;
	}

	cpu_addr = g_dw_globe_info->ob_base[hw->index];
	offset = g_dw_globe_info->ob_offset[hw->index];

	return cpu_addr + offset;
}

static void
pcie_dw_config(struct lsx_pciep_hw_low *hw)
{
	FILE *f_dw_cfg;
	size_t f_ret;
	uint8_t pcie_id = hw->index;

	if (!g_dw_globe_info)
		g_dw_globe_info = malloc(sizeof(struct pciep_dw_globe_info));

	memset(g_dw_globe_info, 0, sizeof(struct pciep_dw_globe_info));

	f_dw_cfg = fopen(PCIEP_DW_GLOBE_INFO_F, "rb");
	if (f_dw_cfg) {
		f_ret = fread(g_dw_globe_info,
			sizeof(struct pciep_dw_globe_info),
			1, f_dw_cfg);
		if (f_ret != 1) {
			LSX_PCIEP_BUS_ERR("%s: %s read failed",
				__func__, PCIEP_DW_GLOBE_INFO_F);
			fclose(f_dw_cfg);
			return;
		}
		fclose(f_dw_cfg);
	} else {
		g_dw_globe_info->dbi_phy[pcie_id] = hw->dbi_phy;
		g_dw_globe_info->ob_base[pcie_id] = hw->out_base;
		g_dw_globe_info->ob_max_size = CFG_32G_SIZE;
		g_dw_globe_info->ob_win_max_size = CFG_4G_SIZE;
	}

	hw->dbi_phy = g_dw_globe_info->dbi_phy[pcie_id];
	hw->out_base = g_dw_globe_info->ob_base[pcie_id];
	hw->out_size = g_dw_globe_info->ob_max_size;
	hw->out_win_max_size = g_dw_globe_info->ob_win_max_size;

	f_dw_cfg = fopen(PCIEP_DW_GLOBE_INFO_F, "wb");
	f_ret = fwrite(g_dw_globe_info,
		sizeof(struct pciep_dw_globe_info),
		1, f_dw_cfg);
	if (f_ret != 1) {
		LSX_PCIEP_BUS_ERR("%s: %s write failed",
			__func__, PCIEP_DW_GLOBE_INFO_F);
	}
	fclose(f_dw_cfg);
}

static void
pcie_dw_deconfig(struct lsx_pciep_hw_low *hw __rte_unused)
{
	int ret;

	if (access(PCIEP_DW_GLOBE_INFO_F, F_OK) != -1) {
		ret = remove(PCIEP_DW_GLOBE_INFO_F);
		if (ret) {
			LSX_PCIEP_BUS_ERR("%s removed failed",
				PCIEP_DW_GLOBE_INFO_F);
		}
	}

	if (g_dw_globe_info) {
		free(g_dw_globe_info);
		g_dw_globe_info = NULL;
	}
}

static struct lsx_pciep_ops pcie_dw_ops = {
	.pcie_config = pcie_dw_config,
	.pcie_deconfig = pcie_dw_deconfig,
	.pcie_fun_init = pcie_dw_fun_init,
	.pcie_disable_ob_win = pcie_dw_disable_ob_win,
	.pcie_disable_ib_win = pcie_dw_disable_ib_win,
	.pcie_map_ob_win = pcie_dw_map_ob_win,
	.pcie_cfg_ob_win = pcie_dw_set_ob_win,
	.pcie_cfg_ib_win = pcie_dw_set_ib_win,
	.pcie_msix_cfg = pcie_dw_msix_init,
	.pcie_get_ob_unmapped = pcie_dw_ob_unmapped,
};

struct lsx_pciep_ops *lsx_pciep_get_dw_ops(void)
{
	return &pcie_dw_ops;
}
