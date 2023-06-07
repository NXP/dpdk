/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2023 NXP
 */

#include <unistd.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>

#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_devargs.h>
#include <rte_memcpy.h>

#include <rte_common.h>
#include <rte_debug.h>
#include <rte_io.h>

#include "lsx_pciep_ctrl.h"

#define BAR0_DEFAULT_SIZE (8 * 1024)
#define BAR1_DEFAULT_SIZE (8 * 1024 * 1024)
#define BAR2_DEFAULT_SIZE (2 * 1024 * 1024)

#define PCIE_MV_OB_WINS_NUM	(256)

#define INDIRECT_ADDR_BNDRY	0xc00
#define PAGE_IDX_SHIFT		10
#define PAGE_ADDR_MASK		0x3ff
#define PAB_CTRL_PAGE_SEL_SHIFT	13
#define PAB_CTRL_PAGE_SEL_MASK	0x3f

#define PAB_CTRL		0x808
#define PAB_CTRL_PAGE_SEL_MASK	0x3f
#define PAB_CTRL_FUNC_SEL_SHIFT	19
#define PAB_CTRL_FUNC_SEL_MASK	0x1ff

/* GPEX CSR */
#define GPEX_CLASSCODE				0x474
#define GPEX_CLASSCODE_SHIFT			16
#define GPEX_CLASSCODE_MASK			0xffff

#define GPEX_ACK_REPLAY_TO			0x438
#define ACK_LAT_TO_VAL_SHIFT			0
#define ACK_LAT_TO_VAL_MASK			0x1fff

#define PCI_BAR_ENABLE				0x4D4
#define PCI_BAR_BAR_SIZE_LDW			0x4D8
#define PCI_BAR_BAR_SIZE_UDW			0x4DC
#define PCI_BAR_SELECT				0x4E0

/* PAB CSR */
#define PAB_CTRL			0x808
#define PAB_CTRL_APIO_EN		(0x1 << 0)
#define PAB_CTRL_PPIO_EN		(0x1 << 1)
#define PAB_CTRL_MAX_BRST_LEN_SHIFT	4
#define PAB_CTRL_MAX_BRST_LEN_MASK	0x3
#define PAB_CTRL_PAGE_SEL_SHIFT		13
#define PAB_CTRL_PAGE_SEL_MASK		0x3f
#define PAB_CTRL_FUNC_SEL_SHIFT		19
#define PAB_CTRL_FUNC_SEL_MASK		0x1ff
#define PAB_RST_CTRL			0x820
#define PAB_BR_STAT			0x80c

/* AXI PIO Engines */
#define PAB_AXI_PIO_CTRL(idx)			(0x840 + 0x10 * (idx))
#define APIO_EN					(0x1 << 0)
#define MEM_WIN_EN				(0x1 << 1)
#define IO_WIN_EN				(0x1 << 2)
#define CFG_WIN_EN				(0x1 << 3)
#define PAB_AXI_PIO_STAT(idx)			(0x844 + 0x10 * (idx))
#define PAB_AXI_PIO_SL_CMD_STAT(idx)		(0x848 + 0x10 * (idx))
#define PAB_AXI_PIO_SL_ADDR_STAT(idx)		(0x84c + 0x10 * (idx))
#define PAB_AXI_PIO_SL_EXT_ADDR_STAT(idx)	(0xb8a0 + 0x4 * (idx))

/* APIO WINs */
#define PAB_AXI_AMAP_PCI_HDR_PARAM(idx)	(0x5ba0 + 0x04 * (idx))
#define PAB_AXI_AMAP_CTRL(idx)		(0xba0 + 0x10 * (idx))
#define PAB_EXT_AXI_AMAP_SIZE(idx)	(0xbaf0 + 0x4 * (idx))
#define PAB_AXI_AMAP_AXI_WIN(idx)	(0xba4 + 0x10 * (idx))
#define PAB_EXT_AXI_AMAP_AXI_WIN(idx)	(0x80a0 + 0x4 * (idx))
#define PAB_AXI_AMAP_PEX_WIN_L(idx)	(0xba8 + 0x10 * (idx))
#define PAB_AXI_AMAP_PEX_WIN_H(idx)	(0xbac + 0x10 * (idx))
#define AXI_AMAP_CTRL_EN		(0x1 << 0)
#define AXI_AMAP_CTRL_TYPE_SHIFT	1
#define AXI_AMAP_CTRL_TYPE_MASK		0x3
#define AXI_AMAP_CTRL_SIZE_SHIFT	10
#define AXI_AMAP_CTRL_SIZE_MASK		0x3fffff

#define OFFSET_TO_PAGE_IDX(off) \
	(((off) >> PAGE_IDX_SHIFT) & PAB_CTRL_PAGE_SEL_MASK)

#define OFFSET_TO_PAGE_ADDR(off) \
	(((off) & PAGE_ADDR_MASK) | INDIRECT_ADDR_BNDRY)

/* PPIO WINs EP mode */
#define PAB_PEX_BAR_AMAP(func, bar)	(0x1ba0 + 0x20 * (func) + 4 * (bar))
#define PAB_EXT_PEX_BAR_AMAP(func, bar)	(0x84a0 + 0x20 * (func) + 4 * (bar))
#define SRIOV_INIT_VFS_TOTAL_VF(func)		(0x644 + (func) * 4)
#define TTL_VF_MASK				0xffff
#define TTL_VF_SHIFT				16
#define INI_VF_MASK				0xffff
#define INI_VF_SHIFT				0
#define GPEX_SRIOV_VF_OFFSET_STRIDE(func)	(0x704 + (func) * 4)
#define PCIE_SRIOV_VF_OFFSET_STRIDE		0x2b4

#define PAB_AXI_TYPE_CFG		0x00
#define PAB_AXI_TYPE_IO			0x01
#define PAB_AXI_TYPE_MEM		0x02
#define PAB_AXI_TYPE_ATOM		0x03
#define PCIE_ATU_TYPE_MEM		(PAB_AXI_TYPE_MEM)

#define PCIE_CFG_READY			0x4b0
#define PCIE_CONFIG_READY		(1 << 0)

#define MSIX_TABLE_PBA_ACCESS		(0xD000)
#define MSIX_TABLE_BASE(v)		(MSIX_TABLE_PBA_ACCESS + (v) * 0x10)
#define PCIE_MSI_MSG_ADDR_OFF		0x8c
#define PCIE_MSI_MSG_DATA_OFF		0x94
#define PCIE_MSI_MSG_ADDR_OFF_VF	0x84
#define PCIE_MSI_MSG_DATA_OFF_VF	0x8c

#define PCIE_VF_OFFSET			(32)

/* 16 bars index */
#define BAR0			0
#define BAR1			1
#define BAR2			2
#define BAR3			3
#define VF_BAR0			4
#define VF_BAR1			5
#define VF_BAR2			6
#define VF_BAR3			7
#define BAR_IDX(pf, bar)	((pf) * 8 + (bar))

#define VF_NUM(pf, vf)		((pf) * PCIE_VF_OFFSET + (vf) + 1)
#define GET_OB_FUNC_NUM(pf, is_vf, vf)	((is_vf) ? VF_NUM(pf, vf) : (pf))
#define GET_IB_FUNC_NUM(pf, is_vf)	((is_vf) ? VF_NUM(pf, 0) : (pf))

#define VF_NUM_128(pf, vf)		((pf) * 128 + (vf) + 1)
#define GET_OB_FUNC_NUM_128(pf, is_vf, vf) \
	(((is_vf) == 0) ? (pf) : VF_NUM_128(pf, vf))

static inline void
ccsr_set_page(struct lsx_pciep_hw_low *hw, uint8_t pg_idx)
{
	uint32_t val;

	val = rte_read32(hw->dbi_vir + PAB_CTRL);
	val &= ~(PAB_CTRL_PAGE_SEL_MASK << PAB_CTRL_PAGE_SEL_SHIFT);
	val |= (pg_idx & PAB_CTRL_PAGE_SEL_MASK) << PAB_CTRL_PAGE_SEL_SHIFT;

	rte_write32(val, hw->dbi_vir + PAB_CTRL);
}

static inline uint32_t
ccsr_readl(struct lsx_pciep_hw_low *hw, uint32_t offset)
{
	if (offset < INDIRECT_ADDR_BNDRY) {
		ccsr_set_page(hw, 0);
		return rte_read32(hw->dbi_vir + offset);
	}

	ccsr_set_page(hw, OFFSET_TO_PAGE_IDX(offset));
	return rte_read32(hw->dbi_vir + OFFSET_TO_PAGE_ADDR(offset));
}

static inline void
ccsr_writel(struct lsx_pciep_hw_low *hw, uint32_t offset, uint32_t value)
{
	if (offset < INDIRECT_ADDR_BNDRY) {
		ccsr_set_page(hw, 0);
		rte_write32(value, hw->dbi_vir + offset);
	} else {
		ccsr_set_page(hw, OFFSET_TO_PAGE_IDX(offset));
		rte_write32(value, hw->dbi_vir +
			OFFSET_TO_PAGE_ADDR(offset));
	}
}

static int
pcie_mv_set_ib_win(struct lsx_pciep_hw_low *hw,
	int pf, int is_vf, int vf __rte_unused,
	int bar, uint64_t phys,
	uint64_t size __rte_unused,
	int resize __rte_unused)
{
	int bar_idx = is_vf ? (bar + 8) : bar;

	ccsr_writel(hw,
		PAB_EXT_PEX_BAR_AMAP(GET_IB_FUNC_NUM(pf, is_vf), bar_idx),
		upper_32_bits(phys));
	ccsr_writel(hw,
		PAB_PEX_BAR_AMAP(GET_IB_FUNC_NUM(pf, is_vf), bar_idx),
		lower_32_bits(phys) | 1);

	return 0;
}

static int
pcie_mv_disable_ob_win(struct lsx_pciep_hw_low *hw, int idx)
{
	uint32_t val;
	int loop;

	if (idx != PCIE_EP_DISABLE_ALL_WIN) {
		val = ccsr_readl(hw, PAB_AXI_AMAP_CTRL(idx));
		val &= ~AXI_AMAP_CTRL_EN;
		ccsr_writel(hw, PAB_AXI_AMAP_CTRL(idx), val);
	} else {
		for (loop = 0; loop < PCIE_MV_OB_WINS_NUM; loop++) {
			val = ccsr_readl(hw, PAB_AXI_AMAP_CTRL(loop));
			val &= ~AXI_AMAP_CTRL_EN;
			ccsr_writel(hw, PAB_AXI_AMAP_CTRL(loop), val);
		}
	}

	return 0;
}

static int
pcie_mv_set_ob_win(struct lsx_pciep_hw_low *hw,
	int idx, int pf, int is_vf, int vf,
	uint64_t cpu_addr,
	uint64_t pci_addr,
	uint64_t size)
{
	uint32_t val;
	uint32_t size_h, size_l;
	uint32_t func = GET_OB_FUNC_NUM(pf, is_vf, vf);

	if (idx >= PCIE_MV_OB_WINS_NUM)
		return -EINVAL;

	size_h = upper_32_bits(~(size - 1));
	size_l = lower_32_bits(~(size - 1));

	val = 0;  /* NSE(no snoop enable):0  ROE(relax ordering enable):0 */
	val |= ((PCIE_ATU_TYPE_MEM & AXI_AMAP_CTRL_TYPE_MASK) <<
		AXI_AMAP_CTRL_TYPE_SHIFT) |
		((size_l >> AXI_AMAP_CTRL_SIZE_SHIFT) <<
		AXI_AMAP_CTRL_SIZE_SHIFT) | AXI_AMAP_CTRL_EN;

	ccsr_writel(hw, PAB_AXI_AMAP_CTRL(idx), val);
	ccsr_writel(hw, PAB_AXI_AMAP_PCI_HDR_PARAM(idx), func);
	ccsr_writel(hw, PAB_AXI_AMAP_AXI_WIN(idx),
		lower_32_bits(cpu_addr));
	ccsr_writel(hw, PAB_EXT_AXI_AMAP_AXI_WIN(idx),
		upper_32_bits(cpu_addr));
	ccsr_writel(hw, PAB_AXI_AMAP_PEX_WIN_L(idx),
		lower_32_bits(pci_addr));
	ccsr_writel(hw, PAB_AXI_AMAP_PEX_WIN_H(idx),
		upper_32_bits(pci_addr));
	ccsr_writel(hw, PAB_EXT_AXI_AMAP_SIZE(idx), size_h);

	return 0;
}

static int
pcie_mv_msix_init(struct lsx_pciep_hw_low *hw,
	uint8_t *out_virt, int pf, int is_vf, int vf,
	uint64_t msg_phy_addr[], void *msg_vir_addr[],
	uint32_t msg_data[], uint64_t *size,
	int vector_total)
{
	int vector;
	uint32_t val = 0;
	uint32_t dev_id = 0;
	uint32_t mdata = 0;
	uint64_t maddr = 0;
	uint32_t addr_h, addr_l;

	if (hw->msi_flag == LSX_PCIEP_DONT_INT)
		return 0;

	if (hw->msi_flag == LSX_PCIEP_MMSI_INT) {
		dev_id = GET_OB_FUNC_NUM(pf, is_vf, vf);

		/* set function number */
		val =  ccsr_readl(hw, PAB_CTRL);
		val &= ~(PAB_CTRL_FUNC_SEL_MASK << PAB_CTRL_FUNC_SEL_SHIFT);
		val |= (dev_id & PAB_CTRL_FUNC_SEL_MASK) <<
			PAB_CTRL_FUNC_SEL_SHIFT;
		ccsr_writel(hw, PAB_CTRL, val);

		if (!is_vf) {
			addr_l = ccsr_readl(hw, PCIE_MSI_MSG_ADDR_OFF
				+ 0x00);
			addr_h = ccsr_readl(hw, PCIE_MSI_MSG_ADDR_OFF
				+ 0x04);
			maddr = (((uint64_t)addr_h) << 32) | addr_l;
			mdata = ccsr_readl(hw, PCIE_MSI_MSG_DATA_OFF);
		} else {
			addr_l = ccsr_readl(hw, PCIE_MSI_MSG_ADDR_OFF_VF
				+ 0x00);
			addr_h = ccsr_readl(hw, PCIE_MSI_MSG_ADDR_OFF_VF
				+ 0x04);
			maddr = (((uint64_t)addr_h) << 32) | addr_l;
			mdata = ccsr_readl(hw, PCIE_MSI_MSG_DATA_OFF_VF);
		}

		for (vector = 0; vector < vector_total; vector++) {
			msg_phy_addr[vector] = hw->out_base + maddr;
			msg_vir_addr[vector] = out_virt + maddr;
			msg_data[vector] = mdata + vector;
		}
		if (size)
			*size = sizeof(uint32_t);
	} else {
		dev_id = GET_OB_FUNC_NUM_128(pf, is_vf, vf);

		/* set function number */
		val =  ccsr_readl(hw, PAB_CTRL);
		val &= ~(PAB_CTRL_FUNC_SEL_MASK << PAB_CTRL_FUNC_SEL_SHIFT);
		val |= (dev_id & PAB_CTRL_FUNC_SEL_MASK)
			<< PAB_CTRL_FUNC_SEL_SHIFT;
		ccsr_writel(hw, PAB_CTRL, val);

		vector_total = 8;

		for (vector = 0; vector < vector_total; vector++) {
			addr_l = ccsr_readl(hw,
					MSIX_TABLE_BASE(vector) + 0x00);
			addr_h = ccsr_readl(hw,
					MSIX_TABLE_BASE(vector) + 0x04);
			maddr = (((uint64_t)addr_h) << 32) | addr_l;
			msg_phy_addr[vector] = hw->out_base + maddr;
			msg_vir_addr[vector] = out_virt + maddr;
			msg_data[vector]  = ccsr_readl(hw,
					MSIX_TABLE_BASE(vector) + 0x08);
		}

		/* clear function number */
		val =  ccsr_readl(hw, PAB_CTRL);
		val &= ~(PAB_CTRL_FUNC_SEL_MASK << PAB_CTRL_FUNC_SEL_SHIFT);
		ccsr_writel(hw, PAB_CTRL, val);
		if (size)
			*size = CFG_MSIX_OB_SIZE;
	}

	return vector_total;
}

static void
pcie_mv_setup_bar(struct lsx_pciep_hw_low *hw,
	int pf, int bar, uint64_t size)
{
	uint32_t value;
	uint64_t size_mask = ~(size - 1);
	int bar_index = BAR_IDX(pf, bar);

	/* Enable this bar */
	value = ccsr_readl(hw, PCI_BAR_ENABLE);
	value |= 1 << bar_index;
	ccsr_writel(hw, PCI_BAR_ENABLE, value);

	/* Set bar size */
	ccsr_writel(hw, PCI_BAR_SELECT, bar_index);
	ccsr_writel(hw, PCI_BAR_BAR_SIZE_LDW, lower_32_bits(size_mask));
	ccsr_writel(hw, PCI_BAR_BAR_SIZE_UDW, upper_32_bits(size_mask));

	/* Enable corresponding inbound window */
	ccsr_writel(hw, PAB_PEX_BAR_AMAP(pf, bar), 1);
}

static void
pcie_mv_setup_pf_bars(struct lsx_pciep_hw_low *hw, int pf)
{
	/* Enable bar0 for reg */
	pcie_mv_setup_bar(hw, pf, BAR0, BAR0_DEFAULT_SIZE);
	/* Enable bar1 for MSIx */
	pcie_mv_setup_bar(hw, pf, BAR1, BAR1_DEFAULT_SIZE);
	/* Enable bar2 for BD */
	pcie_mv_setup_bar(hw, pf, BAR2, BAR2_DEFAULT_SIZE);
}

static void
pcie_mv_setup_bars(struct lsx_pciep_hw_low *hw,
	uint8_t pf)
{
	/* disable all bars */
	ccsr_writel(hw, PCI_BAR_ENABLE, 0);

	if (pf == PF0_IDX)
		pcie_mv_setup_pf_bars(hw, PF0_IDX);
	else if (pf == PF1_IDX)
		pcie_mv_setup_pf_bars(hw, PF1_IDX);
}

static void
pcie_mv_set_sriov(struct lsx_pciep_hw_low *hw, int pf)
{
	unsigned int val;

	/* set PF0 VF number */
	if (pf == PF0_IDX) {
		val = ccsr_readl(hw, SRIOV_INIT_VFS_TOTAL_VF(PF0_IDX));
		val &= ~(TTL_VF_MASK << TTL_VF_SHIFT);
		val |= PCIE_MAX_VF_NUM << TTL_VF_SHIFT;
		val &= ~(INI_VF_MASK << INI_VF_SHIFT);
		val |= PCIE_MAX_VF_NUM << INI_VF_SHIFT;
		ccsr_writel(hw, SRIOV_INIT_VFS_TOTAL_VF(PF0_IDX), val);

		/* set VF offset */
		val =  ccsr_readl(hw, PCIE_SRIOV_VF_OFFSET_STRIDE);
		val += PCIE_MAX_VF_NUM - 1;
		ccsr_writel(hw, GPEX_SRIOV_VF_OFFSET_STRIDE(PF0_IDX), val);
	} else if (pf == PF1_IDX) {
		val = ccsr_readl(hw, SRIOV_INIT_VFS_TOTAL_VF(PF1_IDX));
		val &= ~(TTL_VF_MASK << TTL_VF_SHIFT);
		val |= PCIE_MAX_VF_NUM << TTL_VF_SHIFT;
		val &= ~(INI_VF_MASK << INI_VF_SHIFT);
		val |= PCIE_MAX_VF_NUM << INI_VF_SHIFT;
		ccsr_writel(hw, SRIOV_INIT_VFS_TOTAL_VF(PF1_IDX), val);

		/* set VF offset */
		val =  ccsr_readl(hw, PCIE_SRIOV_VF_OFFSET_STRIDE);
		val += PCIE_MAX_VF_NUM - 1;
		ccsr_writel(hw, GPEX_SRIOV_VF_OFFSET_STRIDE(PF1_IDX), val);
	}
}

static int
pcie_mv_reinit(struct lsx_pciep_hw_low *hw,
	int pf, int is_vf __rte_unused,
	uint16_t vendor_id __rte_unused,
	uint16_t device_id __rte_unused,
	uint16_t class_id __rte_unused)
{
	pcie_mv_setup_bars(hw, pf);
	pcie_mv_set_sriov(hw, pf);

	return 0;
}

static struct lsx_pciep_ops pcie_mv_ops = {
	.pcie_fun_init = pcie_mv_reinit,
	.pcie_disable_ob_win = pcie_mv_disable_ob_win,
	.pcie_cfg_ob_win = pcie_mv_set_ob_win,
	.pcie_cfg_ib_win = pcie_mv_set_ib_win,
	.pcie_msix_cfg = pcie_mv_msix_init,
};

struct lsx_pciep_ops *lsx_pciep_get_mv_ops(void)
{
	return &pcie_mv_ops;
}
