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
#define PCIE_SRIOV_VF_STRIDE		4
#define PCIE_SRIOV_VF_OFFSET		4
#define PCIE_VF_NUM_OFFSET(is_vf, vf)	\
		((is_vf) ? \
		((vf) * PCIE_SRIOV_VF_STRIDE + PCIE_SRIOV_VF_OFFSET) : 0)

#define PCIE_FUNC_NUM(pf, is_vf, vf)	\
		((pf) + PCIE_VF_NUM_OFFSET(is_vf, vf))

#define PCIE_ATU_FUNC_NUM(pf, is_vf, vf)	\
		((PCIE_FUNC_NUM(pf, is_vf, vf)) << PCIE_CTRL1_FUNC_SHIFT)

#define PCIE_ATU_TYPE_MEM		(0x0 << 0)

#define PCIE_ATU_BAR_NUM(bar)		((bar) << 8)

#define MSIX_DOORBELL_REG		0x948
#define MSIX_DOORBELL_PF_SHIFT		24
#define MSIX_DOORBELL_VF_SHIFT		16
#define MSIX_DOORBELL_VF_ACTIVE		0x8000

static void
pcie_dw_disable_ob_win(struct lsx_pciep_ctl_dev *ctldev, int idx)
{
	int loop;

	if (idx >= 0) {
		rte_write32(PCIE_ATU_REGION_OUTBOUND | idx,
				    ctldev->dbi_vir + PCIE_ATU_VIEWPORT);
		rte_write32(0, ctldev->dbi_vir + PCIE_ATU_LOWER_BASE);
		rte_write32(0, ctldev->dbi_vir + PCIE_ATU_UPPER_BASE);
		rte_write32(0, ctldev->dbi_vir + PCIE_ATU_LIMIT);
		rte_write32(0, ctldev->dbi_vir + PCIE_ATU_LOWER_TARGET);
		rte_write32(0, ctldev->dbi_vir + PCIE_ATU_UPPER_TARGET);
		rte_write32(PCIE_ATU_TYPE_MEM,
			ctldev->dbi_vir + PCIE_ATU_CR1);
		rte_write32(0, ctldev->dbi_vir + PCIE_ATU_CR2);
	} else {
		for (loop = 0; loop < PCIE_DW_OB_WINS_NUM; loop++) {
			rte_write32(PCIE_ATU_REGION_OUTBOUND | loop,
				    ctldev->dbi_vir + PCIE_ATU_VIEWPORT);
			rte_write32(0, ctldev->dbi_vir + PCIE_ATU_LOWER_BASE);
			rte_write32(0, ctldev->dbi_vir + PCIE_ATU_UPPER_BASE);
			rte_write32(0, ctldev->dbi_vir + PCIE_ATU_LIMIT);
			rte_write32(0, ctldev->dbi_vir + PCIE_ATU_LOWER_TARGET);
			rte_write32(0, ctldev->dbi_vir + PCIE_ATU_UPPER_TARGET);
			rte_write32(PCIE_ATU_TYPE_MEM,
				ctldev->dbi_vir + PCIE_ATU_CR1);
			rte_write32(0, ctldev->dbi_vir + PCIE_ATU_CR2);
		}
	}
}

static void
pcie_dw_set_ob_win(struct lsx_pciep_ctl_dev *ctldev, int idx,
		   int pf, int is_vf, int vf,
		   uint64_t cpu_addr,
		   uint64_t pci_addr,
		   uint64_t size)
{
	rte_write32(PCIE_ATU_REGION_OUTBOUND | idx,
		    ctldev->dbi_vir + PCIE_ATU_VIEWPORT);

	rte_write32(lower_32_bits(cpu_addr),
		    ctldev->dbi_vir + PCIE_ATU_LOWER_BASE);
	rte_write32(upper_32_bits(cpu_addr),
		    ctldev->dbi_vir + PCIE_ATU_UPPER_BASE);

	rte_write32(lower_32_bits(cpu_addr + size - 1),
		    ctldev->dbi_vir + PCIE_ATU_LIMIT);

	rte_write32(lower_32_bits(pci_addr),
		    ctldev->dbi_vir + PCIE_ATU_LOWER_TARGET);
	rte_write32(upper_32_bits(pci_addr),
		    ctldev->dbi_vir + PCIE_ATU_UPPER_TARGET);

	rte_write32(PCIE_ATU_TYPE_MEM | PCIE_ATU_FUNC_NUM(pf, is_vf, vf),
		    ctldev->dbi_vir + PCIE_ATU_CR1);

	rte_write32(PCIE_ATU_ENABLE, ctldev->dbi_vir + PCIE_ATU_CR2);
}

static void pcie_dw_set_ib_size(uint8_t *bar_base, int bar,
		uint64_t size, int vf_flag)
{
	uint64_t mask;

	/* The least inbound window is 4KiB */
	if (size < (4 * 1024))
		mask = 0;
	else
		mask = size - 1;

	if (vf_flag)
		bar_base += PCIE_SRIOV_VFBAR0 - PCI_BASE_ADDRESS_0;

	switch (bar) {
	case 0:
		rte_write32((uint32_t)mask, bar_base + PCI_BASE_ADDRESS_0);
		break;
	case 1:
		rte_write32((uint32_t)mask, bar_base + PCI_BASE_ADDRESS_1);
		break;
	case 2:
		rte_write32((uint32_t)mask, bar_base + PCI_BASE_ADDRESS_2);
		rte_write32((uint32_t)(mask >> 32),
			bar_base + PCI_BASE_ADDRESS_3);
		break;
	case 4:
		rte_write32((uint32_t)mask, bar_base + PCI_BASE_ADDRESS_4);
		rte_write32((uint32_t)(mask >> 32),
			bar_base + PCI_BASE_ADDRESS_5);
		break;
	default:
		break;
	}
}

static void
pcie_dw_set_ib_win(struct lsx_pciep_ctl_dev *ctldev,
	int idx, int pf, int is_vf,
	int bar, uint64_t phys, uint64_t size, int resize)
{
	uint32_t ctrl1, ctrl2;

	if (resize) {
		uint8_t *bar_base = ctldev->dbi_vir +
			(0x1000 + 0x8000 * (pf));

		rte_write32(0, ctldev->dbi_vir + PCIE_MISC_CONTROL_1_OFF);
		pcie_dw_set_ib_size(bar_base, bar, size, is_vf);
	}
	/** Re-calculate the inbound win idx according to pf and is_vf*/
	idx = PCIE_DW_IB_FUN_IDX(pf, is_vf) * PCI_MAX_RESOURCE;
	idx += bar;
	if (idx >= PCIE_DW_IB_WINS_NUM ||
		bar >= PCI_MAX_RESOURCE) {
		LSX_PCIEP_BUS_ERR("Invalid inbound idx(%d) or bar(%d)",
			idx, bar);

		return;
	}

	ctrl1 = PCIE_ATU_FUNC_NUM(pf, is_vf, 0) |
		PCIE_ATU_TYPE_MEM;

	ctrl2 = PCIE_ATU_ENABLE |
	      PCIE_ATU_BAR_MODE_ENABLE |
	      PCIE_ATU_BAR_NUM(bar) |
	      PCIE_FUNC_NUM_MATCH_EN;
	if (is_vf)
		ctrl2 |= PCIE_VFBAR_MATCH_MODE_EN;

	rte_write32(PCIE_ATU_REGION_INBOUND | idx,
		ctldev->dbi_vir + PCIE_ATU_VIEWPORT);

	rte_write32(lower_32_bits(phys),
		ctldev->dbi_vir + PCIE_ATU_LOWER_TARGET);
	rte_write32(upper_32_bits(phys),
		ctldev->dbi_vir + PCIE_ATU_UPPER_TARGET);

	rte_write32(ctrl1, ctldev->dbi_vir + PCIE_ATU_CR1);
	rte_write32(ctrl2, ctldev->dbi_vir + PCIE_ATU_CR2);
}

static void
pcie_dw_disable_ib_win(struct lsx_pciep_ctl_dev *ctldev, int idx)
{
	int loop;

	if (idx >= 0) {
		rte_write32(PCIE_ATU_REGION_INBOUND | idx,
				    ctldev->dbi_vir + PCIE_ATU_VIEWPORT);
		rte_write32(0, ctldev->dbi_vir + PCIE_ATU_LOWER_TARGET);
		rte_write32(0, ctldev->dbi_vir + PCIE_ATU_UPPER_TARGET);
		rte_write32(PCIE_ATU_TYPE_MEM,
			ctldev->dbi_vir + PCIE_ATU_CR1);
		rte_write32(0, ctldev->dbi_vir + PCIE_ATU_CR2);
	} else {
		for (loop = 0; loop < PCIE_DW_IB_WINS_NUM; loop++) {
			rte_write32(PCIE_ATU_REGION_INBOUND | loop,
				    ctldev->dbi_vir + PCIE_ATU_VIEWPORT);
			rte_write32(0, ctldev->dbi_vir + PCIE_ATU_LOWER_TARGET);
			rte_write32(0, ctldev->dbi_vir + PCIE_ATU_UPPER_TARGET);
			rte_write32(PCIE_ATU_TYPE_MEM,
				ctldev->dbi_vir + PCIE_ATU_CR1);
			rte_write32(0, ctldev->dbi_vir + PCIE_ATU_CR2);
		}
	}
}

static void
pcie_dw_msix_init(struct lsx_pciep_ctl_dev *ctldev,
		  struct rte_lsx_pciep_device *ep_dev)
{
	uint64_t msg_addr, msg_data, dbi_offset;
	int vector;
	uint8_t *dbi, *out_vir = ctldev->out_vir;
	uint32_t win_idx;
	uint64_t out_base = ctldev->ctl_hw->out_base;
	uint64_t out_win_size = ctldev->ctl_hw->out_win_size;

	if (ep_dev->mmsi_flag == LSX_PCIEP_DONT_INT)
		return;

	if (ep_dev->mmsi_flag == LSX_PCIEP_MSIX_INT)
		return;

	/* Multiple MSI */
	/* Read different function */
	if (ctldev->ctl_hw->type == PEX_LX2160_REV2)
		dbi_offset = PCIE_PF1_LX2_DBI_OFF;
	else
		dbi_offset = PCIE_PF1_LS2_DBI_OFF;

	dbi = ctldev->dbi_vir + ep_dev->pf * dbi_offset;

	msg_addr = rte_read32(dbi + PCIE_MSI_MSG_HADDR_OFF);
	msg_addr = ((msg_addr) << 32) |
		   rte_read32(dbi + PCIE_MSI_MSG_LADDR_OFF);
	msg_data = rte_read32(dbi + PCIE_MSI_MSG_DATA_OFF);

	LSX_PCIEP_BUS_INFO("PF%d-VF%d: "
			"MEM:0x%" PRIx64
			"PCI:0x%" PRIx64"\b",
			ep_dev->pf,
			ep_dev->vf,
			msg_addr, msg_data);

	for (vector = 0; vector < 32; vector++) {
		ep_dev->msix_addr[vector] = msg_addr;
		ep_dev->msix_data[vector] = msg_data + vector;
	}

	if (ctldev->ctl_hw->rbp) {
		win_idx = ep_dev->ob_win_idx + LSX_PCIEP_RBP_OB_MSIX;
		ep_dev->msix_phy_base =
			out_base + win_idx * out_win_size;
		ep_dev->msix_virt_base =
			out_vir + win_idx * out_win_size;
		ep_dev->msix_bus_base = ep_dev->msix_addr[0];
		ep_dev->msix_win_size = out_win_size;
		ep_dev->msix_win_init_flag = 1;
		pcie_dw_set_ob_win(ctldev, win_idx, ep_dev->pf,
				ep_dev->is_vf, ep_dev->vf,
				ep_dev->msix_phy_base,
				ep_dev->msix_bus_base,
				ep_dev->msix_win_size);
	}
}

static uint64_t
pcie_dw_msix_get_vaddr(struct lsx_pciep_ctl_dev *ctldev,
		       struct rte_lsx_pciep_device *ep_dev,
		       uint32_t vector)
{
	uint64_t offset;

	if (ep_dev->mmsi_flag == LSX_PCIEP_MSIX_INT)
		return (uint64_t)(ctldev->dbi_vir + MSIX_DOORBELL_REG);


	/* Multiple MSI */
	offset = ep_dev->msix_addr[vector] - ep_dev->msix_bus_base;
	if (offset > ep_dev->msix_win_size)
		return 0;

	return (uint64_t)ep_dev->msix_virt_base + offset;
}

static uint32_t
pcie_dw_msix_get_cmd(struct lsx_pciep_ctl_dev *ctldev __rte_unused,
		     struct rte_lsx_pciep_device *ep_dev,
		     uint32_t vector)
{
	if (ep_dev->mmsi_flag == LSX_PCIEP_MMSI_INT)
		return ep_dev->msix_data[vector];

	/* MSIx */
	int pf = ep_dev->pf;
	int is_vf = ep_dev->is_vf;
	int vf = ep_dev->vf;

	if (is_vf)
		return pf << MSIX_DOORBELL_PF_SHIFT |
		       vf << MSIX_DOORBELL_VF_SHIFT |
		       MSIX_DOORBELL_VF_ACTIVE      |
		       vector;
	else
		return pf << MSIX_DOORBELL_PF_SHIFT |
		       vector;
}

static void
pcie_dw_reinit(struct lsx_pciep_ctl_dev *ctldev, uint8_t pf_mask)
{
	rte_write16(1, ctldev->dbi_vir + PCIE_DBI_RO_WR_EN);

	if (pf_mask & (1 << PF0_IDX)) {
		rte_write16(ctldev->ctl_hw->vendor_id[PF0_IDX],
			ctldev->dbi_vir + PCI_VENDOR_ID);
		rte_write16(ctldev->ctl_hw->device_id[PF0_IDX],
			ctldev->dbi_vir + PCI_DEVICE_ID);
		rte_write16(ctldev->ctl_hw->class_id[PF0_IDX],
			ctldev->dbi_vir + PCI_CLASS_DEVICE);
	}

	if (pf_mask & (1 << PF1_IDX)) {
		rte_write16(ctldev->ctl_hw->vendor_id[PF1_IDX],
			ctldev->dbi_vir + PCIE_CFG_OFFSET + PCI_VENDOR_ID);
		rte_write16(ctldev->ctl_hw->device_id[PF1_IDX],
			ctldev->dbi_vir + PCIE_CFG_OFFSET + PCI_DEVICE_ID);
		rte_write16(ctldev->ctl_hw->class_id[PF1_IDX],
			ctldev->dbi_vir + PCIE_CFG_OFFSET + PCI_CLASS_DEVICE);
	}

	rte_write16(0, ctldev->dbi_vir + PCIE_DBI_RO_WR_EN);
}

static struct lsx_pciep_ops pcie_dw_ops = {
	.pcie_reinit = pcie_dw_reinit,
	.pcie_disable_ob_win = pcie_dw_disable_ob_win,
	.pcie_disable_ib_win = pcie_dw_disable_ib_win,
	.pcie_set_ob_win = pcie_dw_set_ob_win,
	.pcie_set_ib_win = pcie_dw_set_ib_win,
	.pcie_msix_init = pcie_dw_msix_init,
	.pcie_msix_get_vaddr = pcie_dw_msix_get_vaddr,
	.pcie_msix_get_cmd = pcie_dw_msix_get_cmd,
};

struct lsx_pciep_ops *lsx_pciep_get_dw_ops(void)
{
	return &pcie_dw_ops;
}
