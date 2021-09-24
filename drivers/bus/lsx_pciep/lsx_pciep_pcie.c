/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2021 NXP
 */

#include <unistd.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pthread.h>
#include <fcntl.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <signal.h>
#include <stdbool.h>

#include <rte_log.h>
#include <rte_bus.h>
#include <rte_eal_memconfig.h>
#include <rte_malloc.h>
#include <rte_devargs.h>
#include <rte_memcpy.h>
#include <rte_ethdev.h>

#include <rte_common.h>
#include <rte_debug.h>
#include <rte_cycles.h>
#include <rte_log.h>
#include <rte_byteorder.h>
#include <rte_io.h>
#include <rte_byteorder.h>
#include <rte_memzone.h>
#include <rte_ether.h>
#include <rte_log.h>
#include <rte_kvargs.h>
#include <dpaa_of.h>
#include <fsl_qbman_portal.h>
#include <linux/pci_regs.h>
#include <compat.h>
#include <fslmc_vfio.h>
#include <rte_pci.h>
#include <linux/virtio_net.h>
#include <linux/virtio_blk.h>
#include <rte_lsx_pciep_bus.h>

#include "lsx_pciep_dev.h"
#include "lsx_pciep_ctrl.h"

#define LSX_PCIE_REG_PHY_START 0x3400000
#define LSX_PCIE_REG_STRIDE 0x100000

#define LSX_PCIE_DT_REG_ADDR_IDX 0
#define LSX_PCIE_DT_OB_ADDR_IDX 1

#define SVR_MAJOR_VER_MASK	0x00F0

#ifndef SVR_MASK
#define SVR_MASK 0xffff0000
#endif

static struct lsx_pciep_ctl_dev s_pctldev[LSX_MAX_PCIE_NB];
static uint32_t s_pciep_init_flag;

int lsx_pciep_ctl_idx_validated(uint8_t pcie_idx)
{
	if (pcie_idx < LSX_MAX_PCIE_NB)
		return 1;

	return 0;
}

struct lsx_pciep_ctl_dev *
lsx_pciep_ctl_get_dev(uint8_t pcie_idx)
{
	if (pcie_idx >= LSX_MAX_PCIE_NB)
		return NULL;

	if (!lsx_pciep_sim() && !s_pctldev[pcie_idx].ep_enable)
		return NULL;

	return &s_pctldev[pcie_idx];
}

int
lsx_pciep_ctl_rbp_enable(uint8_t pcie_idx)
{
	RTE_ASSERT(pcie_idx < LSX_MAX_PCIE_NB);

	return s_pctldev[pcie_idx].rbp;
}

void
lsx_pciep_ctl_set_sriov_num(uint8_t pcie_idx,
	uint32_t pf0, uint32_t pf1,
	uint32_t pf0_vf_num, uint32_t pf1_vf_num)
{
	struct lsx_pciep_ctl_dev *ctldev;
	uint32_t function_num = 0;

	RTE_ASSERT(pcie_idx < LSX_MAX_PCIE_NB);
	ctldev = &s_pctldev[pcie_idx];

	if (pf0) {
		ctldev->pf_enable[PF0_IDX] = 1;
		function_num++;
		ctldev->vf_num[PF0_IDX] = pf0_vf_num;
		function_num += pf0_vf_num;
	}

	if (pf1) {
		ctldev->pf_enable[PF1_IDX] = 1;
		function_num++;
		ctldev->vf_num[PF1_IDX] = pf1_vf_num;
		function_num += pf1_vf_num;
	}

	ctldev->function_num = function_num;
}

static void
lsx_pciep_ctl_set_rbp(uint8_t pcie_idx, int rbp)
{
	struct lsx_pciep_ctl_dev *ctldev;

	RTE_ASSERT(pcie_idx < LSX_MAX_PCIE_NB);
	ctldev = &s_pctldev[pcie_idx];

	ctldev->rbp = rbp;
}

static void
lsx_pciep_ctl_set_share_ob(uint8_t pcie_idx,
	enum lsx_share_ob share_ob)
{
	struct lsx_pciep_ctl_dev *ctldev;

	RTE_ASSERT(pcie_idx < LSX_MAX_PCIE_NB);
	ctldev = &s_pctldev[pcie_idx];

	ctldev->share_ob = share_ob;
}

void lsx_pciep_ctl_set_all_devs(uint32_t pf0,
	uint32_t pf1, uint32_t pf0_vf_num,
	uint32_t pf1_vf_num, int rbp,
	enum lsx_share_ob share_ob)
{
	int i;

	for (i = 0; i < LSX_MAX_PCIE_NB; i++) {
		lsx_pciep_ctl_set_sriov_num(i, pf0, pf1,
			pf0_vf_num, pf1_vf_num);
		lsx_pciep_ctl_set_rbp(i, rbp);
		lsx_pciep_ctl_set_share_ob(i, share_ob);
	}
}

static bool
lsx_pciep_ctl_is_ep(struct lsx_pciep_ctl_dev *ctldev)
{
	uint32_t mode;

	if (ctldev->type == PEX_LX2160_REV1 ||
	   ctldev->type == PEX_LX2160_REV2 ||
	   ctldev->type == PEX_LS208X)
		return true;

	mode = rte_read8(ctldev->dbi + PCI_HEADER_TYPE);
	mode &= 0x7f;

	if (mode != PCI_HEADER_TYPE_NORMAL)
		return false;

	return true;
}

static enum PEX_TYPE s_pcie_type = PEX_UNKNOWN;

enum PEX_TYPE lsx_pciep_get_type(void)
{
	return s_pcie_type;
}

static int
lsx_pciep_set_type(void)
{
	FILE *svr_file = NULL;
	uint32_t svr_ver;
	enum PEX_TYPE type;
	struct lsx_pciep_ops *ops;
	int i;

	svr_file = fopen("/sys/devices/soc0/soc_id", "r");
	if (!svr_file) {
		LSX_PCIEP_BUS_ERR("Unable to open SoC device.");
		return -1;
	}
	if (fscanf(svr_file, "svr:%x", &svr_ver) < 0) {
		LSX_PCIEP_BUS_ERR("PCIe EP unable to read SoC device\n");
		return -1;
	}

	if ((svr_ver & SVR_MASK) == SVR_LX2160A) {
		if ((svr_ver & SVR_MAJOR_VER_MASK) == 0x10) {
			type = PEX_LX2160_REV1;
			ops = lsx_pciep_get_mv_ops();
		} else {
			type = PEX_LX2160_REV2;
			ops = lsx_pciep_get_dw_ops();
		}
	} else {
		type = PEX_LS208X;
		ops = lsx_pciep_get_dw_ops();
	}

	for (i = 0; i < LSX_MAX_PCIE_NB; i++) {
		s_pctldev[i].type = type;
		s_pctldev[i].ops = ops;
	}
	s_pcie_type = type;

	return 0;
}

uint32_t lsx_pciep_ctl_get_device_id(uint8_t pcie_idx,
	enum lsx_pcie_pf_idx pf_idx)
{
	RTE_ASSERT(pcie_idx < LSX_MAX_PCIE_NB);
	RTE_ASSERT(pf_idx == PF0_IDX || pf_idx == PF1_IDX);

	return s_pctldev[pcie_idx].device_id[pf_idx];
}

static struct lsx_pciep_ctl_dev *
lsx_pciep_node2ctl(const struct device_node *pcie_node)
{
	const uint32_t *addr;
	uint64_t phys_addr, reg_off;
	uint64_t len;
	uint8_t pcie_idx;
	struct lsx_pciep_ctl_dev *ctldev;

	addr = of_get_address(pcie_node, LSX_PCIE_DT_REG_ADDR_IDX,
			&len, NULL);
	if (!addr) {
		LSX_PCIEP_BUS_ERR("PCIe EP %s of_get_address failed\n",
			pcie_node->full_name);

		return NULL;
	}

	phys_addr = of_translate_address(pcie_node, addr);
	if (!phys_addr) {
		LSX_PCIEP_BUS_ERR("PCIe EP %s of_translate_address failed\n",
			pcie_node->full_name);

		return NULL;
	}
	RTE_ASSERT(!(phys_addr & (LSX_PCIE_REG_STRIDE - 1)));
	RTE_ASSERT(phys_addr >= LSX_PCIE_REG_PHY_START);
	RTE_ASSERT(phys_addr < (LSX_PCIE_REG_PHY_START +
			LSX_PCIE_REG_STRIDE * LSX_MAX_PCIE_NB));

	reg_off = phys_addr - LSX_PCIE_REG_PHY_START;

	pcie_idx = reg_off / LSX_PCIE_REG_STRIDE;
	RTE_ASSERT(pcie_idx < LSX_MAX_PCIE_NB);
	RTE_ASSERT((pcie_idx * (uint64_t)LSX_PCIE_REG_STRIDE) == reg_off);

	ctldev = &s_pctldev[pcie_idx];

	ctldev->phy = phys_addr;
	ctldev->size = (uint32_t)len;
	ctldev->index = pcie_idx;

	ctldev->reg = lsx_pciep_map_region(ctldev->phy, ctldev->size);
	if (!ctldev->reg) {
		LSX_PCIEP_BUS_ERR("PCIe EP mmap ERROR\n");

		return NULL;
	}

	ctldev->dbi = ctldev->reg;

	return ctldev;
}

static int
lsx_pciep_node_out_base(struct lsx_pciep_ctl_dev *ctldev,
				const struct device_node *pcie_node)
{
	uint64_t phys_addr;
	const uint32_t *addr;
	uint64_t len;

	addr = of_get_address(pcie_node, LSX_PCIE_DT_OB_ADDR_IDX,
			&len, NULL);
	if (!addr) {
		LSX_PCIEP_BUS_ERR("%s of_get_address failed\n",
			pcie_node->full_name);

		return -ENODEV;
	}

	phys_addr = of_translate_address(pcie_node, addr);
	if (!phys_addr) {
		LSX_PCIEP_BUS_ERR("%s of_translate_address failed\n",
			pcie_node->full_name);

		return -ENODEV;
	}

	ctldev->out_base = phys_addr;

	ctldev->out_vaddr =
		(uint64_t)lsx_pciep_map_region(ctldev->out_base, CFG_32G_SIZE);
	if (ctldev->out_vaddr == 0) {
		LSX_PCIEP_BUS_ERR("failed to map outbound space\n");

		return -ENOMEM;
	}


	LSX_PCIEP_BUS_INFO("The out_base is:0x%" PRIx64
		" mapped to:0x%" PRIx64,
		ctldev->out_base, ctldev->out_vaddr);

	return 0;
}

static void
lsx_pciep_ctl_update_dma_addr(struct lsx_pciep_ctl_dev *ctldev)
{
	if (ctldev->rbp) {
		if (ctldev->type == PEX_LX2160_REV1 ||
			ctldev->type == PEX_LX2160_REV2)
			ctldev->dma_out_base = PCI_DMA_RBP_1T_BASE;
		else
			ctldev->dma_out_base = PCI_DMA_RBP_0_BASE;
	} else {
		ctldev->dma_out_base = ctldev->out_base;
	}
}

static int lsx_pciep_ctl_ob_win_scheme(struct lsx_pciep_ctl_dev *ctldev)
{
	int idx = 0;
	uint64_t current_offset;
	uint16_t current_win_idx = 0, i;
	struct lsx_pciep_norbp_fun_out_info *ob_info;

	if (ctldev->rbp) {
		ctldev->out_win_size = CFG_SHAD_OB_SIZE;
		ctldev->out_win_per_fun = LSX_PCIEP_RBP_OB_WIN_NB;
		ctldev->out_size_per_fun = ctldev->out_win_size *
			ctldev->out_win_per_fun;
		return 0;
	}

	if (ctldev->type == PEX_LX2160_REV2 ||
		ctldev->type == PEX_LS208X)
		ctldev->out_win_size = CFG_4G_SIZE;
	else
		ctldev->out_win_size = CFG_32G_SIZE;

	if (ctldev->share_ob != LSX_PCIEP_OB_PER_FUN) {
		/* All the PF/VFs share global outbound windows,
		 * in case PF/VFs devices are only mapped into
		 * same VM or host.
		 */
		ctldev->out_offset = 0;
		if (ctldev->type == PEX_LX2160_REV2 ||
			ctldev->type == PEX_LS208X) {
			ctldev->out_size = CFG_32G_SIZE;
			ctldev->out_size_per_fun = CFG_32G_SIZE;
		} else {
			ctldev->out_size = CFG_1T_SIZE;
			ctldev->out_size_per_fun = CFG_1T_SIZE;
		}
		ctldev->out_win_start = 0;
		ctldev->out_win_per_fun =
			ctldev->out_size_per_fun / ctldev->out_win_size;
		ctldev->ob_per_fun = NULL;

		return 0;
	}

	ctldev->ob_per_fun =
		malloc(sizeof(struct lsx_pciep_norbp_fun_out_info) *
				ctldev->function_num);


	ctldev->out_offset = 0;
	ctldev->out_win_start = 0;

	if (ctldev->type == PEX_LX2160_REV2 ||
		ctldev->type == PEX_LS208X)
		ctldev->out_size = CFG_32G_SIZE;
	else
		ctldev->out_size = CFG_1T_SIZE;

	ctldev->out_size_per_fun =
		ctldev->out_size / ctldev->function_num;
	if (ctldev->out_size_per_fun < ctldev->out_win_size) {
		LSX_PCIEP_BUS_ERR("Too many functions(%d) to share outbound space.\n",
			ctldev->function_num);

		return -ENODEV;
	}
	ctldev->out_win_per_fun =
		ctldev->out_size_per_fun / ctldev->out_win_size;

	current_offset = ctldev->out_offset;
	current_win_idx = ctldev->out_win_start;

	if (ctldev->pf_enable[PF0_IDX]) {
		ob_info = &ctldev->ob_per_fun[idx];
		ob_info->pf = PF0_IDX;
		ob_info->is_vf = 0;
		ob_info->out_offset = current_offset;
		ob_info->out_win_idx = current_win_idx;
		current_offset += ctldev->out_size_per_fun;
		current_win_idx += ctldev->out_win_per_fun;
		ob_info->out_win_nb = ctldev->out_win_per_fun;
		idx++;
	}

	if (ctldev->pf_enable[PF1_IDX]) {
		ob_info = &ctldev->ob_per_fun[idx];
		ob_info->pf = PF1_IDX;
		ob_info->is_vf = 0;
		ob_info->out_offset = current_offset;
		ob_info->out_win_idx = current_win_idx;
		current_offset += ctldev->out_size_per_fun;
		current_win_idx += ctldev->out_win_per_fun;
		ob_info->out_win_nb = ctldev->out_win_per_fun;
		idx++;
	}

	for (i = 0; i < ctldev->vf_num[PF0_IDX]; i++) {
		ob_info = &ctldev->ob_per_fun[idx];
		ob_info->pf = PF0_IDX;
		ob_info->is_vf = 1;
		ob_info->vf = i;
		ob_info->out_offset = current_offset;
		ob_info->out_win_idx = current_win_idx;
		current_offset += ctldev->out_size_per_fun;
		current_win_idx += ctldev->out_win_per_fun;
		ob_info->out_win_nb = ctldev->out_win_per_fun;
		idx++;
	}

	for (i = 0; i < ctldev->vf_num[PF1_IDX]; i++) {
		ob_info = &ctldev->ob_per_fun[idx];
		ob_info->pf = PF1_IDX;
		ob_info->is_vf = 1;
		ob_info->vf = i;
		ob_info->out_offset = current_offset;
		ob_info->out_win_idx = current_win_idx;
		current_offset += ctldev->out_size_per_fun;
		current_win_idx += ctldev->out_win_per_fun;
		ob_info->out_win_nb = ctldev->out_win_per_fun;
		idx++;
	}

	return 0;
}

static int
lsx_pciep_find_all(void)
{
	int ret, ep_nb = 0;
	const struct device_node *pcie_node;
	const char *compatible;
	struct lsx_pciep_ctl_dev *ctldev = NULL;

	ret = of_init();
	if (ret) {
		LSX_PCIEP_BUS_ERR("of_init failed\n");

		return -ENODEV;
	}

	/* ctldev is temporally pointed to the first
	 * PCIe dev to identify the PEX type.
	 */
	ctldev = &s_pctldev[0];
	switch (ctldev->type) {
	case PEX_UNKNOWN:
		return -ENODEV;

	case PEX_LX2160_REV1:
		compatible = LX2160A_REV1_PCIE_COMPATIBLE;
		break;

	case PEX_LX2160_REV2:
		compatible = LX2160A_REV2_PCIE_COMPATIBLE;
		break;

	case PEX_LS208X:
		compatible = LS2088A_PCIE_COMPATIBLE;
		break;

	default:
		return -ENODEV;
	}

	for_each_compatible_node(pcie_node, NULL, compatible) {
		if (!of_device_is_available(pcie_node))
			continue;

		ctldev = lsx_pciep_node2ctl(pcie_node);
		if (!ctldev)
			continue;
		if (lsx_pciep_id_filtered(ctldev->index))
			continue;

		if (lsx_pciep_ctl_is_ep(ctldev)) {
			ret = lsx_pciep_node_out_base(ctldev, pcie_node);
			if (!ret) {
				lsx_pciep_ctl_update_dma_addr(ctldev);
				ctldev->dbi = (uint8_t *)ctldev->reg;
				lsx_pciep_ctl_ob_win_scheme(ctldev);
				ep_nb++;
				ctldev->ep_enable = 1;
			}
		} else {
			if (ctldev->reg)
				munmap(ctldev->reg, ctldev->size);
		}
	}

	if (!ep_nb && lsx_pciep_sim())
		ep_nb = lsx_pciep_sim_dev_add();

	LSX_PCIEP_BUS_INFO("PCIe EP finds %d pcie ep(s)", ep_nb);

	return ep_nb;
}

static int
lsx_pciep_ctl_init_inbound(struct lsx_pciep_ctl_dev *ctldev,
	uint8_t bar_num, size_t bar_size, uint8_t pf,
	int is_vf, uint8_t vf)
{
	int create = 0;
	struct lsx_pciep_inbound_info *inbound_info;
	struct lsx_pciep_inbound_bar *bar_mem;
	struct lsx_pciep_ops *ops = ctldev->ops;
	char mz_name[RTE_MEMZONE_NAMESIZE];
	const struct rte_memzone *mz;
	size_t mz_size;

	if (bar_size < LSX_PCIEP_INBOUND_MIN_BAR_SIZE)
		bar_size = LSX_PCIEP_INBOUND_MIN_BAR_SIZE;
	if (!rte_is_power_of_2(bar_size))
		bar_size = rte_align64pow2(bar_size);

	if (!ops) {
		LSX_PCIEP_BUS_ERR("%s no ops", __func__);

		return -EINVAL;
	}

	if (!ctldev->inbound_info) {
		ctldev->inbound_info =
			malloc(sizeof(struct lsx_pciep_inbound_info));
		if (!ctldev->inbound_info) {
			LSX_PCIEP_BUS_ERR("%s inbound_info alloc failed",
				__func__);

			return -ENOMEM;
		}
		memset((char *)ctldev->inbound_info, 0,
			sizeof(struct lsx_pciep_inbound_info));
	}

	inbound_info = ctldev->inbound_info;

	if (bar_num >= LSX_PCIEP_INBOUND_BAR_NUM) {
		LSX_PCIEP_BUS_ERR("%s too large bar number(%d)",
			__func__, bar_num);

		return -EINVAL;
	}

	if (pf >= PF_MAX_NB) {
		LSX_PCIEP_BUS_ERR("%s invalid pf(%d)", __func__, pf);

		return -EINVAL;
	}

	if (!is_vf) {
		if (inbound_info->pf_mz[pf][bar_num]) {
			LSX_PCIEP_BUS_ERR("%s pf(%d) bar(%d) has been created!",
				__func__, pf, bar_num);

			return -EINVAL;
		}
		bzero(mz_name, RTE_MEMZONE_NAMESIZE);
		snprintf(mz_name, RTE_MEMZONE_NAMESIZE - 1,
			"mz_pciep%d_pf%d_bar%d",
			ctldev->index, pf, bar_num);
		create = 1;
	} else {
		if (vf >= PCIE_MAX_VF_NUM) {
			LSX_PCIEP_BUS_ERR("%s invalid vf(%d)", __func__, vf);

			return -EINVAL;
		}
		if (!inbound_info->vf_mz[pf][bar_num]) {
			bzero(mz_name, RTE_MEMZONE_NAMESIZE);
			snprintf(mz_name, RTE_MEMZONE_NAMESIZE - 1,
				"mz_pciep%d_pf%d_vf_bar%d",
				ctldev->index, pf, bar_num);
			create = 1;
		}
	}

	if (create) {
		if (is_vf)
			mz_size = bar_size * PCIE_MAX_VF_NUM * 2;
		else
			mz_size = bar_size * 2;
		mz = rte_memzone_reserve_aligned(mz_name,
				mz_size, 0, RTE_MEMZONE_IOVA_CONTIG,
				mz_size);
		if (!mz || !mz->iova || !mz->addr) {
			LSX_PCIEP_BUS_ERR("Unable to allocate DMA memory "
				"of size %zu bytes, idx:%d\n",
				bar_size,
				ctldev->index);

			return -ENOMEM;
		}
		LSX_PCIEP_BUS_INFO("%s len(%d) iova(0x%lx ~ 0x%lx) reserved for inbound window.",
			mz_name, (int)mz_size, mz->iova, mz->iova + mz_size);
		if (!is_vf)
			inbound_info->pf_mz[pf][bar_num] = mz;
		else
			inbound_info->vf_mz[pf][bar_num] = mz;

		if (!lsx_pciep_sim()) {
			ops->pcie_set_ib_win(ctldev,
				LSX_PCIEP_CTRL_IB_IDX(pf, is_vf, bar_num),
				pf, is_vf,
				bar_num,
				mz->iova, mz->len, 0);
		}
	}

	if (!is_vf) {
		mz = inbound_info->pf_mz[pf][bar_num];
		bar_mem = &inbound_info->pf_ib_bar[pf][bar_num];
		bzero(bar_mem->name, RTE_DEV_NAME_MAX_LEN);
		snprintf(bar_mem->name,
			RTE_DEV_NAME_MAX_LEN - 1,
			"pciep%d_pf%d_bar%d",
			ctldev->index, pf, bar_num);
		bar_mem->inbound_virt = (uint8_t *)mz->addr;
		bar_mem->inbound_iova = mz->iova;
		bar_mem->size = mz->len;
	} else {
		mz = inbound_info->vf_mz[pf][bar_num];
		bar_mem = &inbound_info->vf_ib_bar[pf][vf][bar_num];
		snprintf(bar_mem->name,
			RTE_DEV_NAME_MAX_LEN - 1,
			"pciep%d_pf%d_vf%d_bar%d",
			ctldev->index, pf, vf, bar_num);
		bar_mem->inbound_virt =
			(uint8_t *)mz->addr + bar_size * vf;
		bar_mem->inbound_iova =
			mz->iova + bar_size * vf;
		bar_mem->size = bar_size;
	}

	return 0;
}

int lsx_pciep_ctl_init_win(uint8_t pcie_idx)
{
	struct lsx_pciep_ctl_dev *ctldev =
		lsx_pciep_ctl_get_dev(pcie_idx);

	if (ctldev && ctldev->ep_enable && !ctldev->init) {
		if (!lsx_pciep_sim()) {
			if (!ctldev->ops)
				return -EINVAL;
			if (ctldev->share_ob == LSX_PCIEP_OB_PER_FUN ||
				ctldev->share_ob == LSX_PCIEP_OB_PRIMARY_SHARE) {
				if (ctldev->ops->pcie_disable_ob_win)
					ctldev->ops->pcie_disable_ob_win(ctldev, -1);
			}
			if (ctldev->clear_ib &&
				ctldev->ops->pcie_disable_ib_win)
				ctldev->ops->pcie_disable_ib_win(ctldev, -1);
		}
		ctldev->init = 1;
	}

	return 0;
}

#ifndef IORESOURCE_MEM
#define IORESOURCE_MEM        0x00000200
#endif

static int lsx_pciep_sim_rm_dir(const char *dir)
{
	char cur_dir[] = ".";
	char up_dir[] = "..";
	char dir_name[512];
	DIR *dirp;
	struct dirent *dp;
	struct stat dir_stat;

	if (access(dir, F_OK) != 0)
		return 0;

	if (stat(dir, &dir_stat) < 0) {
		perror("get directory stat error");
		return -1;
	}

	if (S_ISREG(dir_stat.st_mode)) {
		remove(dir);
	} else if (S_ISDIR(dir_stat.st_mode)) {
		dirp = opendir(dir);
		while ((dp = readdir(dirp)) != NULL) {
			if (strcmp(cur_dir, dp->d_name) == 0 ||
				strcmp(up_dir, dp->d_name) == 0) {
				continue;
			}

			sprintf(dir_name, "%s/%s", dir, dp->d_name);
			lsx_pciep_sim_rm_dir(dir_name);
		}
		closedir(dirp);

		rmdir(dir);
	} else {
		perror("unknown file type!");
	}

	return 0;
}

int
lsx_pciep_sim_dev_map_inbound(struct rte_lsx_pciep_device *ep_dev)
{
	char dir_name[64];
	char file_name[128];
	char file_link_name[128];
	char buf[1024];
	int status, fd, i, idx = 0, pf = ep_dev->pf;
	uint64_t flag = IORESOURCE_MEM;
	int ret;
	char *penv;
	struct lsx_pciep_ctl_dev *ctldev =
		lsx_pciep_ctl_get_dev(ep_dev->pcie_id);
	uint16_t vendor_id, device_id, class_id;

	if (!lsx_pciep_sim())
		return 0;

	if (ep_dev->is_vf) {
		LSX_PCIEP_BUS_ERR("PCIe EP simulator does not support VF.");

		return -ENODEV;
	}

	vendor_id = ctldev->vendor_id[pf];
	device_id = ctldev->device_id[pf];
	class_id = ctldev->class_id[pf];

	penv = getenv("PCIE_EP_SIM_DEV_PATH");
	if (!penv) {
		snprintf(dir_name, sizeof(dir_name),
			LSX_PCIEP_SIM_DEFAULT_PATH PCI_PRI_FMT,
			ep_dev->pcie_id, LSX_PCIEP_SIM_BUS,
			LSX_PCIEP_SIM_PF_DEV,
			pf);
	} else {
		strcpy(dir_name, penv);
		snprintf(dir_name + strlen(penv),
			sizeof(dir_name) - strlen(penv),
			PCI_PRI_FMT, ep_dev->pcie_id,
			LSX_PCIEP_SIM_BUS,
			LSX_PCIEP_SIM_PF_DEV, pf);
	}

	if (!access(dir_name, F_OK)) {
		status = lsx_pciep_sim_rm_dir(dir_name);
		if (status < 0) {
			LSX_PCIEP_BUS_ERR("Remove dir %s failed\r\n", dir_name);

			return -ENODEV;
		}
	}

	status = mkdir(dir_name, 0777);
	if (status < 0) {
		LSX_PCIEP_BUS_ERR("Create dir %s failed\r\n", dir_name);
		return -ENODEV;
	}

	snprintf(file_name, sizeof(file_name), "%s/vendor", dir_name);
	sprintf(buf, "0x%04x\n", vendor_id);
	fd = open(file_name, O_RDWR | O_CREAT, 0660);
	if (fd < 0) {
		LSX_PCIEP_BUS_ERR("Open file %s failed\r\n", file_name);

		return -ENODEV;
	}
	ret = write(fd, buf, 7);
	if (ret < 0) {
		LSX_PCIEP_BUS_ERR("Write file %s failed\r\n", file_name);
		close(fd);

		return -ENODEV;
	}
	close(fd);

	snprintf(file_name, sizeof(file_name), "%s/device", dir_name);
	sprintf(buf, "0x%04x\n", device_id);
	fd = open(file_name, O_RDWR | O_CREAT, 0660);
	if (fd < 0) {
		LSX_PCIEP_BUS_ERR("Open file %s failed\r\n", file_name);
		return -ENODEV;
	}
	ret = write(fd, buf, 7);
	if (ret < 0) {
		LSX_PCIEP_BUS_ERR("Write file %s failed\r\n", file_name);
		close(fd);
		return -ENODEV;
	}
	close(fd);

	snprintf(file_name, sizeof(file_name), "%s/subsystem_vendor", dir_name);
	sprintf(buf, "0x%04x\n", vendor_id);
	fd = open(file_name, O_RDWR | O_CREAT, 0660);
	if (fd < 0) {
		LSX_PCIEP_BUS_ERR("Open file %s failed\r\n", file_name);
		return -ENODEV;
	}
	ret = write(fd, buf, 7);
	if (ret < 0) {
		LSX_PCIEP_BUS_ERR("Write file %s failed\r\n", file_name);
		close(fd);
		return -ENODEV;
	}
	close(fd);

	snprintf(file_name, sizeof(file_name), "%s/subsystem_device", dir_name);
	sprintf(buf, "0x%04x\n", device_id);
	fd = open(file_name, O_RDWR | O_CREAT, 0660);
	if (fd < 0) {
		LSX_PCIEP_BUS_ERR("Open file %s failed\r\n", file_name);
		return -ENODEV;
	}
	ret = write(fd, buf, 7);
	if (ret < 0) {
		LSX_PCIEP_BUS_ERR("Write file %s failed\r\n", file_name);
		close(fd);
		return -ENODEV;
	}
	close(fd);

	snprintf(file_name, sizeof(file_name), "%s/class", dir_name);
	sprintf(buf, "0x%04x\n", class_id);
	fd = open(file_name, O_RDWR | O_CREAT, 0660);
	if (fd < 0) {
		LSX_PCIEP_BUS_ERR("Open file %s failed\r\n", file_name);
		return -ENODEV;
	}
	ret = write(fd, buf, 7);
	if (ret < 0) {
		LSX_PCIEP_BUS_ERR("Write file %s failed\r\n", file_name);
		close(fd);
		return -ENODEV;
	}
	close(fd);

	snprintf(file_link_name, sizeof(file_link_name),
		"%s/igb_uio", dir_name);
	sprintf(buf, "%s", "igb_uio\n");
	fd = open(file_link_name, O_RDWR | O_CREAT, 0660);
	if (fd < 0) {
		LSX_PCIEP_BUS_ERR("Open file %s failed\r\n", file_name);
		return -ENODEV;
	}
	ret = write(fd, buf, sizeof("igb_uio\n"));
	if (ret < 0) {
		LSX_PCIEP_BUS_ERR("Write file %s failed\r\n", file_name);
		close(fd);
		return -ENODEV;
	}
	close(fd);
	snprintf(file_name, sizeof(file_name), "%s/driver", dir_name);
	ret = symlink(file_link_name, file_name);
	if (ret < 0) {
		LSX_PCIEP_BUS_ERR("Symlink file %s failed\r\n", file_name);
		return -ENODEV;
	}

	snprintf(file_name, sizeof(file_name), "%s/resource", dir_name);
	for (i = 0; i < PCI_MAX_RESOURCE; i++) {
		if (i < LSX_PCIEP_INBOUND_BAR_NUM &&
			ctldev->inbound_info->pf_ib_bar[pf][i].size) {
			sprintf(&buf[idx], "0x%016lx",
				ctldev->inbound_info->pf_ib_bar[pf][i].inbound_phy);
			idx += 18;
			sprintf(&buf[idx], " ");
			idx++;

			sprintf(&buf[idx], "0x%016lx",
				ctldev->inbound_info->pf_ib_bar[pf][i].inbound_phy +
				ctldev->inbound_info->pf_ib_bar[pf][i].size - 1);

			idx += 18;
			sprintf(&buf[idx], " ");
			idx++;

			sprintf(&buf[idx], "0x%016lx\r\n", flag);
			idx += 20;
		} else {
			sprintf(&buf[idx], "0x%016lx", (dma_addr_t)0);
			idx += 18;
			sprintf(&buf[idx], " ");
			idx++;
			sprintf(&buf[idx], "0x%016lx", (dma_addr_t)0);
			idx += 18;
			sprintf(&buf[idx], " ");
			idx++;
			sprintf(&buf[idx], "0x%016lx\r\n", (dma_addr_t)0);
			idx += 20;
		}
	}

	fd = open(file_name, O_RDWR | O_CREAT, 0660);
	if (fd < 0) {
		LSX_PCIEP_BUS_ERR("Open file %s failed\r\n", file_name);
		return -ENODEV;
	}
	ret = write(fd, buf, idx);
	if (ret < 0) {
		LSX_PCIEP_BUS_ERR("Write file %s failed\r\n", file_name);
		close(fd);
		return -ENODEV;
	}
	close(fd);

	printf("ep PEX%d:pf%d bar info:\r\n%s\r\n",
		ep_dev->pcie_id, ep_dev->pf, buf);

	return 0;
}

int
lsx_pciep_ctl_dev_set(uint16_t vendor_id,
	uint16_t device_id, uint16_t class_id,
	uint8_t pcie_id, uint8_t pf)
{
	struct lsx_pciep_ctl_dev *ctldev;

	if (pcie_id >= LSX_MAX_PCIE_NB || pf >= PF_MAX_NB) {
		LSX_PCIEP_BUS_ERR("%s Invalid PCIe ID or PF ID",
			__func__);

		return -EINVAL;
	}

	ctldev = &s_pctldev[pcie_id];
	if (!ctldev->ep_enable) {
		LSX_PCIEP_BUS_ERR("%s PCIe(%d) is not EP",
			__func__, pcie_id);

		return -ENODEV;
	}
	if (!ctldev->pf_enable[pf]) {
		LSX_PCIEP_BUS_ERR("%s PCIe(%d) pf(%d) is not enabled",
			__func__, pcie_id, pf);

		return -ENODEV;
	}

	ctldev->vendor_id[pf] = vendor_id;
	ctldev->device_id[pf] = device_id;
	ctldev->class_id[pf] = class_id;

	if (!lsx_pciep_sim()) {
		if (ctldev->ops && ctldev->ops->pcie_reinit)
			ctldev->ops->pcie_reinit(ctldev, (1 << pf));
	}

	return 0;
}

int
lsx_pciep_init(void)
{
	int ret;

	if (s_pciep_init_flag) {
		LSX_PCIEP_BUS_INFO("%s has been executed!", __func__);

		return 0;
	}

	if (lsx_pciep_set_type())
		return -ENODEV;

	ret = lsx_pciep_find_all();
	if (ret <= 0)
		return -ENODEV;

	s_pciep_init_flag = 1;

	return 0;
}

int
lsx_pciep_uninit(void)
{
	int dev_idx, i, j;
	struct lsx_pciep_ctl_dev *ctldev;
	struct lsx_pciep_inbound_info *inbound_info;

	for (dev_idx = 0; dev_idx < LSX_MAX_PCIE_NB; dev_idx++) {
		ctldev = &s_pctldev[dev_idx];
		if (!ctldev->ep_enable)
			continue;

		inbound_info = ctldev->inbound_info;
		for (i = 0; i < PF_MAX_NB; i++) {
			for (j = 0; j < LSX_PCIEP_INBOUND_BAR_NUM; j++) {
				if (inbound_info->pf_mz[i][j]) {
					rte_memzone_free(inbound_info->pf_mz[i][j]);
					inbound_info->pf_mz[i][j] = NULL;
				}
				if (inbound_info->vf_mz[i][j]) {
					rte_memzone_free(inbound_info->vf_mz[i][j]);
					inbound_info->vf_mz[i][j] = NULL;
				}
			}
		}
		free(inbound_info);
		ctldev->inbound_info = NULL;

		if (ctldev->reg)
			munmap(ctldev->reg, ctldev->size);

		if (ctldev->out_vaddr)
			munmap((void *)ctldev->out_vaddr, CFG_32G_SIZE);

		ctldev->ep_enable = 0;
	}

	s_pciep_init_flag = 0;

	return 0;
}

int
lsx_pciep_set_ib_win(struct rte_lsx_pciep_device *ep_dev,
	uint8_t bar_idx, uint64_t size)
{
	int pcie_id = ep_dev->pcie_id;
	int pf = ep_dev->pf;
	int vf = ep_dev->vf;
	int is_vf = ep_dev->is_vf;
	int ret;
	struct lsx_pciep_ctl_dev *ctldev = &s_pctldev[pcie_id];

	ret = lsx_pciep_ctl_init_inbound(ctldev, bar_idx, size,
		pf, is_vf, vf);
	if (ret) {
		LSX_PCIEP_BUS_ERR("%s Inbound window init failed!",
			ep_dev->device.name);

		return ret;
	}

	if (!is_vf) {
		ep_dev->virt_addr[bar_idx] =
			ctldev->inbound_info->pf_ib_bar[pf][bar_idx].inbound_virt;
	} else {
		ep_dev->virt_addr[bar_idx] =
			ctldev->inbound_info->vf_ib_bar[pf][vf][bar_idx].inbound_virt;
	}

	return 0;
}

static uint64_t
lsx_pciep_set_ob_win_rbp(struct rte_lsx_pciep_device *ep_dev,
		uint64_t pci_addr, uint64_t size)
{
	int pf = ep_dev->pf;
	int vf = ep_dev->vf;
	int is_vf = ep_dev->is_vf;
	int pcie_id = ep_dev->pcie_id;
	uint64_t offset, map_pci_addr, mask;
	struct lsx_pciep_ctl_dev *ctldev = &s_pctldev[pcie_id];
	uint32_t win_idx;

	mask = ctldev->out_win_size - 1;

	offset = pci_addr & mask;
	map_pci_addr = pci_addr & ~mask;

	win_idx = LSX_PCIEP_RBP_OB_WIN_START(pf, is_vf, vf);
	win_idx += LSX_PCIEP_RBP_OB_RC_MEM;
	ep_dev->ob_phy_base =
			ctldev->out_base + win_idx * ctldev->out_win_size;
	ep_dev->ob_virt_base =
			ctldev->out_vaddr + win_idx * ctldev->out_win_size;

	ep_dev->ob_map_bus_base = map_pci_addr;
	ep_dev->ob_orig_bus_base = pci_addr;
	ep_dev->ob_win_size = ctldev->out_win_size;

	if (size > ep_dev->ob_win_size) {
		LSX_PCIEP_BUS_ERR("Outbound PEX%d PF%d-VF%d size expected %ld > %ld",
			ep_dev->pcie_id, pf, vf, size, ep_dev->ob_win_size);
	}

	if (is_vf)
		LSX_PCIEP_BUS_INFO("Outbound PEX%d PF%d-VF%d: Win:%d"
			"  MEM VIRT:0x%" PRIx64
			"  MEM:0x%" PRIx64
			"  PCI:0x%" PRIx64
			"  SIZE:0x%" PRIx64,
			ep_dev->pcie_id, pf, vf, win_idx,
			ep_dev->ob_virt_base,
			ep_dev->ob_phy_base,
			ep_dev->ob_map_bus_base,
			ep_dev->ob_win_size);
	else
		LSX_PCIEP_BUS_INFO("Outbound PEX%d PF%d: Win:%d"
			"  MEM VIRT:0x%" PRIx64
			"  MEM:0x%" PRIx64
			"  PCI:0x%" PRIx64
			"  SIZE:0x%" PRIx64,
			ep_dev->pcie_id, pf, win_idx,
			ep_dev->ob_virt_base,
			ep_dev->ob_phy_base,
			ep_dev->ob_map_bus_base,
			ep_dev->ob_win_size);
	ctldev->ops->pcie_set_ob_win(ctldev, win_idx, pf, is_vf, vf,
				ep_dev->ob_phy_base,
				ep_dev->ob_map_bus_base,
				ep_dev->ob_win_size);

	return ep_dev->ob_virt_base + offset;
}

static uint64_t
lsx_pciep_set_ob_win_norbp(struct rte_lsx_pciep_device *ep_dev)
{
	int pf = ep_dev->pf;
	int is_vf = ep_dev->is_vf;
	int vf = ep_dev->vf;
	int pcie_id = ep_dev->pcie_id;
	struct lsx_pciep_ctl_dev *ctldev = &s_pctldev[pcie_id];
	uint32_t idx, out_win_nb, out_win_start;
	uint64_t pci_addr = 0, out_phy, out_offset = 0;
	uint64_t offset, map_pci_addr, mask;
	struct lsx_pciep_norbp_fun_out_info *ob_info = NULL;

	if (ctldev->ob_per_fun) {
		for (idx = 0; idx < ctldev->function_num; idx++) {
			ob_info = &ctldev->ob_per_fun[idx];
			if (is_vf) {
				if (ob_info->pf == pf && ob_info->is_vf &&
					ob_info->vf == vf)
					break;
			} else {
				if (ob_info->pf == pf && !ob_info->is_vf)
					break;
			}
			ob_info = NULL;
		}

		if (!ob_info)
			return 0;
		out_win_nb = ob_info->out_win_nb;
		out_offset = ob_info->out_offset;
		out_win_start = ob_info->out_win_idx;
	} else {
		out_win_nb = ctldev->out_win_per_fun;
		out_offset = ctldev->out_offset;
		out_win_start = ctldev->out_win_start;
	}

	mask = ctldev->out_win_size - 1;

	offset = pci_addr & mask;
	map_pci_addr = pci_addr & ~mask;

	out_phy = ctldev->out_base + out_offset;
	ep_dev->ob_orig_bus_base = pci_addr;
	ep_dev->ob_map_bus_base = map_pci_addr;
	ep_dev->ob_phy_base = out_phy;
	ep_dev->ob_virt_base = ctldev->out_vaddr + out_offset;
	ep_dev->ob_win_size = ctldev->out_win_size * out_win_nb;

	/* MSIx shares the same outbound */
	ep_dev->msix_bus_base = ep_dev->ob_map_bus_base;
	ep_dev->msix_virt_base = ep_dev->ob_virt_base;
	ep_dev->msix_phy_base = ep_dev->ob_phy_base;
	ep_dev->msix_win_size = ep_dev->ob_win_size;
	ep_dev->msix_win_init_flag = 1;

	if ((!ctldev->ob_per_fun &&
		ctldev->share_ob == LSX_PCIEP_OB_SECONDARY_SHARE) ||
		ctldev->share_ob_complete)
		return ep_dev->ob_virt_base + pci_addr;

	for (idx = 0; idx < out_win_nb; idx++) {
		out_phy += ctldev->out_win_size * idx;
		pci_addr += ctldev->out_win_size * idx;
		ctldev->ops->pcie_set_ob_win(ctldev,
						out_win_start + idx,
					    pf, is_vf, vf,
					    out_phy,
					    pci_addr,
					    ctldev->out_win_size);
	}

	if (!ctldev->ob_per_fun)
		ctldev->share_ob_complete = 1;

	return ep_dev->ob_virt_base + offset;
}

uint64_t
lsx_pciep_set_ob_win(struct rte_lsx_pciep_device *ep_dev,
		uint64_t pci_addr, uint64_t size)
{
	int pcie_id = ep_dev->pcie_id;
	struct lsx_pciep_ctl_dev *ctldev = &s_pctldev[pcie_id];

	if (ctldev->rbp)
		return lsx_pciep_set_ob_win_rbp(ep_dev, pci_addr, size);
	else
		return lsx_pciep_set_ob_win_norbp(ep_dev);
}

void
lsx_pciep_msix_init(struct rte_lsx_pciep_device *ep_dev)
{
	int pcie_id = ep_dev->pcie_id;
	struct lsx_pciep_ctl_dev *ctldev = &s_pctldev[pcie_id];

	ctldev->ops->pcie_msix_init(ctldev, ep_dev);
}

uint64_t
lsx_pciep_msix_get_vaddr(struct rte_lsx_pciep_device *ep_dev,
			   uint32_t vector)
{
	int pcie_id = ep_dev->pcie_id;
	struct lsx_pciep_ctl_dev *ctldev = &s_pctldev[pcie_id];

	return ctldev->ops->pcie_msix_get_vaddr(ctldev, ep_dev, vector);
}

uint32_t
lsx_pciep_msix_get_cmd(struct rte_lsx_pciep_device *ep_dev,
			 uint32_t vector)
{
	int pcie_id = ep_dev->pcie_id;
	struct lsx_pciep_ctl_dev *ctldev = &s_pctldev[pcie_id];

	return ctldev->ops->pcie_msix_get_cmd(ctldev, ep_dev, vector);
}

void
lsx_pciep_msix_cmd_send(uint64_t addr, uint32_t cmd)
{
	rte_write32(cmd, (void *)addr);
}
