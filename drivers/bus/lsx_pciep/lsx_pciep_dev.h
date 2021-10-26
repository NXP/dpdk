/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2021 NXP
 */

#ifndef _LSX_PCIEP_DEV_H_
#define _LSX_PCIEP_DEV_H_

#include <rte_lsx_pciep_bus.h>

/* common definition */

#define LSX_MAX_PCIE_NB 6

#define PCIE_OB_SHADOW_WIN_OFF	0
#define PCIE_OB_MSIX_WIN_OFF	1
#define PCIE_OB_RBP_WIN_OFF	2

#define LS2088A_PCIE_COMPATIBLE "fsl,ls2088a-pcie-ep"
#define LX2160A_REV1_PCIE_COMPATIBLE "fsl,lx2160a-pcie-ep"
#define LX2160A_REV2_PCIE_COMPATIBLE LS2088A_PCIE_COMPATIBLE

#define PCI_DMA_RBP_1T_BASE		(0x010000000000)
#define PCI_DMA_RBP_0_BASE		(0)

#define LSX_PCIEP_QDMA_RBP_SUPPORT 1

#define LSX_PCIE_SIM_IDX 0

struct lsx_pciep_inbound_bar {
	char name[RTE_DEV_NAME_MAX_LEN];
	uint8_t *inbound_virt;
	union {
		uint64_t inbound_iova;
		uint64_t inbound_phy;
	};
	uint64_t size;
};

struct lsx_pciep_norbp_fun_out_info {
	int pf;
	int is_vf;
	int vf;
	uint64_t out_offset;
	uint16_t out_win_idx;
	uint16_t out_win_nb;
};

enum lsx_pciep_rbp_ob_win {
	LSX_PCIEP_RBP_OB_RC_MEM,
	LSX_PCIEP_RBP_OB_MSIX,
	LSX_PCIEP_RBP_OB_WIN_NB
};

static inline int
LSX_PCIEP_RBP_OB_WIN_START(int pf, int is_vf, int vf)
{
	if (is_vf)
		return (((pf) << 6 | (vf + 1)) * LSX_PCIEP_RBP_OB_WIN_NB);
	else
		return (((pf) << 6) * LSX_PCIEP_RBP_OB_WIN_NB);
}

enum lsx_share_ob {
	LSX_PCIEP_OB_PER_FUN,
	LSX_PCIEP_OB_PRIMARY_SHARE,
	LSX_PCIEP_OB_SECONDARY_SHARE
};

enum sriov_fun_idx {
	PF_IDX,
	VF_IDX,
	SRIOV_FUN_MAX
};

struct lsx_pciep_inbound_info {
	const struct rte_memzone
		*pf_mz[PF_MAX_NB][LSX_PCIEP_INBOUND_BAR_NUM];
	/* All the VFs of PF share one mz.*/
	const struct rte_memzone
		*vf_mz[PF_MAX_NB][LSX_PCIEP_INBOUND_BAR_NUM];

	struct lsx_pciep_inbound_bar
		pf_ib_bar[PF_MAX_NB][LSX_PCIEP_INBOUND_BAR_NUM];
	struct lsx_pciep_inbound_bar
		vf_ib_bar[PF_MAX_NB][PCIE_MAX_VF_NUM][LSX_PCIEP_INBOUND_BAR_NUM];
};


/**
 * A structure describing a PCIe controller.
 */
struct lsx_pciep_ctl_dev {
	uint8_t			index;
	uint8_t			init;
	int				ep_enable;
	int				sim;
	uint16_t function_num;
	int pf_enable[PF_MAX_NB];
	int vf_num[PF_MAX_NB];
	uint16_t vendor_id[PF_MAX_NB];
	uint16_t device_id[PF_MAX_NB];
	uint16_t class_id[PF_MAX_NB];

	enum PEX_TYPE		type;

	uint32_t		size;
	uint64_t		phy;
	void			*reg;
	uint8_t			*dbi;

	uint64_t		out_vaddr;
	uint64_t		out_base;
	uint64_t		dma_out_base;

	int			rbp;
	enum lsx_share_ob share_ob;
	int			share_ob_complete;
	int			clear_ib;

	uint64_t out_offset;
	uint64_t out_size;
	uint64_t out_win_size;
	uint64_t out_size_per_fun;
	uint32_t out_win_start;
	uint32_t out_win_per_fun;

	struct lsx_pciep_ops *ops;
	struct lsx_pciep_inbound_info *inbound_info;
	struct lsx_pciep_norbp_fun_out_info *ob_per_fun;
};

int lsx_pciep_ctl_idx_validated(uint8_t pcie_idx);
struct lsx_pciep_ctl_dev *lsx_pciep_ctl_get_dev(uint8_t pcie_idx);

int lsx_pciep_init(void);
int lsx_pciep_uninit(void);
void lsx_pciep_ctl_set_sriov_num(uint8_t pcie_idx,
			uint32_t pf0, uint32_t pf1,
			uint32_t pf0_vf_num, uint32_t pf1_vf_num);
void lsx_pciep_ctl_set_all_devs(uint32_t pf0,
			uint32_t pf1, uint32_t pf0_vf_num,
			uint32_t pf1_vf_num, int rbp,
			enum lsx_share_ob share_ob);
int lsx_pciep_ctl_init_win(uint8_t pcie_idx);

int lsx_pciep_id_filtered(int id);
int lsx_pciep_sim_dev_add(void);
void *lsx_pciep_map_region(uint64_t addr, size_t len);

#endif
