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

struct lsx_pciep_ob_win {
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

/** Provide outbound space shared policy
 * for multiple functions of each PCIe controller.
 *  Note, this policy only works for none RBP mode.
 */
enum lsx_ob_policy {
	LSX_PCIEP_OB_FUN_IDX,
	LSX_PCIEP_OB_SHARE
};

enum sriov_fun_idx {
	PF_IDX,
	VF_IDX,
	SRIOV_FUN_MAX
};

struct lsx_pciep_ib_mem {
	const struct rte_memzone *
		pf_mz[PF_MAX_NB][PCI_MAX_RESOURCE];
	/* All the VFs of PF share one mz.*/
	const struct rte_memzone *
		vf_mz[PF_MAX_NB][PCI_MAX_RESOURCE];

	struct lsx_pciep_inbound_bar
		pf_ib_bar[PF_MAX_NB][PCI_MAX_RESOURCE];
	struct lsx_pciep_inbound_bar
		vf_ib_bar[PF_MAX_NB][PCIE_MAX_VF_NUM][PCI_MAX_RESOURCE];
};

/**
 * Structure describing HW information of PCIe controller.
 * This structure is global information shared between multiple
 * processes.
 */
struct lsx_pciep_ctl_hw {
	uint8_t	index;
	uint8_t	init;
	int sim;
	int rbp;
	int ep_enable;
	int vio_enable[PF_MAX_NB];
	uint16_t function_num;
	int pf_enable[PF_MAX_NB];
	int vf_enable[PF_MAX_NB][PCIE_MAX_VF_NUM];
	uint16_t vendor_id[PF_MAX_NB];
	uint16_t device_id[PF_MAX_NB];
	uint16_t class_id[PF_MAX_NB];

	enum PEX_TYPE type;

	uint32_t dbi_size;
	uint64_t dbi_phy;

	uint64_t out_base;
	uint64_t out_size;
	uint64_t out_map_start;
	uint64_t out_map_size;
	uint16_t out_win_start;
	uint64_t out_win_size;
	uint64_t out_size_per_fun;
	uint32_t out_win_per_fun;

	struct lsx_pciep_ib_mem ib_mem;
	enum lsx_ob_policy ob_policy;
	int share_ob_complete;
	struct lsx_pciep_ob_win ob_win[PF_MAX_NB * (PCIE_MAX_VF_NUM + 1)];
};

/**
 * Structure describing local process information of PCIe controller.
 */
struct lsx_pciep_ctl_dev {
	struct lsx_pciep_ctl_hw *ctl_hw;
	int clear_win;
	uint8_t *dbi_vir;
	uint8_t *out_vir;
	struct lsx_pciep_ops *ops;
};


int lsx_pciep_ctl_idx_validated(uint8_t pcie_idx);
struct lsx_pciep_ctl_dev *lsx_pciep_ctl_get_dev(uint8_t pcie_idx);

int lsx_pciep_primary_init(void);
int lsx_pciep_uninit(void);
int lsx_pciep_ctl_init_win(uint8_t pcie_idx);

int lsx_pciep_sim_dev_add(void);
void *lsx_pciep_map_region(uint64_t addr, size_t len);
int lsx_pciep_share_info_init(void);

#endif
