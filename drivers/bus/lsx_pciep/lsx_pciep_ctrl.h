/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2021 NXP
 */

#ifndef _LSX_PCIEP_CTRL_H_
#define _LSX_PCIEP_CTRL_H_

#include "lsx_pciep_dev.h"

#ifndef lower_32_bits
#define lower_32_bits(n) ((uint32_t)(n))
#endif

#ifndef upper_32_bits
#define upper_32_bits(x) ((uint32_t)(((x) >> 16) >> 16))
#endif

#define LSX_PCIEP_SIM_DEFAULT_PATH "/tmp/"

#define LSX_PCIEP_SIM_DOMAIN_START 0x0000
#define LSX_PCIEP_SIM_BUS 0x01
#define LSX_PCIEP_SIM_PF_DEV 0x00

#define CFG_SHAD_OB_SIZE	(128 * CFG_1M_SIZE)  /* 128M */
#define CFG_MSIX_OB_SIZE	(64 * CFG_1M_SIZE)  /* 64M */

#define LSX_PCIEP_BAR0_DEFAULT_SIZE		(8 * 1024)
#define LSX_PCIEP_BAR1_DEFAULT_SIZE		(8 * 1024 * 1024)
#define LSX_PCIEP_BAR2_DEFAULT_SIZE		(2 * 1024 * 1024)

#define PCI_BASE_ADDRESS_0	0x10	/* 32 bits */
#define PCI_BASE_ADDRESS_1	0x14	/* 32 bits [htype 0,1 only] */
#define PCI_BASE_ADDRESS_2	0x18	/* 32 bits [htype 0 only] */
#define PCI_BASE_ADDRESS_3	0x1c	/* 32 bits */
#define PCI_BASE_ADDRESS_4	0x20	/* 32 bits */
#define PCI_BASE_ADDRESS_5	0x24	/* 32 bits */

#define PCIE_SRIOV_VFBAR0	0x19C

/* 0 <= pf <= 1, 0 <= vf <= 1, 0 <= bar <= 3*/
#define LSX_PCIEP_CTRL_IB_IDX(pf, vf, bar) \
	(((uint8_t)pf) << 3 | ((uint8_t)vf) << 2 | ((uint8_t)bar))

typedef void (*lsx_pciep_ctrl_reinit)(struct lsx_pciep_ctl_dev *ctldev, uint8_t pf_mask);

typedef void (*lsx_pciep_ctrl_disable_ob_win)(struct lsx_pciep_ctl_dev *ctldev,
						int idx);
typedef void (*lsx_pciep_ctrl_disable_ib_win)(struct lsx_pciep_ctl_dev *ctldev,
						int idx);
typedef void (*lsx_pciep_ctrl_set_ob_win)(struct lsx_pciep_ctl_dev *ctldev,
					    int idx,
					    int pf, int is_vf, int vf,
					    uint64_t cpu_addr,
					    uint64_t pci_addr,
					    uint64_t size);

typedef void (*lsx_pciep_ctrl_set_ib_win)(struct lsx_pciep_ctl_dev *ctldev,
	int idx,
	int pf, int is_vf,
	int bar, uint64_t phys, uint64_t size,
	int resize);

typedef void (*lsx_pciep_ctrl_msix_init)(struct lsx_pciep_ctl_dev *ctldev,
	struct rte_lsx_pciep_device *lsinic_dev);

typedef uint64_t (*lsx_pciep_ctrl_msix_get_vaddr)(struct lsx_pciep_ctl_dev *ctldev,
	struct rte_lsx_pciep_device *lsinic_dev,
	uint32_t vector);

typedef uint32_t (*lsx_pciep_ctrl_msix_get_cmd)(struct lsx_pciep_ctl_dev *ctldev,
	struct rte_lsx_pciep_device *lsinic_dev,
	uint32_t vector);

struct lsx_pciep_ops {
	lsx_pciep_ctrl_reinit		pcie_reinit;

	lsx_pciep_ctrl_disable_ob_win	pcie_disable_ob_win;
	lsx_pciep_ctrl_disable_ib_win	pcie_disable_ib_win;
	lsx_pciep_ctrl_set_ob_win	pcie_set_ob_win;
	lsx_pciep_ctrl_set_ib_win	pcie_set_ib_win;

	lsx_pciep_ctrl_msix_init	pcie_msix_init;
	lsx_pciep_ctrl_msix_get_vaddr	pcie_msix_get_vaddr;
	lsx_pciep_ctrl_msix_get_cmd	pcie_msix_get_cmd;
};

struct lsx_pciep_ops *lsx_pciep_get_mv_ops(void);
struct lsx_pciep_ops *lsx_pciep_get_dw_ops(void);

#endif
