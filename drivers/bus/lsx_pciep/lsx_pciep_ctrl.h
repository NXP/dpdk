/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2022 NXP
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

#define CFG_MSIX_OB_SIZE	(64 * CFG_1M_SIZE)  /* 64M */

#define LSX_PCIEP_BAR0_DEFAULT_SIZE		(8 * 1024)
#define LSX_PCIEP_BAR1_DEFAULT_SIZE		(8 * 1024 * 1024)
#define LSX_PCIEP_BAR2_DEFAULT_SIZE		(2 * 1024 * 1024)

struct lsx_pciep_ops {
	void (*pcie_config)(struct lsx_pciep_hw_low *hw);

	void (*pcie_deconfig)(struct lsx_pciep_hw_low *hw);

	int (*pcie_fun_init)(struct lsx_pciep_hw_low *hw,
			int pf, int is_vf, uint16_t vendor_id,
			uint16_t device_id, uint16_t class_id);

	void (*pcie_disable_ob_win)(struct lsx_pciep_hw_low *hw,
			int idx);

	void (*pcie_disable_ib_win)(struct lsx_pciep_hw_low *hw,
			int idx);

	uint64_t (*pcie_map_ob_win)(struct lsx_pciep_hw_low *hw,
			int pf, int is_vf, int vf,
			uint64_t pci_addr, uint64_t size, int shared);

	int (*pcie_cfg_ob_win)(struct lsx_pciep_hw_low *hw,
			int idx, int pf, int is_vf, int vf,
			uint64_t cpu_addr, uint64_t pci_addr,
			uint64_t size);

	int (*pcie_cfg_ib_win)(struct lsx_pciep_hw_low *hw,
			int pf, int is_vf, int vf, int bar,
			uint64_t phys, uint64_t size, int resize);

	int (*pcie_msix_cfg)(struct lsx_pciep_hw_low *hw,
			int pf, int is_vf, int vf,
			uint64_t msg_addr[], uint32_t msg_data[],
			int vector_total);

	uint64_t (*pcie_get_ob_unmapped)(struct lsx_pciep_hw_low *hw);

	int (*pcie_is_sriov)(struct lsx_pciep_hw_low *hw);
};

struct lsx_pciep_ops *lsx_pciep_get_mv_ops(void);
struct lsx_pciep_ops *lsx_pciep_get_dw_ops(void);

#endif
