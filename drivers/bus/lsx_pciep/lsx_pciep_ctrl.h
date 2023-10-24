/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2023 NXP
 */

#ifndef _LSX_PCIEP_CTRL_H_
#define _LSX_PCIEP_CTRL_H_

#include <sys/mman.h>
#include <linux/pci_regs.h>
#include <rte_debug.h>
#include "lsx_pciep_dev.h"

#ifndef __packed
#define __packed __rte_packed
#endif

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

#define CFG_MSIX_OB_SIZE (64 * CFG_1M_SIZE)  /* 64M */

static inline int
lsx_pciep_32bar_to_64bar(uint8_t bar)
{
	if (bar >= PCI_MAX_RESOURCE)
		return -EINVAL;
	if (bar % 2)
		return -EINVAL;

	return bar / 2;
}

static inline int
lsx_pciep_valid_64b_bar_id(uint8_t bar_64b)
{
	if (bar_64b >= (PCI_MAX_RESOURCE / 2))
		return 0;

	return 1;
}

static inline int
lsx_pciep_64bar_to_32bar(uint8_t bar_64b)
{
	if (!lsx_pciep_valid_64b_bar_id(bar_64b))
		return -EINVAL;

	return bar_64b * 2;
}

#define PCI_EXT_CAP_ID_NULL 0

#define PCI_FUN_RESET_SRIOV_CAP (0x1 << 28)

struct pcie_ctrl_cap_head {
	uint8_t cap_id;
	uint8_t next_offset;
} __packed;

struct pcie_ctrl_sriov_cap {
	struct pcie_ctrl_cap_head head;
	uint32_t msix_table_size:11;
	uint32_t rsv1:3;
	uint32_t msix_fun_mask:1;
	uint32_t msix_enable:1;
	uint32_t msix_table_offset_bir;
	uint32_t msix_pba_offset_bir;
} __packed;

struct pcie_ctrl_ext_cap {
	uint32_t ext_cap_id:16;
	uint32_t cap_ver:4;
	uint32_t next_cap_off:12;
} __packed;

struct pcie_ctrl_ext_sriov_cap_ctl {
	uint16_t vf_enable:1;
	uint16_t vf_mig_enable:1;
	uint16_t vf_mig_int_enable:1;
	uint16_t vf_mse:1;
	uint16_t ari_hier:1;
	uint16_t rsv:11;
} __packed;

struct pcie_ctrl_ext_sriov_cap {
	struct pcie_ctrl_ext_cap ext_hdr;
	uint32_t sriov_cap;
	struct pcie_ctrl_ext_sriov_cap_ctl sriov_ctrl;
	uint16_t sriov_stat;
	uint16_t init_vf;
	uint16_t total_vf;
	uint16_t number_vf;
	uint8_t fun_link;
	uint8_t rsv4;
	uint16_t first_vf_pos;
	uint16_t vf_stride;
	uint16_t rsv5;
	uint16_t vf_dev_id;
} __packed;

struct pcie_ctrl_cfg {
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
	uint32_t pfbar[PCI_MAX_RESOURCE];
	uint32_t prefetch_base;
	uint16_t sub_vendor_id;
	uint16_t sub_device_id;
	uint32_t exp_rom_base;
	uint8_t cap_list;
	uint8_t unused0[0x50 - 0x35];
	uint8_t msi_cap_id;
	uint8_t rsv1;
	uint16_t msi_ctrl;
	uint32_t msi_addr_low;
	uint32_t msi_addr_high;
	uint16_t msi_data;
	uint8_t unused1[0x70 - 0x5e];
	uint8_t cap_id;
	uint8_t rsv2;
	uint16_t cap;
	uint32_t dev_cap;
	uint16_t dev_ctrl;
	uint16_t dev_stat;
	uint32_t link_cap;
	uint16_t link_ctrl;
	uint16_t link_stat;
	uint32_t slot_cap;
	uint16_t slot_ctrl;
	uint16_t slot_stat;
	uint16_t root_ctrl;
	uint16_t root_cap;
	uint32_t root_stat;
	uint8_t unused2[0xb0 - 0x94];
	uint8_t msix_cap_id;
	uint8_t rsv3;
	uint16_t msix_ctl;
	uint32_t msix_tbl;
	uint32_t msix_pba;
	uint8_t unused3[0x100 - 0xbc];
	struct pcie_ctrl_ext_cap aer_ext_hdr;
	uint32_t uncorrect_err_stat;
	uint32_t uncorrect_err_mask;
	uint32_t uncorrect_err_ser;
	uint32_t correct_err_stat;
	uint32_t correct_err_mask;
	uint32_t adv_err_cap_ctl;
	uint8_t unused4[0x148 - 0x11c];
	struct pcie_ctrl_ext_cap ari_ext_hdr;
	uint8_t unused5[0x158 - 0x14c];
	struct pcie_ctrl_ext_cap secpci_ext_hdr;
	uint8_t unused6[0x178 - 0x15c];
	struct pcie_ctrl_ext_sriov_cap sriov_ext_cap;
	uint32_t sup_page_size;
	uint32_t sys_page_size;
	uint32_t vfbar[PCI_MAX_RESOURCE];
	uint32_t msao;
	struct pcie_ctrl_ext_cap ats_hdr;
} __packed;

struct pcie_ctrl_msix_entry {
	uint32_t msg_laddr;
	uint32_t msg_haddr;
	uint32_t msg_data;
	uint32_t vec_ctl;
} __packed;

struct pcie_ctrl_msix_pba_entry {
	uint64_t pba_entry;
} __packed;

#define BITS_PER_PBA_ENTRY (sizeof(struct pcie_ctrl_msix_pba_entry) * 8)

struct pcie_ctrl_bar_size_mask {
	uint32_t rsv[4];
	uint32_t bar_mask[PCI_MAX_RESOURCE];
} __packed;

#define PCIE_BAR_MEM_IO_SPACE_IND_SHIFT 0
#define PCIE_BAR_MEM_IO_SPACE_IND_MASK \
	(~(((uint32_t)1) << PCIE_BAR_MEM_IO_SPACE_IND_SHIFT))
#define PCIE_BAR_MEM_SPACE_IND \
	(((uint32_t)0) << PCIE_BAR_MEM_IO_SPACE_IND_SHIFT)
#define PCIE_BAR_IO_SPACE_IND \
	(((uint32_t)1) << PCIE_BAR_MEM_IO_SPACE_IND_SHIFT)
#define PCIE_BAR_SET_MEM_SPACE_IND(bar) \
	do { \
		(bar) &= PCIE_BAR_MEM_IO_SPACE_IND_MASK; \
		(bar) |= PCIE_BAR_MEM_SPACE_IND; \
	} while (0)
#define PCIE_BAR_SET_IO_SPACE_IND(bar) \
	do { \
		(bar) &= PCIE_BAR_MEM_IO_SPACE_IND_MASK; \
		(bar) |= PCIE_BAR_IO_SPACE_IND; \
	} while (0)

#define PCIE_BAR_ADDR_WIDTH_SHIFT 1
#define PCIE_BAR_ADDR_WIDTH_MASK \
	(~(((uint32_t)3) << PCIE_BAR_ADDR_WIDTH_SHIFT))
#define PCIE_BAR_32B_ADDR_TYPE \
	(((uint32_t)0) << PCIE_BAR_ADDR_WIDTH_SHIFT)
#define PCIE_BAR_64B_ADDR_TYPE \
	(((uint32_t)2) << PCIE_BAR_ADDR_WIDTH_SHIFT)
#define PCIE_BAR_SET_32B_WIDTH(bar) \
	do { \
		(bar) &= PCIE_BAR_ADDR_WIDTH_MASK; \
		(bar) |= PCIE_BAR_32B_ADDR_TYPE; \
	} while (0)
#define PCIE_BAR_SET_64B_WIDTH(bar) \
	do { \
		(bar) &= PCIE_BAR_ADDR_WIDTH_MASK; \
		(bar) |= PCIE_BAR_64B_ADDR_TYPE; \
	} while (0)

#define PCIE_BAR_PREF_SHIFT 3
#define PCIE_BAR_PREF_MASK \
	(~(((uint32_t)1) << PCIE_BAR_PREF_SHIFT))
#define PCIE_BAR_PREF_DIS (((uint32_t)0) << PCIE_BAR_PREF_SHIFT)
#define PCIE_BAR_PREF_EN (((uint32_t)1) << PCIE_BAR_PREF_SHIFT)
#define PCIE_BAR_ENABLE_PREFETCH(bar) \
	do { \
		(bar) &= PCIE_BAR_PREF_MASK; \
		(bar) |= PCIE_BAR_PREF_EN; \
	} while (0)
#define PCIE_BAR_DISABLE_PREFETCH(bar) \
	do { \
		(bar) &= PCIE_BAR_PREF_MASK; \
		(bar) |= PCIE_BAR_PREF_DIS; \
	} while (0)

#define PCIE_BAR_ADDR_SHIFT 12
#define PCIE_BAR_ADDR_MASK (0xfffff)
#define PCIE_BAR_SIZE(bar, size) \
	do { \
		uint64_t bar_64 = (bar); \
		\
		bar_64 &= (PCIE_BAR_ADDR_MASK << PCIE_BAR_ADDR_SHIFT); \
		bar_64 = bar_64 >> PCIE_BAR_ADDR_SHIFT; \
		bar_64 = PCIE_BAR_ADDR_MASK + 1 - bar_64; \
		bar_64 = bar_64 << PCIE_BAR_ADDR_SHIFT; \
		size = bar_64; \
	} while (0)

#define PCIE_BAR64_ADDR_MASK (0xfffffffffffff)
#define PCIE_BAR64_SIZE(bar, size) \
	do { \
		uint64_t bar_64 = (bar); \
		\
		bar_64 &= (PCIE_BAR64_ADDR_MASK << PCIE_BAR_ADDR_SHIFT); \
		bar_64 = bar_64 >> PCIE_BAR_ADDR_SHIFT; \
		bar_64 = PCIE_BAR64_ADDR_MASK + 1 - bar_64; \
		bar_64 = bar_64 << PCIE_BAR_ADDR_SHIFT; \
		size = bar_64; \
	} while (0)

static inline int
lsx_pciep_read_config(const void *base,
	void *buf, size_t len, off_t offset)
{
	uint8_t *dst = buf;
	const uint8_t *src = (const uint8_t *)base + offset;

	if (len == sizeof(uint8_t)) {
		*((uint8_t *)dst) = rte_read8(src);
		return 0;
	}

	if (len == sizeof(uint16_t)) {
		if (((uint64_t)src) % sizeof(uint16_t)) {
			rte_panic("%s: PCIe config read16 addr(%p)",
				__func__, src);
			return -EIO;
		}
		*((uint16_t *)dst) = rte_read16(src);
		return 0;
	}

	if (len == sizeof(uint32_t)) {
		if (((uint64_t)src) % sizeof(uint32_t)) {
			rte_panic("%s: PCIe config read32 addr(%p)",
				__func__, src);
			return -EIO;
		}
		*((uint32_t *)dst) = rte_read32(src);
		return 0;
	}

	if (len == (sizeof(uint32_t) + sizeof(uint8_t))) {
		if (((uint64_t)src) % sizeof(uint32_t)) {
			rte_panic("%s: PCIe config read40 addr(%p)",
				__func__, src);
			return -EIO;
		}
		*((uint32_t *)dst) = rte_read32(src);
		src += sizeof(uint32_t);
		dst += sizeof(uint32_t);
		*dst = rte_read8(src);
		return 0;
	}

	if (len == (sizeof(uint32_t) + sizeof(uint16_t))) {
		if (((uint64_t)src) % sizeof(uint32_t)) {
			rte_panic("%s: PCIe config read40 addr(%p)",
				__func__, src);
			return -EIO;
		}
		*((uint32_t *)dst) = rte_read32(src);
		src += sizeof(uint32_t);
		dst += sizeof(uint32_t);
		*((uint16_t *)dst) = rte_read16(src);
		return 0;
	}

	if (len == sizeof(uint64_t)) {
		if (((uint64_t)src) % sizeof(uint32_t)) {
			rte_panic("%s: PCIe config read64 addr(%p)",
				__func__, src);
			return -EIO;
		}
		*((uint32_t *)dst) = rte_read32(src);
		src += sizeof(uint32_t);
		dst += sizeof(uint32_t);
		*((uint32_t *)dst) = rte_read32(src);
		return 0;
	}

	rte_panic("%s: Invalid PCIe config read size(%ld)",
		__func__, len);

	return -EIO;
}

static inline int
lsx_pciep_write_config(void *base,
	const void *buf, size_t len, off_t offset)
{
	const uint8_t *src = buf;
	uint8_t *dst = (uint8_t *)base + offset;

	if (len == sizeof(uint8_t)) {
		rte_write8(*src, dst);
		return 0;
	}

	if (len == sizeof(uint16_t)) {
		if (((uint64_t)dst) % sizeof(uint16_t)) {
			rte_panic("%s: PCIe config write16 addr(%p)",
				__func__, dst);
			return -EIO;
		}
		rte_write16(*((const uint16_t *)src), dst);
		return 0;
	}

	if (len == sizeof(uint32_t)) {
		if (((uint64_t)dst) % sizeof(uint32_t)) {
			rte_panic("%s: PCIe config write32 addr(%p)",
				__func__, dst);
			return -EIO;
		}
		rte_write32(*((const uint32_t *)src), dst);
		return 0;
	}

	if (len == (sizeof(uint32_t) + sizeof(uint8_t))) {
		if (((uint64_t)dst) % sizeof(uint32_t)) {
			rte_panic("%s: PCIe config write40 addr(%p)",
				__func__, src);
			return -EIO;
		}
		rte_write32(*((const uint32_t *)src), dst);
		src += sizeof(uint32_t);
		dst += sizeof(uint32_t);
		rte_write8(*src, dst);
		return 0;
	}

	if (len == (sizeof(uint32_t) + sizeof(uint16_t))) {
		if (((uint64_t)src) % sizeof(uint32_t)) {
			rte_panic("%s: PCIe config write40 addr(%p)",
				__func__, src);
			return -EIO;
		}
		rte_write32(*((const uint32_t *)src), dst);
		src += sizeof(uint32_t);
		dst += sizeof(uint32_t);
		rte_write16(*((const uint16_t *)src), dst);
		return 0;
	}

	if (len == sizeof(uint64_t)) {
		if (((uint64_t)src) % sizeof(uint32_t)) {
			rte_panic("%s: PCIe config write64 addr(%p)",
				__func__, src);
			return -EIO;
		}
		rte_write32(*((const uint32_t *)src), dst);
		src += sizeof(uint32_t);
		dst += sizeof(uint32_t);
		rte_write16(*((const uint32_t *)src), dst);
		return 0;
	}

	rte_panic("%s: Invalid PCIe config write size(%ld)",
		__func__, len);

	return -EIO;
}

#define PCIE_EP_DISABLE_ALL_WIN (-1)

struct lsx_pciep_ops {
	void (*pcie_config)(struct lsx_pciep_hw_low *hw);

	void (*pcie_deconfig)(struct lsx_pciep_hw_low *hw);

	int (*pcie_fun_init)(struct lsx_pciep_hw_low *hw,
			int pf, int is_vf, int vf,
			uint16_t vendor_id, uint16_t device_id,
			uint16_t class_id);

	int (*pcie_fun_init_ext)(struct lsx_pciep_hw_low *hw,
			int pf, int is_vf, int vf,
			uint16_t sub_vendor_id, uint16_t sub_device_id,
			int sriov_disable, int ari_disable, int ats_disable);

	int (*pcie_disable_ob_win)(struct lsx_pciep_hw_low *hw,
			int idx);

	int (*pcie_disable_ib_win)(struct lsx_pciep_hw_low *hw,
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
			uint64_t phys, uint64_t size);

	int (*pcie_msix_cfg)(struct lsx_pciep_hw_low *hw,
			uint8_t *out_vir, int pf, int is_vf, int vf,
			uint64_t msg_phy_addr[], void *msg_vir_addr[],
			uint32_t msg_data[], uint64_t *size,
			int vector_total);

	int (*pcie_msix_decfg)(struct lsx_pciep_hw_low *hw,
			uint8_t *out_vir, int pf, int is_vf, int vf,
			uint64_t msg_phy_addr[], void *msg_vir_addr[],
			uint64_t size[], int vector_total);

	uint64_t (*pcie_get_ob_unmapped)(struct lsx_pciep_hw_low *hw);

	int (*pcie_is_sriov)(struct lsx_pciep_hw_low *hw);
};

struct lsx_pciep_ops *lsx_pciep_get_mv_ops(void);
struct lsx_pciep_ops *lsx_pciep_get_dw_ops(void);

#endif
