/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2023 NXP
 */

#ifndef _LSX_PCIEP_CTRL_H_
#define _LSX_PCIEP_CTRL_H_

#include <sys/mman.h>
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

#define PCIE_EXT_CAP_ID_NULL 0x00
#define PCIE_EXT_CAP_ID_AER 0x01
#define PCIE_EXT_CAP_ID_VC 0x02
#define PCIE_EXT_CAP_ID_DSN 0x03
#define PCIE_EXT_CAP_ID_PB 0x04
#define PCIE_EXT_CAP_ID_RCLINK 0x05
#define PCIE_EXT_CAP_ID_RCILINK 0x06
#define PCIE_EXT_CAP_ID_RCEC 0x07
#define PCIE_EXT_CAP_ID_MFVC 0x08
#define PCIE_EXT_CAP_ID_VC2 0x09
#define PCIE_EXT_CAP_ID_RCRB 0x0a
#define PCIE_EXT_CAP_ID_VNDR 0x0b
#define PCIE_EXT_CAP_ID_ACS 0x0d
#define PCIE_EXT_CAP_ID_ARI 0x0e
#define PCIE_EXT_CAP_ID_ATS 0x0f
#define PCIE_EXT_CAP_ID_SRIOV 0x10
#define PCIE_EXT_CAP_ID_MRIOV 0x11
#define PCIE_EXT_CAP_ID_MCAST 0x12
#define PCIE_EXT_CAP_ID_PRI 0x13
#define PCIE_EXT_CAP_ID_REBAR 0x15
#define PCIE_EXT_CAP_ID_DPA 0x16
#define PCIE_EXT_CAP_ID_TPH 0x17
#define PCIE_EXT_CAP_ID_LTR 0x18
#define PCIE_EXT_CAP_ID_SECPCI 0x19
#define PCIE_EXT_CAP_ID_PMUX 0x1a
#define PCIE_EXT_CAP_ID_PASID 0x1b
#define PCIE_EXT_CAP_ID_LNR 0x1c
#define PCIE_EXT_CAP_ID_DPC 0x1d
#define PCIE_EXT_CAP_ID_L1PM 0x1e
#define PCIE_EXT_CAP_ID_PTM 0x1f
#define PCIE_EXT_CAP_ID_M_PCIE 0x20
#define PCIE_EXT_CAP_ID_FRS 0x21
#define PCIE_EXT_CAP_ID_RTR 0x22
#define PCIE_EXT_CAP_ID_DVSEC 0x23
#define PCIE_EXT_CAP_ID_VF_REBAR 0x24
#define PCIE_EXT_CAP_ID_DLNK 0x25
#define PCIE_EXT_CAP_ID_16GT 0x26
#define PCIE_EXT_CAP_ID_LMR 0x27
#define PCIE_EXT_CAP_ID_HIER_ID 0x28
#define PCIE_EXT_CAP_ID_NPEM 0x29

#define PCIE_FUN_RESET_SRIOV_CAP (0x1 << 28)

struct pcie_ctrl_ext_cap {
	uint32_t next_cap_off:12;
	uint32_t cap_ver:4;
	uint32_t ext_cap_id:16;
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
	uint8_t unused0[0x50 - 0x30];
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
	uint32_t adv_err_report_cap_id;
	uint32_t uncorrect_err_stat;
	uint32_t uncorrect_err_mask;
	uint32_t uncorrect_err_ser;
	uint32_t correct_err_stat;
	uint32_t correct_err_mask;
	uint32_t adv_err_cap_ctl;
	uint8_t unused4[0x178 - 0x11c];
	uint32_t sriov_ext_cap_header;
	uint32_t sriov_cap;
	uint16_t sriov_ctrl;
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
	uint32_t sup_page_size;
	uint32_t sys_page_size;
	uint32_t vfbar[PCI_MAX_RESOURCE];
} __packed;

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

static inline int
lsx_pciep_is_align_16(const void *addr)
{
	uint64_t x = (uint64_t)addr;

	if (x & 0x1)
		return 0;

	return 1;
}

static inline int
lsx_pciep_is_align_32(const void *addr)
{
	uint64_t x = (uint64_t)addr;

	if (x & 0x3)
		return 0;

	return 1;
}

static inline int
lsx_pciep_is_align_64(const void *addr)
{
	uint64_t x = (uint64_t)addr;

	if (x & 0x7)
		return 0;

	return 1;
}

static inline int
lsx_pciep_is_align_128(const void *addr)
{
	uint64_t x = (uint64_t)addr;

	if (x & 0xf)
		return 0;

	return 1;
}

static inline void
lsx_pciep_read_config(const void *base,
	void *buf, size_t len, off_t offset)
{
	uint8_t *dst = buf;
	const uint8_t *src = (const uint8_t *)base + offset;

	if (!lsx_pciep_is_align_16(src) && len > 0) {
		*dst = rte_read8(src);
		dst++;
		src++;
		len--;
	}

	if (!lsx_pciep_is_align_32(src) && len >= sizeof(uint16_t)) {
		*((uint16_t *)dst) = rte_read16(src);
		dst += sizeof(uint16_t);
		src += sizeof(uint16_t);
		len -= sizeof(uint16_t);
	}

	if (!lsx_pciep_is_align_64(src) && len >= sizeof(uint32_t)) {
		*((uint32_t *)dst) = rte_read32(src);
		dst += sizeof(uint32_t);
		src += sizeof(uint32_t);
		len -= sizeof(uint32_t);
	}

	if (!lsx_pciep_is_align_128(src) && len >= sizeof(uint64_t)) {
		*((uint64_t *)dst) = rte_read64(src);
		dst += sizeof(uint64_t);
		src += sizeof(uint64_t);
		len -= sizeof(uint64_t);
	}

	while (len >= sizeof(__uint128_t)) {
		RTE_VERIFY(lsx_pciep_is_align_128(src));
		*((uint64_t *)dst) = rte_read64(src);
		dst += sizeof(uint64_t);
		src += sizeof(uint64_t);
		len -= sizeof(uint64_t);

		*((uint64_t *)dst) = rte_read64(src);
		dst += sizeof(uint64_t);
		src += sizeof(uint64_t);
		len -= sizeof(uint64_t);
	}

	while (len >= sizeof(uint64_t)) {
		RTE_VERIFY(lsx_pciep_is_align_64(src));
		*((uint64_t *)dst) = rte_read64(src);
		dst += sizeof(uint64_t);
		src += sizeof(uint64_t);
		len -= sizeof(uint64_t);
	}

	while (len >= sizeof(uint32_t)) {
		RTE_VERIFY(lsx_pciep_is_align_32(src));
		*((uint32_t *)dst) = rte_read32(src);
		dst += sizeof(uint32_t);
		src += sizeof(uint32_t);
		len -= sizeof(uint32_t);
	}

	while (len >= sizeof(uint16_t)) {
		RTE_VERIFY(lsx_pciep_is_align_16(src));
		*((uint16_t *)dst) = rte_read16(src);
		dst += sizeof(uint16_t);
		src += sizeof(uint16_t);
		len -= sizeof(uint16_t);
	}

	while (len > 0) {
		*dst = rte_read8(src);
		dst++;
		src++;
		len--;
	}

	RTE_ASSERT(!len);
}

static inline void
lsx_pciep_write_config(void *base,
	const void *buf, size_t len, off_t offset)
{
	const uint8_t *src = buf;
	uint8_t *dst = (uint8_t *)base + offset;

	if (!lsx_pciep_is_align_16(dst) && len > 0) {
		rte_write8(*src, dst);
		dst++;
		src++;
		len--;
	}

	if (!lsx_pciep_is_align_32(dst) && len >= sizeof(uint16_t)) {
		rte_write16(*((const uint16_t *)src), dst);
		dst += sizeof(uint16_t);
		src += sizeof(uint16_t);
		len -= sizeof(uint16_t);
	}

	if (!lsx_pciep_is_align_64(dst) && len >= sizeof(uint32_t)) {
		rte_write32(*((const uint32_t *)src), dst);
		dst += sizeof(uint32_t);
		src += sizeof(uint32_t);
		len -= sizeof(uint32_t);
	}

	if (!lsx_pciep_is_align_128(dst) && len >= sizeof(uint64_t)) {
		rte_write64(*((const uint64_t *)src), dst);
		dst += sizeof(uint64_t);
		src += sizeof(uint64_t);
		len -= sizeof(uint64_t);
	}

	while (len >= sizeof(__uint128_t)) {
		RTE_VERIFY(lsx_pciep_is_align_128(dst));
		rte_write64(*((const uint64_t *)src), dst);
		dst += sizeof(uint64_t);
		src += sizeof(uint64_t);
		len -= sizeof(uint64_t);

		rte_write64(*((const uint64_t *)src), dst);
		dst += sizeof(uint64_t);
		src += sizeof(uint64_t);
		len -= sizeof(uint64_t);
	}

	while (len >= sizeof(uint64_t)) {
		RTE_VERIFY(lsx_pciep_is_align_64(dst));
		rte_write64(*((const uint64_t *)src), dst);
		dst += sizeof(uint64_t);
		src += sizeof(uint64_t);
		len -= sizeof(uint64_t);
	}

	while (len >= sizeof(uint32_t)) {
		RTE_VERIFY(lsx_pciep_is_align_32(dst));
		rte_write32(*((const uint32_t *)src), dst);
		dst += sizeof(uint32_t);
		src += sizeof(uint32_t);
		len -= sizeof(uint32_t);
	}

	while (len >= sizeof(uint16_t)) {
		RTE_VERIFY(lsx_pciep_is_align_16(dst));
		rte_write16(*((const uint16_t *)src), dst);
		dst += sizeof(uint16_t);
		src += sizeof(uint16_t);
		len -= sizeof(uint16_t);
	}

	while (len > 0) {
		rte_write8(*src, dst);
		dst++;
		src++;
		len--;
	}

	RTE_ASSERT(!len);
}

#define PCIE_EP_DISABLE_ALL_WIN (-1)

struct lsx_pciep_ops {
	void (*pcie_config)(struct lsx_pciep_hw_low *hw);

	void (*pcie_deconfig)(struct lsx_pciep_hw_low *hw);

	int (*pcie_fun_init)(struct lsx_pciep_hw_low *hw,
			int pf, int is_vf, uint16_t vendor_id,
			uint16_t device_id, uint16_t class_id);

	int (*pcie_fun_init_ext)(struct lsx_pciep_hw_low *hw,
			int pf, uint16_t sub_vendor_id,
			uint16_t sub_device_id, int sriov_disable);

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
			uint64_t phys, uint64_t size, int resize);

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
