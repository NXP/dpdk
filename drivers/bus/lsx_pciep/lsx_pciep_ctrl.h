/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2023 NXP
 */

#ifndef _LSX_PCIEP_CTRL_H_
#define _LSX_PCIEP_CTRL_H_

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

#define PCIE_FUN_RESET_SRIOV_CAP (0x1 << 28)

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

struct lsx_pciep_ops {
	void (*pcie_config)(struct lsx_pciep_hw_low *hw);

	void (*pcie_deconfig)(struct lsx_pciep_hw_low *hw);

	int (*pcie_fun_init)(struct lsx_pciep_hw_low *hw,
			int pf, int is_vf, uint16_t vendor_id,
			uint16_t device_id, uint16_t class_id);

	int (*pcie_fun_init_ext)(struct lsx_pciep_hw_low *hw,
			int pf, uint16_t sub_vendor_id,
			uint16_t sub_device_id);

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
