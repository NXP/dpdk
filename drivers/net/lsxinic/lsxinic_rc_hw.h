/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018-2021 NXP
 */

#ifndef _LSXINIC_RC_HW_H_
#define _LSXINIC_RC_HW_H_
#include <rte_ether.h>
#include "lsxinic_common_pmd.h"
#include "lsxinic_common_reg.h"

#define __iomem

#define ALIGN(x, a) (((x) + ((typeof(x))(a) - 1)) & ~((typeof(x))(a) - 1))

#ifndef DMA_64BIT_MAS
#define DMA_64BIT_MASK  0xffffffffffffffffULL
#endif
#define BITS_PER_LONG   (__SIZEOF_LONG__ * 8)
#ifndef DMA_BIT_MASK
#define DMA_BIT_MASK(n)(((n) == 64) ? DMA_64BIT_MASK : ((1ULL << (n)) - 1))
#endif

#ifndef DECLARE_BITMAP
#ifndef BITS_TO_LONGS
#define BITS_TO_LONGS(bits) (((bits) + BITS_PER_LONG - 1) / BITS_PER_LONG)
#endif
#define DECLARE_BITMAP(name, bits) long name[BITS_TO_LONGS(bits)]
#endif

static inline int
test_and_set_bit(unsigned long nr, void *addr)
{
	unsigned long mask = 1 << (nr & 0x1f);
	int *m = ((int *)addr) + (nr >> 5);
	int old = *m;
	*m = old | mask;
	return (old & mask) != 0;
}

static inline void
clear_bit(unsigned long nr, void *addr)
{
	int *m = ((int *)addr) + (nr >> 5);
	*m &= ~(1 << (nr & 31));
}

static inline int
test_bit(int nr, const void *addr)
{
	return (1UL & (((const int *)addr)[nr >> 5] >> (nr & 31))) != 0UL;
}

static inline void
set_bit(unsigned long nr, void *addr)
{
	int *m = ((int *)addr) + (nr >> 5);
	*m |= 1 << (nr & 31);
}

enum lxsnic_mac_type {
	lxsnic_undefined = 0,
	lxsnic_2575,
	lxsnic__num_macs  /* List is 1-based, so subtract 1 for true count. */

};

struct lxsnic_hw;

struct lxsnic_mac_info {
	uint8_t addr[RTE_ETHER_ADDR_LEN];
	uint8_t perm_addr[RTE_ETHER_ADDR_LEN];
	enum lxsnic_mac_type type;
	uint16_t mta_reg_count;
	uint16_t rar_entry_count;
};

struct lxsnic_hw {
	void *back;
	uint8_t __iomem *hw_addr;
	uint64_t hw_addr_len;
	struct lxsnic_mac_info mac;
	uint16_t device_id;
	uint16_t vendor_id;
	uint16_t subsystem_device_id;
	uint16_t subsystem_vendor_id;
	uint8_t revision_id;
};

#endif /* _LSXINIC_RC_HW_H_ */
