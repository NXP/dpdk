/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020-2021 NXP
 */

#ifndef _LSINIC_COMMON_PMD_H_
#define _LSINIC_COMMON_PMD_H_

#include <rte_io.h>
#include "rte_tm.h"
#include <rte_pci.h>

#include "lsxinic_common_logs.h"

static __rte_always_inline uint32_t
LSINIC_READ_REG(void *reg)
{
	return rte_read32(reg);
}

static __rte_always_inline void
LSINIC_WRITE_REG(void *reg, uint32_t value)
{
	return rte_write32(value, reg);
}

static __rte_always_inline uint64_t
LSINIC_READ_REG_64B(void *addr)
{
	return rte_read64(addr);
}

static __rte_always_inline void
LSINIC_WRITE_REG_64B(uint64_t *reg, uint64_t value)
{
	return rte_write64(value, reg);
}

#endif
