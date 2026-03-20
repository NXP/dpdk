/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2026 NXP
 */

#ifndef _LSXINIC_COMMON_HELPER_H_
#define _LSXINIC_COMMON_HELPER_H_

#ifndef LSINIC_KMOD
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <ethdev_driver.h>
#include <rte_io.h>
#endif
#include "lsxinic_common_reg.h"

#ifndef LSINIC_KMOD
#define perf_log printf

static inline uint64_t
lsinic_common_cycles_per_us(void)
{
	uint64_t start_cycles, end_cycles;

	start_cycles = rte_get_timer_cycles();
	rte_delay_ms(1000);
	end_cycles = rte_get_timer_cycles();
	return (end_cycles - start_cycles) / (1000 * 1000);
}
#endif

static inline uint32_t LSINIC_READ_REG(void *reg)
{
#ifdef LSINIC_KMOD
	return ioread32(reg);
#else
	return rte_read32(reg);
#endif
}

static inline void LSINIC_WRITE_REG(void *reg, uint32_t value)
{
#ifdef LSINIC_KMOD
	return iowrite32(value, reg);
#else
	return rte_write32(value, reg);
#endif
}

static inline uint64_t LSINIC_READ_REG_64B(void *addr)
{
#ifdef LSINIC_KMOD
	return readq(addr);
#else
	return rte_read64(addr);
#endif
}

static inline void LSINIC_WRITE_REG_64B(uint64_t *reg, uint64_t value)
{
#ifdef LSINIC_KMOD
	return writeq(value, reg);
#else
	return rte_write64(value, reg);
#endif
}

#define LSINIC_REG_BAR_MAX_SIZE \
	(LSINIC_ETH_REG_OFFSET + sizeof(struct lsinic_eth_reg))

#define LSXINIC_BAR_MIN_SIZE 0x1000
static inline uint64_t lsinic_reg_bar_size(void)
{
	uint64_t size;

#ifdef LSINIC_KMOD
	size = roundup_pow_of_two(LSINIC_REG_BAR_MAX_SIZE);
#else
	size = rte_align64pow2(LSINIC_REG_BAR_MAX_SIZE);
#endif
	return size > LSXINIC_BAR_MIN_SIZE ? size : LSXINIC_BAR_MIN_SIZE;
}

static inline uint64_t lsinic_ring_bar_size(uint16_t ring_num)
{
	uint64_t size = LSINIC_RING_PAIR_SIZE(ring_num);

	size += LSINIC_RING_BD_OFFSET;
#ifdef LSINIC_KMOD
	size = roundup_pow_of_two(size);
#else
	size = rte_align64pow2(size);
#endif

	return size > LSXINIC_BAR_MIN_SIZE ? size : LSXINIC_BAR_MIN_SIZE;
}

static inline uint64_t lsinic_reg_ring_bar_size(uint16_t ring_num)
{
	return lsinic_reg_bar_size() + lsinic_ring_bar_size(ring_num);
}

static inline uint64_t lsinic_reg_ring_bar_offset(int is_reg)
{
	if (is_reg)
		return 0;
	return lsinic_reg_bar_size();
}

#ifndef LSINIC_KMOD
void lsinic_mbuf_print_all(const struct rte_mbuf *mbuf);
void print_port_status_cycle(struct rte_eth_dev *eth_dev,
	uint64_t *prev_cycs, enum lsinic_port_type port_type);
#endif
#endif /* _LSXINIC_COMMON_HELPER_H_ */
