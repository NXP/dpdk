/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2026 NXP
 */

#ifndef _LSXINIC_COMMON_HELPER_H_
#define _LSXINIC_COMMON_HELPER_H_

#include <rte_mbuf.h>
#include <rte_ether.h>
#include <ethdev_driver.h>
#include "lsxinic_common_reg.h"

#define LSINIC_REG_BAR_MAX_SIZE \
	(LSINIC_ETH_REG_OFFSET + sizeof(struct lsinic_eth_reg))

#define LSXINIC_BAR_MIN_SIZE 0x1000
static inline uint64_t lsinic_reg_bar_size(void)
{
	uint64_t size = rte_align64pow2(LSINIC_REG_BAR_MAX_SIZE);

	return size > LSXINIC_BAR_MIN_SIZE ? size : LSXINIC_BAR_MIN_SIZE;
}

static inline uint64_t lsinic_ring_bar_size(uint16_t ring_num)
{
	uint64_t size = LSINIC_RING_PAIR_SIZE(ring_num);

	size += LSINIC_RING_BD_OFFSET;

	size = rte_align64pow2(size);
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

void lsinic_mbuf_print_all(const struct rte_mbuf *mbuf);
void print_port_status(struct rte_eth_dev *eth_dev,
	uint64_t *core_mask, uint32_t debug_interval,
	enum lsinic_port_type port_type);

#endif /* _LSXINIC_COMMON_HELPER_H_ */
