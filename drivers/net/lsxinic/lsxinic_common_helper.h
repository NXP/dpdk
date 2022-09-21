/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2021 NXP
 */

#ifndef _LSXINIC_COMMON_HELPER_H_
#define _LSXINIC_COMMON_HELPER_H_

#include <rte_mbuf.h>
#include <rte_ether.h>
#include <ethdev_driver.h>

void lsinic_mbuf_print_all(const struct rte_mbuf *mbuf);
void print_port_status(struct rte_eth_dev *eth_dev,
	uint64_t *core_mask, uint32_t debug_interval,
	enum lsinic_port_type port_type);

#endif /* _LSXINIC_COMMON_HELPER_H_ */
