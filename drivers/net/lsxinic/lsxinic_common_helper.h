/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2021 NXP
 */

#ifndef _LSXINIC_COMMON_HELPER_H_
#define _LSXINIC_COMMON_HELPER_H_

#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ethdev_vdev.h>

void print_buf(void *data, uint32_t len, uint32_t width);
void print_eth(const struct rte_mbuf *mbuf);
void print_ip(const struct rte_mbuf *mbuf);
void print_mbuf(const struct rte_mbuf *mbuf);
void print_mbuf_all(const struct rte_mbuf *mbuf);
void print_port_status(struct rte_eth_dev *eth_dev,
	uint64_t *core_mask, uint32_t debug_interval, int is_ep,
	int is_vio_ep);

#endif /* _LSXINIC_COMMON_HELPER_H_ */
