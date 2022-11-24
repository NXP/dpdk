/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018-2022 NXP
 */

#ifndef _LSXINIC_RC_RXTX_H_
#define _LSXINIC_RC_RXTX_H_

#include "lsxinic_rc_ethdev.h"

#define U_BURST_MAX \
	(LSINIC_MAX_BURST_NUM + XMIT_IDX_EXTRA_SPACE)

union lsinic_ep2rc_notify {
	struct lsinic_bd_desc ep_tx_addr[U_BURST_MAX];
	struct lsinic_ep_rx_src_addrl ep_tx_addrl[U_BURST_MAX];
	struct lsinic_ep_rx_src_addrx ep_tx_addrx[U_BURST_MAX];
};

uint16_t
lxsnic_eth_xmit_pkts(void *tx_queue,
	struct rte_mbuf **tx_pkts,
	uint16_t nb_pkts);
uint16_t
lxsnic_eth_recv_pkts(void *rx_queue,
	struct rte_mbuf **rx_pkts,
	uint16_t nb_pkts);

#endif /* _LSXINIC_RC_RXTX_H_ */
