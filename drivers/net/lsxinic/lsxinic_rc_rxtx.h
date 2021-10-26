/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018-2021 NXP
 */

#ifndef _LSXINIC_RC_RXTX_H_
#define _LSXINIC_RC_RXTX_H_

#include "lsxinic_rc_ethdev.h"

uint16_t
lxsnic_eth_xmit_pkts(void *tx_queue,
	struct rte_mbuf **tx_pkts,
	uint16_t nb_pkts);
uint16_t
lxsnic_eth_recv_pkts(void *rx_queue,
	struct rte_mbuf **rx_pkts,
	uint16_t nb_pkts);

#endif /* _LSXINIC_RC_RXTX_H_ */
