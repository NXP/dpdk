/*-
 *   BSD LICENSE
 *
 *   Copyright (c) 2014 Freescale Semiconductor. All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Freescale Semiconductor nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/* System headers */
#ifndef DPDK_APP_H
#define DPDK_APP_H 1

#include <stdbool.h>

#define MAX_ETHDEV_NAME 32
#define ETHDEV_NAME_PREFIX      "dpaaeth"

#define ENABLE_OP	1
#define DISABLE_OP	0

#define DPAA_MBUF_HW_ANNOTATION		64
#define DPAA_FD_PTA_SIZE		64

#if (DPAA_MBUF_HW_ANNOTATION + DPAA_FD_PTA_SIZE) > RTE_PKTMBUF_HEADROOM
#error "Annotation requirement is more than RTE_PKTMBUF_HEADROOM"
#endif

/* we will re-use the HEADROOM for annotation in RX */
#define DPAA_HW_BUF_RESERVE	0
#define DPAA_PACKET_LAYOUT_ALIGN	64 /*changing from 256 */

#define MAX_PKTS_BURST 32
struct usdpaa_mbufs {
	struct rte_mbuf *mbuf[MAX_PKTS_BURST];
	int next;
};

struct usdpaa_eth_link {
	uint32_t link_speed;        /**< ETH_SPEED_NUM_ */
	uint16_t link_duplex  : 2;  /**< ETH_LINK_[HALF/FULL]_DUPLEX */
	uint16_t link_autoneg : 1;  /**< ETH_LINK_SPEED_[AUTONEG/FIXED] */
	uint16_t link_status  : 1;  /**< ETH_LINK_[DOWN/UP] */
};

struct usdpaa_eth_stats {
	uint64_t ipackets;  /**< Total number of successfully received packets. */
	uint64_t opackets;  /**< Total number of successfully transmitted packets.*/
	uint64_t ibytes;    /**< Total number of successfully received bytes. */
	uint64_t obytes;    /**< Total number of successfully transmitted bytes. */
	uint64_t ierrors;   /**< Total number of erroneous received packets. */
	uint64_t oerrors;   /**< Total number of failed transmitted packets. */
};

struct dpaaeth_txq {
		int port_id;
		int queue_id;
		struct rte_eth_dev *dev;
};

extern __thread bool thread_portal_init;

int add_usdpaa_devices_to_pcilist(int num_ethports);
int usdpaa_portal_init(void *arg);
int usdpaa_get_num_ports(void);
int usdpaa_pre_rte_eal_init(void);
char *usdpaa_get_iface_macaddr(uint32_t portid);
void usdpaa_set_promisc_mode(uint32_t port_id, uint32_t op);
void usdpaa_port_control(uint32_t port_id, uint32_t op);
int usdpaa_add_devices_to_pcilist(int num_ethports);
void usdpaa_enable_pkio(void);
void usdpaa_get_iface_link(uint32_t port_id, struct usdpaa_eth_link *link);
void usdpaa_get_iface_stats(uint32_t port_id, struct usdpaa_eth_stats *stats);

uint16_t usdpaa_eth_queue_rx(void *q,
			     struct rte_mbuf **bufs,
			    uint16_t nb_bufs);

uint16_t usdpaa_eth_ring_tx(void *q,
			    struct rte_mbuf **bufs,
			    uint16_t nb_bufs);

uint32_t usdpaa_get_num_rx_queue(uint32_t portid);
uint32_t usdpaa_get_num_tx_queue(uint32_t portid);

int usdpaa_set_rx_queues(uint32_t portid, uint32_t queue_id,
			 void **rx_queues, struct rte_mempool *mp);

#ifdef RTE_LIBRTE_DPAA_DEBUG_DRIVER_DISPLAY
void display_frame(uint32_t fqid, const struct qm_fd *fd);
#else
#define display_frame(a, b)
#endif

#endif
