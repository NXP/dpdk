/*-
 *   BSD LICENSE
 *
 *   Copyright (c) 2015-2016 Freescale Semiconductor, Inc. All rights reserved.
 *   Copyright 2016,2018 NXP
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
 *     * Neither the name of Freescale Semiconductor, Inc nor the names of its
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

#ifndef _DPAA2_ETHDEV_H
#define _DPAA2_ETHDEV_H

#include <rte_event_eth_rx_adapter.h>
#include <rte_pmd_dpaa2.h>

#include <dpaa2_hw_pvt.h>

#include <mc/fsl_dpni.h>
#include <mc/fsl_mc_sys.h>
#include <fsl_qbman_portal.h>

#define DPAA2_MIN_RX_BUF_SIZE 512
#define DPAA2_MAX_RX_PKT_LEN  10240 /*WRIOP support*/

#define MAX_TCS			DPNI_MAX_TC
#define MAX_RX_QUEUES		128
#define MAX_TX_QUEUES		16
#define MAX_DPNI		8

/*default tc to be used for ,congestion, distribution etc configuration. */
#define DPAA2_DEF_TC		0

/* Threshold for a Tx queue to *Enter* Congestion state.
 */
#define CONG_ENTER_TX_THRESHOLD   512

/* Threshold for a queue to *Exit* Congestion state.
 */
#define CONG_EXIT_TX_THRESHOLD    480

#define CONG_RETRY_COUNT 18000

/* RX queue tail drop threshold
 * currently considering 32 KB packets
 */
#define CONG_THRESHOLD_RX_Q  (64 * 1024)
#define CONG_RX_OAL	128

/* Size of the input SMMU mapped memory required by MC */
#define DIST_PARAM_IOVA_SIZE 256

/* Enable TX Congestion control support
 * default is disable
 */
#define DPAA2_TX_CGR_OFF	0x01

/* Drop packets with parsing error in hw */
#define DPAA2_PARSE_ERR_DROP	0x02

/* Disable RX tail drop, default is enable */
#define DPAA2_RX_TAILDROP_OFF	0x04

#define DPAA2_RSS_OFFLOAD_ALL ( \
	ETH_RSS_IP | \
	ETH_RSS_UDP | \
	ETH_RSS_TCP | \
	ETH_RSS_SCTP)

/* LX2 FRC Parsed values (Little Endian) */
#define DPAA2_PKT_TYPE_ETHER		0x0060
#define DPAA2_PKT_TYPE_IPV4		0x0000
#define DPAA2_PKT_TYPE_IPV6		0x0020
#define DPAA2_PKT_TYPE_IPV4_EXT \
			(0x0001 | DPAA2_PKT_TYPE_IPV4)
#define DPAA2_PKT_TYPE_IPV6_EXT \
			(0x0001 | DPAA2_PKT_TYPE_IPV6)
#define DPAA2_PKT_TYPE_IPV4_TCP \
			(0x000e | DPAA2_PKT_TYPE_IPV4)
#define DPAA2_PKT_TYPE_IPV6_TCP \
			(0x000e | DPAA2_PKT_TYPE_IPV6)
#define DPAA2_PKT_TYPE_IPV4_UDP \
			(0x0010 | DPAA2_PKT_TYPE_IPV4)
#define DPAA2_PKT_TYPE_IPV6_UDP \
			(0x0010 | DPAA2_PKT_TYPE_IPV6)
#define DPAA2_PKT_TYPE_IPV4_SCTP	\
			(0x000f | DPAA2_PKT_TYPE_IPV4)
#define DPAA2_PKT_TYPE_IPV6_SCTP	\
			(0x000f | DPAA2_PKT_TYPE_IPV6)
#define DPAA2_PKT_TYPE_IPV4_ICMP \
			(0x0003 | DPAA2_PKT_TYPE_IPV4)
#define DPAA2_PKT_TYPE_IPV6_ICMP \
			(0x0003 | DPAA2_PKT_TYPE_IPV6)
#define DPAA2_PKT_TYPE_VLAN_1		0x0160
#define DPAA2_PKT_TYPE_VLAN_2		0x0260

#define DPAA2_QOS_TABLE_RECONFIGURE	1
#define DPAA2_FS_TABLE_RECONFIGURE	2

/*Externaly defined*/
extern const struct rte_flow_ops dpaa2_flow_ops;
extern enum rte_filter_type dpaa2_filter_type;
extern enum pmd_dpaa2_ts dpaa2_enable_ts;

struct dpaa2_dev_priv {
	void *hw;
	int32_t hw_id;
	int32_t qdid;
	uint16_t token;
	uint8_t nb_tx_queues;
	uint8_t nb_rx_queues;
	void *rx_vq[MAX_RX_QUEUES];
	void *tx_vq[MAX_TX_QUEUES];

	struct dpaa2_bp_list *bp_list; /**<Attached buffer pool list */
	uint32_t options;
	uint8_t max_mac_filters;
	uint8_t max_vlan_filters;
	uint8_t num_rx_tc;
	uint8_t flags; /*dpaa2 config flags */
	struct pattern_s {
		uint8_t item_count;
		uint8_t pattern_type[DPKG_MAX_NUM_OF_EXTRACTS];
	} pattern[MAX_TCS + 1];

	struct extract_s {
		struct dpkg_profile_cfg qos_key_cfg;
		struct dpkg_profile_cfg fs_key_cfg[MAX_TCS];
		uint64_t qos_extract_param;
		uint64_t fs_extract_param[MAX_TCS];
	} extract;

	uint16_t ss_offset;
	uint64_t ss_iova;
	uint64_t ss_param_iova;
	uint8_t en_ordered;
	uint8_t en_loose_ordered;
};

int dpaa2_distset_to_dpkg_profile_cfg(uint64_t req_dist_set,
				      struct dpkg_profile_cfg *kg_cfg);

int dpaa2_setup_flow_dist(struct rte_eth_dev *eth_dev,
			  uint64_t req_dist_set);

int dpaa2_remove_flow_dist(struct rte_eth_dev *eth_dev,
			   uint8_t tc_index);

int dpaa2_attach_bp_list(struct dpaa2_dev_priv *priv, void *blist);

int dpaa2_eth_eventq_attach(const struct rte_eth_dev *dev,
		int eth_rx_queue_id,
		uint16_t dpcon_id,
		const struct rte_event_eth_rx_adapter_queue_conf *queue_conf);

int dpaa2_eth_eventq_detach(const struct rte_eth_dev *dev,
		int eth_rx_queue_id);

uint16_t dpaa2_dev_rx(void *queue, struct rte_mbuf **bufs, uint16_t nb_pkts);

uint16_t dpaa2_dev_loopback_rx(void *queue, struct rte_mbuf **bufs,
				uint16_t nb_pkts);
uint16_t dpaa2_dev_prefetch_rx2(void *queue, struct rte_mbuf **bufs,
				uint16_t nb_pkts);
uint16_t dpaa2_dev_prefetch_rx(void *queue, struct rte_mbuf **bufs,
			       uint16_t nb_pkts);
void dpaa2_dev_process_parallel_event(struct qbman_swp *swp,
				      const struct qbman_fd *fd,
				      const struct qbman_result *dq,
				      struct dpaa2_queue *rxq,
				      struct rte_event *ev);
void dpaa2_dev_process_atomic_event(struct qbman_swp *swp,
				    const struct qbman_fd *fd,
				    const struct qbman_result *dq,
				    struct dpaa2_queue *rxq,
				    struct rte_event *ev);
void dpaa2_dev_process_ordered_event(struct qbman_swp *swp,
				     const struct qbman_fd *fd,
				     const struct qbman_result *dq,
				     struct dpaa2_queue *rxq,
				     struct rte_event *ev);
uint16_t dpaa2_dev_tx(void *queue, struct rte_mbuf **bufs, uint16_t nb_pkts);
uint16_t dpaa2_dev_tx_ordered(void *queue, struct rte_mbuf **bufs,
			      uint16_t nb_pkts);
uint16_t dummy_dev_tx(void *queue, struct rte_mbuf **bufs, uint16_t nb_pkts);
void dpaa2_dev_free_eqresp_buf(uint16_t eqresp_ci);

#endif /* _DPAA2_ETHDEV_H */
