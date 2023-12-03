/* SPDX-License-Identifier: BSD-3-Clause
 *
 *   Copyright (c) 2015-2016 Freescale Semiconductor, Inc. All rights reserved.
 *   Copyright 2016-2023 NXP
 *
 */

#ifndef _DPAA2_ETHDEV_H
#define _DPAA2_ETHDEV_H

#include <rte_event_eth_rx_adapter.h>
#include <rte_pmd_dpaa2.h>

#include <rte_fslmc.h>
#include <dpaa2_hw_pvt.h>
#include "dpaa2_tm.h"

#include <mc/fsl_dpni.h>
#include <mc/fsl_mc_sys.h>

#include "base/dpaa2_hw_dpni_annot.h"

#define BIT(x)		((uint64_t)1 << ((x)))

#define DPAA2_MIN_RX_BUF_SIZE 512
#define DPAA2_MAX_RX_PKT_LEN  10240 /*WRIOP support*/

#define MAX_TCS			DPNI_MAX_TC
#define MAX_RX_QUEUES		128
#define MAX_TX_QUEUES		16
#define MAX_DPNI		8
#define DPAA2_MAX_CHANNELS	16

#define DPAA2_EXTRACT_PARAM_MAX_SIZE \
	RTE_ALIGN(sizeof(struct dpni_ext_set_rx_tc_dist), 256)

#define DPAA2_EXTRACT_ALLOC_KEY_MAX_SIZE 256

#define DPAA2_RX_DEFAULT_NBDESC 512

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
 * currently considering 64 KB packets
 */
#define CONG_THRESHOLD_RX_BYTES_Q  (64 * 1024)
#define CONG_RX_OAL	128

/* Size of the input SMMU mapped memory required by MC */
#define DIST_PARAM_IOVA_SIZE DPAA2_EXTRACT_PARAM_MAX_SIZE

/* Enable TX Congestion control support
 * default is disable
 */
#define DPAA2_TX_CGR_OFF	BIT(0)
/* Drop packets with parsing error in hw */
#define DPAA2_PARSE_ERR_DROP	BIT(1)
/* Disable RX tail drop, default is enable */
#define DPAA2_RX_TAILDROP_OFF	BIT(2)
/* Tx confirmation enabled */
#define DPAA2_TX_CONF_ENABLE	BIT(3)

/* Disable prefetch Rx mode to get exact requested packets */
#define DPAA2_NO_PREFETCH_RX	BIT(4)

/* Driver level loop mode to simply transmit the ingress traffic */
#define DPAA2_RX_LOOPBACK_MODE	BIT(5)

/* HW loopback the egress traffic to self ingress*/
#define DPAA2_TX_MAC_LOOPBACK_MODE 	BIT(6)

#define DPAA2_TX_SERDES_LOOPBACK_MODE 	BIT(7)

#define DPAA2_TX_DPNI_LOOPBACK_MODE 	BIT(8)

#define DPAA2_TX_LOOPBACK_MODE \
	(DPAA2_TX_MAC_LOOPBACK_MODE | \
	DPAA2_TX_SERDES_LOOPBACK_MODE | \
	DPAA2_TX_DPNI_LOOPBACK_MODE)

#define DPAA2_RSS_OFFLOAD_ALL ( \
	ETH_RSS_L2_PAYLOAD | \
	ETH_RSS_IP | \
	ETH_RSS_UDP | \
	ETH_RSS_TCP | \
	ETH_RSS_SCTP | \
	ETH_RSS_MPLS)

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
			(0x0003 | DPAA2_PKT_TYPE_IPV4_EXT)
#define DPAA2_PKT_TYPE_IPV6_ICMP \
			(0x0003 | DPAA2_PKT_TYPE_IPV6_EXT)
#define DPAA2_PKT_TYPE_VLAN_1		0x0160
#define DPAA2_PKT_TYPE_VLAN_2		0x0260

/* enable timestamp in mbuf*/
extern bool dpaa2_enable_ts[];

/*Externaly defined*/
extern const struct rte_flow_ops dpaa2_flow_ops;
extern enum rte_filter_type dpaa2_filter_type;

extern const struct rte_tm_ops dpaa2_tm_ops;

extern bool dpaa2_enable_err_queue;

extern bool dpaa2_print_parser_result;

/* Global pool used by driver for SG list TX */
extern struct rte_mempool *dpaa2_tx_sg_pool;
/* Maximum SG segments */
#define DPAA2_MAX_SGS 128
/* SG pool size */
#define DPAA2_POOL_SIZE 2048
/* SG pool cache size */
#define DPAA2_POOL_CACHE_SIZE 256
/* structure to free external and indirect
 * buffers.
 */
struct sw_buf_free {
	/* To which packet this segment belongs */
	uint16_t pkt_id;
	/* The actual segment */
	struct rte_mbuf *seg;
};

/* 00 00 00 - last 6 bit represent data, annotation,
 * context stashing setting 01 01 00 (0x14)
 * (in following order ->DS AS CS)
 * to enable 1 line data, 1 line annotation.
 * For LX2, this setting should be 01 00 00 (0x10)
 */
#define DPAA2_FLC_STASHING_MAX_BIT_SIZE 2
#define DPAA2_FLC_STASHING_MAX_CACHE_LINE \
	((1ULL << DPAA2_FLC_STASHING_MAX_BIT_SIZE) - 1)

enum dpaa2_flc_stashing_type {
	DPAA2_FLC_CNTX_STASHING = 0,
	DPAA2_FLC_ANNO_STASHING =
		DPAA2_FLC_CNTX_STASHING + DPAA2_FLC_STASHING_MAX_BIT_SIZE,
	DPAA2_FLC_DATA_STASHING =
		DPAA2_FLC_ANNO_STASHING + DPAA2_FLC_STASHING_MAX_BIT_SIZE
};

static inline void
dpaa2_flc_stashing_set(enum dpaa2_flc_stashing_type type,
	uint8_t cache_line, uint64_t *flc)
{
	RTE_ASSERT(cache_line <= DPAA2_FLC_STASHING_MAX_CACHE_LINE);
	RTE_ASSERT(type == DPAA2_FLC_CNTX_STASHING ||
		type == DPAA2_FLC_ANNO_STASHING ||
		type == DPAA2_FLC_DATA_STASHING);

	(*flc) &= ~(DPAA2_FLC_STASHING_MAX_CACHE_LINE << type);
	(*flc) |= (cache_line << type);
}

static inline void
dpaa2_flc_stashing_clear_all(uint64_t *flc)
{
	dpaa2_flc_stashing_set(DPAA2_FLC_CNTX_STASHING, 0, flc);
	dpaa2_flc_stashing_set(DPAA2_FLC_ANNO_STASHING, 0, flc);
	dpaa2_flc_stashing_set(DPAA2_FLC_DATA_STASHING, 0, flc);
}

#define DPAA2_FS_FLC_FS_MARK_OFFSET \
	(DPAA2_FLC_DATA_STASHING + DPAA2_FLC_STASHING_MAX_BIT_SIZE)

#define DPAA2_FS_FLC_TC_OFFSET \
	(DPAA2_FS_FLC_FS_MARK_OFFSET + DPAA2_FLC_STASHING_MAX_BIT_SIZE)

#define DPAA2_FS_FLC_TC_BIT_SIZE (sizeof(uint8_t) * 8)
#define DPAA2_FS_FLC_TC_MASK ((1 << DPAA2_FS_FLC_TC_BIT_SIZE) - 1)

#define DPAA2_FS_FLC_FLOW_OFFSET \
	(DPAA2_FS_FLC_TC_OFFSET + DPAA2_FS_FLC_TC_BIT_SIZE)

#define DPAA2_ECPRI_MAX_EXTRACT_NB 8

#define DPAA2_IBTH_MAX_EXTRACT_NB 4

struct ipv4_sd_addr_extract_rule {
	uint32_t ipv4_src;
	uint32_t ipv4_dst;
};

struct ipv6_sd_addr_extract_rule {
	uint8_t ipv6_src[NH_FLD_IPV6_ADDR_SIZE];
	uint8_t ipv6_dst[NH_FLD_IPV6_ADDR_SIZE];
};

struct ipv4_ds_addr_extract_rule {
	uint32_t ipv4_dst;
	uint32_t ipv4_src;
};

struct ipv6_ds_addr_extract_rule {
	uint8_t ipv6_dst[NH_FLD_IPV6_ADDR_SIZE];
	uint8_t ipv6_src[NH_FLD_IPV6_ADDR_SIZE];
};

union ip_addr_extract_rule {
	struct ipv4_sd_addr_extract_rule ipv4_sd_addr;
	struct ipv6_sd_addr_extract_rule ipv6_sd_addr;
	struct ipv4_ds_addr_extract_rule ipv4_ds_addr;
	struct ipv6_ds_addr_extract_rule ipv6_ds_addr;
};

union ip_src_addr_extract_rule {
	uint32_t ipv4_src;
	uint8_t ipv6_src[NH_FLD_IPV6_ADDR_SIZE];
};

union ip_dst_addr_extract_rule {
	uint32_t ipv4_dst;
	uint8_t ipv6_dst[NH_FLD_IPV6_ADDR_SIZE];
};

enum ip_addr_extract_type {
	IP_NONE_ADDR_EXTRACT,
	IP_SRC_EXTRACT,
	IP_DST_EXTRACT,
	IP_SRC_DST_EXTRACT,
	IP_DST_SRC_EXTRACT
};

enum key_prot_type {
	/* HW extracts from standard protocol fields*/
	DPAA2_NET_PROT_KEY,
	/* HW extracts from FAF of PR*/
	DPAA2_FAF_KEY,
	/* HW extracts from PR other than FAF*/
	DPAA2_PR_KEY
};

struct key_prot_field {
	enum key_prot_type type;
	enum net_prot prot;
	uint32_t key_field;
};

struct dpaa2_key_profile {
	uint8_t num;
	uint8_t key_offset[DPKG_MAX_NUM_OF_EXTRACTS];
	uint8_t key_size[DPKG_MAX_NUM_OF_EXTRACTS];

	enum ip_addr_extract_type ip_addr_type;
	uint8_t ip_addr_extract_idx;
	uint8_t ip_addr_key_offset;

	uint8_t l4_sp_present;
	uint8_t l4_sp_extract_idx;
	uint8_t l4_sp_key_offset;
	uint8_t l4_dp_present;
	uint8_t l4_dp_extract_idx;
	uint8_t l4_dp_key_offset;
	struct key_prot_field prot_field[DPKG_MAX_NUM_OF_EXTRACTS];
	uint16_t key_max_size;
};

struct dpaa2_key_extract {
	struct dpkg_profile_cfg dpkg;
	struct dpaa2_key_profile key_profile;
};

struct extract_s {
	struct dpaa2_key_extract qos_key_extract;
	struct dpaa2_key_extract tc_key_extract[MAX_TCS];
	uint8_t *qos_extract_param;
	uint8_t *tc_extract_param[MAX_TCS];
};

struct dpaa2_dev_priv {
	void *hw;
	int32_t hw_id;
	int32_t qdid;
	uint16_t token;
	uint8_t nb_tx_queues;
	uint8_t nb_rx_queues;
	uint32_t options;
	void *rx_vq[MAX_RX_QUEUES];
	void *tx_vq[MAX_TX_QUEUES];
	struct dpaa2_bp_list *bp_list; /**<Attached buffer pool list */
	void *tx_conf_vq[MAX_TX_QUEUES * DPAA2_MAX_CHANNELS];
	void *rx_err_vq;
	uint32_t flags; /*dpaa2 config flags */
	uint8_t max_mac_filters;
	uint8_t max_vlan_filters;
	uint8_t num_rx_tc;
	uint8_t num_tx_tc;
	uint16_t qos_entries;
	uint16_t fs_entries;
	uint8_t dist_queues;
	uint8_t num_channels;
	uint8_t en_ordered;
	uint8_t en_loose_ordered;
	uint8_t max_cgs;
	uint8_t cgid_in_use[MAX_RX_QUEUES];

	struct extract_s extract;

	uint16_t ss_offset;
	uint64_t ss_iova;
	uint64_t ss_param_iova;
	/*stores timestamp of last received packet on dev*/
	uint64_t rx_timestamp;
	/*stores timestamp of last received tx confirmation packet on dev*/
	uint64_t tx_timestamp;
	/* stores pointer to next tx_conf queue that should be processed,
	 * it corresponds to last packet transmitted
	 */
	struct dpaa2_queue *next_tx_conf_queue;

	struct rte_eth_dev *eth_dev; /**< Pointer back to holding ethdev */
	rte_spinlock_t lpbk_qp_lock;

	uint8_t channel_inuse;
	struct dpaa2_dev_flow *curr;
	LIST_HEAD(, dpaa2_dev_flow) flows;
	LIST_HEAD(nodes, dpaa2_tm_node) nodes;
	LIST_HEAD(shaper_profiles, dpaa2_tm_shaper_profile) shaper_profiles;
};

int dpaa2_distset_to_dpkg_profile_cfg(uint64_t req_dist_set,
				      struct dpkg_profile_cfg *kg_cfg);

int dpaa2_setup_flow_dist(struct rte_eth_dev *eth_dev,
		uint64_t req_dist_set, int tc_index);

int dpaa2_remove_flow_dist(struct rte_eth_dev *eth_dev,
			   uint8_t tc_index);

int dpaa2_attach_bp_list(struct dpaa2_dev_priv *priv,
	struct fsl_mc_io *dpni, void *blist);

int dpaa2_eth_eventq_attach(const struct rte_eth_dev *dev,
		int eth_rx_queue_id,
		struct dpaa2_dpcon_dev *dpcon,
		const struct rte_event_eth_rx_adapter_queue_conf *queue_conf);

int dpaa2_eth_eventq_detach(const struct rte_eth_dev *dev,
		int eth_rx_queue_id);

uint16_t dpaa2_dev_rx(void *queue, struct rte_mbuf **bufs, uint16_t nb_pkts);

uint16_t dpaa2_dev_loopback_rx(void *queue, struct rte_mbuf **bufs,
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
uint16_t dpaa2_dev_tx_multi_txq_ordered(void **queue,
		struct rte_mbuf **bufs, uint16_t nb_pkts);

uint16_t dummy_dev_tx(void *queue, struct rte_mbuf **bufs, uint16_t nb_pkts);
void dpaa2_dev_free_eqresp_buf(uint16_t eqresp_ci, struct dpaa2_queue *dpaa2_q);
void dpaa2_flow_clean(struct rte_eth_dev *dev);
uint16_t dpaa2_dev_tx_conf(void *queue)  __attribute__((unused));
int dpaa2_soft_parser_loaded(void);

int dpaa2_timesync_enable(struct rte_eth_dev *dev);
int dpaa2_timesync_disable(struct rte_eth_dev *dev);
int dpaa2_timesync_read_time(struct rte_eth_dev *dev,
					struct timespec *timestamp);
int dpaa2_timesync_write_time(struct rte_eth_dev *dev,
					const struct timespec *timestamp);
int dpaa2_timesync_adjust_time(struct rte_eth_dev *dev, int64_t delta);
int dpaa2_timesync_read_rx_timestamp(struct rte_eth_dev *dev,
						struct timespec *timestamp,
						uint32_t flags __rte_unused);
int dpaa2_timesync_read_tx_timestamp(struct rte_eth_dev *dev,
					  struct timespec *timestamp);

int
dpaa2_dev_recycle_config(struct rte_eth_dev *eth_dev);
int
dpaa2_dev_recycle_deconfig(struct rte_eth_dev *eth_dev);
int
dpaa2_dev_recycle_qp_setup(struct rte_dpaa2_device *dpaa2_dev,
	uint16_t qidx, uint64_t cntx,
	eth_tx_burst_t tx_lpbk, eth_rx_burst_t rx_lpbk,
	struct dpaa2_queue **txq,
	struct dpaa2_queue **rxq);

#endif /* _DPAA2_ETHDEV_H */
