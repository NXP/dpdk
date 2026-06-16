/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018-2026 NXP
 */

#ifndef _RTE_PMD_DPAA2_H
#define _RTE_PMD_DPAA2_H

/**
 * @file rte_pmd_dpaa2.h
 *
 * NXP dpaa2 PMD specific functions.
 */

#include <rte_compat.h>
#include <rte_flow.h>
#include <rte_ethdev.h>

/**
 * Create a flow rule to demultiplex ethernet traffic to separate network
 * interfaces.
 *
 * @param dpdmux_id
 *    ID of the DPDMUX MC object.
 * @param[in] pattern
 *    Pattern specification.
 * @param[in] actions
 *    Associated actions.
 *
 * @return
 *    0 in case of success,  otherwise failure.
 */
int
rte_pmd_dpaa2_mux_flow_create(uint32_t dpdmux_id,
	struct rte_flow_item pattern[],
	struct rte_flow_action actions[]);
int
rte_pmd_dpaa2_mux_flow_destroy(uint32_t dpdmux_id,
	uint16_t entry_index);
int
rte_pmd_dpaa2_mux_flow_l2(uint32_t dpdmux_id,
	uint8_t mac_addr[6], uint16_t vlan_id, int dest_if);

uint8_t
rte_pmd_dpaa2_mux_multi_enum(uint8_t num, uint32_t ids[]);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * Dump demultiplex ethernet traffic counters
 *
 * @param f
 *    output stream
 * @param dpdmux_id
 *    ID of the DPDMUX MC object.
 * @param num_if
 *    number of interface in dpdmux object
 *
 */
__rte_experimental
void
rte_pmd_dpaa2_mux_dump_counter(FILE *f, uint32_t dpdmux_id, int num_if);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * demultiplex interface max rx frame length configure
 *
 * @param dpdmux_id
 *    ID of the DPDMUX MC object.
 * @param max_rx_frame_len
 *    maximum receive frame length (will be checked to be minimux of all dpnis)
 *
 */
__rte_experimental
int
rte_pmd_dpaa2_mux_rx_frame_len(uint32_t dpdmux_id, uint16_t max_rx_frame_len);

__rte_experimental
int
rte_pmd_dpaa2_mux_default_id(uint32_t dpdmux_id, uint16_t *id);

__rte_experimental
int
rte_pmd_dpaa2_mux_ep_name(uint32_t dpdmux_id,
	uint16_t id, const char **name);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * Do thread specific initialization
 */
__rte_experimental
void
rte_pmd_dpaa2_thread_init(void);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * Generate the DPAA2 WRIOP based hash value
 *
 * @param key
 *    Array of key data
 * @param size
 *    Size of the hash input key in bytes
 *
 * @return
 *   - 0 if successful.
 *   - Negative in case of failure.
 */

__rte_experimental
uint32_t
rte_pmd_dpaa2_get_tlu_hash(uint8_t *key, int size);

__rte_experimental
int
rte_pmd_dpaa2_set_opr(uint16_t port_id, uint16_t rx_queue_id);

__rte_experimental
int
rte_pmd_dpaa2_dev_is_dpaa2(uint32_t eth_id);
__rte_experimental
const char *
rte_pmd_dpaa2_ep_name(uint32_t eth_id);
uint16_t
rte_pmd_dpaa2_clean_tx_conf(uint32_t eth_id,
	uint16_t txq_id);
int
rte_pmd_dpaa2_rx_get_offset(uint16_t port_id, struct rte_mbuf *m,
	uint8_t *l3_off, uint8_t *l4_off, uint8_t *l5_off);
uint16_t
rte_dpaa2_dev_tx_multi_ports(uint16_t port_id[],
	uint16_t txq_id[], struct rte_mbuf **bufs,
	uint16_t nb_pkts);

struct rte_pmd_dpaa2_rxq_info {
	struct rte_eth_rxq_info rxq_info;
	uint8_t tc_id;
	uint16_t flow_id;
};

__rte_experimental
int
rte_pmd_dpaa2_rx_queue_info_get(uint16_t port_id, uint16_t queue_id,
	struct rte_pmd_dpaa2_rxq_info *qinfo);

struct rte_pmd_dpaa2_dev_info {
	struct rte_eth_dev_info dev_info;
	uint8_t rx_tc_num;
	uint8_t tx_tc_num;
	uint16_t qos_entries;
	uint16_t fs_entries;
	uint16_t dist_queues;
};

__rte_experimental
int
rte_pmd_dpaa2_dev_info_get(uint16_t port_id,
	struct rte_pmd_dpaa2_dev_info *dev_info);

enum rte_dpaa2_sch_mode {
	RTE_DPAA2_SCH_PULL,
	RTE_DPAA2_SCH_PUSH
};

__rte_experimental
void *
rte_dpaa2_scheduler_init(enum rte_dpaa2_sch_mode sch_mode);
__rte_experimental
int
rte_dpaa2_scheduler_start(void *scheduler_handle);
__rte_experimental
int
rte_dpaa2_scheduler_destroy(void *scheduler_handle);
__rte_experimental
int
rte_dpaa2_scheduler_add(void *scheduler_handle,
	uint16_t port_id, uint16_t rxq_id, uint8_t priority);

/* rte_dpaa2_scheduler_rx()- DPCON scheduler receive function
 * @scheduler_handle: DPCON scheduler handle
 * @mbuf:             Packet mbuf
 * @nb_pkts:          Number of packets to be received.
 * Return Number of received packet.
 */
__rte_experimental
uint16_t
rte_dpaa2_scheduler_rx(void *scheduler_handle, struct rte_mbuf **mbuf,
	uint16_t nb_pkts);

#define RTE_DPAA2_EVENT_PORT_CFG_ATOMIC RTE_BIT32(31)

int
rte_pmd_dpaa2_flow_table_query(uint16_t portid);

/** User sets default actions(TC/flow) by private configuration.
 */
struct rte_dpaa2_default_action_conf {
	uint8_t default_tc;
	uint8_t max_tc;
	uint16_t default_flows[];
};

__rte_experimental
int
rte_dpaa2_eth_dev_configure_default_action(uint16_t port_id,
	struct rte_dpaa2_default_action_conf *def_act_conf);

#define RTE_DPAA2_ONE_LEVEL_GROUP_FLOW 0
#define RTE_DPAA2_QOS_GROUP_FLOW 1
#define RTE_DPAA2_FS_GROUP_FLOW 2

#define RTE_PMD_DPAA2_FLOW_GROUP_TYPE_OFFSET 8
#define RTE_PMD_DPAA2_FLOW_GROUP_ID_MASK \
	((((uint32_t)1) << RTE_PMD_DPAA2_FLOW_GROUP_TYPE_OFFSET) - 1)

#define RTE_DPAA2_FLOW_GROUP_TYPE_SET(group, type) \
	((group) |= ((type) << RTE_PMD_DPAA2_FLOW_GROUP_TYPE_OFFSET))

#define RTE_DPAA2_FLOW_GROUP_TYPE_GET(group) \
	((group) >> RTE_PMD_DPAA2_FLOW_GROUP_TYPE_OFFSET)

#define RTE_DPAA2_FLOW_GROUP_ID_GET(group) \
	((group) & RTE_PMD_DPAA2_FLOW_GROUP_ID_MASK)

/** Parameter "type" should be:
 *RTE_DPAA2_ONE_LEVEL_GROUP_FLOW or
 *RTE_DPAA2_QOS_GROUP_FLOW or
 *RTE_DPAA2_FS_GROUP_FLOW
 */
__rte_experimental
static inline struct rte_flow *
rte_dpaa2_flow_create(uint16_t port_id,
		const struct rte_flow_attr *attr,
		const struct rte_flow_item pattern[],
		const struct rte_flow_action actions[],
		struct rte_flow_error *error, uint32_t type)
{
	struct rte_flow_attr _attr;

	rte_memcpy(&_attr, attr, sizeof(struct rte_flow_attr));
	RTE_DPAA2_FLOW_GROUP_TYPE_SET(_attr.group, type);
	return rte_flow_create(port_id, &_attr, pattern, actions, error);
}

__rte_experimental
int
rte_dpaa2_flow_group_set_miss_actions(uint16_t port_id,
		uint32_t group_id, uint32_t type,
		const struct rte_flow_group_attr *attr,
		const struct rte_flow_action actions[],
		struct rte_flow_error *error);
#endif /* _RTE_PMD_DPAA2_H */
