/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018-2023 NXP
 */

#ifndef _RTE_PMD_DPAA2_H
#define _RTE_PMD_DPAA2_H

/**
 * @file rte_pmd_dpaa2.h
 *
 * NXP dpaa2 PMD specific functions.
 *
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 */

#include <rte_flow.h>

/**
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
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
 *    A valid handle in case of success, NULL otherwise.
 */
__rte_experimental
struct rte_flow *
rte_pmd_dpaa2_mux_flow_create(uint32_t dpdmux_id,
			      struct rte_flow_item *pattern[],
			      struct rte_flow_action *actions[]);

struct dpdmux_l2_rule*
rte_pmd_dpaa2_mux_flow_l2(uint32_t dpdmux_id,
			  uint8_t mac_addr[6],
			  uint16_t vlan_id,
			  int dest_if);

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

/**
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * Create a custom hash key on basis of offset of start of packet and size.
 * for e.g. if we need GRE packets (non-vlan and without any extra headers)
 * to be hashed on basis of inner IP header, we will provide offset as:
 * 14 (eth) + 20 (IP) + 4 (GRE) + 12 (Inner Src offset) = 50 and size
 * as 8 bytes.
 *
 * @param port_id
 *    The port identifier of the Ethernet device.
 * @param offset
 *    Offset from the start of packet which needs to be included to
 *    calculate hash
 * @param size
 *    Size of the hash input key
 *
 * @return
 *   - 0 if successful.
 *   - Negative in case of failure.
 */
__rte_experimental
int
rte_pmd_dpaa2_set_custom_hash(uint16_t port_id,
			      uint16_t offset,
			      uint8_t size);

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
 * Do thread specific I/O initialization & warmup to reduce initial delays
 *
 */
__rte_experimental
int
rte_pmd_dpaa2_thread_warmup(uint8_t rx_flag);

#endif /* _RTE_PMD_DPAA2_H */
