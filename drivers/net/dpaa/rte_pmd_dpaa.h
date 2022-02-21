/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018,2022 NXP
 */

#ifndef _PMD_DPAA_H_
#define _PMD_DPAA_H_

/**
 * @file rte_pmd_dpaa.h
 *
 * NXP dpaa PMD specific functions.
 *
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 */

/**
 * Enable/Disable TX loopback
 *
 * @param port
 *    The port identifier of the Ethernet device.
 * @param on
 *    1 - Enable TX loopback.
 *    0 - Disable TX loopback.
 * @return
 *   - (0) if successful.
 *   - (-ENODEV) if *port* invalid.
 *   - (-EINVAL) if bad parameter.
 */
int
rte_pmd_dpaa_set_tx_loopback(uint16_t port, uint8_t on);

/**
 * Set TX rate limit
 *
 * @param port_id
 *    The port identifier of the Ethernet device.
 * @param burst
 *    Max burst size(KBytes) of the Ethernet device.
 *    0 - Disable TX rate limit.
 * @param rate
 *    Max rate(Kb/sec) of the Ethernet device.
 *    0 - Disable TX rate limit.
 * @return
 *    0 - if successful.
 *    <0 - if failed, with proper error code.
 */
int
rte_pmd_dpaa_port_set_rate_limit(uint16_t port_id, uint16_t burst,
				 uint32_t rate);

#endif /* _PMD_DPAA_H_ */
