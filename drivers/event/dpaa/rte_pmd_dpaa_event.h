/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019 NXP
 */

#ifndef _RTE_PMD_DPAA_EVENT_H
#define _RTE_PMD_DPAA_EVENT_H

#include <rte_eventdev_pmd.h>

/**
 * @file rte_pmd_dpaa_event.h
 *
 * NXP dpaa event PMD specific functions.
 *
 */

/**
 * Callback function to be registered for processing received packets.
 * The callback has to be registered for each queue.
 * outbuf need to be typecasted as per queue type.
 * Currently only eth and crypto are supported.
 *   ethernet queues = 'struct rte_mbuf *'
 *   crypto queues = 'struct rte_crypto_op *'
 */
typedef void (*process_packet_cb_t)(void *outbuf, void *cntx);

/**
 * Eth/Crypto Rx queue configuration update structure
 */
struct rte_dpaa_dev_qconf_update_t {
	/** Callback which will be called internally to process the packets
	 * received on the rx queue
	 */
	process_packet_cb_t process_packet_cb;
	/** Context to be returned in callback */
	void *cntx;
};

/**
 * Register processing callback to rx queue of an eth device.
 *
 * @param id
 *  Adapter identifier.
 * @param eth_dev_id
 *  Port identifier of Ethernet device.
 * @param rx_queue_id
 *  Ethernet device receive queue index. If rx_queue_id is -1,
 *  then all Rx queues configured for the device will use same callback.
 * @param conf
 *  Configuration update structure for eth queues
 *
 * @return
 *  - 0: Success, Receive queue added correctly.
 *  - <0: Error code on failure.
 */
int
rte_dpaa_event_eth_rx_queue_update(uint8_t id,
		uint16_t eth_dev_id,
		int32_t rx_queue_id,
		struct rte_dpaa_dev_qconf_update_t *conf);

/**
 * Register processing callback to queue pair of a crypto device.
 * The callback will be called when packet is received from the
 * crypto device.
 *
 * @param id
 *  Adapter identifier.
 * @param cdev_id
 *  Cryptodev identifier.
 * @param queue_pair_id
 *  Cryptodev queue pair identifier. If queue_pair_id is set -1,
 *  then all queues configured for the device will use the same callback.
 * @param conf
 *  Configuration update structure for crypto queues
 *
 * @return
 *  - 0: Success, callback registered successfully.
 *  - <0: Error code on failure.
 */
int
rte_dpaa_event_crypto_qp_update(uint8_t id,
		uint8_t cdev_id,
		int32_t queue_pair_id,
		struct rte_dpaa_dev_qconf_update_t *conf);

/**
 * Get the epoll fd for the event port (portal) for the calling thread.
 * This API will affine the calling thread if not already affined.
 * Also assign a portal if not assigned. DPAA mandates that the given
 * thread shall be affined to a single physical core only.
 *
 * @param port_id
 *  Port id of the portal affined for this thread
 *
 * @return
 *    >0 Epoll event fd.
 *    <=0 error
 */
int
rte_dpaa_event_get_epoll_fd(uint8_t port_id);

/**
 * Process the packets received on the event port (portal).
 * Queue based processing callback 'process_mbuf' would be
 * called internally.
 *
 * @param dev_id
 *   The identifier of the device.
 * @param port_id
 *   The identifier of the event port.
 *
 * @return
 *  - >=0 Number of packets processed.
 *  - <0: Error code on failure.
 */
int
rte_dpaa_event_process_packets(uint8_t dev_id, uint8_t port_id, int rx_budget);

/**
 * Clear the event irq once the irq is acknowledged
 *
 * @param eventfd
 *  event fd retrieved by rte_dpaa_event_get_epoll_fd
 * @param readset
 *  fd set on which event has occured and irq need to be cleared
 */
void
rte_dpaa_event_clear_irq(int eventfd, fd_set *readset);

#endif /* _RTE_PMD_DPAA_EVENT_H */
