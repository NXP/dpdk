/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2019 Marvell International Ltd.
 * Copyright 2026 NXP
 */

#ifndef __L2FWD_EVENT_H__
#define __L2FWD_EVENT_H__

#include <rte_common.h>
#include <rte_eventdev.h>
#include <rte_event_eth_rx_adapter.h>
#include <rte_event_eth_tx_adapter.h>
#include <rte_mbuf.h>
#include <rte_spinlock.h>

#include "l2fwd_common.h"

typedef uint32_t (*event_device_setup_cb)(struct l2fwd_resources *rsrc);
typedef void (*event_port_setup_cb)(struct l2fwd_resources *rsrc);
typedef void (*event_queue_setup_cb)(struct l2fwd_resources *rsrc,
				     uint32_t event_queue_cfg);
typedef void (*adapter_setup_cb)(struct l2fwd_resources *rsrc);
typedef void (*event_loop_cb)(struct l2fwd_resources *rsrc);

struct event_queues {
	uint8_t *event_q_id;
	uint8_t	nb_queues;
};

struct event_ports {
	uint8_t *event_p_id;
	uint8_t	nb_ports;
	rte_spinlock_t lock;
};

struct event_rx_adptr {
	uint32_t service_id;
	uint8_t	nb_rx_adptr;
	uint8_t *rx_adptr;
};

struct event_tx_adptr {
	uint32_t service_id;
	uint8_t	nb_tx_adptr;
	uint8_t *tx_adptr;
};

struct event_setup_ops {
	event_device_setup_cb event_device_setup;
	event_queue_setup_cb event_queue_setup;
	event_port_setup_cb event_port_setup;
	adapter_setup_cb adapter_setup;
	event_loop_cb l2fwd_event_loop;
};

struct l2fwd_event_resources {
	uint8_t tx_mode_q;
	uint8_t deq_depth;
	uint8_t has_burst;
	uint8_t event_d_id;
	uint8_t disable_implicit_release;
	/*
	 * Dedicated event port used only by the main lcore to inject wake-up
	 * events at shutdown. Keeping a separate port avoids driving a
	 * worker's CPU-affine event port from a foreign lcore (which some
	 * PMDs, e.g. DPAA2, warn about and is functionally incorrect).
	 */
	uint8_t wake_p_id;
	uint8_t wake_q_id;
	uint8_t has_wake_port;
	struct event_ports evp;
	struct event_queues evq;
	struct event_setup_ops ops;
	struct event_rx_adptr rx_adptr;
	struct event_tx_adptr tx_adptr;
	struct rte_event_port_conf def_p_conf;
};

/*
 * Reserve one extra event port and one extra event queue, both dedicated to
 * injecting wake-up events at shutdown from the main lcore. This avoids
 * driving a worker's CPU-affine event port from a foreign lcore (which some
 * PMDs, e.g. DPAA2, warn about and is functionally incorrect).
 *
 * The wake-up queue is a normal event queue that no Rx adapter feeds, so it
 * never carries datapath traffic and cannot cause packet loss. The wake-up
 * port is linked only to this queue, which also satisfies PMDs (e.g. DPAA2)
 * that require an enqueue port to have at least one linked queue.
 *
 * Enabled only if the caller requests it (enable) AND the device has BOTH a
 * spare port and a spare queue beyond the datapath needs. Must be called
 * before rte_event_dev_configure(), and with *nb_event_queues already holding
 * the datapath queue count.
 *
 * enable is normally set only when the configured dequeue timeout is large
 * enough (see L2FWD_EVENT_WAKEUP_THRESHOLD_NS) that a blocking worker would
 * noticeably delay shutdown; below that threshold the extra port and queue
 * are not worth reserving.
 *
 * tx_last is true when the last datapath queue is a Tx single-link queue
 * (generic mode) that must remain the last queue; the wake queue is then
 * inserted just before it. Otherwise the wake queue is appended at the end.
 */
static inline void
l2fwd_event_wake_reserve(struct l2fwd_event_resources *evt_rsrc, bool enable,
	uint8_t max_event_ports, uint8_t num_workers, uint8_t max_event_queues,
	bool tx_last, uint8_t *nb_event_ports, uint8_t *nb_event_queues)
{
	evt_rsrc->has_wake_port = 0;
	*nb_event_ports = num_workers;

	if (!enable)
		return;
	if (max_event_ports <= num_workers)
		return;
	if (*nb_event_queues >= max_event_queues)
		return;

	evt_rsrc->has_wake_port = 1;
	evt_rsrc->wake_p_id = num_workers;
	*nb_event_ports = num_workers + 1;

	if (tx_last)
		evt_rsrc->wake_q_id = *nb_event_queues - 1;
	else
		evt_rsrc->wake_q_id = *nb_event_queues;
	*nb_event_queues += 1;
}

/*
 * Set up the dedicated wake-up port (if reserved) and link it to the
 * dedicated wake-up queue only.
 *
 * The wake-up queue is a normal event queue that no Rx adapter feeds, so it
 * never carries datapath traffic (no packet loss). Worker ports are linked to
 * it in addition to their traffic queues, so a NEW event injected on the
 * wake-up queue is scheduled to a worker and wakes it from a blocking
 * dequeue. The wake-up port is linked to this queue so that PMDs which
 * require an enqueue port to have at least one linked queue (e.g. DPAA2) work
 * correctly, while normal traffic queues stay off this port.
 */
static inline void
l2fwd_event_wake_port_setup(struct l2fwd_event_resources *evt_rsrc,
	const struct rte_event_port_conf *port_conf)
{
	uint8_t wake_q_id;
	int ret;

	if (!evt_rsrc->has_wake_port)
		return;

	ret = rte_event_port_setup(evt_rsrc->event_d_id, evt_rsrc->wake_p_id, port_conf);
	if (ret) {
		rte_panic("Error(%d) in configuring wake event port %d\n",
			ret, evt_rsrc->wake_p_id);
	}

	wake_q_id = evt_rsrc->wake_q_id;
	ret = rte_event_port_link(evt_rsrc->event_d_id, evt_rsrc->wake_p_id,
		&wake_q_id, NULL, 1);
	if (ret != 1) {
		rte_panic("Error(%d) in linking wake event port %d to wake queue\n",
			ret, evt_rsrc->wake_p_id);
	}
}

void l2fwd_event_resource_setup(struct l2fwd_resources *rsrc);
void l2fwd_event_wakeup(struct l2fwd_resources *rsrc);
void l2fwd_event_set_generic_ops(struct event_setup_ops *ops);
void l2fwd_event_set_internal_port_ops(struct event_setup_ops *ops);
void l2fwd_event_service_setup(struct l2fwd_resources *rsrc);

#endif /* __L2FWD_EVENT_H__ */
