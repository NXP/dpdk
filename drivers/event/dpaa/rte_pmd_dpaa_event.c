/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019 NXP
 */

#include <rte_dpaa_bus.h>
#include <rte_dpaa_logs.h>
#include <rte_ethdev.h>
#include <rte_cryptodev.h>
#include <rte_cryptodev_pmd.h>
#include "rte_pmd_dpaa_event.h"
#include "dpaa_eventdev.h"
#include <dpaa_ethdev.h>
#ifdef RTE_LIBRTE_SECURITY
#include <dpaa_sec_event.h>
#endif

int
rte_dpaa_event_eth_rx_queue_update(uint8_t id __rte_unused,
		uint16_t eth_dev_id,
		int32_t rx_queue_id __rte_unused,
		struct rte_dpaa_dev_qconf_update_t *conf __rte_unused)
{
	struct rte_eth_dev *dev = &rte_eth_devices[eth_dev_id];

	RTE_SET_USED(dev);
	return 0/*dpaa_eth_eventq_update(dev, rx_queue_id, conf)*/;
}

int
rte_dpaa_event_crypto_qp_update(uint8_t id __rte_unused,
		uint8_t cdev_id,
		int32_t qp_id __rte_unused,
		struct rte_dpaa_dev_qconf_update_t *conf __rte_unused)
{
	struct rte_cryptodev *dev = rte_cryptodev_pmd_get_dev(cdev_id);

	RTE_SET_USED(dev);
	return 0/*dpaa_sec_eventq_update(dev, qp_id, conf)*/;
}

int
rte_dpaa_event_get_epoll_fd(uint8_t port_id __rte_unused)
{
	int ret;

	if (unlikely(!RTE_PER_LCORE(dpaa_io))) {
		/* Affine current thread context to a qman portal */
		ret = rte_dpaa_portal_init((void *)0);
		if (ret) {
			DPAA_EVENTDEV_ERR("Unable to initialize portal");
			return ret;
		}
	}
	qman_irqsource_add(QM_PIRQ_DQRI);
	ret = qman_thread_fd();

	return ret;
}

int
rte_dpaa_event_process_packets(uint8_t dev_id,
		uint8_t port_id,
		int rx_budget)
{
	struct rte_eventdev *dev = &rte_eventdevs[dev_id];
	struct dpaa_port *portal = (struct dpaa_port *)
				(dev->data->ports[port_id]);
	int ret;
	u16 ch_id;
	void *buffers;
	struct rte_event ev;
	u32 num_frames, i;

	if (unlikely(!RTE_PER_LCORE(dpaa_io))) {
		/* Affine current thread context to a qman portal */
		ret = rte_dpaa_portal_init((void *)0);
		if (ret) {
			DPAA_EVENTDEV_ERR("Unable to initialize portal");
			return ret;
		}
	}

	if (unlikely(!portal->is_port_linked)) {
		/*
		 * Affine event queue for current thread context
		 * to a qman portal.
		 */
		for (i = 0; i < portal->num_linked_evq; i++) {
			ch_id = portal->evq_info[i].ch_id;
			dpaa_eventq_portal_add(ch_id);
		}
		portal->is_port_linked = true;
	}

	/* Lets dequeue the frames */
	num_frames = qman_portal_dequeue(&ev, rx_budget, &buffers);

	qman_irqsource_add(QM_PIRQ_DQRI);

	return num_frames;
}

void
rte_dpaa_event_clear_irq(int eventfd, fd_set *readset)
{
	/* Calling irqsource_remove() prior to thread_irq()
	 * means thread_irq() will not process whatever caused
	 * the interrupts, however it does ensure that, once
	 * thread_irq() re-enables interrupts, they won't fire
	 * again immediately.
	 */
	qman_irqsource_remove(~0);
	drain_4_bytes(eventfd, readset);
	qman_thread_irq();
}
