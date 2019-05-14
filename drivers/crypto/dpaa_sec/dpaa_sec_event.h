/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019 NXP
 *
 */

#ifndef _DPAA_SEC_EVENT_H_
#define _DPAA_SEC_EVENT_H_

#include <rte_pmd_dpaa_event.h>

int
dpaa_sec_eventq_attach(const struct rte_cryptodev *dev,
		int qp_id,
		uint16_t ch_id,
		const struct rte_event *event);

int
dpaa_sec_eventq_update(const struct rte_cryptodev *dev,
		int qp_id,
		struct rte_dpaa_dev_qconf_update_t *conf);

int
dpaa_sec_eventq_detach(const struct rte_cryptodev *dev,
		int qp_id);

enum qman_cb_dqrr_result
dpaa_sec_process_atomic_event(void *event,
			struct qman_portal *qm __rte_unused,
			struct qman_fq *outq,
			const struct qm_dqrr_entry *dqrr,
			void **bufs);

enum qman_cb_dqrr_result
dpaa_sec_process_event_app_cb(void *event,
			struct qman_portal *qm __rte_unused,
			struct qman_fq *outq,
			const struct qm_dqrr_entry *dqrr,
			void **bufs);

enum qman_cb_dqrr_result
dpaa_sec_process_parallel_event(void *event,
			struct qman_portal *qm __always_unused,
			struct qman_fq *outq,
			const struct qm_dqrr_entry *dqrr,
			void **bufs);

#endif /* _DPAA_SEC_EVENT_H_ */
