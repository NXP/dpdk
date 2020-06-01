/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 NXP
 */

#ifndef _PMD_LA12XX_H_
#define _PMD_LA12XX_H_

#include <rte_bbdev.h>
#include <geul_feca.h>

/** Structure specifying a single operation for la12xx */
struct rte_la122x_bbdev_op {
	/** Parameters for FECA job */
	feca_job_t feca_obj;
	/** The input buffer */
	struct rte_bbdev_op_data input;
	/** The output buffer */
	struct rte_bbdev_op_data output;
};

/**
 * Enqueue a burst of operations for encode or decode to a queue of the device.
 * This functions only enqueues as many operations as currently possible and
 * does not block until @p num_ops entries in the queue are available.
 * This function does not provide any error notification to avoid the
 * corresponding overhead.
 *
 * @param dev_id
 *   The identifier of the device.
 * @param queue_id
 *   The index of the queue.
 * @param ops
 *   Pointer array containing operations to be enqueued Must have at least
 *   @p num_ops entries
 * @param num_ops
 *   The maximum number of operations to enqueue.
 *
 * @return
 *   The number of operations actually enqueued (this is the number of processed
 *   entries in the @p ops array).
 */
uint16_t
rte_pmd_la12xx_enqueue_ops(uint16_t dev_id, uint16_t queue_id,
		struct rte_la122x_bbdev_op **ops, uint16_t num_ops);

/**
 * Dequeue a burst of processed encode/decode operations from a queue of
 * the device.
 * This functions returns only the current contents of the queue, and does not
 * block until @ num_ops is available.
 * This function does not provide any error notification to avoid the
 * corresponding overhead.
 *
 * @param dev_id
 *   The identifier of the device.
 * @param queue_id
 *   The index of the queue.
 * @param ops
 *   Pointer array where operations will be dequeued to. Must have at least
 *   @p num_ops entries
 * @param num_ops
 *   The maximum number of operations to dequeue.
 *
 * @return
 *   The number of operations actually dequeued (this is the number of entries
 *   copied into the @p ops array).
 */
uint16_t
rte_pmd_la12xx_dequeue_ops(uint16_t dev_id, uint16_t queue_id,
		struct rte_la122x_bbdev_op **ops, uint16_t num_ops);

#endif
