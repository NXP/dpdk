/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 NXP
 */

#ifndef _PMD_LA12XX_H_
#define _PMD_LA12XX_H_

#include <rte_bbdev.h>
#include <rte_mbuf.h>
#include <rte_mbuf_pool_ops.h>
#include <rte_errno.h>

#include <geul_feca.h>

#define rte_pmd_la12xx_pktmbuf_mtod rte_pktmbuf_mtod
#define rte_pmd_la12xx_pktmbuf_alloc_bulk rte_pktmbuf_alloc_bulk
#define rte_pmd_la12xx_pktmbuf_alloc rte_pktmbuf_alloc
#define rte_pmd_la12xx_pktmbuf_mtod_offset rte_pktmbuf_mtod_offset
#define rte_pmd_la12xx_pktmbuf_data_len rte_pktmbuf_pkt_len
#define rte_pmd_la12xx_pktmbuf_reset rte_pktmbuf_reset

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

/**
 * BBDEV LA12xx specific append len bytes to an mbuf.
 *
 * Append len bytes to an mbuf and return a pointer to the start address
 * of the added data. If there is not enough tailroom in the last
 * segment, the function will return NULL, without modifying the mbuf.
 *
 * @param m
 *   The packet mbuf.
 * @param len
 *   The amount of data to append (in bytes).
 * @return
 *   A pointer to the start of the newly appended data, or
 *   NULL if there is not enough tailroom space in the last segment
 */
static inline
char *rte_pmd_la12xx_pktmbuf_append(struct rte_mbuf *m, uint32_t len)
{
	void *tail;
	struct rte_mbuf *m_last;

	m_last = rte_pktmbuf_lastseg(m);

	/* We take an assumption here that there is enough tailroom present */
	tail = (char *)m_last->buf_addr + m_last->data_off + m_last->pkt_len;
	m_last->pkt_len  = (m_last->pkt_len + len);
	return (char *) tail;
}

/* Helper to create a mbuf pool for LA12xx with given mempool ops name*/
static inline struct rte_mempool *
rte_pmd_la12xx_pktmbuf_pool_create(const char *name, unsigned int n,
	unsigned int cache_size, uint16_t priv_size, uint32_t data_room_size,
	int socket_id)
{
	struct rte_mempool *mp;
	struct rte_pktmbuf_pool_private mbp_priv;
	const char *mp_ops_name = NULL;
	unsigned elt_size;
	int ret;

	if (RTE_ALIGN(priv_size, RTE_MBUF_PRIV_ALIGN) != priv_size) {
		RTE_LOG(ERR, MBUF, "mbuf priv_size=%u is not aligned\n",
			priv_size);
		rte_errno = EINVAL;
		return NULL;
	}

	elt_size = sizeof(struct rte_mbuf) + (unsigned)priv_size +
		(unsigned)data_room_size;
	memset(&mbp_priv, 0, sizeof(mbp_priv));
	mbp_priv.mbuf_data_room_size = data_room_size;
	mbp_priv.mbuf_priv_size = priv_size;

	mp = rte_mempool_create_empty(name, n, elt_size, cache_size,
		 sizeof(struct rte_pktmbuf_pool_private), socket_id, 0);
	if (mp == NULL)
		return NULL;

	if (mp_ops_name == NULL)
		mp_ops_name = rte_mbuf_best_mempool_ops();
	ret = rte_mempool_set_ops_byname(mp, mp_ops_name, NULL);
	if (ret != 0) {
		RTE_LOG(ERR, MBUF, "error setting mempool handler\n");
		rte_mempool_free(mp);
		rte_errno = -ret;
		return NULL;
	}
	rte_pktmbuf_pool_init(mp, &mbp_priv);

	ret = rte_mempool_populate_default(mp);
	if (ret < 0) {
		rte_mempool_free(mp);
		rte_errno = -ret;
		return NULL;
	}

	rte_mempool_obj_iter(mp, rte_pktmbuf_init, NULL);

	return mp;
}

/**
 * Returns the length of the LA12xx mbuf packet.
 *
 * @param m
 *   The packet mbuf.
 */
static inline uint32_t rte_pmd_la12xx_pktmbuf_pkt_len(struct rte_mbuf *m)
{
	uint32_t pkt_len = m->pkt_len;

	while (m->next != NULL) {
		m = m->next;
		pkt_len += m->pkt_len;
	}
	return pkt_len;
}

/**
 * Chain an mbuf to another for LA12xx mbuf, thereby creating a segmented packet.
 *
 * Note: The implementation will do a linear walk over the segments to find
 * the tail entry. For cases when there are many segments, it's better to
 * chain the entries manually.
 *
 * @param head
 *   The head of the mbuf chain (the first packet)
 * @param tail
 *   The mbuf to put last in the chain
 *
 * @return
 *   - 0, on success.
 *   - -EOVERFLOW, if the chain segment limit exceeded
 */
static inline int rte_pmd_la12xx_pktmbuf_chain(
		struct rte_mbuf *head,
		struct rte_mbuf *tail)
{
	struct rte_mbuf *cur_tail;

	/* Check for number-of-segments-overflow */
	if (head->nb_segs + tail->nb_segs > RTE_MBUF_MAX_NB_SEGS)
		return -EOVERFLOW;

	/* Chain 'tail' onto the old tail */
	cur_tail = rte_pktmbuf_lastseg(head);
	cur_tail->next = tail;

	/* accumulate number of segments and total length.
	 * NB: elaborating the addition like this instead of using
	 *     -= allows us to ensure the result type is uint16_t
	 *     avoiding compiler warnings on gcc 8.1 at least */
	head->nb_segs = (uint16_t)(head->nb_segs + tail->nb_segs);
	return 0;
}

#endif
