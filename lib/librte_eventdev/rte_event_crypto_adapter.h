/*
 *   Copyright(c) 2017 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _RTE_EVENT_CRYPTO_ADAPTER_
#define _RTE_EVENT_CRYPTO_ADAPTER_

/**
 * This adapter adds support to enqueue crypto completion to event device.
 * The packet flow from cryptodev to the event device can be accomplished
 * using either HW or SW mechanisms.
 * The adapter uses a EAL service core function for SW based packet transfer
 * and uses the eventdev PMD functions to configure HW based packet transfer
 * between the cryptodev and the event device.
 *
 * The event crypto adapter provides common APIs to configure the packet flow
 * from the cryptodev to event devices on both HW and SW.
 * The crypto event adapter's functions are:
 *  - rte_event_crypto_adapter_create_ext()
 *  - rte_event_crypto_adapter_create()
 *  - rte_event_crypto_adapter_free()
 *  - rte_event_crypto_adapter_queue_pair_add()
 *  - rte_event_crypto_adapter_queue_pair_del()
 *  - rte_event_crypto_adapter_start()
 *  - rte_event_crypto_adapter_stop()
 *  - rte_event_crypto_adapter_stats_get()
 *  - rte_event_crypto_adapter_stats_reset()

 * The applicaton creates an instance using rte_event_crypto_adapter_create()
 * or rte_event_crypto_adapter_create_ext().
 *
 * Cryptodev queue pair addition/deletion is done
 * using rte_event_crypto_adapter_queue_pair_xxx() API.
 *
 * Adapter uses rte_event_crypto_queue_pair_conf to decide whether the event
 * enqueue is based on RTE_EVENT_CRYPTO_ENQ_MULTI_EVENTQ or
 * RTE_EVENT_CRYPTO_ENQ_MBUF_MULTI_EVENTQ.
 * In case of RTE_EVENT_CRYPTO_ENQ_MULTI_EVENTQ,
 * rte_event_crypto_queue_pair_conf::ev will be used for event enqueue.
 * In case of RTE_EVENT_CRYPTO_ENQ_MBUF_MULTI_EVENTQ,
 * members of rte_event_crypto_metadata will be used for event enqueue.
 *
 * The metadata offset is used to configure the location of the
 * rte_event_crypto_metadata structure within the mbuf's private metadata area.
 *
 * When the application sends crypto operations to the adapter,
 * the crypto queue pair identifier needs to be specified, similarly eventdev
 * parameters such as the flow id, scheduling type etc are needed by the
 * adapter when it enqueues mbufs from completed crypto operations to eventdev.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <rte_service.h>

#include "rte_eventdev.h"

#define RTE_EVENT_CRYPTO_ADAPTER_MAX_INSTANCE 32

 /**
 * @warning
 * @b EXPERIMENTAL: this enum may change without prior notice
 *
 * Crypto event queue conf type
 */
enum rte_event_crypto_conf_type {
	RTE_EVENT_CRYPTO_CONF_TYPE_EVENT = 1,
	/**< Refer RTE_EVENT_CRYPTO_ADAPTER_CAP_MULTI_EVENTQ */
	RTE_EVENT_CRYPTO_CONF_TYPE_MBUF,
	/**< Refer RTE_EVENT_CRYPTO_ADAPTER_CAP_MBUF_MULTI_EVENTQ */
	RTE_EVENT_CRYPTO_CONF_TYPE_MAX
};

 /**
 * @warning
 * @b EXPERIMENTAL: this enum may change without prior notice
 *
 * Crypto event adapter type
 */
enum rte_event_crypto_adapter_type {
	RTE_EVENT_CRYPTO_ADAPTER_RX_ONLY = 1,
	/**< Start only Rx part of crypto adapter.
	* Packets dequeued from cryptodev are new to eventdev and
	* events will be treated as RTE_EVENT_OP_NEW */
	RTE_EVENT_CRYPTO_ADAPTER_RX_TX,
	/**< Start both Rx & Tx part of crypto adapter.
	* Packet's event context will be retained and
	* event will be treated as RTE_EVENT_OP_FORWARD */
};

/**
 * @warning
 * @b EXPERIMENTAL: this structure may change without prior notice
 *
 * Adapter configuration structure that the adapter configuration callback
 * function is expected to fill out
 * @see rte_event_crypto_adapter_conf_cb
 */
struct rte_event_crypto_adapter_conf {
	uint8_t event_port_id;
	/**< Event port identifier, the adapter enqueues crypto_op events to
	 * this port.
	 */
	uint32_t max_nb_rx;
	/**< The adapter can return early if it has processed at least
	 * max_nb_rx crypto_ops. This isn't treated as a requirement; batching
	 * may cause the adapter to process more than max_nb_rx crypto_ops.
	 */
};

/**
 * @warning
 * @b EXPERIMENTAL: this structure may change without prior notice
 *
 * Crypto event metadata structure
 */
struct rte_event_crypto_metadata {
	union {
		uint64_t u64;
		/**< Opaque 64-bit value */
		struct rte_crypto_op *crypto_op;
		/**< pointer to struct rte_crypto_op */
	};
	uint32_t flow_id:20;
	/**< eventdev flow identifier */
	uint32_t sub_event_type:8;
	/**< eventdev sub-event type */
	uint32_t sched_type:2;
	/**< eventdev scheduling type */
	uint16_t event_qid;
	/**< eventdev queue identifier */
	uint16_t cryptodev_qp_id;
	/**< crypto queue pair index */
	uint8_t priority;
	/**< eventdev priority */
	uint8_t reserved[15];
	/**< Bytes reserved for future extension */
};

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Function type used for adapter configuration callback. The callback is
 * used to fill in members of the struct rte_event_crypto_adapter_conf, this
 * callback is invoked when creating a SW service for packet transfer from
 * cryptodev queue pair to the event device. The SW service is created within
 * the rte_event_crypto_adapter_queue_add() function if SW based packet
 * transfers from cryptodev queue pair to the event device are required.
 *
 * @param id
 *  Adapter identifier.
 *
 * @param dev_id
 *  Event device identifier.
 *
 * @param [out] conf
 *  Structure that needs to be populated by this callback.
 *
 * @param arg
 *  Argument to the callback. This is the same as the conf_arg passed to the
 *  rte_event_crypto_adapter_create_ext().
 */
typedef int (*rte_event_crypto_adapter_conf_cb) (uint8_t id, uint8_t cdev_id,
			struct rte_event_crypto_adapter_conf *conf,
			void *arg);

/**
 * @warning
 * @b EXPERIMENTAL: this structure may change without prior notice
 *
 * Queue pair configuration structure
 */
struct rte_event_crypto_queue_pair_conf {
	enum rte_event_crypto_conf_type type;
	/**< Flags for handling received packets */
	union {
		uint32_t mbuf_metadata_offset;
		/**<
		* The metadata offset indicates the location of the
		* rte_event_crypto_metadata structure within the mbuf's
		* private metadata area.
		*/
		struct rte_event ev;
		/**<
		* When queuing is set to RTE_EVENT_CRYPTO_ENQ_MULTI_EVENTQ
		* the values from the following event fields will be used for
		*  queuing mbuf events:
		*   - queue_id: Targeted event queue ID for received packets.
		*   - priority: Event priority of packets from this queue in
		*                the event queue relative to other events.
		*   - sched_type: Scheduling type for packets from this queue
		*                  pair.
		*   - flow_id: Identifier indicating the packet flow.
		*   - sub_event_type: Sub event type for received packets
		*
		* The event adapter sets ev.event_type to RTE_EVENT_TYPE_CRYPTO
		* in the enqueued event.
		*/
	};
};

/**
 * @warning
 * @b EXPERIMENTAL: this structure may change without prior notice
 *
 * A structure used to retrieve statistics for an event crypto adapter
 * instance.
 */

struct rte_event_crypto_adapter_stats {
	uint64_t event_poll_count;
	/**< Event port poll count */
	uint64_t event_dequeue_count;
	/**< Event dequeue count */
	uint64_t crypto_enq_fail;
	/**< Cryptodev enqueue failed count */
	uint64_t crypto_deq_count;
	/**< Cryptodev dequeue count */
	uint64_t event_enq_retry_count;
	/**< Event enqueue retry count */
	uint64_t event_enq_fail_count;
	/**< Event enqueue fail count */
};

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Create a new event crypto adapter with the specified identifier.
 *
 * @param id
 *  The identifier of the event crypto adapter.
 *
 * @param cdev_id
 *  The identifier of the cryptodev to configure.
 *
 * @param conf_cb
 *  Callback function that fills in members of a
 *  struct rte_event_crypto_adapter_conf struct passed into
 *  it.
 *
 * @param conf_arg
 *  Argument that is passed to the conf_cb function.
 *
 * @return
 *   - 0: Success
 *   - <0: Error code on failure
 */
int rte_event_crypto_adapter_create_ext(uint8_t id, uint8_t cdev_id,
				rte_event_crypto_adapter_conf_cb conf_cb,
				void *conf_arg);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Create a new event crypto adapter with the specified identifier.
 * This function uses an internal configuration function that creates an event
 * port. This default function reconfigures the event device with an
 * additional event port and setups up the event port using the port_config
 * parameter passed into this function. In case the application needs more
 * control in configuration of the service, it should use the
 * rte_event_crypto_adapter_create_ext() version.
 *
 * @param id
 *  The identifier of the event crypto adapter.
 *
 * @param cdev_id
 *  The identifier of the cryptodev to configure.
 *
 * @param port_config
 *  Argument of type *rte_event_port_conf* that is passed to the conf_cb
 *  function.
 *
 * @return
 *   - 0: Success
 *   - <0: Error code on failure
 */
int rte_event_crypto_adapter_create(uint8_t id, uint8_t dev_id,
				    struct rte_event_port_conf *port_config);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Free an event crypto adapter
 *
 * @param id
 *  Adapter identifier.
 *
 * @return
 *   - 0: Success
 *   - <0: Error code on failure, If the adapter still has queue pairs
 *      added to it, the function returns -EBUSY.
 */
int rte_event_crypto_adapter_free(uint8_t id);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Add a queue pair to an event crypto adapter.
 *
 * @param id
 *  Adapter identifier.
 *
 * @param cdev_id
 *  Cryptodev identifier.
 *
 * @param queue_pair_id
 *  Cryptodev queue pair identifier.
 *
 * @param conf
 *  Additional configuration structure of type
 *  *rte_event_crypto_queue_pair_conf*
 *
 * @return
 *  - 0: Success, Receive queue pair added correctly.
 *  - <0: Error code on failure.
 */
int rte_event_crypto_adapter_queue_pair_add(uint8_t id,
			uint8_t cdev_id,
			int32_t queue_pair_id,
			const struct rte_event_crypto_queue_pair_conf *conf);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Delete a queue pair from an event crypto adapter.
 *
 * @param id
 *  Adapter identifier.
 *
 * @param cdev_id
 *  Identifier of Cryptodev.
 *
 * @param queue_pair_id
 *  Cryptodev queue pair identifier.
 *
 * @return
 *  - 0: Success, queue pair deleted successfully.
 *  - <0: Error code on failure.
 */
int rte_event_crypto_adapter_queue_pair_del(uint8_t id, uint8_t cdev_id,
					    int32_t queue_pair_id);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Start event crypto adapter
 *
 * @param id
 *  Adapter identifier.
 *
 * @param type
 *  Flag to indicate to start Rx only or both Rx & Tx.
 *
 * @return
 *  - 0: Success, Adapter started successfully.
 *  - <0: Error code on failure.
 */
int rte_event_crypto_adapter_start(uint8_t id,
				   enum rte_event_crypto_adapter_type type);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Stop event crypto adapter
 *
 * @param id
 *  Adapter identifier.
 *
 * @param type
 *  Flag to indicate to start Rx only or both Rx & Tx.
 *
 * @return
 *  - 0: Success, Adapter stopped successfully.
 *  - <0: Error code on failure.
 */
int rte_event_crypto_adapter_stop(uint8_t id,
				  enum rte_event_crypto_adapter_type type);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Retrieve statistics for an adapter
 *
 * @param id
 *  Adapter identifier.
 *
 * @param [out] stats
 *  A pointer to structure used to retrieve statistics for an adapter.
 *
 * @return
 *  - 0: Success, retrieved successfully.
 *  - <0: Error code on failure.
 */
int rte_event_crypto_adapter_stats_get(uint8_t id,
				struct rte_event_crypto_adapter_stats *stats);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Reset statistics for an adapter.
 *
 * @param id
 *  Adapter identifier.
 *
 * @return
 *  - 0: Success, statistics reset successfully.
 *  - <0: Error code on failure.
 */
int rte_event_crypto_adapter_stats_reset(uint8_t id);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Retrieve the service ID of an adapter. If the adapter doesn't use
 * a rte_service function, this function returns -ESRCH.
 *
 * @param id
 *  Adapter identifier.
 *
 * @param [out] service_id
 *  A pointer to a uint32_t, to be filled in with the service id.
 *
 * @return
 *  - 0: Success
 *  - <0: Error code on failure, if the adapter doesn't use a rte_service
 * function, this function returns -ESRCH.
 */
int rte_event_crypto_adapter_service_id_get(uint8_t id, uint32_t *service_id);

#ifdef __cplusplus
}
#endif
#endif	/* _RTE_EVENT_CRYPTO_ADAPTER_ */
