#include <rte_cycles.h>
#include <rte_common.h>
#include <rte_dev.h>
#include <rte_errno.h>
#include <rte_cryptodev.h>
#include <rte_cryptodev_pmd.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_thash.h>

#include "rte_eventdev.h"
#include "rte_eventdev_pmd.h"
#include "rte_event_crypto_adapter.h"

#define BATCH_SIZE			32
#define BLOCK_CNT_THRESHOLD		10
#define CRYPTO_EVENT_BUFFER_SIZE	(4*BATCH_SIZE)

#define CRYPTO_ADAPTER_SERVICE_NAME_LEN	32
#define CRYPTO_ADAPTER_MEM_NAME_LEN	32

#define RSS_KEY_SIZE	40

/*
 * There is an instance of this struct per polled Rx queue added to the
 * adapter
 */
struct crypto_poll_entry {
	/* crypto port to poll */
	uint8_t crypto_dev_id;
	/* crypto rx queue to poll */
	uint16_t crypto_rx_qid;
};

/* Instance per adapter */
struct rte_crypto_event_enqueue_buffer {
	/* Count of events in this buffer */
	uint16_t count;
	/* Array of events in this buffer */
	struct rte_event events[CRYPTO_EVENT_BUFFER_SIZE];
};

struct rte_event_crypto_adapter {
	/* RSS key */
	uint8_t rss_key_be[RSS_KEY_SIZE];
	/* Event device identifier */
	uint8_t eventdev_id;
	/* Per crypto device structure */
	struct crypto_device_info *crypto_devices;
	/* Event port identifier */
	uint8_t event_port_id;
	/* Lock to serialize config updates with service function */
	rte_spinlock_t rx_lock;
	/* Max mbufs processed in any service function invocation */
	uint32_t max_nb_rx;
	/* Receive queues that need to be polled */
	struct crypto_poll_entry *crypto_poll;
	/* Size of the crypto_poll array */
	uint16_t num_rx_polled;
	/* Weighted round robin schedule */
	uint32_t *wrr_sched;
	/* wrr_sched[] size */
	uint32_t wrr_len;
	/* Next entry in wrr[] to begin polling */
	uint32_t wrr_pos;
	/* Event burst buffer */
	struct rte_crypto_event_enqueue_buffer event_enqueue_buffer;
	/* Per adapter stats */
	struct rte_event_crypto_adapter_stats stats;
	/* Block count, counts upto BLOCK_CNT_THRESHOLD */
	uint16_t enq_block_count;
	/* Block start ts */
	uint64_t rx_enq_block_start_ts;
	/* Configuration callback for rte_service configuration */
	rte_event_crypto_adapter_conf_cb conf_cb;
	/* Configuration callback argument */
	void *conf_arg;
	/* Set if  default_cb is being used */
	int default_cb_arg;
	/* Service initialization state */
	uint8_t service_inited;
	/* Total count of Rx queues in adapter */
	uint32_t nb_queues;
	/* Memory allocation name */
	char mem_name[CRYPTO_ADAPTER_MEM_NAME_LEN];
	/* Socket identifier cached from eventdev */
	int socket_id;
	/* Per adapter EAL service */
	uint32_t service_id;
} __rte_cache_aligned;

/* Per crypto device */
struct crypto_device_info {
	struct rte_cryptodev *dev;
	struct crypto_rx_queue_info *rx_queue;
	/* Set if cryptodev->eventdev packet transfer uses a
	 * hardware mechanism
	 */
	uint8_t internal_event_port;
	/* Set if the adapter is processing rx queues for
	 * this crypto device and packet processing has been
	 * started, allows for the code to know if the PMD
	 * rx_adapter_stop callback needs to be invoked
	 */
	uint8_t dev_rx_started;
	/* If nb_dev_queues > 0, the start callback will
	 * be invoked if not already invoked
	 */
	uint16_t nb_dev_queues;
};

/* Per Rx queue */
struct crypto_rx_queue_info {
	int queue_enabled;	/* True if added */
	uint16_t wt;		/* Polling weight */
	uint8_t event_queue_id;	/* Event queue to enqueue packets to */
	uint8_t sched_type;	/* Sched type for events */
	uint8_t priority;	/* Event priority */
	uint32_t flow_id;	/* App provided flow identifier */
	uint32_t flow_id_mask;	/* Set to ~0 if app provides flow id else 0 */
};

static struct rte_event_crypto_adapter **event_crypto_adapter;

static inline int
valid_id(uint8_t id)
{
	return id < RTE_EVENT_CRYPTO_ADAPTER_MAX_INSTANCE;
}

#define RTE_EVENT_CRYPTO_ADAPTER_ID_VALID_OR_ERR_RET(id, retval) do { \
	if (!valid_id(id)) { \
		RTE_EDEV_LOG_ERR("Invalid crypto Rx adapter id = %d\n", id); \
		return retval; \
	} \
} while (0)

#if 0
static inline int
sw_rx_adapter_queue_count(struct rte_event_crypto_adapter *rx_adapter)
{
	return rx_adapter->num_rx_polled;
}

/* Greatest common divisor */
static uint16_t gcd_u16(uint16_t a, uint16_t b)
{
	uint16_t r = a % b;

	return r ? gcd_u16(b, r) : b;
}

/* Returns the next queue in the polling sequence
 *
 * http://kb.linuxvirtualserver.org/wiki/Weighted_Round-Robin_Scheduling
 */
static int
wrr_next(struct rte_event_crypto_adapter *rx_adapter,
	 unsigned int n, int *cw,
	 struct crypto_poll_entry *crypto_poll, uint16_t max_wt,
	 uint16_t gcd, int prev)
{
	int i = prev;
	uint16_t w;

	while (1) {
		uint16_t q;
		uint8_t d;

		i = (i + 1) % n;
		if (i == 0) {
			*cw = *cw - gcd;
			if (*cw <= 0)
				*cw = max_wt;
		}

		q = crypto_poll[i].crypto_rx_qid;
		d = crypto_poll[i].crypto_dev_id;
		w = rx_adapter->crypto_devices[d].rx_queue[q].wt;

		if ((int)w >= *cw)
			return i;
	}
}

static inline void
mtoip(struct rte_mbuf *m, struct ipv4_hdr **ipv4_hdr,
	struct ipv6_hdr **ipv6_hdr)
{
	struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);
	struct vlan_hdr *vlan_hdr;

	*ipv4_hdr = NULL;
	*ipv6_hdr = NULL;

	switch (crypto_hdr->ether_type) {
	case RTE_BE16(ETHER_TYPE_IPv4):
		*ipv4_hdr = (struct ipv4_hdr *)(eth_hdr + 1);
		break;

	case RTE_BE16(ETHER_TYPE_IPv6):
		*ipv6_hdr = (struct ipv6_hdr *)(eth_hdr + 1);
		break;

	case RTE_BE16(ETHER_TYPE_VLAN):
		vlan_hdr = (struct vlan_hdr *)(eth_hdr + 1);
		switch (vlan_hdr->eth_proto) {
		case RTE_BE16(ETHER_TYPE_IPv4):
			*ipv4_hdr = (struct ipv4_hdr *)(vlan_hdr + 1);
			break;
		case RTE_BE16(ETHER_TYPE_IPv6):
			*ipv6_hdr = (struct ipv6_hdr *)(vlan_hdr + 1);
			break;
		default:
			break;
		}
		break;

	default:
		break;
	}
}

/* Calculate RSS hash for IPv4/6 */
static inline uint32_t
do_softrss(struct rte_mbuf *m, const uint8_t *rss_key_be)
{
	uint32_t input_len;
	void *tuple;
	struct rte_ipv4_tuple ipv4_tuple;
	struct rte_ipv6_tuple ipv6_tuple;
	struct ipv4_hdr *ipv4_hdr;
	struct ipv6_hdr *ipv6_hdr;

	mtoip(m, &ipv4_hdr, &ipv6_hdr);

	if (ipv4_hdr) {
		ipv4_tuple.src_addr = rte_be_to_cpu_32(ipv4_hdr->src_addr);
		ipv4_tuple.dst_addr = rte_be_to_cpu_32(ipv4_hdr->dst_addr);
		tuple = &ipv4_tuple;
		input_len = RTE_THASH_V4_L3_LEN;
	} else if (ipv6_hdr) {
		rte_thash_load_v6_addrs(ipv6_hdr,
					(union rte_thash_tuple *)&ipv6_tuple);
		tuple = &ipv6_tuple;
		input_len = RTE_THASH_V6_L3_LEN;
	} else
		return 0;

	return rte_softrss_be(tuple, input_len, rss_key_be);
}

static inline int
rx_enq_blocked(struct rte_event_crypto_adapter *rx_adapter)
{
	return !!rx_adapter->enq_block_count;
}

static inline void
rx_enq_block_start_ts(struct rte_event_crypto_adapter *rx_adapter)
{
	if (rx_adapter->rx_enq_block_start_ts)
		return;

	rx_adapter->enq_block_count++;
	if (rx_adapter->enq_block_count < BLOCK_CNT_THRESHOLD)
		return;

	rx_adapter->rx_enq_block_start_ts = rte_get_tsc_cycles();
}

static inline void
rx_enq_block_end_ts(struct rte_event_crypto_adapter *rx_adapter,
		    struct rte_event_crypto_adapter_stats *stats)
{
	if (unlikely(!stats->rx_enq_start_ts))
		stats->rx_enq_start_ts = rte_get_tsc_cycles();

	if (likely(!rx_enq_blocked(rx_adapter)))
		return;

	rx_adapter->enq_block_count = 0;
	if (rx_adapter->rx_enq_block_start_ts) {
		stats->rx_enq_end_ts = rte_get_tsc_cycles();
		stats->rx_enq_block_cycles += stats->rx_enq_end_ts -
		    rx_adapter->rx_enq_block_start_ts;
		rx_adapter->rx_enq_block_start_ts = 0;
	}
}

/* Add event to buffer, free space check is done prior to calling
 * this function
 */
static inline void
buf_event_enqueue(struct rte_event_crypto_adapter *rx_adapter,
		  struct rte_event *ev)
{
	struct rte_crypto_event_enqueue_buffer *buf =
	    &rx_adapter->event_enqueue_buffer;
	rte_memcpy(&buf->events[buf->count++], ev, sizeof(struct rte_event));
}

/* Enqueue buffered events to event device */
static inline uint16_t
flush_event_buffer(struct rte_event_crypto_adapter *rx_adapter)
{
	struct rte_crypto_event_enqueue_buffer *buf =
	    &rx_adapter->event_enqueue_buffer;
	struct rte_event_crypto_adapter_stats *stats = &rx_adapter->stats;

	uint16_t n = rte_event_enqueue_new_burst(rx_adapter->eventdev_id,
					rx_adapter->event_port_id,
					buf->events,
					buf->count);
	if (n != buf->count) {
		memmove(buf->events,
			&buf->events[n],
			(buf->count - n) * sizeof(struct rte_event));
		stats->rx_enq_retry++;
	}

	n ? rx_enq_block_end_ts(rx_adapter, stats) :
		rx_enq_block_start_ts(rx_adapter);

	buf->count -= n;
	stats->rx_enq_count += n;

	return n;
}

static inline void
fill_event_buffer(struct rte_event_crypto_adapter *rx_adapter,
	uint8_t dev_id,
	uint16_t rx_queue_id,
	struct rte_mbuf **mbufs,
	uint16_t num)
{
	uint32_t i;
	struct crypto_device_info *crypto_device_info =
					&rx_adapter->crypto_devices[dev_id];
	struct crypto_rx_queue_info *crypto_rx_queue_info =
					&crypto_device_info->rx_queue[rx_queue_id];

	int32_t qid = crypto_rx_queue_info->event_queue_id;
	uint8_t sched_type = crypto_rx_queue_info->sched_type;
	uint8_t priority = crypto_rx_queue_info->priority;
	uint32_t flow_id;
	struct rte_event events[BATCH_SIZE];
	struct rte_mbuf *m = mbufs[0];
	uint32_t rss_mask;
	uint32_t rss;
	int do_rss;

	/* 0xffff ffff if PKT_RX_RSS_HASH is set, otherwise 0 */
	rss_mask = ~(((m->ol_flags & PKT_RX_RSS_HASH) != 0) - 1);
	do_rss = !rss_mask && !crypto_rx_queue_info->flow_id_mask;

	for (i = 0; i < num; i++) {
		m = mbufs[i];
		struct rte_event *ev = &events[i];

		rss = do_rss ?
			do_softrss(m, rx_adapter->rss_key_be) : m->hash.rss;
		flow_id =
		    crypto_rx_queue_info->flow_id &
				crypto_rx_queue_info->flow_id_mask;
		flow_id |= rss & ~crypto_rx_queue_info->flow_id_mask;

		ev->flow_id = flow_id;
		ev->op = RTE_EVENT_OP_NEW;
		ev->sched_type = sched_type;
		ev->queue_id = qid;
		ev->event_type = RTE_EVENT_TYPE_crypto_adapter;
		ev->sub_event_type = 0;
		ev->priority = priority;
		ev->mbuf = m;

		buf_event_enqueue(rx_adapter, ev);
	}
}

/*
 * Polls receive queues added to the event adapter and enqueues received
 * packets to the event device.
 *
 * The receive code enqueues initially to a temporary buffer, the
 * temporary buffer is drained anytime it holds >= BATCH_SIZE packets
 *
 * If there isn't space available in the temporary buffer, packets from the
 * Rx queue aren't dequeued from the crypto device, this back pressures the
 * crypto device, in virtual device environments this back pressure is relayed to
 * the hypervisor's switching layer where adjustments can be made to deal with
 * it.
 */
static inline uint32_t
crypto_poll(struct rte_event_crypto_adapter *rx_adapter)
{
	uint32_t num_queue;
	uint16_t n;
	uint32_t nb_rx = 0;
	struct rte_mbuf *mbufs[BATCH_SIZE];
	struct rte_crypto_event_enqueue_buffer *buf;
	uint32_t wrr_pos;
	uint32_t max_nb_rx;

	wrr_pos = rx_adapter->wrr_pos;
	max_nb_rx = rx_adapter->max_nb_rx;
	buf = &rx_adapter->event_enqueue_buffer;
	struct rte_event_crypto_adapter_stats *stats = &rx_adapter->stats;

	/* Iterate through a WRR sequence */
	for (num_queue = 0; num_queue < rx_adapter->wrr_len; num_queue++) {
		unsigned int poll_idx = rx_adapter->wrr_sched[wrr_pos];
		uint16_t qid = rx_adapter->crypto_poll[poll_idx].crypto_rx_qid;
		uint8_t d = rx_adapter->crypto_poll[poll_idx].crypto_dev_id;

		/* Don't do a batch dequeue from the rx queue if there isn't
		 * enough space in the enqueue buffer.
		 */
		if (buf->count >= BATCH_SIZE)
			flush_event_buffer(rx_adapter);
		if (BATCH_SIZE > (crypto_EVENT_BUFFER_SIZE - buf->count))
			break;

		stats->rx_poll_count++;
		n = rte_crypto_rx_burst(d, qid, mbufs, BATCH_SIZE);

		if (n) {
			stats->rx_packets += n;
			/* The check before rte_crypto_rx_burst() ensures that
			 * all n mbufs can be buffered
			 */
			fill_event_buffer(rx_adapter, d, qid, mbufs, n);
			nb_rx += n;
			if (nb_rx > max_nb_rx) {
				rx_adapter->wrr_pos =
				    (wrr_pos + 1) % rx_adapter->wrr_len;
				return nb_rx;
			}
		}

		if (++wrr_pos == rx_adapter->wrr_len)
			wrr_pos = 0;
	}

	return nb_rx;
}
#endif

static int
rte_event_crypto_adapter_init(void)
{
	const char *name = "rte_event_crypto_adapter_array";
	const struct rte_memzone *mz;
	unsigned int sz;

	sz = sizeof(*event_crypto_adapter) *
	    RTE_EVENT_CRYPTO_ADAPTER_MAX_INSTANCE;
	sz = RTE_ALIGN(sz, RTE_CACHE_LINE_SIZE);

	mz = rte_memzone_lookup(name);
	if (mz == NULL) {
		mz = rte_memzone_reserve_aligned(name, sz, rte_socket_id(), 0,
						 RTE_CACHE_LINE_SIZE);
		if (mz == NULL) {
			RTE_EDEV_LOG_ERR("failed to reserve memzone err = %"
					PRId32, rte_errno);
			return -rte_errno;
		}
	}

	event_crypto_adapter = mz->addr;
	return 0;
}

static inline struct rte_event_crypto_adapter *
id_to_crypto_adapter(uint8_t id)
{
	return event_crypto_adapter ?
		event_crypto_adapter[id] : NULL;
}

static int
default_conf_cb(uint8_t id, uint8_t dev_id,
		struct rte_event_crypto_adapter_conf *conf, void *arg)
{
	int ret;
	struct rte_eventdev *dev;
	struct rte_event_dev_config dev_conf;
	int started;
	uint8_t port_id;
	struct rte_event_port_conf *port_conf = arg;
	struct rte_event_crypto_adapter *rx_adapter = id_to_crypto_adapter(id);

	dev = &rte_eventdevs[rx_adapter->eventdev_id];
	dev_conf = dev->data->dev_conf;

	started = dev->data->dev_started;
	if (started)
		rte_event_dev_stop(dev_id);
	port_id = dev_conf.nb_event_ports;
	dev_conf.nb_event_ports += 1;
	ret = rte_event_dev_configure(dev_id, &dev_conf);
	if (ret) {
		RTE_EDEV_LOG_ERR("failed to configure event dev %u\n",
						dev_id);
		if (started)
			rte_event_dev_start(dev_id);
		return ret;
	}

	ret = rte_event_port_setup(dev_id, port_id, port_conf);
	if (ret) {
		RTE_EDEV_LOG_ERR("failed to setup event port %u\n",
					port_id);
		return ret;
	}

	conf->event_port_id = port_id;
	conf->max_nb_rx = 128;
	if (started)
		rte_event_dev_start(dev_id);
	rx_adapter->default_cb_arg = 1;
	return ret;
}

static void
update_queue_info(struct rte_event_crypto_adapter *rx_adapter,
		struct crypto_device_info *dev_info,
		int32_t rx_queue_id,
		uint8_t add)
{
	struct crypto_rx_queue_info *queue_info;
	int enabled;
	uint16_t i;

	if (dev_info->rx_queue == NULL)
		return;

	if (rx_queue_id == -1) {
		for (i = 0; i < dev_info->dev->data->nb_queue_pairs; i++)
			update_queue_info(rx_adapter, dev_info, i, add);
	} else {
		queue_info = &dev_info->rx_queue[rx_queue_id];
		enabled = queue_info->queue_enabled;
		if (add) {
			rx_adapter->nb_queues += !enabled;
			dev_info->nb_dev_queues += !enabled;
		} else {
			rx_adapter->nb_queues -= enabled;
			dev_info->nb_dev_queues -= enabled;
		}
		queue_info->queue_enabled = !!add;
	}
}

#if 0
static int
event_crypto_queue_pair_del(struct rte_event_crypto_adapter *rx_adapter,
			    struct crypto_device_info *dev_info,
			    uint16_t rx_queue_id)
{
	struct crypto_rx_queue_info *queue_info;

	if (rx_adapter->nb_queues == 0)
		return 0;

	queue_info = &dev_info->rx_queue[rx_queue_id];
	rx_adapter->num_rx_polled -= queue_info->queue_enabled;
	update_queue_info(rx_adapter, dev_info, rx_queue_id, 0);
	return 0;
}

static void
event_crypto_queue_pair_add(struct rte_event_crypto_adapter *rx_adapter,
		struct crypto_device_info *dev_info,
		uint16_t rx_queue_id,
		const struct rte_event_crypto_queue_pair_conf *conf)

{
	struct crypto_rx_queue_info *queue_info;
	const struct rte_event *ev = &conf->ev;

	queue_info = &dev_info->rx_queue[rx_queue_id];
	queue_info->event_queue_id = ev->queue_id;
	queue_info->sched_type = ev->sched_type;
	queue_info->priority = ev->priority;
	queue_info->wt = conf->servicing_weight;

	if (conf->rx_queue_flags &
			RTE_EVENT_CRYPTO_ADAPTER_QUEUE_FLOW_ID_VALID) {
		queue_info->flow_id = ev->flow_id;
		queue_info->flow_id_mask = ~0;
	}

	/* The same queue can be added more than once */
	rx_adapter->num_rx_polled += !queue_info->queue_enabled;
	update_queue_info(rx_adapter, dev_info, rx_queue_id, 1);
}
#endif
static int
rx_adapter_ctrl(uint8_t id, enum rte_event_crypto_adapter_type type, int start)
{
	struct rte_event_crypto_adapter *rx_adapter;
	struct rte_eventdev *dev;
	struct crypto_device_info *dev_info;
	uint32_t i;
	int stop = !start;

	RTE_EVENT_CRYPTO_ADAPTER_ID_VALID_OR_ERR_RET(id, -EINVAL);
	rx_adapter = id_to_crypto_adapter(id);
	if (rx_adapter == NULL)
		return -EINVAL;

	dev = &rte_eventdevs[rx_adapter->eventdev_id];

	for (i = 0; i < rte_cryptodev_count(); i++) {
		dev_info = &rx_adapter->crypto_devices[i];
		/* if start  check for num dev queues */
		if (start && !dev_info->nb_dev_queues)
			continue;
		/* if stop check if dev has been started */
		if (stop && !dev_info->dev_rx_started)
			continue;
		dev_info->dev_rx_started = start;
		if (dev_info->internal_event_port == 0)
			continue;
		start ? (*dev->dev_ops->crypto_adapter_start)(dev, type,
						rte_cryptodev_pmd_get_dev(i)) :
			(*dev->dev_ops->crypto_adapter_stop)(dev, type,
						rte_cryptodev_pmd_get_dev(i));
	}

	return 0;
}

int
rte_event_crypto_adapter_create_ext(uint8_t id, uint8_t dev_id,
				rte_event_crypto_adapter_conf_cb conf_cb,
				void *conf_arg)
{
	struct rte_event_crypto_adapter *rx_adapter;
	int ret;
	int socket_id;
	uint8_t i;
	char mem_name[CRYPTO_ADAPTER_SERVICE_NAME_LEN];
	const uint8_t default_rss_key[] = {
		0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2,
		0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0,
		0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4,
		0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c,
		0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa,
	};

	RTE_EVENT_CRYPTO_ADAPTER_ID_VALID_OR_ERR_RET(id, -EINVAL);
	RTE_EVENTDEV_VALID_DEVID_OR_ERR_RET(dev_id, -EINVAL);
	if (conf_cb == NULL)
		return -EINVAL;

	if (event_crypto_adapter == NULL) {
		ret = rte_event_crypto_adapter_init();
		if (ret)
			return ret;
	}

	rx_adapter = id_to_crypto_adapter(id);
	if (rx_adapter != NULL) {
		RTE_EDEV_LOG_ERR("crypto Rx adapter exists id = %" PRIu8, id);
		return -EEXIST;
	}

	socket_id = rte_event_dev_socket_id(dev_id);
	snprintf(mem_name, CRYPTO_ADAPTER_MEM_NAME_LEN,
		"rte_event_crypto_adapter_%d",
		id);

	rx_adapter = rte_zmalloc_socket(mem_name, sizeof(*rx_adapter),
			RTE_CACHE_LINE_SIZE, socket_id);
	if (rx_adapter == NULL) {
		RTE_EDEV_LOG_ERR("failed to get mem for rx adapter");
		return -ENOMEM;
	}

	rx_adapter->eventdev_id = dev_id;
	rx_adapter->socket_id = socket_id;
	rx_adapter->conf_cb = conf_cb;
	rx_adapter->conf_arg = conf_arg;
	strcpy(rx_adapter->mem_name, mem_name);
	rx_adapter->crypto_devices = rte_zmalloc_socket(rx_adapter->mem_name,
					rte_cryptodev_count() *
					sizeof(struct crypto_device_info), 0,
					socket_id);
	rte_convert_rss_key((const uint32_t *)default_rss_key,
			(uint32_t *)rx_adapter->rss_key_be,
			    RTE_DIM(default_rss_key));

	if (rx_adapter->crypto_devices == NULL) {
		RTE_EDEV_LOG_ERR("failed to get mem for crypto devices\n");
		rte_free(rx_adapter);
		return -ENOMEM;
	}
	rte_spinlock_init(&rx_adapter->rx_lock);
	for (i = 0; i < rte_cryptodev_count(); i++)
		rx_adapter->crypto_devices[i].dev = rte_cryptodev_pmd_get_dev(i);

	event_crypto_adapter[id] = rx_adapter;
	if (conf_cb == default_conf_cb)
		rx_adapter->default_cb_arg = 1;
	return 0;
}

int
rte_event_crypto_adapter_create(uint8_t id, uint8_t dev_id,
		struct rte_event_port_conf *port_config)
{
	struct rte_event_port_conf *pc;
	int ret;

	if (port_config == NULL)
		return -EINVAL;
	RTE_EVENT_CRYPTO_ADAPTER_ID_VALID_OR_ERR_RET(id, -EINVAL);

	pc = rte_malloc(NULL, sizeof(*pc), 0);
	if (pc == NULL)
		return -ENOMEM;
	*pc = *port_config;
	ret = rte_event_crypto_adapter_create_ext(id, dev_id,
					default_conf_cb,
					pc);
	if (ret)
		rte_free(pc);
	return ret;
}

int
rte_event_crypto_adapter_free(uint8_t id)
{
	struct rte_event_crypto_adapter *rx_adapter;

	RTE_EVENT_CRYPTO_ADAPTER_ID_VALID_OR_ERR_RET(id, -EINVAL);

	rx_adapter = id_to_crypto_adapter(id);
	if (rx_adapter == NULL)
		return -EINVAL;

	if (rx_adapter->nb_queues) {
		RTE_EDEV_LOG_ERR("%" PRIu16 " Rx queues not deleted",
				rx_adapter->nb_queues);
		return -EBUSY;
	}

	if (rx_adapter->default_cb_arg)
		rte_free(rx_adapter->conf_arg);
	rte_free(rx_adapter->crypto_devices);
	rte_free(rx_adapter);
	event_crypto_adapter[id] = NULL;

	return 0;
}

int
rte_event_crypto_adapter_queue_pair_add(uint8_t id,
		uint8_t cdev_id,
		int32_t queue_pair_id,
		const struct rte_event_crypto_queue_pair_conf *conf)
{
	int ret;
	uint32_t cap;
	struct rte_event_crypto_adapter *adapter;
	struct rte_eventdev *dev;
	struct crypto_device_info *dev_info;

	RTE_EVENT_CRYPTO_ADAPTER_ID_VALID_OR_ERR_RET(id, -EINVAL);
	if (!rte_cryptodev_pmd_is_valid_dev(cdev_id))
		return -EINVAL;

	adapter = id_to_crypto_adapter(id);
	if ((adapter == NULL) || (conf == NULL))
		return -EINVAL;

	dev = &rte_eventdevs[adapter->eventdev_id];
	ret = rte_event_crypto_adapter_caps_get(adapter->eventdev_id,
						cdev_id,
						&cap);
	if (ret) {
		RTE_EDEV_LOG_ERR("Failed to get adapter caps edev %" PRIu8
			"crypto port %" PRIu8, id, cdev_id);
		return ret;
	}
#if 0
	if ((cap & RTE_EVENT_CRYPTO_ADAPTER_CAP_OVERRIDE_FLOW_ID) == 0
		&& (conf->rx_queue_flags &
			RTE_EVENT_CRYPTO_ADAPTER_QUEUE_FLOW_ID_VALID)) {
		RTE_EDEV_LOG_ERR("Flow ID override is not supported,"
				" crypto port: %" PRIu8 " adapter id: %" PRIu8,
				crypto_dev_id, id);
		return -EINVAL;
	}

	if ((cap & RTE_EVENT_CRYPTO_ADAPTER_CAP_MULTI_EVENTQ) == 0 &&
		(queue_pair_id != -1)) {
		RTE_EDEV_LOG_ERR("Rx queues can only be connected to single "
			"event queue id %u crypto port %u", id, crypto_dev_id);
		return -EINVAL;
	}
#endif
	if (queue_pair_id != -1 && (uint16_t)queue_pair_id >=
			rte_cryptodev_pmd_get_dev(cdev_id)->data->nb_queue_pairs) {
		RTE_EDEV_LOG_ERR("Invalid queue_pair_id %" PRIu16,
			 (uint16_t)queue_pair_id);
		return -EINVAL;
	}

	dev_info = &adapter->crypto_devices[cdev_id];

	if (cap & RTE_EVENT_CRYPTO_ADAPTER_CAP_INTERNAL_PORT) {
		RTE_FUNC_PTR_OR_ERR_RET(*dev->dev_ops->crypto_adapter_queue_add,
					-ENOTSUP);
		if (dev_info->rx_queue == NULL) {
			dev_info->rx_queue =
			    rte_zmalloc_socket(adapter->mem_name,
					dev_info->dev->data->nb_queue_pairs *
					sizeof(struct crypto_rx_queue_info), 0,
					adapter->socket_id);
			if (dev_info->rx_queue == NULL)
				return -ENOMEM;
		}

		ret = (*dev->dev_ops->crypto_adapter_queue_add)(dev,
				rte_cryptodev_pmd_get_dev(cdev_id),
				queue_pair_id, conf);
		if (ret == 0) {
			update_queue_info(adapter,
					&adapter->crypto_devices[cdev_id],
					queue_pair_id,
					1);
		}
	} else
		return -ENOTSUP;

	return ret;
}

int
rte_event_crypto_adapter_queue_pair_del(uint8_t id, uint8_t cdev_id,
				int32_t queue_pair_id)
{
	int ret = 0;
	struct rte_eventdev *dev;
	struct rte_event_crypto_adapter *adapter;
	struct crypto_device_info *dev_info;
	uint32_t cap;

	RTE_EVENT_CRYPTO_ADAPTER_ID_VALID_OR_ERR_RET(id, -EINVAL);
	if (!rte_cryptodev_pmd_is_valid_dev(cdev_id))
		return -EINVAL;

	adapter = id_to_crypto_adapter(id);
	if (adapter == NULL)
		return -EINVAL;

	dev = &rte_eventdevs[adapter->eventdev_id];
	ret = rte_event_crypto_adapter_caps_get(adapter->eventdev_id,
						cdev_id,
						&cap);
	if (ret)
		return ret;

	if (queue_pair_id != -1 && (uint16_t)queue_pair_id >=
		rte_cryptodev_pmd_get_dev(cdev_id)->data->nb_queue_pairs) {
		RTE_EDEV_LOG_ERR("Invalid rx queue_id %" PRIu16,
			 (uint16_t)queue_pair_id);
		return -EINVAL;
	}

	dev_info = &adapter->crypto_devices[cdev_id];

	if (cap & RTE_EVENT_CRYPTO_ADAPTER_CAP_INTERNAL_PORT) {
		RTE_FUNC_PTR_OR_ERR_RET(*dev->dev_ops->crypto_adapter_queue_del,
				 -ENOTSUP);
		ret = (*dev->dev_ops->crypto_adapter_queue_del)(dev,
					rte_cryptodev_pmd_get_dev(cdev_id),
						queue_pair_id);
		if (ret == 0) {
			update_queue_info(adapter,
					&adapter->crypto_devices[cdev_id],
					queue_pair_id,
					0);
			if (dev_info->nb_dev_queues == 0) {
				rte_free(dev_info->rx_queue);
				dev_info->rx_queue = NULL;
			}
		}
	} else
		return -ENOTSUP;

	return ret;
}


int
rte_event_crypto_adapter_start(uint8_t id,
			       enum rte_event_crypto_adapter_type type)
{
	return rx_adapter_ctrl(id, type, 1);
}

int
rte_event_crypto_adapter_stop(uint8_t id,
			      enum rte_event_crypto_adapter_type type)
{
	return rx_adapter_ctrl(id, type, 0);
}

int
rte_event_crypto_adapter_stats_get(uint8_t id,
		struct rte_event_crypto_adapter_stats *stats)
{
	struct rte_event_crypto_adapter *rx_adapter;
	struct rte_event_crypto_adapter_stats dev_stats_sum = { 0 };
	struct rte_event_crypto_adapter_stats dev_stats;
	struct rte_eventdev *dev;
	struct crypto_device_info *dev_info;
	uint32_t i;
	int ret;

	RTE_EVENT_CRYPTO_ADAPTER_ID_VALID_OR_ERR_RET(id, -EINVAL);

	rx_adapter = id_to_crypto_adapter(id);
	if (rx_adapter  == NULL || stats == NULL)
		return -EINVAL;

	dev = &rte_eventdevs[rx_adapter->eventdev_id];
	memset(stats, 0, sizeof(*stats));
	for (i = 0; i < rte_cryptodev_count(); i++) {
		dev_info = &rx_adapter->crypto_devices[i];
		if (dev_info->internal_event_port == 0 ||
			dev->dev_ops->crypto_adapter_stats_get == NULL)
			continue;
		ret = (*dev->dev_ops->crypto_adapter_stats_get)(dev,
					rte_cryptodev_pmd_get_dev(i),
					&dev_stats);
		if (ret)
			continue;
		dev_stats_sum.event_dequeue_count +=
					dev_stats.event_dequeue_count;
	}

	if (rx_adapter->service_inited)
		*stats = rx_adapter->stats;

	stats->event_dequeue_count += dev_stats_sum.event_dequeue_count;
	return 0;
}

int
rte_event_crypto_adapter_stats_reset(uint8_t id)
{
	struct rte_event_crypto_adapter *rx_adapter;
	struct rte_eventdev *dev;
	struct crypto_device_info *dev_info;
	uint32_t i;

	RTE_EVENT_CRYPTO_ADAPTER_ID_VALID_OR_ERR_RET(id, -EINVAL);

	rx_adapter = id_to_crypto_adapter(id);
	if (rx_adapter == NULL)
		return -EINVAL;

	dev = &rte_eventdevs[rx_adapter->eventdev_id];
	for (i = 0; i < rte_cryptodev_count(); i++) {
		dev_info = &rx_adapter->crypto_devices[i];
		if (dev_info->internal_event_port == 0 ||
			dev->dev_ops->crypto_adapter_stats_reset == NULL)
			continue;
		(*dev->dev_ops->crypto_adapter_stats_reset)(dev,
					rte_cryptodev_pmd_get_dev(i));
	}

	memset(&rx_adapter->stats, 0, sizeof(rx_adapter->stats));
	return 0;
}

int
rte_event_crypto_adapter_service_id_get(uint8_t id, uint32_t *service_id)
{
	struct rte_event_crypto_adapter *rx_adapter;

	RTE_EVENT_CRYPTO_ADAPTER_ID_VALID_OR_ERR_RET(id, -EINVAL);

	rx_adapter = id_to_crypto_adapter(id);
	if (rx_adapter == NULL || service_id == NULL)
		return -EINVAL;

	if (rx_adapter->service_inited)
		*service_id = rx_adapter->service_id;

	return rx_adapter->service_inited ? 0 : -ESRCH;
}
