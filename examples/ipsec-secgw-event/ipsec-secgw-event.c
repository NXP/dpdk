/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2016 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *   Copyright 2018 NXP
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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>

#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_acl.h>
#include <rte_lpm.h>
#include <rte_lpm6.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_cryptodev.h>

#include "ipsec.h"
#include "parser.h"

#include <rte_eventdev.h>
#include <rte_event_eth_rx_adapter.h>
#include <rte_event_crypto_adapter.h>
int eventdev_id;
int adapter_id;

#define RTE_LOGTYPE_IPSEC RTE_LOGTYPE_USER1

#define MAX_JUMBO_PKT_LEN  9600

#define MEMPOOL_CACHE_SIZE 256

#define NB_MBUF	(32000)

#define CDEV_QUEUE_DESC 2048
#define CDEV_MP_NB_OBJS 2048
#define CDEV_MP_CACHE_SZ 64

#define OPTION_CONFIG		"port_config"
#define OPTION_SINGLE_SA	"single-sa"
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */

#define NB_SOCKETS 4

/* Configure how many packets ahead to prefetch, when reading packets */
#define PREFETCH_OFFSET	3

#define MAX_RX_QUEUE_PER_LCORE 16

#define MAX_LCORE_PARAMS 1024

#define UNPROTECTED_PORT(port) (unprotected_port_mask & (1 << portid))

#define INVALID_EVENDEV_ID 0xFF

#define DEFAULT_SOCKET_ID 0

/*
 * Configurable number of RX/TX ring descriptors
 */
#define IPSEC_SECGW_RX_DESC_DEFAULT 128
#define IPSEC_SECGW_TX_DESC_DEFAULT 512
static uint16_t nb_rxd = IPSEC_SECGW_RX_DESC_DEFAULT;
static uint16_t nb_txd = IPSEC_SECGW_TX_DESC_DEFAULT;

#if RTE_BYTE_ORDER != RTE_LITTLE_ENDIAN
#define __BYTES_TO_UINT64(a, b, c, d, e, f, g, h) \
	(((uint64_t)((a) & 0xff) << 56) | \
	((uint64_t)((b) & 0xff) << 48) | \
	((uint64_t)((c) & 0xff) << 40) | \
	((uint64_t)((d) & 0xff) << 32) | \
	((uint64_t)((e) & 0xff) << 24) | \
	((uint64_t)((f) & 0xff) << 16) | \
	((uint64_t)((g) & 0xff) << 8)  | \
	((uint64_t)(h) & 0xff))
#else
#define __BYTES_TO_UINT64(a, b, c, d, e, f, g, h) \
	(((uint64_t)((h) & 0xff) << 56) | \
	((uint64_t)((g) & 0xff) << 48) | \
	((uint64_t)((f) & 0xff) << 40) | \
	((uint64_t)((e) & 0xff) << 32) | \
	((uint64_t)((d) & 0xff) << 24) | \
	((uint64_t)((c) & 0xff) << 16) | \
	((uint64_t)((b) & 0xff) << 8) | \
	((uint64_t)(a) & 0xff))
#endif
#define ETHADDR(a, b, c, d, e, f) (__BYTES_TO_UINT64(a, b, c, d, e, f, 0, 0))

#define ETHADDR_TO_UINT64(addr) __BYTES_TO_UINT64( \
		addr.addr_bytes[0], addr.addr_bytes[1], \
		addr.addr_bytes[2], addr.addr_bytes[3], \
		addr.addr_bytes[4], addr.addr_bytes[5], \
		0, 0)

/* port/source ethernet addr and destination ethernet addr */
struct ethaddr_info {
	uint64_t src, dst;
};

struct ethaddr_info ethaddr_tbl[RTE_MAX_ETHPORTS] = {
	{ 0, ETHADDR(0x00, 0x16, 0x3e, 0x7e, 0x94, 0x9a) },
	{ 0, ETHADDR(0x00, 0x16, 0x3e, 0x22, 0xa1, 0xd9) },
	{ 0, ETHADDR(0x00, 0x16, 0x3e, 0x08, 0x69, 0x26) },
	{ 0, ETHADDR(0x00, 0x16, 0x3e, 0x49, 0x9e, 0xdd) }
};

/* mask of enabled ports */
static uint32_t enabled_port_mask;
static int32_t promiscuous_on = 1;
static int32_t numa_on = 1; /**< NUMA is enabled by default. */
static uint32_t nb_lcores;
static uint32_t single_sa;
static uint32_t single_sa_idx;
static uint32_t frame_size;
static uint32_t sched_type;

pthread_mutex_t sa_lock;

struct cdev_qp_index_list cdev_qp_list;

enum dequeue_mode lcore_dequeue_mode[RTE_MAX_LCORE];

struct port_params {
	uint16_t port_id;
	uint16_t num_queues;
} __rte_cache_aligned;

static struct port_params port_params[RTE_MAX_ETHPORTS];
static uint16_t nb_port_params;

struct lcore_rx_queue {
	uint16_t port_id;
	uint8_t queue_id;
} __rte_cache_aligned;

struct lcore_params {
	uint16_t port_id;
	uint8_t queue_id;
	uint8_t lcore_id;
} __rte_cache_aligned;

static uint16_t nb_lcore_params;

struct buffer {
	uint16_t len;
	struct rte_mbuf *m_table[MAX_PKT_BURST] __rte_aligned(sizeof(void *));
};

struct lcore_conf {
	struct buffer tx_mbufs[RTE_MAX_ETHPORTS];
	struct ipsec_ctx inbound;
	struct ipsec_ctx outbound;
	struct rt_ctx *rt4_ctx;
	struct rt_ctx *rt6_ctx;
} __rte_cache_aligned;

static struct lcore_conf lcore_conf[RTE_MAX_LCORE];

static struct rte_eth_conf port_conf = {
	.rxmode = {
		.mq_mode	= ETH_MQ_RX_RSS,
		.max_rx_pkt_len = ETHER_MAX_LEN,
		.split_hdr_size = 0,
		.offloads = DEV_RX_OFFLOAD_CHECKSUM |
			    DEV_RX_OFFLOAD_CRC_STRIP,
		.ignore_offload_bitfield = 1,
	},
	.rx_adv_conf = {
		.rss_conf = {
			.rss_key = NULL,
			.rss_hf = ETH_RSS_IP | ETH_RSS_UDP |
				ETH_RSS_TCP | ETH_RSS_SCTP,
		},
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
};

static struct socket_ctx socket_ctx[NB_SOCKETS];

struct traffic_type {
	const uint8_t *data[MAX_PKT_BURST * 2];
	struct rte_mbuf *pkts[MAX_PKT_BURST * 2];
	uint32_t res[MAX_PKT_BURST * 2];
	uint32_t num;
};

struct ipsec_traffic {
	struct traffic_type ipsec;
	struct traffic_type ip4;
	struct traffic_type ip6;
};

struct cdev_qp_index *
get_next_cdev_qp(void)
{
	int index;

	if (!cdev_qp_list.num)
		return NULL;

	cdev_qp_list.last_used++;
	if (cdev_qp_list.last_used == cdev_qp_list.num)
		cdev_qp_list.last_used = 0;

	index = cdev_qp_list.last_used;
	cdev_qp_list.cdev_qp[index].num_users++;

// TODO: Check if num users > max sessions */
	return &(cdev_qp_list.cdev_qp[index]);
}

static inline void
prepare_packet_from_sec(struct rte_mbuf *pkt, struct ipsec_traffic *t)
{
	uint8_t *nlp;
	struct ip *ip;

	ip = rte_pktmbuf_mtod(pkt, struct ip *);
	if (ip->ip_v == IPVERSION) {
		nlp = (uint8_t *)((char *)pkt->buf_addr + pkt->data_off);
		nlp = RTE_PTR_ADD(nlp, offsetof(struct ip, ip_p));
		if (*nlp == IPPROTO_ESP)
			t->ipsec.pkts[(t->ipsec.num)++] = pkt;
		else {
			t->ip4.data[t->ip4.num] = nlp;
			t->ip4.pkts[(t->ip4.num)++] = pkt;
		}
	} else if (ip->ip_v == IP6_VERSION) {
		nlp = (uint8_t *)((char *)pkt->buf_addr + pkt->data_off);
		nlp = RTE_PTR_ADD(nlp, offsetof(struct ip6_hdr, ip6_nxt));
		if (*nlp == IPPROTO_ESP)
			t->ipsec.pkts[(t->ipsec.num)++] = pkt;
		else {
			t->ip6.data[t->ip6.num] = nlp;
			t->ip6.pkts[(t->ip6.num)++] = pkt;
		}
	} else {
		/* Unknown/Unsupported type, drop the packet */
		RTE_LOG(ERR, IPSEC, "Unsupported packet type\n");
		rte_pktmbuf_free(pkt);
	}

}

static inline void
prepare_packet_from_eth(struct rte_mbuf *pkt, struct ipsec_traffic *t)
{
	uint8_t *nlp;
	struct ether_hdr *eth;

	eth = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
	if (eth->ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv4)) {
		nlp = (uint8_t *)rte_pktmbuf_adj(pkt, ETHER_HDR_LEN);
		nlp = RTE_PTR_ADD(nlp, offsetof(struct ip, ip_p));
		if (*nlp == IPPROTO_ESP)
			t->ipsec.pkts[(t->ipsec.num)++] = pkt;
		else {
			t->ip4.data[t->ip4.num] = nlp;
			t->ip4.pkts[(t->ip4.num)++] = pkt;
		}
	} else if (eth->ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv6)) {
		nlp = (uint8_t *)rte_pktmbuf_adj(pkt, ETHER_HDR_LEN);
		nlp = RTE_PTR_ADD(nlp, offsetof(struct ip6_hdr, ip6_nxt));
		if (*nlp == IPPROTO_ESP)
			t->ipsec.pkts[(t->ipsec.num)++] = pkt;
		else {
			t->ip6.data[t->ip6.num] = nlp;
			t->ip6.pkts[(t->ip6.num)++] = pkt;
		}
	} else {
		/* Unknown/Unsupported type, drop the packet */
		RTE_LOG(ERR, IPSEC, "Unsupported packet type\n");
		rte_pktmbuf_free(pkt);
	}
}

static inline void
prepare_event_traffic(struct rte_event ev[], struct ipsec_traffic *from_eth,
		struct ipsec_traffic *from_sec,
		uint16_t nb_ev)
{
	int i;

	from_eth->ipsec.num = 0;
	from_eth->ip4.num = 0;
	from_eth->ip6.num = 0;
	from_sec->ipsec.num = 0;
	from_sec->ip4.num = 0;
	from_sec->ip6.num = 0;

	for (i = 0; i < (nb_ev - PREFETCH_OFFSET); i++) {
		if (ev[i + PREFETCH_OFFSET].event_type == RTE_EVENT_TYPE_ETHDEV)
			rte_prefetch0(rte_pktmbuf_mtod(
					ev[i + PREFETCH_OFFSET].mbuf,
					void *));
		else if (ev[i + PREFETCH_OFFSET].event_type
					== RTE_EVENT_TYPE_CRYPTODEV)
			rte_prefetch0(rte_pktmbuf_mtod(
				ev[i + PREFETCH_OFFSET].crypto_op->sym->m_src,
				void *));
		if (ev[i].event_type == RTE_EVENT_TYPE_ETHDEV)
			prepare_packet_from_eth(ev[i].mbuf, from_eth);
		else if (ev[i].event_type == RTE_EVENT_TYPE_CRYPTODEV)
			prepare_packet_from_sec(ev[i].crypto_op->sym->m_src, from_sec);
	}
	/* Process left packets */
	for (; i < nb_ev; i++) {
		if (ev[i].event_type == RTE_EVENT_TYPE_ETHDEV)
			prepare_packet_from_eth(ev[i].mbuf, from_eth);
		else if (ev[i].event_type == RTE_EVENT_TYPE_CRYPTODEV)
			prepare_packet_from_sec(ev[i].crypto_op->sym->m_src, from_sec);
	}
}

static inline void
prepare_tx_pkt(struct rte_mbuf *pkt, uint16_t port)
{
	struct ip *ip;
	struct ether_hdr *ethhdr;

	ip = rte_pktmbuf_mtod(pkt, struct ip *);

	ethhdr = (struct ether_hdr *)rte_pktmbuf_prepend(pkt, ETHER_HDR_LEN);

	if (ip->ip_v == IPVERSION) {
		pkt->ol_flags |= PKT_TX_IP_CKSUM | PKT_TX_IPV4;
		pkt->l3_len = sizeof(struct ip);
		pkt->l2_len = ETHER_HDR_LEN;

		ethhdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
	} else {
		pkt->ol_flags |= PKT_TX_IPV6;
		pkt->l3_len = sizeof(struct ip6_hdr);
		pkt->l2_len = ETHER_HDR_LEN;

		ethhdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv6);
	}

	memcpy(&ethhdr->s_addr, &ethaddr_tbl[port].src,
			sizeof(struct ether_addr));
	memcpy(&ethhdr->d_addr, &ethaddr_tbl[port].dst,
			sizeof(struct ether_addr));
}

static inline void
prepare_tx_burst(struct rte_mbuf *pkts[], uint16_t nb_pkts, uint16_t port)
{
	int32_t i;
	const int32_t prefetch_offset = 2;

	for (i = 0; i < (nb_pkts - prefetch_offset); i++) {
		rte_mbuf_prefetch_part2(pkts[i + prefetch_offset]);
		prepare_tx_pkt(pkts[i], port);
	}
	/* Process left packets */
	for (; i < nb_pkts; i++)
		prepare_tx_pkt(pkts[i], port);
}

/* Send burst of packets on an output interface */
static inline int32_t
send_burst(struct lcore_conf *qconf, uint16_t n, uint16_t port)
{
	struct rte_mbuf **m_table;
	int32_t ret;
	uint16_t queueid = 0;

	m_table = (struct rte_mbuf **)qconf->tx_mbufs[port].m_table;

	prepare_tx_burst(m_table, n, port);

	ret = rte_eth_tx_burst(port, queueid, m_table, n);
	if (unlikely(ret < n)) {
		do {
			rte_pktmbuf_free(m_table[ret]);
		} while (++ret < n);
	}

	return 0;
}

/* Enqueue a single packet, and send burst if queue is filled */
static inline int32_t
send_single_packet(struct rte_mbuf *m, uint16_t port)
{
	uint32_t lcore_id;
	uint16_t len;
	struct lcore_conf *qconf;

	lcore_id = rte_lcore_id();

	qconf = &lcore_conf[lcore_id];
	len = qconf->tx_mbufs[port].len;
	qconf->tx_mbufs[port].m_table[len] = m;
	len++;

	/* enough pkts to be sent */
	if (unlikely(len == MAX_PKT_BURST)) {
		send_burst(qconf, MAX_PKT_BURST, port);
		len = 0;
	}

	qconf->tx_mbufs[port].len = len;
	return 0;
}

static inline void
inbound_sp_sa(struct sp_ctx *sp, struct sa_ctx *sa, struct traffic_type *ip,
		uint16_t lim)
{
	struct rte_mbuf *m;
	uint32_t i, j, res, sa_idx;

	if (ip->num == 0 || sp == NULL)
		return;

	rte_acl_classify((struct rte_acl_ctx *)sp, ip->data, ip->res,
			ip->num, DEFAULT_MAX_CATEGORIES);

	j = 0;
	for (i = 0; i < ip->num; i++) {
		m = ip->pkts[i];
		res = ip->res[i];
		if (res & BYPASS) {
			ip->pkts[j++] = m;
			continue;
		}
		if (res & DISCARD || i < lim) {
			rte_pktmbuf_free(m);
			continue;
		}
		/* Only check SPI match for processed IPSec packets */
		sa_idx = ip->res[i] & PROTECT_MASK;
		if (sa_idx >= IPSEC_SA_MAX_ENTRIES ||
				!inbound_sa_check(sa, m, sa_idx)) {
			rte_pktmbuf_free(m);
			continue;
		}
		ip->pkts[j++] = m;
	}
	ip->num = j;
}
static inline void
process_pkts_inbound(struct ipsec_ctx *ipsec_ctx,
		struct ipsec_traffic *traffic)
{
	ipsec_inbound(ipsec_ctx, traffic->ipsec.pkts,
			traffic->ipsec.num);
}

static inline void
outbound_sp(struct sp_ctx *sp, struct traffic_type *ip,
		struct traffic_type *ipsec)
{
	struct rte_mbuf *m;
	uint32_t i, j, sa_idx;

	if (ip->num == 0 || sp == NULL)
		return;

	rte_acl_classify((struct rte_acl_ctx *)sp, ip->data, ip->res,
			ip->num, DEFAULT_MAX_CATEGORIES);

	j = 0;
	for (i = 0; i < ip->num; i++) {
		m = ip->pkts[i];
		sa_idx = ip->res[i] & PROTECT_MASK;
		if (ip->res[i] & DISCARD)
			rte_pktmbuf_free(m);
		else if (sa_idx < IPSEC_SA_MAX_ENTRIES) {
			ipsec->res[ipsec->num] = sa_idx;
			ipsec->pkts[ipsec->num++] = m;
		} else /* BYPASS */
			ip->pkts[j++] = m;
	}
	ip->num = j;
}
static inline void
process_pkts_outbound(struct ipsec_ctx *ipsec_ctx,
		struct ipsec_traffic *traffic)
{
	traffic->ipsec.num = 0;

	outbound_sp(ipsec_ctx->sp4_ctx, &traffic->ip4, &traffic->ipsec);

	outbound_sp(ipsec_ctx->sp6_ctx, &traffic->ip6, &traffic->ipsec);

	ipsec_outbound(ipsec_ctx, traffic->ipsec.pkts,
			traffic->ipsec.res, traffic->ipsec.num);
}

#if 0
static inline void
process_pkts_inbound_nosp(struct ipsec_ctx *ipsec_ctx,
		struct ipsec_traffic *traffic)
{
	struct rte_mbuf *m;
	uint32_t nb_pkts_in, i, idx;

	/* Drop any IPv4 traffic from unprotected ports */
	for (i = 0; i < traffic->ip4.num; i++)
		rte_pktmbuf_free(traffic->ip4.pkts[i]);

	traffic->ip4.num = 0;

	/* Drop any IPv6 traffic from unprotected ports */
	for (i = 0; i < traffic->ip6.num; i++)
		rte_pktmbuf_free(traffic->ip6.pkts[i]);

	traffic->ip6.num = 0;

	nb_pkts_in = ipsec_inbound(ipsec_ctx, traffic->ipsec.pkts,
			traffic->ipsec.num, MAX_PKT_BURST);

	for (i = 0; i < nb_pkts_in; i++) {
		m = traffic->ipsec.pkts[i];
		struct ip *ip = rte_pktmbuf_mtod(m, struct ip *);
		if (ip->ip_v == IPVERSION) {
			idx = traffic->ip4.num++;
			traffic->ip4.pkts[idx] = m;
		} else {
			idx = traffic->ip6.num++;
			traffic->ip6.pkts[idx] = m;
		}
	}
}

static inline void
process_pkts_outbound_nosp(struct ipsec_ctx *ipsec_ctx,
		struct ipsec_traffic *traffic)
{
	struct rte_mbuf *m;
	uint32_t nb_pkts_out, i;
	struct ip *ip;

	/* Drop any IPsec traffic from protected ports */
	for (i = 0; i < traffic->ipsec.num; i++)
		rte_pktmbuf_free(traffic->ipsec.pkts[i]);

	traffic->ipsec.num = 0;

	for (i = 0; i < traffic->ip4.num; i++)
		traffic->ip4.res[i] = single_sa_idx;

	for (i = 0; i < traffic->ip6.num; i++)
		traffic->ip6.res[i] = single_sa_idx;

	nb_pkts_out = ipsec_outbound(ipsec_ctx, traffic->ip4.pkts,
			traffic->ip4.res, traffic->ip4.num,
			MAX_PKT_BURST);

	/* They all sue the same SA (ip4 or ip6 tunnel) */
	m = traffic->ipsec.pkts[i];
	ip = rte_pktmbuf_mtod(m, struct ip *);
	if (ip->ip_v == IPVERSION)
		traffic->ip4.num = nb_pkts_out;
	else
		traffic->ip6.num = nb_pkts_out;
}
#endif

static inline int32_t
get_hop_for_offload_pkt(struct rte_mbuf *pkt, int is_ipv6)
{
	struct ipsec_mbuf_metadata *priv;
	struct ipsec_sa *sa;

	priv = get_priv(pkt);

	sa = priv->sa;
	if (unlikely(sa == NULL)) {
		RTE_LOG(ERR, IPSEC, "SA not saved in private data\n");
		goto fail;
	}

	if (is_ipv6)
		return sa->portid;

	/* else */
	return (sa->portid | RTE_LPM_LOOKUP_SUCCESS);

fail:
	if (is_ipv6)
		return -1;

	/* else */
	return 0;
}

static inline void
route4_pkts(struct rt_ctx *rt_ctx, struct rte_mbuf *pkts[], uint8_t nb_pkts)
{
	uint32_t hop[MAX_PKT_BURST * 2];
	uint32_t dst_ip[MAX_PKT_BURST * 2];
	int32_t pkt_hop = 0;
	uint16_t i, offset;
	uint16_t lpm_pkts = 0;

	if (nb_pkts == 0)
		return;

	/* Need to do an LPM lookup for non-inline packets. Inline packets will
	 * have port ID in the SA
	 */

	for (i = 0; i < nb_pkts; i++) {
		if (!(pkts[i]->ol_flags & PKT_TX_SEC_OFFLOAD)) {
			/* Security offload not enabled. So an LPM lookup is
			 * required to get the hop
			 */
			offset = offsetof(struct ip, ip_dst);
			dst_ip[lpm_pkts] = *rte_pktmbuf_mtod_offset(pkts[i],
					uint32_t *, offset);
			dst_ip[lpm_pkts] = rte_be_to_cpu_32(dst_ip[lpm_pkts]);
			lpm_pkts++;
		}
	}

	rte_lpm_lookup_bulk((struct rte_lpm *)rt_ctx, dst_ip, hop, lpm_pkts);

	lpm_pkts = 0;

	for (i = 0; i < nb_pkts; i++) {
		if (pkts[i]->ol_flags & PKT_TX_SEC_OFFLOAD) {
			/* Read hop from the SA */
			pkt_hop = get_hop_for_offload_pkt(pkts[i], 0);
		} else {
			/* Need to use hop returned by lookup */
			pkt_hop = hop[lpm_pkts++];
		}

		if ((pkt_hop & RTE_LPM_LOOKUP_SUCCESS) == 0) {
			rte_pktmbuf_free(pkts[i]);
			continue;
		}
		send_single_packet(pkts[i], pkt_hop & 0xff);
	}
}

static inline void
route6_pkts(struct rt_ctx *rt_ctx, struct rte_mbuf *pkts[], uint8_t nb_pkts)
{
	int32_t hop[MAX_PKT_BURST * 2];
	uint8_t dst_ip[MAX_PKT_BURST * 2][16];
	uint8_t *ip6_dst;
	int32_t pkt_hop = 0;
	uint16_t i, offset;
	uint16_t lpm_pkts = 0;

	if (nb_pkts == 0)
		return;

	/* Need to do an LPM lookup for non-inline packets. Inline packets will
	 * have port ID in the SA
	 */

	for (i = 0; i < nb_pkts; i++) {
		if (!(pkts[i]->ol_flags & PKT_TX_SEC_OFFLOAD)) {
			/* Security offload not enabled. So an LPM lookup is
			 * required to get the hop
			 */
			offset = offsetof(struct ip6_hdr, ip6_dst);
			ip6_dst = rte_pktmbuf_mtod_offset(pkts[i], uint8_t *,
					offset);
			memcpy(&dst_ip[lpm_pkts][0], ip6_dst, 16);
			lpm_pkts++;
		}
	}

	rte_lpm6_lookup_bulk_func((struct rte_lpm6 *)rt_ctx, dst_ip, hop,
			lpm_pkts);

	lpm_pkts = 0;

	for (i = 0; i < nb_pkts; i++) {
		if (pkts[i]->ol_flags & PKT_TX_SEC_OFFLOAD) {
			/* Read hop from the SA */
			pkt_hop = get_hop_for_offload_pkt(pkts[i], 1);
		} else {
			/* Need to use hop returned by lookup */
			pkt_hop = hop[lpm_pkts++];
		}

		if (pkt_hop == -1) {
			rte_pktmbuf_free(pkts[i]);
			continue;
		}
		send_single_packet(pkts[i], pkt_hop & 0xff);
	}
}

static inline void
route_pkts_from_sec(struct lcore_conf *qconf, struct ipsec_traffic *t)
{
	uint32_t i, idx;
	struct rte_mbuf *m;

// TODO: Have sa check optional??
	inbound_sp_sa(qconf->inbound.sp4_ctx, qconf->inbound.sa_ctx,
		      &t->ip4, 0);
	inbound_sp_sa(qconf->inbound.sp6_ctx, qconf->inbound.sa_ctx,
		      &t->ip6, 0);

	for (i = 0; i < t->ipsec.num; i++) {
		m = t->ipsec.pkts[i];
		struct ip *ip = rte_pktmbuf_mtod(m, struct ip *);
		if (ip->ip_v == IPVERSION) {
			idx = t->ip4.num++;
			t->ip4.pkts[idx] = m;
		} else {
			idx = t->ip6.num++;
			t->ip6.pkts[idx] = m;
		}
	}

	route4_pkts(qconf->rt4_ctx, t->ip4.pkts, t->ip4.num);
	route6_pkts(qconf->rt6_ctx, t->ip6.pkts, t->ip6.num);
}

static inline void
process_event_pkts(struct lcore_conf *qconf, struct rte_event ev[],
		uint8_t nb_ev)
{
	struct ipsec_traffic from_eth_traffic;
	struct ipsec_traffic from_sec_traffic;

	prepare_event_traffic(ev, &from_eth_traffic, &from_sec_traffic, nb_ev);

	route_pkts_from_sec(qconf, &from_sec_traffic);

// TODO: Single SA??
	process_pkts_inbound(&qconf->inbound, &from_eth_traffic);
	process_pkts_outbound(&qconf->outbound, &from_eth_traffic);

	route4_pkts(qconf->rt4_ctx, from_eth_traffic.ip4.pkts, from_eth_traffic.ip4.num);
	route6_pkts(qconf->rt6_ctx, from_eth_traffic.ip6.pkts, from_eth_traffic.ip6.num);
}

static inline void
drain_buffers(struct lcore_conf *qconf)
{
	struct buffer *buf;
	uint32_t portid;

	for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++) {
		buf = &qconf->tx_mbufs[portid];
		if (buf->len == 0)
			continue;
		send_burst(qconf, buf->len, portid);
		buf->len = 0;
	}
}

/* main processing loop */
static int32_t
main_loop(__attribute__((unused)) void *dummy)
{
	struct rte_event ev[MAX_PKT_BURST];
	uint32_t lcore_id, lcore_index, nb_rx;
	uint64_t prev_tsc, diff_tsc, cur_tsc;
	uint8_t event_port_id = INVALID_EVENDEV_ID;
	struct lcore_conf *qconf;
	int32_t socket_id;
	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1)
			/ US_PER_S * BURST_TX_DRAIN_US;

	prev_tsc = 0;
	lcore_id = rte_lcore_id();
	lcore_index = rte_lcore_index(lcore_id);
	event_port_id = lcore_index;

	qconf = &lcore_conf[lcore_id];
	socket_id = rte_lcore_to_socket_id(lcore_id);

	qconf->rt4_ctx = socket_ctx[socket_id].rt_ip4;
	qconf->rt6_ctx = socket_ctx[socket_id].rt_ip6;
	qconf->inbound.sp4_ctx = socket_ctx[socket_id].sp_ip4_in;
	qconf->inbound.sp6_ctx = socket_ctx[socket_id].sp_ip6_in;
	qconf->inbound.sa_ctx = socket_ctx[socket_id].sa_in;
	qconf->inbound.session_pool = socket_ctx[socket_id].session_pool;
	qconf->outbound.sp4_ctx = socket_ctx[socket_id].sp_ip4_out;
	qconf->outbound.sp6_ctx = socket_ctx[socket_id].sp_ip6_out;
	qconf->outbound.sa_ctx = socket_ctx[socket_id].sa_out;
	qconf->outbound.session_pool = socket_ctx[socket_id].session_pool;

	RTE_LOG(INFO, IPSEC, "entering main loop on lcore %u\n", lcore_id);

	while (1) {
		cur_tsc = rte_rdtsc();

		/* TX queue buffer drain */
		diff_tsc = cur_tsc - prev_tsc;

		if (unlikely(diff_tsc > drain_tsc)) {
			drain_buffers(qconf);
			prev_tsc = cur_tsc;
		}

		/* Read events from Event device */
		nb_rx = rte_event_dequeue_burst(eventdev_id, event_port_id, ev,
				MAX_PKT_BURST, 100);
		if (nb_rx)
			process_event_pkts(qconf, ev, nb_rx);

	}

	return 0;
}

static uint8_t
get_port_nb_rx_queues(const uint16_t port)
{
	uint16_t i;

	for (i = 0; i < nb_port_params; i++)
		if (port_params[i].port_id == port)
			return port_params[i].num_queues;
	return 0;
}

/* display usage */
static void
print_usage(const char *prgname)
{
	printf("%s [EAL options] -- -p PORTMASK -P -m MODE -u PORTMASK"
		"  --"OPTION_CONFIG" (port,num_queues)[,(port,num_queues]"
		" --single-sa SAIDX -f CONFIG_FILE\n"
		"  -p PORTMASK: hexadecimal bitmask of ports to configure\n"
		"  -P : enable promiscuous mode\n"
		"  -m : mode - ordered(default), atomic or parallel\n"
		"  -j FRAMESIZE: jumbo frame maximum size\n"
		"  --"OPTION_CONFIG": (port,num_queues): "
		"port configuration\n"
		"  --single-sa SAIDX: use single SA index for outbound, "
		"bypassing the SP\n"
		"  -f CONFIG_FILE: Configuration file path\n"
		" make sure to enable event device using --vdev='event_dpaa2' "
		" or vdev='event_dpaa'\n",
		prgname);
}

static int
parse_port_config(const char *q_arg)
{
	char s[256];
	const char *p, *p0 = q_arg;
	char *end;
	enum fieldnames {
		FLD_PORT = 0,
		FLD_NUM_QUEUES,
		_NUM_FLD
	};
	unsigned long int_fld[_NUM_FLD];
	char *str_fld[_NUM_FLD];
	int i;
	unsigned size;

	nb_lcore_params = 0;

	while ((p = strchr(p0,'(')) != NULL) {
		++p;
		if((p0 = strchr(p,')')) == NULL)
			return -1;

		size = p0 - p;
		if(size >= sizeof(s))
			return -1;

		snprintf(s, sizeof(s), "%.*s", size, p);
		if (rte_strsplit(s, sizeof(s), str_fld, _NUM_FLD, ',') != _NUM_FLD)
			return -1;
		for (i = 0; i < _NUM_FLD; i++){
			errno = 0;
			int_fld[i] = strtoul(str_fld[i], &end, 0);
			if (errno != 0 || end == str_fld[i] || int_fld[i] > 255)
				return -1;
		}
		if (nb_port_params >= RTE_MAX_ETHPORTS) {
			printf("exceeded max number of port params: %hu\n",
				nb_port_params);
			return -1;
		}
		port_params[nb_port_params].port_id =
			(uint8_t)int_fld[FLD_PORT];
		port_params[nb_port_params].num_queues =
			(uint8_t)int_fld[FLD_NUM_QUEUES];
		++nb_port_params;
	}
	return 0;
}

static int32_t
parse_portmask(const char *portmask)
{
	char *end = NULL;
	unsigned long pm;

	/* parse hexadecimal string */
	pm = strtoul(portmask, &end, 16);
	if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;

	if ((pm == 0) && errno)
		return -1;

	return pm;
}

static int32_t
parse_decimal(const char *str)
{
	char *end = NULL;
	unsigned long num;

	num = strtoul(str, &end, 10);
	if ((str[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;

	return num;
}

#define __STRNCMP(name, opt) (!strncmp(name, opt, sizeof(opt)))
static int32_t
parse_args_long_options(struct option *lgopts, int32_t option_index)
{
	int32_t ret = -1;
	const char *optname = lgopts[option_index].name;

	if (__STRNCMP(optname, OPTION_CONFIG)) {
		ret = parse_port_config(optarg);
		if (ret)
			printf("invalid config\n");
	}

	if (__STRNCMP(optname, OPTION_SINGLE_SA)) {
		ret = parse_decimal(optarg);
		if (ret != -1) {
			single_sa = 1;
			single_sa_idx = ret;
			printf("Configured with single SA index %u\n",
					single_sa_idx);
			ret = 0;
		}
	}

	return ret;
}
#undef __STRNCMP

static int32_t
parse_args(int32_t argc, char **argv)
{
	int32_t opt, ret;
	char **argvopt;
	int32_t option_index;
	char *prgname = argv[0];
	static struct option lgopts[] = {
		{OPTION_CONFIG, 1, 0, 0},
		{OPTION_SINGLE_SA, 1, 0, 0},
		{NULL, 0, 0, 0}
	};
	int32_t f_present = 0;

	argvopt = argv;

	while ((opt = getopt_long(argc, argvopt, "p:Pu:f:j:e:a:l:m:",
				lgopts, &option_index)) != EOF) {

		switch (opt) {
		case 'p':
			enabled_port_mask = parse_portmask(optarg);
			if (enabled_port_mask == 0) {
				printf("invalid portmask\n");
				print_usage(prgname);
				return -1;
			}
			break;
		case 'P':
			printf("Promiscuous mode selected\n");
			promiscuous_on = 1;
			break;
		case 'm':
			sched_type = (uint8_t)atoi(optarg);
			if (sched_type != RTE_SCHED_TYPE_ORDERED &&
			    sched_type != RTE_SCHED_TYPE_ATOMIC &&
			    sched_type != RTE_SCHED_TYPE_PARALLEL) {
				printf("invalid mode\n");
				print_usage(prgname);
				return -1;
			}
			break;
		case 'f':
			if (f_present == 1) {
				printf("\"-f\" option present more than "
					"once!\n");
				print_usage(prgname);
				return -1;
			}
			if (parse_cfg_file(optarg) < 0) {
				printf("parsing file \"%s\" failed\n",
					optarg);
				print_usage(prgname);
				return -1;
			}
			f_present = 1;
			break;
		case 'j':
			{
				int32_t size = parse_decimal(optarg);
				if (size <= 1518) {
					printf("Invalid jumbo frame size\n");
					if (size < 0) {
						print_usage(prgname);
						return -1;
					}
					printf("Using default value 9000\n");
					frame_size = 9000;
				} else {
					frame_size = size;
				}
			}
			printf("Enabled jumbo frames size %u\n", frame_size);
			break;
		case 0:
			if (parse_args_long_options(lgopts, option_index)) {
				print_usage(prgname);
				return -1;
			}
			break;
		default:
			print_usage(prgname);
			return -1;
		}
	}

	if (f_present == 0) {
		printf("Mandatory option \"-f\" not present\n");
		return -1;
	}

	if (optind >= 0)
		argv[optind-1] = prgname;

	ret = optind-1;
	optind = 1; /* reset getopt lib */
	return ret;
}

static int
eventdev_eth_configure(void)
{
	struct rte_event_port_conf adapter_port_config = {0};
	struct rte_event_eth_rx_adapter_queue_conf queue_conf = {0};
	uint8_t queue_id = 0, queue_prio = 0;
	int ret, i, j;

	ret = rte_event_eth_rx_adapter_create(adapter_id, eventdev_id,
					      &adapter_port_config);
	if (ret < 0)
		rte_exit(EXIT_FAILURE,
			"rte_event_eth_rx_adapter_create: err=%d\n", ret);

	queue_conf.rx_queue_flags =
				RTE_EVENT_ETH_RX_ADAPTER_QUEUE_FLOW_ID_VALID;

	for (i = 0; i < nb_port_params; i++) {
		for (j = 0; j < port_params[i].num_queues; j++) {
			queue_conf.ev.queue_id = queue_id;
			queue_conf.ev.priority = queue_prio;
			queue_conf.ev.flow_id = port_params[i].port_id;
			queue_conf.ev.sched_type = sched_type;

			ret = rte_event_eth_rx_adapter_queue_add(adapter_id,
					port_params[i].port_id,
					j, &queue_conf);
			if (ret < 0)
				rte_exit(EXIT_FAILURE,
					"rte_event_eth_rx_adapter_queue_add: err=%d\n",
					ret);
		}
	}

	return 0;
}

static int
eventdev_crypto_configure(void)
{
	struct rte_event_crypto_queue_pair_conf queue_conf = {0};
	struct rte_event_port_conf adapter_port_config = {0};
	struct cdev_qp_index *cdev_qp;
	uint8_t queue_id = 0, queue_prio = 0;
	int ret, i;

	ret = rte_event_crypto_adapter_create(adapter_id, eventdev_id,
					      &adapter_port_config);
	if (ret < 0)
		rte_exit(EXIT_FAILURE,
			"rte_event_crypto_adapter_create: err=%d\n", ret);

	for (i = 0; i < cdev_qp_list.num; i++) {
		cdev_qp = &cdev_qp_list.cdev_qp[i];
		queue_conf.type = RTE_EVENT_CRYPTO_CONF_TYPE_EVENT;
		queue_conf.ev.flow_id = cdev_qp->cdev_id;
		queue_conf.ev.sched_type = sched_type;
		queue_conf.ev.event_type = RTE_EVENT_TYPE_CRYPTODEV;
		queue_conf.ev.priority = queue_prio;
		queue_conf.ev.queue_id = queue_id;

		ret = rte_event_crypto_adapter_queue_pair_add(adapter_id,
				cdev_qp->cdev_id, cdev_qp->queue_id,
				&queue_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				"rte_event_crypto_adapter_queue_pair_add: err=%d\n",
				ret);
	}

	return 0;
}

static int
eventdev_configure(void)
{
	struct rte_event_dev_config eventdev_conf = {0};
	struct rte_event_dev_info eventdev_def_conf = {0};
	struct rte_event_queue_conf eventq_conf = {0};
	uint8_t queue_id = 0;
	uint32_t i;
	int ret;

	/* get default values of eventdev*/
	ret = rte_event_dev_info_get(eventdev_id, &eventdev_def_conf);
	if (ret < 0)
		rte_exit(EXIT_FAILURE,
			"rte_event_dev_info_get: err=%d\n", ret);

	eventdev_conf.nb_events_limit = -1;
	eventdev_conf.nb_event_queues = 1;
	eventdev_conf.nb_event_ports = nb_lcores;
	eventdev_conf.nb_event_queue_flows =
			eventdev_def_conf.max_event_queue_flows;
	eventdev_conf.nb_event_port_dequeue_depth =
			eventdev_def_conf.max_event_port_dequeue_depth;
	eventdev_conf.nb_event_port_enqueue_depth =
			eventdev_def_conf.max_event_port_enqueue_depth;

	ret = rte_event_dev_configure(eventdev_id, &eventdev_conf);
	if (ret < 0)
		rte_exit(EXIT_FAILURE,
			"rte_event_dev_configure: err=%d\n", ret);

// TODO: Pass correct parameters for ordered/atomic/parallel
	eventq_conf.nb_atomic_order_sequences = 2048;
	eventq_conf.nb_atomic_flows = 1;
	eventq_conf.schedule_type = sched_type;
	ret = rte_event_queue_setup(eventdev_id, queue_id, &eventq_conf);
	if (ret < 0)
		rte_exit(EXIT_FAILURE,
			"rte_event_queue_setup: err=%d\n", ret);

	for (i = 0; i < nb_lcores; i++) {
		ret = rte_event_port_setup(eventdev_id, i, NULL);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				"rte_event_port_setup: err=%d\n", ret);
	}

	for (i = 0; i < nb_lcores; i++) {
		rte_event_port_link(eventdev_id, i, &queue_id, NULL, 1);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				"rte_event_port_link: err=%d\n", ret);
	}

	eventdev_eth_configure();

	eventdev_crypto_configure();

	ret = rte_event_dev_start(eventdev_id);
	if (ret < 0)
		rte_exit(EXIT_FAILURE,
			"rte_event_dev_start: err=%d\n", ret);

	return 0;
}

static void
print_ethaddr(const char *name, const struct ether_addr *eth_addr)
{
	char buf[ETHER_ADDR_FMT_SIZE];
	ether_format_addr(buf, ETHER_ADDR_FMT_SIZE, eth_addr);
	printf("%s%s", name, buf);
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(uint16_t port_num, uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
	uint16_t portid;
	uint8_t count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;

	printf("\nChecking link status");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		all_ports_up = 1;
		for (portid = 0; portid < port_num; portid++) {
			if ((port_mask & (1 << portid)) == 0)
				continue;
			memset(&link, 0, sizeof(link));
			rte_eth_link_get_nowait(portid, &link);
			/* print link status if flag set */
			if (print_flag == 1) {
				if (link.link_status)
					printf(
					"Port%d Link Up - speed %u Mbps -%s\n",
						portid, link.link_speed,
				(link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
					("full-duplex") : ("half-duplex\n"));
				else
					printf("Port %d Link Down\n", portid);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == ETH_LINK_DOWN) {
				all_ports_up = 0;
				break;
			}
		}
		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
			printf(".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			printf("done\n");
		}
	}
}

static int32_t
cryptodevs_init(void)
{
	struct rte_cryptodev_config dev_conf;
	struct rte_cryptodev_qp_conf qp_conf;
	struct cdev_qp_index *cdev_qp;
	uint32_t max_sess_sz = 0, sess_sz;
	int16_t cdev_id;
	uint16_t qp;

	pthread_mutex_init(&sa_lock, NULL);
	cdev_qp_list.last_used = -1;

	for (cdev_id = 0; cdev_id < rte_cryptodev_count(); cdev_id++) {
		sess_sz = rte_cryptodev_get_private_session_size(cdev_id);
		if (sess_sz > max_sess_sz)
			max_sess_sz = sess_sz;
	}

	for (cdev_id = 0; cdev_id < rte_cryptodev_count(); cdev_id++) {
		struct rte_cryptodev_info cdev_info;

		rte_cryptodev_info_get(cdev_id, &cdev_info);

		dev_conf.socket_id = rte_cryptodev_socket_id(cdev_id);
		dev_conf.nb_queue_pairs = cdev_info.max_nb_queue_pairs;

		if (!socket_ctx[dev_conf.socket_id].session_pool) {
			char mp_name[RTE_MEMPOOL_NAMESIZE];
			struct rte_mempool *sess_mp;

			snprintf(mp_name, RTE_MEMPOOL_NAMESIZE,
					"sess_mp_%u", dev_conf.socket_id);
			sess_mp = rte_mempool_create(mp_name,
					CDEV_MP_NB_OBJS,
					max_sess_sz,
					CDEV_MP_CACHE_SZ,
					0, NULL, NULL, NULL,
					NULL, dev_conf.socket_id,
					0);
			if (sess_mp == NULL)
				rte_exit(EXIT_FAILURE,
					"Cannot create session pool on socket %d\n",
					dev_conf.socket_id);
			else
				printf("Allocated session pool on socket %d\n",
					dev_conf.socket_id);
			socket_ctx[dev_conf.socket_id].session_pool = sess_mp;
		}

		if (rte_cryptodev_configure(cdev_id, &dev_conf))
			rte_panic("Failed to initialize cryptodev %u\n",
					cdev_id);

		qp_conf.nb_descriptors = CDEV_QUEUE_DESC;
		for (qp = 0; qp < dev_conf.nb_queue_pairs; qp++) {
			if (rte_cryptodev_queue_pair_setup(cdev_id, qp,
					&qp_conf, dev_conf.socket_id,
					socket_ctx[dev_conf.socket_id].session_pool))
				rte_panic("Failed to setup queue %u for "
						"cdev_id %u\n",	0, cdev_id);

			cdev_qp = &cdev_qp_list.cdev_qp[cdev_qp_list.num];
			cdev_qp->id = cdev_qp_list.num++;
			cdev_qp->cdev_id = cdev_id;
			cdev_qp->queue_id = qp;
		}
	}

	printf("\n");

	return 0;
}

static void
port_init(uint16_t portid)
{
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf *txconf;
	uint16_t nb_tx_queue, nb_rx_queue;
	uint16_t tx_queueid, rx_queueid;
	int32_t ret;
	struct ether_addr ethaddr;

	rte_eth_dev_info_get(portid, &dev_info);

	printf("Configuring device port %u:\n", portid);

	rte_eth_macaddr_get(portid, &ethaddr);
	ethaddr_tbl[portid].src = ETHADDR_TO_UINT64(ethaddr);
	print_ethaddr("Address: ", &ethaddr);
	printf("\n");

	nb_rx_queue = get_port_nb_rx_queues(portid);
// TODO: For parallel queues set nb_tx_queue to nb_lcores??
	nb_tx_queue = 1;

	if (nb_rx_queue > dev_info.max_rx_queues)
		rte_exit(EXIT_FAILURE, "Error: queue %u not available "
				"(max rx queue is %u)\n",
				nb_rx_queue, dev_info.max_rx_queues);

	if (nb_tx_queue > dev_info.max_tx_queues)
		rte_exit(EXIT_FAILURE, "Error: queue %u not available "
				"(max tx queue is %u)\n",
				nb_tx_queue, dev_info.max_tx_queues);

	printf("Creating queues: nb_rx_queue=%d nb_tx_queue=%u...\n",
			nb_rx_queue, nb_tx_queue);

	if (frame_size) {
		port_conf.rxmode.max_rx_pkt_len = frame_size;
		port_conf.rxmode.offloads |= DEV_RX_OFFLOAD_JUMBO_FRAME;
	}

	if (dev_info.rx_offload_capa & DEV_RX_OFFLOAD_SECURITY)
		port_conf.rxmode.offloads |= DEV_RX_OFFLOAD_SECURITY;
	if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_SECURITY)
		port_conf.txmode.offloads |= DEV_TX_OFFLOAD_SECURITY;

	ret = rte_eth_dev_configure(portid, nb_rx_queue, nb_tx_queue,
			&port_conf);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Cannot configure device: "
				"err=%d, port=%d\n", ret, portid);

	ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd, &nb_txd);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Cannot adjust number of descriptors: "
				"err=%d, port=%d\n", ret, portid);

	/* init one TX queue per lcore */
	tx_queueid = 0;
	for (tx_queueid = 0; tx_queueid < nb_tx_queue; tx_queueid++) {
		/* init TX queue */
		printf("Setup txq=%d\n", tx_queueid);

		txconf = &dev_info.default_txconf;
		txconf->txq_flags = 0;

		ret = rte_eth_tx_queue_setup(portid, tx_queueid, nb_txd,
				DEFAULT_SOCKET_ID, txconf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup: "
					"err=%d, port=%d\n", ret, portid);
	}


	/* init RX queues */
	for (rx_queueid = 0; rx_queueid < nb_rx_queue; rx_queueid++) {
		printf("Setup rxq=%d\n", rx_queueid);

		ret = rte_eth_rx_queue_setup(portid, rx_queueid,
				nb_rxd,	DEFAULT_SOCKET_ID, NULL,
				socket_ctx[DEFAULT_SOCKET_ID].mbuf_pool);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				"rte_eth_rx_queue_setup: err=%d, "
				"port=%d\n", ret, portid);
	}
	printf("\n");
}

static void
pool_init(struct socket_ctx *ctx, int32_t socket_id, uint32_t nb_mbuf)
{
	char s[64];
	uint32_t buff_size = frame_size ? (frame_size + RTE_PKTMBUF_HEADROOM) :
			RTE_MBUF_DEFAULT_BUF_SIZE;


	snprintf(s, sizeof(s), "mbuf_pool_%d", socket_id);
	ctx->mbuf_pool = rte_pktmbuf_pool_create(s, nb_mbuf,
			MEMPOOL_CACHE_SIZE, ipsec_metadata_size(),
			buff_size,
			socket_id);
	if (ctx->mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool on socket %d\n",
				socket_id);
	else
		printf("Allocated mbuf pool on socket %d\n", socket_id);
}

int32_t
main(int32_t argc, char **argv)
{
	int32_t ret;
	uint32_t lcore_id;
	uint8_t socket_id;
	uint16_t portid, nb_ports;
	int16_t cdev_id;

	/* init EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL parameters\n");
	argc -= ret;
	argv += ret;

	/* parse application arguments (after the EAL ones) */
	ret = parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid parameters\n");

	nb_ports = rte_eth_dev_count();
	nb_lcores = rte_lcore_count();

	/* Replicate each context per socket */
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;

		if (numa_on)
			socket_id = (uint8_t)rte_lcore_to_socket_id(lcore_id);
		else
			socket_id = 0;

		if (socket_ctx[socket_id].mbuf_pool)
			continue;

		sa_init(&socket_ctx[socket_id], socket_id);

		sp4_init(&socket_ctx[socket_id], socket_id);

		sp6_init(&socket_ctx[socket_id], socket_id);

		rt_init(&socket_ctx[socket_id], socket_id);

		pool_init(&socket_ctx[socket_id], socket_id, NB_MBUF);
	}

	for (portid = 0; portid < nb_ports; portid++) {
		if ((enabled_port_mask & (1 << portid)) == 0)
			continue;

		port_init(portid);
	}

	eventdev_id = rte_event_dev_get_dev_id("event_dpaa2");
	if (eventdev_id < 0)
		eventdev_id = rte_event_dev_get_dev_id("event_dpaa");
	if (eventdev_id < 0)
		rte_exit(EXIT_FAILURE, "No event device found");

	cryptodevs_init();

	ret = eventdev_configure();
	if (ret < 0)
		rte_exit(EXIT_FAILURE,
			"eventdev_configure: err=%d\n", ret);

	/* start ports */
	for (portid = 0; portid < nb_ports; portid++) {
		if ((enabled_port_mask & (1 << portid)) == 0)
			continue;

		/* Start device */
		ret = rte_eth_dev_start(portid);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_dev_start: "
					"err=%d, port=%d\n", ret, portid);
		/*
		 * If enabled, put device in promiscuous mode.
		 * This allows IO forwarding mode to forward packets
		 * to itself through 2 cross-connected  ports of the
		 * target machine.
		 */
		if (promiscuous_on)
			rte_eth_promiscuous_enable(portid);
	}

	for (cdev_id = 0; cdev_id < rte_cryptodev_count(); cdev_id++) {
		if (rte_cryptodev_start(cdev_id))
			rte_panic("Failed to start cryptodev %u\n",
					cdev_id);
	}

	check_all_ports_link_status(nb_ports, enabled_port_mask);

	rte_eal_mp_remote_launch(main_loop, NULL, CALL_MASTER);

	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0)
			return -1;
	}

	return 0;
}
