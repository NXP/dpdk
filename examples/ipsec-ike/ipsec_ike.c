/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2016 Intel Corporation
 * Copyright 2023 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>
#include <unistd.h>

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
#include <rte_cryptodev.h>
#include <rte_security.h>
#include <rte_ip.h>
#include <rte_ip_frag.h>
#include <rte_arp.h>
#include <rte_tm.h>

#include "ipsec_ike.h"
#include "xfrm_km.h"

static char s_dump_flow_prefix[sizeof("IPSEC_IKE: ") - 1];
#define DUMP_FLOW_PREFIX s_dump_flow_prefix
#define DUMP_FLOW_BUF_SIZE 2048

#define MEMPOOL_CACHE_SIZE 256

#define NB_MBUF	(32000)

#define CDEV_QUEUE_DESC 2048
#define CDEV_MP_NB_OBJS 1024
#define CDEV_MP_CACHE_SZ 64

#define CDEV_DEFAULT_ID 0
#define CDEV_DEFAULT_QP 1

static uint8_t s_cdev_id = CDEV_DEFAULT_ID;
static uint16_t s_cdev_qp = CDEV_DEFAULT_QP;

/*
 * Configurable number of RX/TX ring descriptors
 */
static uint16_t s_nb_rxd = 128;
static uint16_t s_nb_txd = 128;

#define MTU_TO_FRAMELEN(x)	\
	((x) + RTE_ETHER_HDR_LEN + RTE_ETHER_CRC_LEN)

#define M_NUM (1024 * 1024)
#define G_NUM (1024 * M_NUM)

static char *s_sec_port_nm;
static char *s_tap_port_nm;

static uint16_t s_sec_port_id = RTE_MAX_ETHPORTS;
static uint16_t s_tap_port_id = RTE_MAX_ETHPORTS;

static int s_icmp_reply = 1;
static int s_frame_dump;
static int s_perf_log = 1;
static int s_static_sa_sp;

static uint8_t s_tap_ethaddr[RTE_ETHER_ADDR_LEN] = {
	0x92, 0xc7, 0x31, 0xe0, 0x0e, 0x19
};

#define CMD_LINE_OPT_SEC_PORT	"sec_port"
#define CMD_LINE_OPT_TAP_PORT	"tap_port"
#define CMD_LINE_OPT_ICMP_REPLY "icmp_reply"
#define CMD_LINE_OPT_FRAME_DUMP "frame_dump"
#define CMD_LINE_OPT_PERF_LOG "perf_log"
#define CMD_LINE_OPT_STATIC_POL "static_pol"

enum {
	/* long options mapped to a short option */

	/* first long only option value must be >= 256, so that we won't
	 * conflict with short options
	 */
	CMD_LINE_OPT_MIN_NUM = 256,
	CMD_LINE_OPT_SEC_PORT_NUM,
	CMD_LINE_OPT_TAP_PORT_NUM,
	CMD_LINE_OPT_ICMP_REPLY_NUM,
	CMD_LINE_OPT_FRAME_DUMP_NUM,
	CMD_LINE_OPT_PERF_LOG_NUM,
	CMD_LINE_OPT_STATIC_POL_NUM
};

static const char s_short_options[] =
	"h"  /* help */
	;

static const struct option s_lgopts[] = {
	{CMD_LINE_OPT_SEC_PORT, 1, 0, CMD_LINE_OPT_SEC_PORT_NUM},
	{CMD_LINE_OPT_TAP_PORT, 1, 0, CMD_LINE_OPT_TAP_PORT_NUM},
	{CMD_LINE_OPT_ICMP_REPLY, 0, 0, CMD_LINE_OPT_ICMP_REPLY_NUM},
	{CMD_LINE_OPT_FRAME_DUMP, 0, 0, CMD_LINE_OPT_FRAME_DUMP_NUM},
	{CMD_LINE_OPT_PERF_LOG, 1, 0, CMD_LINE_OPT_PERF_LOG_NUM},
	{CMD_LINE_OPT_STATIC_POL, 0, 0, CMD_LINE_OPT_STATIC_POL_NUM},
	{NULL, 0, 0, 0}
};

/*
 * RX/TX HW offload capabilities to enable/use on ethernet ports.
 * By default all capabilities are enabled.
 */
static uint64_t dev_rx_offload = UINT64_MAX;
static uint64_t dev_tx_offload = UINT64_MAX;

static uint64_t s_inbound_bytes;
static uint64_t s_outbound_bytes;
static uint64_t s_inbound_frames;
static uint64_t s_outbound_frames;
static uint64_t s_rx_frames;
static uint64_t s_tx_frames;
static uint64_t s_rx_overhead_bytes;
static uint64_t s_tx_overhead_bytes;

static struct ipsec_ike_mem_ctx s_mem_ctx;

static const struct rte_eth_conf s_port_conf = {
	.rxmode = {
		.mq_mode = RTE_ETH_MQ_RX_RSS,
		.max_lro_pkt_size = RTE_ETHER_MAX_LEN,
		.offloads = RTE_ETH_RX_OFFLOAD_CHECKSUM,
	},
	.rx_adv_conf = {
		.rss_conf = {
			.rss_key = NULL,
			.rss_hf = RTE_ETH_RSS_IP | RTE_ETH_RSS_UDP |
				RTE_ETH_RSS_TCP | RTE_ETH_RSS_SCTP,
		},
	},
	.txmode = {
		.mq_mode = RTE_ETH_MQ_TX_NONE,
	},
};

#define IPSEC_ETH_QP_MAX_NB 16
static uint16_t s_eth_qp_nb = (IPSEC_ETH_QP_MAX_NB / 4);

static struct ipsec_ike_cntx s_ipsec_ike_cntx;

struct ipsec_ike_cntx *
ipsec_ike_get_cntx(void)
{
	return &s_ipsec_ike_cntx;
}

static inline void
ipsec_ike_single_sa_out_lookup(struct rte_mbuf *pkt,
	void **sa_ret)
{
	struct rte_ipv4_hdr *ipv4_hdr = NULL;
	struct rte_ipv6_hdr *ipv6_hdr = NULL;
	union ipsec_ike_addr src, dst;
	struct ipsec_ike_sa_entry *sa = NULL;

	*sa_ret = NULL;

	if (pkt->packet_type & RTE_PTYPE_L3_IPV4) {
		ipv4_hdr = rte_pktmbuf_mtod(pkt, struct rte_ipv4_hdr *);
		rte_memcpy(src.ip4, &ipv4_hdr->src_addr, sizeof(rte_be32_t));
		rte_memcpy(dst.ip4, &ipv4_hdr->dst_addr, sizeof(rte_be32_t));
	} else if (pkt->packet_type & RTE_PTYPE_L3_IPV6) {
		ipv6_hdr = rte_pktmbuf_mtod(pkt, struct rte_ipv6_hdr *);
		rte_memcpy(src.ip6, ipv6_hdr->src_addr, 16);
		rte_memcpy(dst.ip6, ipv6_hdr->dst_addr, 16);
	} else {
		RTE_LOG(ERR, IPSEC_IKE, "Invalid mbuf packet type(%08x)\n",
			pkt->packet_type);
		return;
	}

	/**Lookup outbound SP to get associated SA.*/
	sa = xfm_sp_entry_lookup_sa(&src, &dst, INVALID_SPI,
			ipv4_hdr ? AF_INET : AF_INET6, 0, -1);
	if (!sa)
		return;

	*sa_ret = sa;
}

static inline void
ipsec_ike_single_sa_in_lookup(struct rte_mbuf *pkt,
	void **sa_ret)
{
	struct rte_esp_hdr *esp;
	struct rte_ipv4_hdr *ipv4_hdr = NULL;
	struct rte_ipv6_hdr *ipv6_hdr = NULL;
	union ipsec_ike_addr src, dst;
	struct ipsec_ike_sa_entry *sa = NULL;

	*sa_ret = NULL;

	if (pkt->packet_type & RTE_PTYPE_L3_IPV4) {
		ipv4_hdr = rte_pktmbuf_mtod(pkt, struct rte_ipv4_hdr *);
		rte_memcpy(src.ip4, &ipv4_hdr->src_addr, sizeof(rte_be32_t));
		rte_memcpy(dst.ip4, &ipv4_hdr->dst_addr, sizeof(rte_be32_t));
	} else if (pkt->packet_type & RTE_PTYPE_L3_IPV6) {
		ipv6_hdr = rte_pktmbuf_mtod(pkt, struct rte_ipv6_hdr *);
		rte_memcpy(src.ip6, ipv6_hdr->src_addr, 16);
		rte_memcpy(dst.ip6, ipv6_hdr->dst_addr, 16);
	} else {
		RTE_LOG(ERR, IPSEC_IKE, "Invalid mbuf packet type(%08x)\n",
			pkt->packet_type);
		return;
	}

	esp = rte_pktmbuf_mtod_offset(pkt, struct rte_esp_hdr *, pkt->l3_len);

	if (esp->spi == INVALID_SPI)
		return;

	/**Lookup inbound SP to get associated SA.*/
	sa = xfm_sp_entry_lookup_sa(&src, &dst, esp->spi,
			ipv4_hdr ? AF_INET : AF_INET6, 1, -1);
	if (!sa)
		return;

	*sa_ret = sa;
}

static void
ipsec_ike_sa_in_lookup(struct rte_mbuf *pkts[],
	void *sa[], uint16_t nb_pkts)
{
	uint32_t i;

	for (i = 0; i < nb_pkts; i++)
		ipsec_ike_single_sa_in_lookup(pkts[i], &sa[i]);
}

static void
ipsec_ike_sa_out_lookup(struct rte_mbuf *pkts[],
	void *sa[], uint16_t nb_pkts)
{
	uint32_t i;

	for (i = 0; i < nb_pkts; i++)
		ipsec_ike_single_sa_out_lookup(pkts[i], &sa[i]);
}

uint16_t
ipsec_ike_max_queue_pair(void)
{
	return s_eth_qp_nb;
}

int
ipsec_ike_static_sa_sp_enabled(void)
{
	return s_static_sa_sp;
}

static void
dump_arp_info(struct rte_mbuf *pkt, int from_tap)
{
	const struct rte_ether_hdr *eth;
	const struct rte_arp_hdr *arp;
	const char *dir_type = from_tap ? "Tap" : "Sec";
	char log_buf[DUMP_FLOW_BUF_SIZE];
	uint8_t sender[sizeof(rte_be32_t)], target[sizeof(rte_be32_t)];
	uint16_t log_offset = 0;

	eth = rte_pktmbuf_mtod(pkt, const struct rte_ether_hdr *);

	log_offset += sprintf(&log_buf[log_offset],
		"%s eth src/dst:%02x:%02x:%02x:%02x:%02x:%02x",
		dir_type,
		eth->src_addr.addr_bytes[0], eth->src_addr.addr_bytes[1],
		eth->src_addr.addr_bytes[2], eth->src_addr.addr_bytes[3],
		eth->src_addr.addr_bytes[4], eth->src_addr.addr_bytes[5]);
	log_offset += sprintf(&log_buf[log_offset],
		"/%02x:%02x:%02x:%02x:%02x:%02x",
		eth->dst_addr.addr_bytes[0], eth->dst_addr.addr_bytes[1],
		eth->dst_addr.addr_bytes[2], eth->dst_addr.addr_bytes[3],
		eth->dst_addr.addr_bytes[4], eth->dst_addr.addr_bytes[5]);

	if (eth->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {
		log_offset += sprintf(&log_buf[log_offset],
			" ethtype(%04x)\n",
			rte_be_to_cpu_16(eth->ether_type));
	} else {
		arp = (const void *)(eth + 1);
		rte_memcpy(sender, &arp->arp_data.arp_sip, sizeof(rte_be32_t));
		rte_memcpy(target, &arp->arp_data.arp_tip, sizeof(rte_be32_t));
		log_offset += sprintf(&log_buf[log_offset], " ARP\n");
		log_offset += sprintf(&log_buf[log_offset],
			"%sopcode(%d) sender:%d.%d.%d.%d, target:%d.%d.%d.%d\n",
			DUMP_FLOW_PREFIX, arp->arp_opcode,
			sender[0], sender[1], sender[2], sender[3],
			target[0], target[1], target[2], target[3]);
	}

	RTE_LOG(INFO, IPSEC_IKE, "%s", log_buf);
}

static void
dump_pkt_info(struct rte_mbuf *pkt, int is_crypted,
	int is_inbound, int has_eth, int from_tap)
{
	const struct rte_ether_hdr *eth;
	const struct rte_ipv4_hdr *iph4;
	const struct rte_esp_hdr *esp;
	char log_buf[DUMP_FLOW_BUF_SIZE];
	uint8_t src[sizeof(rte_be32_t)], dst[sizeof(rte_be32_t)];
	uint16_t log_offset = 0;
	const char *crypt_type = "crypt";
	const char *ip_type = "Tunnel ";
	const char *dir_type = "Inbound";
	struct ipsec_ike_priv *priv;

	if (!s_frame_dump)
		return;

	priv = rte_mbuf_to_priv(pkt);

	if (has_eth)
		eth = rte_pktmbuf_mtod(pkt, const struct rte_ether_hdr *);
	else
		eth = (const void *)priv->cntx;

	/** IPv4 support only.*/
	if (eth->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
		dump_arp_info(pkt, from_tap);
		return;
	}

	if (has_eth)
		iph4 = (const void *)(eth + 1);
	else
		iph4 = rte_pktmbuf_mtod(pkt, const void *);

	if (is_crypted && iph4->next_proto_id != IPPROTO_ESP)
		return;

	if (!is_crypted) {
		crypt_type = "plain";
		if (from_tap)
			ip_type = "";
		else
			ip_type = "Inner ";
	}

	if (from_tap)
		dir_type = "Tap";
	else if (is_inbound)
		dir_type = "Inbound";
	else
		dir_type = "Outbound";

	log_offset += sprintf(&log_buf[log_offset],
		"%s %s eth src/dst:%02x:%02x:%02x:%02x:%02x:%02x",
		dir_type, crypt_type,
		eth->src_addr.addr_bytes[0], eth->src_addr.addr_bytes[1],
		eth->src_addr.addr_bytes[2], eth->src_addr.addr_bytes[3],
		eth->src_addr.addr_bytes[4], eth->src_addr.addr_bytes[5]);
	log_offset += sprintf(&log_buf[log_offset],
		"/%02x:%02x:%02x:%02x:%02x:%02x\n",
		eth->dst_addr.addr_bytes[0], eth->dst_addr.addr_bytes[1],
		eth->dst_addr.addr_bytes[2], eth->dst_addr.addr_bytes[3],
		eth->dst_addr.addr_bytes[4], eth->dst_addr.addr_bytes[5]);
	rte_memcpy(src, &iph4->src_addr, sizeof(rte_be32_t));
	rte_memcpy(dst, &iph4->dst_addr, sizeof(rte_be32_t));
	log_offset += sprintf(&log_buf[log_offset],
		"%s%sIPv4 src/dst:%d.%d.%d.%d/%d.%d.%d.%d",
		DUMP_FLOW_PREFIX, ip_type,
		src[0], src[1], src[2], src[3],
		dst[0], dst[1], dst[2], dst[3]);
	if (is_crypted) {
		if (iph4->next_proto_id != IPPROTO_ESP) {
			log_offset += sprintf(&log_buf[log_offset],
				"\n%s ERROR Tunnel protocal(%d)\n",
				DUMP_FLOW_PREFIX,
				iph4->next_proto_id);
		} else {
			esp = (const void *)(iph4 + 1);
			log_offset += sprintf(&log_buf[log_offset],
				"\n%sESP SPI:0x%08x, SEQ:0x%08x\n",
				DUMP_FLOW_PREFIX,
				rte_be_to_cpu_32(esp->spi),
				rte_be_to_cpu_32(esp->seq));
		}
	} else {
		log_offset += sprintf(&log_buf[log_offset],
			" next proto: %s(%d), len:%d\n",
			ip_next_prot_name(iph4->next_proto_id),
			iph4->next_proto_id,
			rte_be_to_cpu_16(iph4->total_length));
	}
	RTE_LOG(INFO, IPSEC_IKE, "%s", log_buf);
}

static inline void
adjust_inbound_ipv4_pktlen(struct rte_mbuf *m,
	const struct rte_ipv4_hdr *iph, uint32_t l2_len)
{
	uint32_t plen, trim;

	plen = rte_be_to_cpu_16(iph->total_length) + l2_len;
	if (plen < m->pkt_len) {
		trim = m->pkt_len - plen;
		rte_pktmbuf_trim(m, trim);
	}
}

static void
adjust_inbound_ipv4(struct rte_mbuf *pkt)
{
	const struct rte_ether_hdr *eth;
	const struct rte_ipv4_hdr *iph4;
	struct ipsec_ike_priv *priv;

	eth = rte_pktmbuf_mtod(pkt, const struct rte_ether_hdr *);
	priv = rte_mbuf_to_priv(pkt);
	if (s_icmp_reply)
		rte_memcpy(priv->cntx, eth, sizeof(struct rte_ether_hdr));

	iph4 = (void *)rte_pktmbuf_adj(pkt, RTE_ETHER_HDR_LEN);
	adjust_inbound_ipv4_pktlen(pkt, iph4, 0);

	pkt->l2_len = 0;
	pkt->l3_len = sizeof(*iph4);
}

static inline void
prepare_inbound_one_packet(struct rte_mbuf *pkt,
	int *is_esp, uint16_t q_idx)
{
	const struct rte_ether_hdr *eth;
	const struct rte_ipv4_hdr *iph4;
	uint16_t tx_nb;

	dump_pkt_info(pkt, 0, 1, 1, 0);

	eth = rte_pktmbuf_mtod(pkt, const struct rte_ether_hdr *);
	if (eth->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
		iph4 = (const void *)(eth + 1);
		if (iph4->next_proto_id != IPPROTO_ESP) {
			tx_nb = 0;
			if (s_tap_port_id != RTE_MAX_ETHPORTS) {
				tx_nb = rte_eth_tx_burst(s_tap_port_id,
						q_idx, &pkt, 1);
			}
			if (!tx_nb)
				rte_pktmbuf_free(pkt);

			if (is_esp)
				*is_esp = 0;
			return;
		}
		s_rx_overhead_bytes += pkt->pkt_len +
			RTE_TM_ETH_FRAMING_OVERHEAD_FCS;
		s_rx_frames++;

		adjust_inbound_ipv4(pkt);
		if (is_esp)
			*is_esp = 1;
	} else {
		tx_nb = 0;
		if (s_tap_port_id != RTE_MAX_ETHPORTS)
			tx_nb = rte_eth_tx_burst(s_tap_port_id, q_idx, &pkt, 1);

		if (!tx_nb)
			rte_pktmbuf_free(pkt);
		if (is_esp)
			*is_esp = 0;
	}
}

static inline void
prepare_inbound_traffic(struct rte_mbuf **pkts,
	uint16_t nb_pkts, int is_esp[], uint16_t q_idx)
{
	int32_t i;

	for (i = 0; i < nb_pkts; i++)
		prepare_inbound_one_packet(pkts[i], &is_esp[i], q_idx);
}

static void
enqueue_cop_burst(struct rte_crypto_op **cop,
	uint16_t qp, uint16_t nb)
{
	uint32_t ret, i;

	ret = rte_cryptodev_enqueue_burst(s_cdev_id, qp, cop, nb);
	if (ret != nb) {
		RTE_LOG(ERR, IPSEC_IKE, "EQ invalid return:%d\n",
			ret);
		/* drop packets that we fail to enqueue */
		for (i = ret; i < nb; i++)
			rte_pktmbuf_free(cop[i]->sym->m_src);
	}
}

static inline void
ipsec_ike_sa_enqueue(struct rte_mbuf *pkts[],
	void *sas, uint16_t nb_pkts, uint16_t qp)
{
	int i;
	struct ipsec_ike_priv *priv;
	struct ipsec_ike_sa_entry *sa = sas;
	struct rte_ipsec_session *ips = ipsec_ike_sa_2_session(sa);
	struct rte_crypto_op *cops[nb_pkts];

	if (ips->type != RTE_SECURITY_ACTION_TYPE_LOOKASIDE_PROTOCOL) {
		RTE_LOG(ERR, IPSEC_IKE,
			"Type(%d) not support, Lookaside support only!\n",
				ips->type);
		rte_pktmbuf_free_bulk(pkts, nb_pkts);
		return;
	} else if (!ips->security.ses) {
		RTE_LOG(ERR, IPSEC_IKE,
			"Session has not been created!\n");
		rte_pktmbuf_free_bulk(pkts, nb_pkts);
		return;
	}

	for (i = 0; i < nb_pkts; i++) {
		priv = rte_mbuf_to_priv(pkts[i]);
		priv->sa = sa;

		priv->cop.type = RTE_CRYPTO_OP_TYPE_SYMMETRIC;
		priv->cop.status = RTE_CRYPTO_OP_STATUS_NOT_PROCESSED;

		priv->sym_cop.m_src = pkts[i];

		rte_security_attach_session(&priv->cop, ips->security.ses);
		cops[i] = &priv->cop;
	}

	enqueue_cop_burst(cops, qp, nb_pkts);
}

static inline void
ipsec_ike_enqueue(struct rte_mbuf *pkts[],
	void *sas[], uint16_t nb_pkts, uint16_t qp)
{
	int i, j = 0;
	struct ipsec_ike_priv *priv;
	struct ipsec_ike_sa_entry *sa;
	struct rte_ipsec_session *ips;
	struct rte_crypto_op *ops[nb_pkts];

	for (i = 0; i < nb_pkts; i++) {
		if (unlikely(!sas[i])) {
			rte_pktmbuf_free(pkts[i]);
			continue;
		}

		priv = rte_mbuf_to_priv(pkts[i]);
		sa = sas[i];
		priv->sa = sa;
		ips = ipsec_ike_sa_2_session(sa);

		switch (ips->type) {
		case RTE_SECURITY_ACTION_TYPE_LOOKASIDE_PROTOCOL:
			priv->cop.type = RTE_CRYPTO_OP_TYPE_SYMMETRIC;
			priv->cop.status = RTE_CRYPTO_OP_STATUS_NOT_PROCESSED;

			if (!ips->security.ses) {
				RTE_LOG(ERR, IPSEC_IKE,
					"Session has not been created!\n");
				rte_pktmbuf_free(pkts[i]);
				continue;
			}

			priv->sym_cop.m_src = pkts[i];

			rte_security_attach_session(&priv->cop,
				ips->security.ses);
			break;
		default:
			RTE_LOG(ERR, IPSEC_IKE,
				"Invalid session action type(%d)\n",
				ips->type);
			rte_pktmbuf_free(pkts[i]);
			continue;
		}
		ops[j] = &priv->cop;
		j++;
	}

	enqueue_cop_burst(ops, qp, j);
}

static void
ipsec_ike_inbound(struct rte_mbuf *pkts[],
	uint16_t nb_pkts, uint16_t qp)
{
	void *saptr[nb_pkts];

	ipsec_ike_sa_in_lookup(pkts, saptr, nb_pkts);

	ipsec_ike_enqueue(pkts, saptr, nb_pkts, qp);
}

static void
ipsec_ike_outbound(struct rte_mbuf *pkts[],
	uint16_t nb_pkts, uint16_t qp)
{
	void *saptr[nb_pkts];

	ipsec_ike_sa_out_lookup(pkts, saptr, nb_pkts);

	ipsec_ike_enqueue(pkts, saptr, nb_pkts, qp);
}

static inline int
ipsec_ike_dequeue(struct rte_mbuf *pkts[], uint16_t max_pkts,
	uint16_t c_qp)
{
	int32_t nb_pkts = 0, j, nb_cops;
	struct ipsec_ike_priv *priv;
	struct rte_crypto_op *cops[max_pkts];
	struct ipsec_ike_sa_entry *sa;
	struct rte_mbuf *pkt;

	nb_cops = rte_cryptodev_dequeue_burst(s_cdev_id, c_qp,
		cops, max_pkts);

	for (j = 0; j < nb_cops; j++) {
		pkt = cops[j]->sym->m_src;

		priv = rte_mbuf_to_priv(pkt);
		sa = priv->sa;

		RTE_ASSERT(sa);

		if (ipsec_ike_sa_2_action(sa) ==
			RTE_SECURITY_ACTION_TYPE_LOOKASIDE_PROTOCOL) {
			if (cops[j]->status) {
				rte_pktmbuf_free(pkt);
				continue;
			}
		}
		pkts[nb_pkts++] = pkt;
	}

	/* return packets */
	return nb_pkts;
}

static inline void
ipsec_ike_handle_inbound_pkts(struct rte_mbuf **pkts,
	uint8_t nb_pkts, uint16_t eth_qp, uint16_t c_qp)
{
	int is_esp[nb_pkts], i, j = 0;
	struct rte_mbuf *pkts_prepared[nb_pkts];

	prepare_inbound_traffic(pkts, nb_pkts, is_esp, eth_qp);
	for (i = 0; i < nb_pkts; i++) {
		if (is_esp[i]) {
			pkts_prepared[j] = pkts[i];
			j++;
		}
	}

	ipsec_ike_inbound(pkts_prepared, j, c_qp);
}

static struct rte_mbuf *
single_icmp_reply(struct rte_mbuf *pkt)
{
	struct rte_ether_hdr *eth;
	struct rte_ipv4_hdr *iph4;
	struct rte_icmp_hdr *icmp;
	uint8_t ipv4addr[sizeof(rte_be32_t)];
	struct ipsec_ike_priv *priv = rte_mbuf_to_priv(pkt);

	eth = (void *)priv->cntx;
	if (eth->ether_type != rte_be_to_cpu_16(RTE_ETHER_TYPE_IPV4)) {
		rte_pktmbuf_free(pkt);
		return NULL;
	}
	iph4 = rte_pktmbuf_mtod(pkt, struct rte_ipv4_hdr *);
	if (iph4->next_proto_id != IPPROTO_ICMP) {
		rte_pktmbuf_free(pkt);
		return NULL;
	}
	icmp = (void *)(iph4 + 1);
	if (icmp->icmp_type != RTE_IP_ICMP_ECHO_REQUEST) {
		rte_pktmbuf_free(pkt);
		return NULL;
	}

	rte_memcpy(eth->dst_addr.addr_bytes, eth->src_addr.addr_bytes,
		RTE_ETHER_ADDR_LEN);
	rte_memcpy(eth->src_addr.addr_bytes, s_tap_ethaddr,
		RTE_ETHER_ADDR_LEN);
	iph4->hdr_checksum = 0;
	iph4->fragment_offset = 0;

	rte_memcpy(ipv4addr, &iph4->dst_addr, sizeof(rte_be32_t));
	rte_memcpy(&iph4->dst_addr, &iph4->src_addr,
		sizeof(rte_be32_t));
	rte_memcpy(&iph4->src_addr, ipv4addr,
		sizeof(rte_be32_t));
	iph4->hdr_checksum = rte_ipv4_cksum(iph4);

	icmp->icmp_type = RTE_IP_ICMP_ECHO_REPLY;
	icmp->icmp_cksum = 0;
	icmp->icmp_cksum = rte_raw_cksum(icmp,
		pkt->pkt_len -
		sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr));
	icmp->icmp_cksum = ~(icmp->icmp_cksum);

	return pkt;
}

static void
burst_icmp_reply(uint16_t c_qp, struct rte_mbuf *pkts[],
	uint16_t nb)
{
	struct rte_mbuf *icmp_reply[nb], *reply;
	uint16_t i, j = 0;

	for (i = 0; i < nb; i++) {
		reply = single_icmp_reply(pkts[i]);
		if (reply) {
			dump_pkt_info(reply, 0, 0, 0, 0);
			icmp_reply[j] = reply;
			j++;
		}
	}
	ipsec_ike_outbound(icmp_reply, j, c_qp);
}

static void
ipsec_ike_dequeue_post(struct rte_mbuf *pkts[],
	uint16_t nb_rx, uint16_t e_qp, uint16_t c_qp)
{
	uint16_t i, i_nb = 0, e_nb = 0, nb_tx;
	struct ipsec_ike_priv *priv;
	struct rte_ipv4_hdr *iph4;
	struct rte_mbuf *e_pkts[nb_rx];
	struct rte_mbuf *i_pkts[nb_rx];
	uint32_t tx_bytes_oh[nb_rx];

	for (i = 0; i < nb_rx; i++) {
		priv = rte_mbuf_to_priv(pkts[i]);
		if (priv->sa->sess_conf.ipsec.direction ==
			RTE_SECURITY_IPSEC_SA_DIR_EGRESS) {
			iph4 = rte_pktmbuf_mtod(pkts[i], void *);

			rte_memcpy((char *)iph4 - sizeof(struct rte_ether_hdr),
				priv->cntx, sizeof(struct rte_ether_hdr));
			pkts[i]->data_off -= sizeof(struct rte_ether_hdr);
			pkts[i]->pkt_len += sizeof(struct rte_ether_hdr);
			pkts[i]->data_len += sizeof(struct rte_ether_hdr);
			dump_pkt_info(pkts[i], 1, 0, 1, 0);
			e_pkts[e_nb] = pkts[i];
			s_outbound_bytes += pkts[i]->pkt_len;
			tx_bytes_oh[e_nb] = pkts[i]->pkt_len +
				RTE_TM_ETH_FRAMING_OVERHEAD_FCS;
			e_nb++;
			s_outbound_frames++;
		} else {
			dump_pkt_info(pkts[i], 0, 1, 0, 0);
			i_pkts[i_nb] = pkts[i];
			s_inbound_bytes += pkts[i]->pkt_len;
			i_nb++;
			s_inbound_frames++;
		}
	}
	nb_tx = rte_eth_tx_burst(s_sec_port_id, e_qp,
		e_pkts, e_nb);
	for (i = 0; i < nb_tx; i++)
		s_tx_overhead_bytes += tx_bytes_oh[i];
	s_tx_frames += nb_tx;
	if (nb_tx < e_nb)
		rte_pktmbuf_free_bulk(&e_pkts[nb_tx], e_nb - nb_tx);

	if (s_icmp_reply)
		burst_icmp_reply(c_qp, i_pkts, i_nb);
	else
		rte_pktmbuf_free_bulk(i_pkts, i_nb);
}

/* main processing loop */
static int32_t
main_loop(__attribute__((unused)) void *dummy)
{
	struct rte_mbuf *pkts[MAX_PKT_BURST];
	int32_t nb_rx, nb_tx, i;
	uint16_t e_qp = 0, c_qp = 0;
	struct ipsec_ike_sa_entry *sa;

	RTE_LOG(INFO, IPSEC_IKE, "Enter main loop on lcore %u\n",
		rte_lcore_id());

	while (1) {
		nb_rx = rte_eth_rx_burst(s_sec_port_id, e_qp,
				pkts, MAX_PKT_BURST);
		if (nb_rx > 0) {
			/**Lookup sa by rxq index(SA index).*/
			sa = xfm_sp_entry_lookup_sa(NULL, NULL, INVALID_SPI,
					0, 1, e_qp);
			if (sa) {
				for (i = 0; i < nb_rx; i++) {
					s_rx_overhead_bytes += pkts[i]->pkt_len;
					dump_pkt_info(pkts[i], 1, 1, 1, 0);
					adjust_inbound_ipv4(pkts[i]);
				}
				s_rx_overhead_bytes +=
					RTE_TM_ETH_FRAMING_OVERHEAD_FCS * nb_rx;
				s_rx_frames += nb_rx;
				ipsec_ike_sa_enqueue(pkts, sa, nb_rx, c_qp);
			} else {
				ipsec_ike_handle_inbound_pkts(pkts, nb_rx,
					e_qp, c_qp);
			}
		}

		nb_rx = ipsec_ike_dequeue(pkts, MAX_PKT_BURST, c_qp);
		if (nb_rx)
			ipsec_ike_dequeue_post(pkts, nb_rx, e_qp, c_qp);

		if (s_tap_port_id != RTE_MAX_ETHPORTS) {
			nb_rx = rte_eth_rx_burst(s_tap_port_id, e_qp,
					pkts, MAX_PKT_BURST);
			if (nb_rx > 0) {
				for (i = 0; i < nb_rx; i++)
					dump_pkt_info(pkts[i], 0, 0, 1, 1);
				nb_tx = rte_eth_tx_burst(s_sec_port_id, e_qp,
					pkts, nb_rx);
				if (nb_tx < nb_rx) {
					rte_pktmbuf_free_bulk(&pkts[nb_tx],
						nb_rx - nb_tx);
				}
			}
		}
		e_qp++;
		if (e_qp == s_eth_qp_nb)
			e_qp = 0;
		c_qp++;
		if (c_qp == s_cdev_qp)
			c_qp = 0;
	}

	return 0;
}

static int32_t
parse_args(int32_t argc, char **argv)
{
	int opt;
	int64_t ret;
	char **argvopt;
	int32_t option_index;
	char *prgname = argv[0];

	argvopt = argv;

	while ((opt = getopt_long(argc, argvopt, s_short_options,
				s_lgopts, &option_index)) != EOF) {
		switch (opt) {
		case CMD_LINE_OPT_SEC_PORT_NUM:
			s_sec_port_nm = strdup(optarg);
			RTE_LOG(INFO, IPSEC_IKE,
				"Sec port:%s\n", s_sec_port_nm);
			break;
		case CMD_LINE_OPT_TAP_PORT_NUM:
			s_tap_port_nm = strdup(optarg);
			RTE_LOG(INFO, IPSEC_IKE,
				"Tap port:%s\n", s_tap_port_nm);
			break;
		case CMD_LINE_OPT_ICMP_REPLY_NUM:
			s_icmp_reply = 1;
			RTE_LOG(INFO, IPSEC_IKE,
				"ICMP reply enabled.\n");
			break;
		case CMD_LINE_OPT_FRAME_DUMP_NUM:
			s_frame_dump = 1;
			RTE_LOG(INFO, IPSEC_IKE,
				"Frame dump enabled.\n");
			break;
		case CMD_LINE_OPT_PERF_LOG_NUM:
			s_perf_log = atoi(optarg);
			RTE_LOG(INFO, IPSEC_IKE,
				"Perf log %s.\n",
				s_perf_log ? "enabled" : "disabled");
			break;
		case CMD_LINE_OPT_STATIC_POL_NUM:
			s_static_sa_sp = 1;
			RTE_LOG(INFO, IPSEC_IKE,
				"Static SA/SP enabled.\n");
			break;
		default:
			return -EINVAL;
		}
	}

	if (optind >= 0)
		argv[optind - 1] = prgname;

	ret = optind - 1;
	optind = 1; /* reset getopt lib */
	return ret;
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_port_link_status(uint16_t portid)
{
	struct rte_eth_link link;
	int ret, time_out = 30;

check_again:
	memset(&link, 0, sizeof(link));
	ret = rte_eth_link_get_nowait(portid, &link);
	if (ret < 0) {
		RTE_LOG(WARNING, IPSEC_IKE,
			"Port %u link get failed: %s\n",
			portid, rte_strerror(-ret));
		return;
	}

	if (link.link_status) {
		RTE_LOG(INFO, IPSEC_IKE,
			"Port%d Link Up - speed %u Mbps -%s\n",
			portid, link.link_speed,
			(link.link_duplex == RTE_ETH_LINK_FULL_DUPLEX) ?
			("full-duplex") : ("half-duplex"));
	} else {
		time_out--;
		if (time_out > 0) {
			rte_delay_ms(100);
			goto check_again;
		}
		RTE_LOG(WARNING, IPSEC_IKE,
			"Port %d Link Down\n", portid);
	}
}

static void
ipsec_ike_cryptodev_init(void)
{
	struct rte_cryptodev_config dev_conf;
	struct rte_cryptodev_qp_conf qp_conf;
	uint16_t qp;
	struct rte_cryptodev_info cdev_info;

	rte_cryptodev_info_get(s_cdev_id, &cdev_info);

	dev_conf.socket_id = 0;
	dev_conf.nb_queue_pairs = s_cdev_qp;
	dev_conf.ff_disable = RTE_CRYPTODEV_FF_ASYMMETRIC_CRYPTO;

	if (rte_cryptodev_configure(s_cdev_id, &dev_conf)) {
		rte_panic("Failed to initialize cryptodev %u\n",
			s_cdev_id);
	}

	qp_conf.nb_descriptors = CDEV_QUEUE_DESC;
	qp_conf.mp_session = s_mem_ctx.session_pool;
	for (qp = 0; qp < dev_conf.nb_queue_pairs; qp++)
		if (rte_cryptodev_queue_pair_setup(s_cdev_id, qp,
				&qp_conf, dev_conf.socket_id)) {
			rte_exit(EXIT_FAILURE,
				"Failed to setup pq%u for cryptodev %d\n",
				qp, s_cdev_id);
		}

	if (rte_cryptodev_start(s_cdev_id)) {
		rte_exit(EXIT_FAILURE,
			"Failed to start cryptodev %u\n",
			s_cdev_id);
	}
}

static int
ipsec_ike_port_init(uint16_t portid)
{
	uint32_t frame_size;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf *txconf;
	int32_t ret;
	struct rte_ether_addr ethaddr;
	struct rte_eth_conf local_port_conf;
	struct rte_eth_rxconf rxq_conf;
	uint16_t idx;

	rte_memcpy(&local_port_conf, &s_port_conf,
		sizeof(struct rte_eth_conf));

	ret = rte_eth_dev_info_get(portid, &dev_info);
	if (ret) {
		RTE_LOG(ERR, IPSEC_IKE,
			"Get port(%d) info failed(%d)\n",
			portid, ret);
		return ret;
	}

	/* limit allowed HW offloafs, as user requested */
	dev_info.rx_offload_capa &= dev_rx_offload;
	dev_info.tx_offload_capa &= dev_tx_offload;

	ret = rte_eth_macaddr_get(portid, &ethaddr);
	if (ret) {
		RTE_LOG(ERR, IPSEC_IKE,
			"Get port(%d) mac address failed(%d)\n",
			portid, ret);
		return ret;
	}

	frame_size = MTU_TO_FRAMELEN(RTE_ETHER_MTU);
	local_port_conf.rxmode.max_lro_pkt_size = frame_size;

	/* Check that all required capabilities are supported */
	if ((local_port_conf.rxmode.offloads &
		dev_info.rx_offload_capa) !=
		local_port_conf.rxmode.offloads) {
		RTE_LOG(ERR, IPSEC_IKE,
			"Port(%d) RX offload required(%lx) not support(%lx)\n",
			portid, local_port_conf.rxmode.offloads,
			dev_info.rx_offload_capa);
		return -ENOTSUP;
	}

	if ((local_port_conf.txmode.offloads &
		dev_info.tx_offload_capa) !=
		local_port_conf.txmode.offloads) {
		RTE_LOG(ERR, IPSEC_IKE,
			"Port(%d) TX offload required(%lx) not support(%lx)\n",
			portid, local_port_conf.txmode.offloads,
			dev_info.tx_offload_capa);
		return -ENOTSUP;
	}

	if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
		local_port_conf.txmode.offloads |=
			RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

	if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_IPV4_CKSUM)
		local_port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_IPV4_CKSUM;

	local_port_conf.rx_adv_conf.rss_conf.rss_hf &=
		dev_info.flow_type_rss_offloads;
	if (local_port_conf.rx_adv_conf.rss_conf.rss_hf !=
			s_port_conf.rx_adv_conf.rss_conf.rss_hf) {
		RTE_LOG(ERR, IPSEC_IKE,
			"Port(%d) RX rss hash fun(%lx) not support(%lx)\n",
			portid, local_port_conf.rx_adv_conf.rss_conf.rss_hf,
			s_port_conf.rx_adv_conf.rss_conf.rss_hf);
		return -ENOTSUP;
	}

	ret = rte_eth_dev_configure(portid, s_eth_qp_nb, s_eth_qp_nb,
			&local_port_conf);
	if (ret < 0) {
		RTE_LOG(ERR, IPSEC_IKE,
			"Port(%d) configure failed(%d)\n",
			portid, ret);
		return ret;
	}

	ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid,
		&s_nb_rxd, &s_nb_txd);
	if (ret < 0) {
		RTE_LOG(ERR, IPSEC_IKE,
			"Port(%d) adjust rx tx desc failed(%d)\n",
			portid, ret);
		return ret;
	}

	txconf = &dev_info.default_txconf;
	txconf->offloads = local_port_conf.txmode.offloads;

	for (idx = 0; idx < s_eth_qp_nb; idx++) {
		ret = rte_eth_tx_queue_setup(portid, idx, s_nb_txd,
				0, txconf);
		if (ret < 0) {
			RTE_LOG(ERR, IPSEC_IKE,
				"Port(%d) txq(%d) setup failed(%d)\n",
				portid, idx, ret);
			return ret;
		}
	}

	/* init RX queues */
	rxq_conf = dev_info.default_rxconf;
	rxq_conf.offloads = local_port_conf.rxmode.offloads;
	for (idx = 0; idx < s_eth_qp_nb; idx++) {
		ret = rte_eth_rx_queue_setup(portid, idx,
				s_nb_rxd, 0, &rxq_conf,
				s_mem_ctx.mbuf_pool);
		if (ret < 0) {
			RTE_LOG(ERR, IPSEC_IKE,
				"Port(%d) rxq(%d) setup failed(%d)\n",
				portid, idx, ret);
			return ret;
		}
	}

	return 0;
}

static size_t
max_session_size(void)
{
	size_t max_sz, sz;
	void *sec_ctx;

	max_sz = 0;
	sz = rte_cryptodev_sym_get_private_session_size(s_cdev_id);
	if (sz > max_sz)
		max_sz = sz;

	/* Get security context of the crypto device */
	sec_ctx = rte_cryptodev_get_sec_ctx(s_cdev_id);
	if (sec_ctx) {
		/* Get size of security session */
		sz = rte_security_session_get_size(sec_ctx);
		if (sz > max_sz)
			max_sz = sz;
	}

	sec_ctx = rte_eth_dev_get_sec_ctx(s_sec_port_id);
	if (!sec_ctx)
		return max_sz;

	sz = rte_security_session_get_size(sec_ctx);
	if (sz > max_sz)
		max_sz = sz;

	return max_sz;
}

static void
session_pool_init(struct ipsec_ike_mem_ctx *ctx, size_t sess_sz)
{
	char mp_name[RTE_MEMPOOL_NAMESIZE];
	struct rte_mempool *sess_mp;

	snprintf(mp_name, RTE_MEMPOOL_NAMESIZE, "sess_mp");
	sess_mp = rte_cryptodev_sym_session_pool_create(mp_name,
		CDEV_MP_NB_OBJS, sess_sz, CDEV_MP_CACHE_SZ, 0, 0);
	ctx->session_pool = sess_mp;

	if (!ctx->session_pool)
		rte_exit(EXIT_FAILURE, "Cannot init session pool\n");
}

static void
session_priv_pool_init(struct ipsec_ike_mem_ctx *ctx,
	size_t sess_sz)
{
	char mp_name[RTE_MEMPOOL_NAMESIZE];
	struct rte_mempool *sess_mp;

	snprintf(mp_name, RTE_MEMPOOL_NAMESIZE, "sess_mp_priv");
	sess_mp = rte_mempool_create(mp_name,
			CDEV_MP_NB_OBJS,
			sess_sz,
			CDEV_MP_CACHE_SZ,
			0, NULL, NULL, NULL,
			NULL, 0,
			0);
	ctx->session_priv_pool = sess_mp;

	if (!ctx->session_priv_pool)
		rte_exit(EXIT_FAILURE, "Cannot init session priv pool\n");
}

static void
pool_init(struct ipsec_ike_mem_ctx *ctx, uint32_t nb_mbuf)
{
	char s[64];

	snprintf(s, sizeof(s), "mbuf_pool");
	ctx->mbuf_pool = rte_pktmbuf_pool_create(s, nb_mbuf,
			MEMPOOL_CACHE_SIZE,
			sizeof(struct ipsec_ike_priv),
			RTE_MBUF_DEFAULT_BUF_SIZE, 0);

	if (!ctx->mbuf_pool)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");
}

static int
_ipsec_ike_create_session_by_sa(struct ipsec_ike_mem_ctx *mem_ctx,
	struct ipsec_ike_sa_entry *sa, struct rte_ipsec_session *ips,
	uint8_t dev_id)
{
	struct rte_security_ctx *ctx;

	if (ips->type != RTE_SECURITY_ACTION_TYPE_LOOKASIDE_PROTOCOL)
		return -ENOTSUP;

	ctx = rte_cryptodev_get_sec_ctx(dev_id);

	ips->security.ses = rte_security_session_create(ctx,
		&sa->sess_conf, mem_ctx->session_priv_pool);
	if (!ips->security.ses) {
		RTE_LOG(ERR, IPSEC_IKE, "Lookaside Session init failed\n");
		return -EINVAL;
	}

	return 0;
}

int
ipsec_ike_create_session_by_sa(struct ipsec_ike_sa_entry *sa)
{
	return _ipsec_ike_create_session_by_sa(&s_mem_ctx,
			sa, &sa->session, s_cdev_id);
}

static int
ipsec_ike_default_inbound_flow(uint32_t priority,
	uint16_t tc, uint16_t index)
{
	struct rte_flow_attr flow_attr;
	struct rte_flow_item flow_item[2];
	struct rte_flow_action flow_action[2];
	struct rte_flow_action_queue ingress_queue;
	struct rte_flow_error error;
	void *flow;

	memset(&flow_attr, 0, sizeof(struct rte_flow_attr));
	memset(flow_item, 0, 2 * sizeof(struct rte_flow_item));
	memset(flow_action, 0, 2 * sizeof(struct rte_flow_action));
	memset(&error, 0, sizeof(struct rte_flow_error));

	flow_attr.group = tc;
	flow_attr.priority = priority;
	flow_attr.ingress = 1;

	flow_item[0].type = RTE_FLOW_ITEM_TYPE_ETH;
	flow_item[0].spec = NULL;
	flow_item[0].mask = NULL;

	flow_item[1].type = RTE_FLOW_ITEM_TYPE_END;

	memset(&ingress_queue, 0, sizeof(struct rte_flow_action_queue));
	ingress_queue.index = index;
	flow_action[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
	flow_action[0].conf = &ingress_queue;
	flow_action[1].type = RTE_FLOW_ACTION_TYPE_END;

	flow = rte_flow_create(s_sec_port_id, &flow_attr,
		flow_item, flow_action, &error);
	if (flow) {
		RTE_LOG(INFO, IPSEC_IKE,
			"%s: Default flow (index=%d) create successfully\n",
			__func__, index);
		return 0;
	}

	RTE_LOG(ERR, IPSEC_IKE,
		"%s: Default flow (index=%d) create failed(%s)\n", __func__,
		index, error.message);

	return -EIO;
}

int
ipsec_ike_sp_in_flow_in_add(struct ipsec_ike_sp_entry *sp,
	int parse_spi, uint16_t tc, uint16_t tc_idx,
	uint16_t flow_index)
{
	struct rte_flow_attr flow_attr;
	struct rte_flow_item flow_item[3];
	struct rte_flow_action flow_action[2];
	struct rte_flow_item_ipv4 spec_ip4, mask_ip4;
	struct rte_flow_item_ipv6 spec_ip6, mask_ip6;
	struct rte_flow_item_esp spec_esp, mask_esp;
	struct rte_flow_action_queue ingress_queue;
	struct rte_flow_error error;
	void *flow;

	memset(&flow_attr, 0, sizeof(struct rte_flow_attr));
	memset(flow_item, 0, 3 * sizeof(struct rte_flow_item));
	memset(flow_action, 0, 2 * sizeof(struct rte_flow_action));
	memset(&spec_ip4, 0, sizeof(struct rte_flow_item_ipv4));
	memset(&mask_ip4, 0, sizeof(struct rte_flow_item_ipv4));
	memset(&spec_ip6, 0, sizeof(struct rte_flow_item_ipv6));
	memset(&mask_ip6, 0, sizeof(struct rte_flow_item_ipv6));
	memset(&spec_esp, 0, sizeof(struct rte_flow_item_esp));
	memset(&mask_esp, 0, sizeof(struct rte_flow_item_esp));
	memset(&error, 0, sizeof(struct rte_flow_error));

	flow_attr.group = tc;
	flow_attr.priority = tc_idx;
	flow_attr.ingress = 1;

	if (sp->family == AF_INET) {
		flow_item[0].type = RTE_FLOW_ITEM_TYPE_IPV4;
		rte_memcpy(&spec_ip4.hdr.src_addr, sp->src.ip4,
			sizeof(rte_be32_t));
		rte_memcpy(&spec_ip4.hdr.dst_addr, sp->dst.ip4,
			sizeof(rte_be32_t));
		mask_ip4.hdr.src_addr = 0xffffffff;
		mask_ip4.hdr.dst_addr = 0xffffffff;
		flow_item[0].spec = &spec_ip4;
		flow_item[0].mask = &mask_ip4;
	} else if (sp->family == AF_INET6) {
		flow_item[0].type = RTE_FLOW_ITEM_TYPE_IPV6;
		rte_memcpy(spec_ip6.hdr.src_addr, sp->src.ip6, 16);
		rte_memcpy(spec_ip6.hdr.dst_addr, sp->dst.ip6, 16);
		memset(mask_ip6.hdr.src_addr, 0xff, 16);
		memset(mask_ip6.hdr.dst_addr, 0xff, 16);
		flow_item[0].spec = &spec_ip6;
		flow_item[0].mask = &mask_ip6;
	} else {
		RTE_LOG(ERR, IPSEC_IKE,
			"%s: Invalid IP family(%d)\n", __func__, sp->family);
		return -EINVAL;
	}

	if (parse_spi) {
		flow_item[1].type = RTE_FLOW_ITEM_TYPE_ESP;
		spec_esp.hdr.spi = sp->spi;
		mask_esp.hdr.spi = 0xffffffff;
		flow_item[1].spec = &spec_esp;
		flow_item[1].mask = &mask_esp;
		flow_item[2].type = RTE_FLOW_ITEM_TYPE_END;
	} else {
		flow_item[1].type = RTE_FLOW_ITEM_TYPE_END;
	}

	memset(&ingress_queue, 0, sizeof(struct rte_flow_action_queue));
	ingress_queue.index = flow_index;
	flow_action[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
	flow_action[0].conf = &ingress_queue;
	flow_action[1].type = RTE_FLOW_ACTION_TYPE_END;

	flow = rte_flow_create(s_sec_port_id, &flow_attr,
		flow_item, flow_action, &error);
	if (flow) {
		RTE_LOG(INFO, IPSEC_IKE,
			"%s: Policy flow (index=%d) create successfully\n",
			__func__, flow_index);
		rte_memcpy(&sp->action, flow_action,
			sizeof(struct rte_flow_action));
		rte_memcpy(&sp->attr, &flow_attr,
			sizeof(struct rte_flow_attr));
		if (sp->family == AF_INET) {
			rte_memcpy(&sp->ipv4_spec, &spec_ip4,
				sizeof(struct rte_flow_item_ipv4));
		} else {
			rte_memcpy(&sp->ipv6_spec, &spec_ip6,
				sizeof(struct rte_flow_item_ipv6));
		}
		if (parse_spi) {
			rte_memcpy(&sp->esp_spec, &spec_esp,
				sizeof(struct rte_flow_item_esp));
		}
		sp->flow = flow;
		sp->flow_idx = flow_index;
		return 0;
	}

	RTE_LOG(ERR, IPSEC_IKE,
		"%s: Policy flow (index=%d) create failed(%s)\n", __func__,
		flow_index, error.message);

	return -EIO;
}

int
ipsec_ike_sp_in_flow_in_del(struct ipsec_ike_sp_entry *sp)
{
	int ret;
	struct rte_flow_error err;

	if (!sp->flow)
		return 0;
	ret = rte_flow_destroy(s_sec_port_id, sp->flow, &err);
	if (ret) {
		RTE_LOG(ERR, IPSEC_IKE,
			"%s: Policy flow (index=%d) destroy failed(%s)\n",
			__func__, sp->flow_idx, err.message);
		return ret;
	}
	sp->flow = NULL;
	return 0;
}

static void *
ipsec_ike_perf_statistics(void *arg)
{
	cpu_set_t cpuset;
	uint64_t rx_pkts = 0;
	uint64_t tx_pkts = 0;
	uint64_t inbound_pkts = 0;
	uint64_t outbound_pkts = 0;
	uint64_t rx_bytes_oh = 0;
	uint64_t tx_bytes_oh = 0;
	uint64_t inbound_bytes = 0;
	uint64_t outbound_bytes = 0;
	struct rte_eth_stats stats;
	int ret, interval = 5;
	double diff, diffp;

	CPU_SET(0, &cpuset);
	ret = pthread_setaffinity_np(pthread_self(),
			sizeof(cpu_set_t), &cpuset);
	sleep(2);
	rx_pkts = s_rx_frames;
	tx_pkts = s_tx_frames;
	inbound_pkts = s_inbound_frames;
	outbound_pkts = s_outbound_frames;
	rx_bytes_oh = s_rx_overhead_bytes;
	tx_bytes_oh = s_tx_overhead_bytes;
	inbound_bytes = s_inbound_bytes;
	outbound_bytes = s_outbound_bytes;

loop:
	sleep(interval);
	if (s_sec_port_id == RTE_MAX_ETHPORTS)
		goto loop;
	ret = rte_eth_stats_get(s_sec_port_id, &stats);
	if (!ret) {
		RTE_LOG(INFO, IPSEC_IKE,
			"Port RX missed(%ld), RX error(%ld), TX error(%ld)\n",
			stats.imissed, stats.ierrors, stats.oerrors);
	}

	diff = (s_rx_overhead_bytes - rx_bytes_oh) * 8;
	diffp = s_rx_frames - rx_pkts;
	RTE_LOG(INFO, IPSEC_IKE,
		"Port RX bytes(%ld), frames(%ld), %fGbps, %fMpps\n",
		s_rx_overhead_bytes, s_rx_frames,
		diff / interval / G_NUM,
		diffp / interval / M_NUM);
	rx_bytes_oh = s_rx_overhead_bytes;
	rx_pkts = s_rx_frames;

	diff = (s_tx_overhead_bytes - tx_bytes_oh) * 8;
	diffp = s_tx_frames - tx_pkts;
	RTE_LOG(INFO, IPSEC_IKE,
		"Port TX bytes(%ld), frames(%ld), %fGbps, %fMpps\n",
		s_tx_overhead_bytes, s_tx_frames,
		diff / interval / G_NUM,
		diffp / interval / M_NUM);
	tx_bytes_oh = s_tx_overhead_bytes;
	tx_pkts = s_tx_frames;

	diff = (s_inbound_bytes - inbound_bytes) * 8;
	diffp = s_inbound_frames - inbound_pkts;
	RTE_LOG(INFO, IPSEC_IKE,
		"SEC Inbound bytes(%ld), frames(%ld), %fGbps, %fMpps\n",
		s_inbound_bytes, s_inbound_frames,
		diff / interval / G_NUM,
		diffp / interval / M_NUM);
	inbound_bytes = s_inbound_bytes;
	inbound_pkts = s_inbound_frames;

	diff = (s_outbound_bytes - outbound_bytes) * 8;
	diffp = s_outbound_frames - outbound_pkts;
	RTE_LOG(INFO, IPSEC_IKE,
		"SEC Outbound bytes(%ld), frames(%ld), %fGbps %fMpps\n\n",
		s_outbound_bytes, s_outbound_frames,
		diff / interval / G_NUM,
		diffp / interval / M_NUM);
	outbound_bytes = s_outbound_bytes;
	outbound_pkts = s_outbound_frames;

	goto loop;

	return arg;
}

int32_t
main(int32_t argc, char **argv)
{
	int32_t ret;
	uint32_t lcore_id, port;
	size_t sess_sz;
	char port_nm[RTE_ETH_NAME_MAX_LEN];
	pthread_t tid;

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

	for (port = 0; port < RTE_MAX_ETHPORTS; port++) {
		if (s_sec_port_nm && s_sec_port_id == RTE_MAX_ETHPORTS) {
			ret = rte_eth_dev_get_name_by_port(port, port_nm);
			if (!ret && !strcmp(port_nm, s_sec_port_nm))
				s_sec_port_id = port;
		}
		if (s_tap_port_nm && s_tap_port_id == RTE_MAX_ETHPORTS) {
			ret = rte_eth_dev_get_name_by_port(port, port_nm);
			if (!ret && !strcmp(port_nm, s_tap_port_nm))
				s_tap_port_id = port;
		}
	}

	if (s_sec_port_id == s_tap_port_id &&
		s_sec_port_id != RTE_MAX_ETHPORTS) {
		RTE_LOG(ERR, IPSEC_IKE,
			"Sec port(%d) should NOT be tap port\n",
			s_sec_port_id);
		return -EINVAL;
	}

	if (s_sec_port_id == RTE_MAX_ETHPORTS)
		s_sec_port_id = 0;

	RTE_LOG(ERR, IPSEC_IKE,
		"IPSec port(%d)/IKE port(%d)\n",
		s_sec_port_id, s_tap_port_id);

	sess_sz = max_session_size();

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;

		/* mbuf_pool is initialised by the pool_init() function*/
		if (s_mem_ctx.mbuf_pool)
			continue;

		pool_init(&s_mem_ctx, NB_MBUF);
		session_pool_init(&s_mem_ctx, sess_sz);
		session_priv_pool_init(&s_mem_ctx, sess_sz);
		break;
	}

	ret = ipsec_ike_port_init(s_sec_port_id);
	if (ret) {
		rte_exit(EXIT_FAILURE,
			"Init security port%d failed(%d)\n",
			s_sec_port_id, ret);
	}

	if (s_tap_port_id != RTE_MAX_ETHPORTS) {
		ret = ipsec_ike_port_init(s_tap_port_id);
		if (ret) {
			rte_exit(EXIT_FAILURE,
				"Init tap port%d failed(%d)\n",
				s_tap_port_id, ret);
		}
	}

	s_ipsec_ike_cntx.sp_in_fast = rte_zmalloc(NULL,
		sizeof(void *) * (s_eth_qp_nb - 1),
		RTE_CACHE_LINE_SIZE);
	s_ipsec_ike_cntx.max_flow_in_nb = s_eth_qp_nb - 1;
	ret = ipsec_ike_default_inbound_flow(s_eth_qp_nb - 1,
		0, s_eth_qp_nb - 1);
	if (ret) {
		RTE_LOG(WARNING, IPSEC_IKE,
			"Create IPSec port(%d) default flow failed(%d)\n",
			s_sec_port_id, ret);
	}

	ipsec_ike_cryptodev_init();

	ret = rte_eth_dev_start(s_sec_port_id);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE,
			"Start port%d failed(%d)\n",
			s_sec_port_id, ret);
	}
	ret = rte_eth_promiscuous_enable(s_sec_port_id);
	if (ret) {
		rte_exit(EXIT_FAILURE,
			"Enable port%d promiscuous failed: %s\n",
			s_sec_port_id, rte_strerror(-ret));
	}

	check_port_link_status(s_sec_port_id);

	if (s_tap_port_id != RTE_MAX_ETHPORTS) {
		ret = rte_eth_dev_start(s_tap_port_id);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				"Start port%d failed(%d)\n",
				s_tap_port_id, ret);
		}
		ret = rte_eth_promiscuous_enable(s_tap_port_id);
		if (ret) {
			rte_exit(EXIT_FAILURE,
				"Enable port%d promiscuous failed: %s\n",
				s_tap_port_id, rte_strerror(-ret));
		}
		check_port_link_status(s_tap_port_id);
	}

	ret = setup_xfrm_msgloop();
	if (ret)
		return ret;

	if (s_perf_log) {
		ret = pthread_create(&tid, NULL,
			ipsec_ike_perf_statistics, NULL);
		if (ret) {
			RTE_LOG(WARNING, IPSEC_IKE,
				"Perf log failed(%d)\n", ret);
		}
	}

	memset(s_dump_flow_prefix, ' ', sizeof(s_dump_flow_prefix));

	/* launch per-lcore init on every lcore */
	rte_eal_mp_remote_launch(main_loop, NULL, CALL_MAIN);
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		ret = rte_eal_wait_lcore(lcore_id);
		if (ret < 0)
			return ret;
	}
	if (s_ipsec_ike_cntx.sp_in_fast) {
		rte_free(s_ipsec_ike_cntx.sp_in_fast);
		s_ipsec_ike_cntx.sp_in_fast = NULL;
		s_ipsec_ike_cntx.max_flow_in_nb = 0;
	}

	RTE_LOG(INFO, IPSEC_IKE, "IPSEC endpoint Finished.. bye!\n");

	return 0;
}
