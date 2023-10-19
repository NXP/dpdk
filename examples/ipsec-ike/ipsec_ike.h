/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2016-2017 Intel Corporation
 * Copyright 2023 NXP
 */

#ifndef __IPSEC_IKE_H__
#define __IPSEC_IKE_H__

#include <stdint.h>

#include <rte_byteorder.h>
#include <rte_crypto.h>
#include <rte_security.h>
#include <rte_flow.h>
#include <rte_ipsec.h>
#include <rte_eventdev.h>
#include <rte_event_eth_rx_adapter.h>
#include <rte_event_eth_tx_adapter.h>

#define RTE_LOGTYPE_IPSEC_IKE RTE_LOGTYPE_USER1

#define MAX_PKT_BURST 32

#define IPSEC_OFFLOAD_ESN_SOFTLIMIT 0xffffff00

#define INVALID_SPI (0)

#define IPSEC_SP_MAX_ENTRIES_MASK 0xff
#define IPSEC_SP_MAX_ENTRIES (IPSEC_SP_MAX_ENTRIES_MASK + 1)

#define UNUSED(x) (void)(x)

union ipsec_ike_addr {
	uint8_t ip4[sizeof(rte_be32_t)];
	uint8_t ip6[16];
};

#define MAX_KEY_SIZE 36

enum ipsec_ike_sa_flag {
	IP4_TUNNEL = (1 << 0),
	IP6_TUNNEL = (1 << 1),
	TRANSPORT = (1 << 2),
	IP4_TRANSPORT = (1 << 3),
	IP6_TRANSPORT = (1 << 4)
};

struct ipsec_ike_sa_head {
	struct ipsec_ike_sa_entry *lh_first;
};

struct ipsec_ike_sp_head {
	struct ipsec_ike_sp_entry *lh_first;
};

struct ipsec_ike_sa_entry {
	LIST_ENTRY(ipsec_ike_sa_entry) next;
	struct rte_ipsec_session session;
	uint64_t seq;
	enum ipsec_ike_sa_flag sa_flags;
	uint16_t family;
	union ipsec_ike_addr src;
	union ipsec_ike_addr dst;
	uint8_t cipher_key[MAX_KEY_SIZE];
	uint16_t cipher_key_len;
	uint8_t auth_key[MAX_KEY_SIZE];
	uint16_t auth_key_len;
	uint16_t portid;

	struct rte_crypto_sym_xform auth_xform;
	struct rte_crypto_sym_xform ciph_xform;
	struct rte_security_session_conf sess_conf;
};

struct ipsec_ike_sp_entry {
	LIST_ENTRY(ipsec_ike_sp_entry) next;
	union ipsec_ike_addr src;
	union ipsec_ike_addr dst;
	rte_be32_t spi;
	uint16_t family;
	uint32_t priority;
	uint32_t index;

	struct rte_flow_action action;
	struct rte_flow_attr attr;
	union {
		struct rte_flow_item_ipv4 ipv4_spec;
		struct rte_flow_item_ipv6 ipv6_spec;
	};
	struct rte_flow_item_esp esp_spec;
	struct rte_flow *flow;
	uint32_t flow_idx;

	struct ipsec_ike_sa_entry *sa;
};

struct ipsec_ike_cntx {
	struct ipsec_ike_sa_head sa_list;
	struct ipsec_ike_sp_head sp_ipv4_in_list;
	struct ipsec_ike_sp_head sp_ipv6_in_list;
	struct ipsec_ike_sp_head sp_ipv4_out_list;
	struct ipsec_ike_sp_head sp_ipv6_out_list;

	uint16_t max_flow_in_nb;
	struct ipsec_ike_sp_entry **sp_in_fast;
};

struct ipsec_ike_priv {
	struct ipsec_ike_sa_entry *sa;
	struct rte_crypto_op cop;
	struct rte_crypto_sym_op sym_cop;
	uint8_t cntx[32];
} __rte_cache_aligned;

#define IS_TRANSPORT(flags) ((flags) & TRANSPORT)

#define IS_TUNNEL(flags) ((flags) & (IP4_TUNNEL | IP6_TUNNEL))

#define IS_IP4(flags) ((flags) & (IP4_TUNNEL | IP4_TRANSPORT))

#define IS_IP6(flags) ((flags) & (IP6_TUNNEL | IP6_TRANSPORT))

#define IS_IP4_TUNNEL(flags) ((flags) & IP4_TUNNEL)

#define IS_IP6_TUNNEL(flags) ((flags) & IP6_TUNNEL)

struct ipsec_ike_mem_ctx {
	struct rte_mempool *mbuf_pool;
	struct rte_mempool *session_pool;
	struct rte_mempool *session_priv_pool;
};

struct ipsec_ike_cntx *
ipsec_ike_get_cntx(void);

uint16_t
ipsec_ike_max_queue_pair(void);

int
ipsec_ike_static_sa_sp_enabled(void);


static inline const char *
ip_next_prot_name(uint8_t next_proto_id)
{
	if (next_proto_id == IPPROTO_ICMP)
		return "ICMP";
	else if (next_proto_id == IPPROTO_TCP)
		return "TCP";
	else if (next_proto_id == IPPROTO_UDP)
		return "UDP";
	else if (next_proto_id == IPPROTO_IPV6)
		return "IPv6 in";
	else if (next_proto_id == IPPROTO_GRE)
		return "GRE";
	else if (next_proto_id == IPPROTO_ESP)
		return "ESP";
	else if (next_proto_id == IPPROTO_AH)
		return "AH";
	else if (next_proto_id == IPPROTO_SCTP)
		return "SCTP";
	else
		return "Unknown";
}

static inline struct rte_ipsec_session *
ipsec_ike_sa_2_session(struct ipsec_ike_sa_entry *sa)
{
	return &sa->session;
}

static inline enum rte_security_session_action_type
ipsec_ike_sa_2_action(struct ipsec_ike_sa_entry *sa)
{
	struct rte_ipsec_session *ips;

	ips = ipsec_ike_sa_2_session(sa);
	return ips->type;
}

int
ipsec_ike_create_session_by_sa(struct ipsec_ike_sa_entry *sa);

int
ipsec_ike_sp_in_flow_in_add(struct ipsec_ike_sp_entry *sp,
	int parse_spi,	uint16_t tc, uint16_t tc_idx,
	uint16_t flow_index);

int
ipsec_ike_sp_in_flow_in_del(struct ipsec_ike_sp_entry *sp);

#endif /* __IPSEC_IKE_H__ */
