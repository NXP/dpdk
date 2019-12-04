/* * SPDX-License-Identifier: BSD-3-Clause
 *   Copyright 2018 NXP
 */

#include <sys/queue.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>

#include <rte_ethdev.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_flow_driver.h>
#include <rte_tailq.h>

#include <fsl_dpni.h>
#include <fsl_dpkg.h>

#include <dpaa2_ethdev.h>
#include <dpaa2_pmd_logs.h>

/* Workaround to discriminate the UDP/TCP/SCTP
 * with next protocol of l3.
 * MC/WRIOP are not able to identify
 * the l4 protocol with l4 ports.
 */
int mc_l4_port_identification;

enum flow_rule_ipaddr_type {
	FLOW_NONE_IPADDR,
	FLOW_IPV4_ADDR,
	FLOW_IPV6_ADDR
};

struct flow_rule_ipaddr {
	enum flow_rule_ipaddr_type ipaddr_type;
	int qos_ipsrc_offset;
	int qos_ipdst_offset;
	int fs_ipsrc_offset;
	int fs_ipdst_offset;
};

struct rte_flow {
	LIST_ENTRY(rte_flow) next; /**< Pointer to the next flow structure. */
	struct dpni_rule_cfg qos_rule;
	struct dpni_rule_cfg fs_rule;
	uint16_t qos_index;
	uint16_t fs_index;
	uint8_t key_size;
	uint8_t tc_id; /** Traffic Class ID. */
	uint8_t flow_type;
	uint8_t tc_index; /** index within this Traffic Class. */
	enum rte_flow_action_type action;
	uint16_t flow_id;
	/* Special for IP address to specify the offset
	 * in key/mask.
	 */
	struct flow_rule_ipaddr ipaddr_rule;
	struct dpni_fs_action_cfg action_cfg;
};

static const
enum rte_flow_item_type dpaa2_supported_pattern_type[] = {
	RTE_FLOW_ITEM_TYPE_END,
	RTE_FLOW_ITEM_TYPE_ETH,
	RTE_FLOW_ITEM_TYPE_VLAN,
	RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_ICMP,
	RTE_FLOW_ITEM_TYPE_UDP,
	RTE_FLOW_ITEM_TYPE_TCP,
	RTE_FLOW_ITEM_TYPE_SCTP,
	RTE_FLOW_ITEM_TYPE_GRE,
};

static const
enum rte_flow_action_type dpaa2_supported_action_type[] = {
	RTE_FLOW_ACTION_TYPE_END,
	RTE_FLOW_ACTION_TYPE_QUEUE,
	RTE_FLOW_ACTION_TYPE_RSS
};

/* Max of enum rte_flow_item_type + 1, for both IPv4 and IPv6*/
#define DPAA2_FLOW_ITEM_TYPE_GENERIC_IP (RTE_FLOW_ITEM_TYPE_META + 1)

enum rte_filter_type dpaa2_filter_type = RTE_ETH_FILTER_NONE;

#ifndef __cplusplus
static const struct rte_flow_item_eth dpaa2_flow_item_eth_mask = {
	.dst.addr_bytes = "\xff\xff\xff\xff\xff\xff",
	.src.addr_bytes = "\xff\xff\xff\xff\xff\xff",
	.type = RTE_BE16(0xffff),
};

static const struct rte_flow_item_vlan dpaa2_flow_item_vlan_mask = {
	.tci = RTE_BE16(0xffff),
};

static const struct rte_flow_item_ipv4 dpaa2_flow_item_ipv4_mask = {
	.hdr.src_addr = RTE_BE32(0xffffffff),
	.hdr.dst_addr = RTE_BE32(0xffffffff),
	.hdr.next_proto_id = 0xff,
};

static const struct rte_flow_item_ipv6 dpaa2_flow_item_ipv6_mask = {
	.hdr = {
		.src_addr =
			"\xff\xff\xff\xff\xff\xff\xff\xff"
			"\xff\xff\xff\xff\xff\xff\xff\xff",
		.dst_addr =
			"\xff\xff\xff\xff\xff\xff\xff\xff"
			"\xff\xff\xff\xff\xff\xff\xff\xff",
		.proto = 0xff
	},
};

static const struct rte_flow_item_icmp dpaa2_flow_item_icmp_mask = {
	.hdr.icmp_type = 0xff,
	.hdr.icmp_code = 0xff,
};

static const struct rte_flow_item_udp dpaa2_flow_item_udp_mask = {
	.hdr = {
		.src_port = RTE_BE16(0xffff),
		.dst_port = RTE_BE16(0xffff),
	},
};

static const struct rte_flow_item_tcp dpaa2_flow_item_tcp_mask = {
	.hdr = {
		.src_port = RTE_BE16(0xffff),
		.dst_port = RTE_BE16(0xffff),
	},
};

static const struct rte_flow_item_sctp dpaa2_flow_item_sctp_mask = {
	.hdr = {
		.src_port = RTE_BE16(0xffff),
		.dst_port = RTE_BE16(0xffff),
	},
};

static const struct rte_flow_item_gre dpaa2_flow_item_gre_mask = {
	.protocol = RTE_BE16(0xffff),
};

#endif


static inline void dpaa2_flow_extract_key_set(
	struct dpaa2_key_info *key_info, int index, uint8_t size)
{
	key_info->key_size[index] = size;
	if (index > 0) {
		key_info->key_offset[index] =
			key_info->key_offset[index - 1] +
			key_info->key_size[index - 1];
	} else {
		key_info->key_offset[index] = 0;
	}
	key_info->key_total_size += size;
}

static int dpaa2_flow_extract_add(
	struct dpaa2_key_extract *key_extract,
	enum net_prot prot,
	uint32_t field, uint8_t field_size)
{
	int index, ip_src = -1, ip_dst = -1;
	struct dpkg_profile_cfg *dpkg = &key_extract->dpkg;
	struct dpaa2_key_info *key_info = &key_extract->key_info;

	if (dpkg->num_extracts >=
		DPKG_MAX_NUM_OF_EXTRACTS) {
		DPAA2_PMD_WARN("Number of extracts overflows");
		return -1;
	}
	/* Before reorder, the IP SRC and IP DST are already last
	 * extract(s).
	 */
	for (index = 0; index < dpkg->num_extracts; index++) {
		if (dpkg->extracts[index].extract.from_hdr.prot ==
			NET_PROT_IP) {
			if (dpkg->extracts[index].extract.from_hdr.field ==
				NH_FLD_IP_SRC) {
				ip_src = index;
			}
			if (dpkg->extracts[index].extract.from_hdr.field ==
				NH_FLD_IP_DST) {
				ip_dst = index;
			}
		}
	}

	if (ip_src >= 0)
		RTE_ASSERT((ip_src + 2) >= dpkg->num_extracts);

	if (ip_dst >= 0)
		RTE_ASSERT((ip_dst + 2) >= dpkg->num_extracts);

	if (prot == NET_PROT_IP &&
		(field == NH_FLD_IP_SRC ||
		field == NH_FLD_IP_DST)) {
		index = dpkg->num_extracts;
	} else {
		if (ip_src >= 0 && ip_dst >= 0)
			index = dpkg->num_extracts - 2;
		else if (ip_src >= 0 || ip_dst >= 0)
			index = dpkg->num_extracts - 1;
		else
			index = dpkg->num_extracts;
	}

	dpkg->extracts[index].type =	DPKG_EXTRACT_FROM_HDR;
	dpkg->extracts[index].extract.from_hdr.type = DPKG_FULL_FIELD;
	dpkg->extracts[index].extract.from_hdr.prot = prot;
	dpkg->extracts[index].extract.from_hdr.field = field;
	if (prot == NET_PROT_IP &&
		(field == NH_FLD_IP_SRC ||
		field == NH_FLD_IP_DST)) {
		dpaa2_flow_extract_key_set(key_info, index, 0);
	} else {
		dpaa2_flow_extract_key_set(key_info, index, field_size);
	}

	if (prot == NET_PROT_IP) {
		if (field == NH_FLD_IP_SRC) {
			if (key_info->ipv4_dst_offset >= 0) {
				key_info->ipv4_src_offset =
					key_info->ipv4_dst_offset +
					NH_FLD_IPV4_ADDR_SIZE;
			} else {
				key_info->ipv4_src_offset =
					key_info->key_offset[index - 1] +
						key_info->key_size[index - 1];
			}
			if (key_info->ipv6_dst_offset >= 0) {
				key_info->ipv6_src_offset =
					key_info->ipv6_dst_offset +
					NH_FLD_IPV6_ADDR_SIZE;
			} else {
				key_info->ipv6_src_offset =
					key_info->key_offset[index - 1] +
						key_info->key_size[index - 1];
			}
		} else if (field == NH_FLD_IP_DST) {
			if (key_info->ipv4_src_offset >= 0) {
				key_info->ipv4_dst_offset =
					key_info->ipv4_src_offset +
					NH_FLD_IPV4_ADDR_SIZE;
			} else {
				key_info->ipv4_dst_offset =
					key_info->key_offset[index - 1] +
						key_info->key_size[index - 1];
			}
			if (key_info->ipv6_src_offset >= 0) {
				key_info->ipv6_dst_offset =
					key_info->ipv6_src_offset +
					NH_FLD_IPV6_ADDR_SIZE;
			} else {
				key_info->ipv6_dst_offset =
					key_info->key_offset[index - 1] +
						key_info->key_size[index - 1];
			}
		}
	}

	if (index == dpkg->num_extracts) {
		dpkg->num_extracts++;
		return 0;
	}

	if (ip_src >= 0) {
		ip_src++;
		dpkg->extracts[ip_src].type =
			DPKG_EXTRACT_FROM_HDR;
		dpkg->extracts[ip_src].extract.from_hdr.type =
			DPKG_FULL_FIELD;
		dpkg->extracts[ip_src].extract.from_hdr.prot =
			NET_PROT_IP;
		dpkg->extracts[ip_src].extract.from_hdr.field =
			NH_FLD_IP_SRC;
		dpaa2_flow_extract_key_set(key_info, ip_src, 0);
		key_info->ipv4_src_offset += field_size;
		key_info->ipv6_src_offset += field_size;
	}
	if (ip_dst >= 0) {
		ip_dst++;
		dpkg->extracts[ip_dst].type =
			DPKG_EXTRACT_FROM_HDR;
		dpkg->extracts[ip_dst].extract.from_hdr.type =
			DPKG_FULL_FIELD;
		dpkg->extracts[ip_dst].extract.from_hdr.prot =
			NET_PROT_IP;
		dpkg->extracts[ip_dst].extract.from_hdr.field =
			NH_FLD_IP_DST;
		dpaa2_flow_extract_key_set(key_info, ip_dst, 0);
		key_info->ipv4_dst_offset += field_size;
		key_info->ipv6_dst_offset += field_size;
	}

	dpkg->num_extracts++;

	return 0;
}

/* Protocol discrimination.
 * Discriminate IPv4/IPv6/vLan by Eth type.
 * Discriminate UDP/TCP/ICMP by next proto of IP.
 */
static inline int
dpaa2_flow_proto_discrimination_extract(
	struct dpaa2_key_extract *key_extract,
	enum rte_flow_item_type type)
{
	if (type == RTE_FLOW_ITEM_TYPE_ETH) {
		return dpaa2_flow_extract_add(
				key_extract, NET_PROT_ETH,
				NH_FLD_ETH_TYPE,
				sizeof(rte_be16_t));
	} else if (type == (enum rte_flow_item_type)
		DPAA2_FLOW_ITEM_TYPE_GENERIC_IP) {
		return dpaa2_flow_extract_add(
				key_extract, NET_PROT_IP,
				NH_FLD_IP_PROTO,
				NH_FLD_IP_PROTO_SIZE);
	}

	return -1;
}

static inline int dpaa2_flow_extract_search(
	struct dpkg_profile_cfg *dpkg,
	enum net_prot prot, uint32_t field)
{
	int i;

	for (i = 0; i < dpkg->num_extracts; i++) {
		if (dpkg->extracts[i].extract.from_hdr.prot == prot &&
			dpkg->extracts[i].extract.from_hdr.field == field) {
			return i;
		}
	}

	return -1;
}

static inline int dpaa2_flow_extract_key_offset(
	struct dpaa2_key_extract *key_extract,
	enum net_prot prot, uint32_t field)
{
	int i;
	struct dpkg_profile_cfg *dpkg = &key_extract->dpkg;
	struct dpaa2_key_info *key_info = &key_extract->key_info;

	if (prot == NET_PROT_IPV4 ||
		prot == NET_PROT_IPV6)
		i = dpaa2_flow_extract_search(dpkg, NET_PROT_IP, field);
	else
		i = dpaa2_flow_extract_search(dpkg, prot, field);

	if (i >= 0) {
		if (prot == NET_PROT_IPV4 && field == NH_FLD_IP_SRC)
			return key_info->ipv4_src_offset;
		else if (prot == NET_PROT_IPV4 && field == NH_FLD_IP_DST)
			return key_info->ipv4_dst_offset;
		else if (prot == NET_PROT_IPV6 && field == NH_FLD_IP_SRC)
			return key_info->ipv6_src_offset;
		else if (prot == NET_PROT_IPV6 && field == NH_FLD_IP_DST)
			return key_info->ipv6_dst_offset;
		else
			return key_info->key_offset[i];
	} else {
		return -1;
	}
}

struct proto_discrimination {
	enum rte_flow_item_type type;
	union {
		rte_be16_t eth_type;
		uint8_t ip_proto;
	};
};

static int
dpaa2_flow_proto_discrimination_rule(
	struct dpaa2_dev_priv *priv, struct rte_flow *flow,
	struct proto_discrimination proto, int group)
{
	enum net_prot prot;
	uint32_t field;
	int offset;
	size_t key_iova;
	size_t mask_iova;
	rte_be16_t eth_type;
	uint8_t ip_proto;

	if (proto.type == RTE_FLOW_ITEM_TYPE_ETH) {
		prot = NET_PROT_ETH;
		field = NH_FLD_ETH_TYPE;
	} else if (proto.type == DPAA2_FLOW_ITEM_TYPE_GENERIC_IP) {
		prot = NET_PROT_IP;
		field = NH_FLD_IP_PROTO;
	} else {
		DPAA2_PMD_ERR(
			"Only Eth and IP support to discriminate next proto.");
		return -1;
	}

	offset = dpaa2_flow_extract_key_offset(&priv->extract.qos_key_extract,
			prot, field);
	if (offset < 0) {
		DPAA2_PMD_ERR("QoS prot %d field %d extract failed",
				prot, field);
		return -1;
	}
	key_iova = flow->qos_rule.key_iova + offset;
	mask_iova = flow->qos_rule.mask_iova + offset;
	if (proto.type == RTE_FLOW_ITEM_TYPE_ETH) {
		eth_type = proto.eth_type;
		memcpy((void *)key_iova, (const void *)(&eth_type),
			sizeof(rte_be16_t));
		eth_type = 0xffff;
		memcpy((void *)mask_iova, (const void *)(&eth_type),
			sizeof(rte_be16_t));
	} else {
		ip_proto = proto.ip_proto;
		memcpy((void *)key_iova, (const void *)(&ip_proto),
			sizeof(uint8_t));
		ip_proto = 0xff;
		memcpy((void *)mask_iova, (const void *)(&ip_proto),
			sizeof(uint8_t));
	}

	offset = dpaa2_flow_extract_key_offset(
			&priv->extract.tc_key_extract[group],
			prot, field);
	if (offset < 0) {
		DPAA2_PMD_ERR("FS prot %d field %d extract failed",
				prot, field);
		return -1;
	}
	key_iova = flow->fs_rule.key_iova + offset;
	mask_iova = flow->fs_rule.mask_iova + offset;

	if (proto.type == RTE_FLOW_ITEM_TYPE_ETH) {
		eth_type = proto.eth_type;
		memcpy((void *)key_iova, (const void *)(&eth_type),
			sizeof(rte_be16_t));
		eth_type = 0xffff;
		memcpy((void *)mask_iova, (const void *)(&eth_type),
			sizeof(rte_be16_t));
	} else {
		ip_proto = proto.ip_proto;
		memcpy((void *)key_iova, (const void *)(&ip_proto),
			sizeof(uint8_t));
		ip_proto = 0xff;
		memcpy((void *)mask_iova, (const void *)(&ip_proto),
			sizeof(uint8_t));
	}

	return 0;
}

static inline int
dpaa2_flow_rule_data_set(
	struct dpaa2_key_extract *key_extract,
	struct dpni_rule_cfg *rule,
	enum net_prot prot, uint32_t field,
	const void *key, const void *mask, int size)
{
	int offset = dpaa2_flow_extract_key_offset(key_extract,
				prot, field);

	if (offset < 0) {
		DPAA2_PMD_ERR("prot %d, field %d extract failed",
			prot, field);
		return -1;
	}
	memcpy((void *)(size_t)(rule->key_iova + offset), key, size);
	memcpy((void *)(size_t)(rule->mask_iova + offset), mask, size);

	return 0;
}

static inline int
_dpaa2_flow_rule_move_ipaddr_tail(
	struct dpaa2_key_extract *key_extract,
	struct dpni_rule_cfg *rule, int src_offset,
	uint32_t field, bool ipv4)
{
	size_t key_src;
	size_t mask_src;
	size_t key_dst;
	size_t mask_dst;
	int dst_offset, len;
	enum net_prot prot;
	char tmp[NH_FLD_IPV6_ADDR_SIZE];

	if (field != NH_FLD_IP_SRC &&
		field != NH_FLD_IP_DST) {
		DPAA2_PMD_ERR("Field of IP addr reorder must be IP SRC/DST");
		return -1;
	}
	if (ipv4)
		prot = NET_PROT_IPV4;
	else
		prot = NET_PROT_IPV6;
	dst_offset = dpaa2_flow_extract_key_offset(key_extract,
				prot, field);
	if (dst_offset < 0) {
		DPAA2_PMD_ERR("Field %d reorder extract failed", field);
		return -1;
	}
	key_src = rule->key_iova + src_offset;
	mask_src = rule->mask_iova + src_offset;
	key_dst = rule->key_iova + dst_offset;
	mask_dst = rule->mask_iova + dst_offset;
	if (ipv4)
		len = sizeof(rte_be32_t);
	else
		len = NH_FLD_IPV6_ADDR_SIZE;

	memcpy(tmp, (char *)key_src, len);
	memcpy((char *)key_dst, tmp, len);

	memcpy(tmp, (char *)mask_src, len);
	memcpy((char *)mask_dst, tmp, len);

	return 0;
}

static inline int
dpaa2_flow_rule_move_ipaddr_tail(
	struct rte_flow *flow, struct dpaa2_dev_priv *priv,
	int fs_group)
{
	int ret;
	enum net_prot prot;

	if (flow->ipaddr_rule.ipaddr_type == FLOW_NONE_IPADDR)
		return 0;

	if (flow->ipaddr_rule.ipaddr_type == FLOW_IPV4_ADDR)
		prot = NET_PROT_IPV4;
	else
		prot = NET_PROT_IPV6;

	if (flow->ipaddr_rule.qos_ipsrc_offset >= 0) {
		ret = _dpaa2_flow_rule_move_ipaddr_tail(
				&priv->extract.qos_key_extract,
				&flow->qos_rule,
				flow->ipaddr_rule.qos_ipsrc_offset,
				NH_FLD_IP_SRC, prot == NET_PROT_IPV4);
		if (ret) {
			DPAA2_PMD_ERR("QoS src address reorder failed");
			return -1;
		}
		flow->ipaddr_rule.qos_ipsrc_offset =
			dpaa2_flow_extract_key_offset(
				&priv->extract.qos_key_extract,
				prot, NH_FLD_IP_SRC);
	}

	if (flow->ipaddr_rule.qos_ipdst_offset >= 0) {
		ret = _dpaa2_flow_rule_move_ipaddr_tail(
				&priv->extract.qos_key_extract,
				&flow->qos_rule,
				flow->ipaddr_rule.qos_ipdst_offset,
				NH_FLD_IP_DST, prot == NET_PROT_IPV4);
		if (ret) {
			DPAA2_PMD_ERR("QoS dst address reorder failed");
			return -1;
		}
		flow->ipaddr_rule.qos_ipdst_offset =
			dpaa2_flow_extract_key_offset(
				&priv->extract.qos_key_extract,
				prot, NH_FLD_IP_DST);
	}

	if (flow->ipaddr_rule.fs_ipsrc_offset >= 0) {
		ret = _dpaa2_flow_rule_move_ipaddr_tail(
				&priv->extract.tc_key_extract[fs_group],
				&flow->fs_rule,
				flow->ipaddr_rule.fs_ipsrc_offset,
				NH_FLD_IP_SRC, prot == NET_PROT_IPV4);
		if (ret) {
			DPAA2_PMD_ERR("FS src address reorder failed");
			return -1;
		}
		flow->ipaddr_rule.fs_ipsrc_offset =
			dpaa2_flow_extract_key_offset(
				&priv->extract.tc_key_extract[fs_group],
				prot, NH_FLD_IP_SRC);
	}
	if (flow->ipaddr_rule.fs_ipdst_offset >= 0) {
		ret = _dpaa2_flow_rule_move_ipaddr_tail(
				&priv->extract.tc_key_extract[fs_group],
				&flow->fs_rule,
				flow->ipaddr_rule.fs_ipdst_offset,
				NH_FLD_IP_DST, prot == NET_PROT_IPV4);
		if (ret) {
			DPAA2_PMD_ERR("FS dst address reorder failed");
			return -1;
		}
		flow->ipaddr_rule.fs_ipdst_offset =
			dpaa2_flow_extract_key_offset(
				&priv->extract.tc_key_extract[fs_group],
				prot, NH_FLD_IP_DST);
	}

	return 0;
}

static int
dpaa2_flow_extract_support(
	const uint8_t *mask_src,
	enum rte_flow_item_type type)
{
	char mask[64];
	int i, size = 0;
	const char *mask_support = 0;

	switch (type) {
	case RTE_FLOW_ITEM_TYPE_ETH:
		mask_support = (const char *)&dpaa2_flow_item_eth_mask;
		size = sizeof(struct rte_flow_item_eth);
		break;
	case RTE_FLOW_ITEM_TYPE_VLAN:
		mask_support = (const char *)&dpaa2_flow_item_vlan_mask;
		size = sizeof(struct rte_flow_item_vlan);
		break;
	case RTE_FLOW_ITEM_TYPE_IPV4:
		mask_support = (const char *)&dpaa2_flow_item_ipv4_mask;
		size = sizeof(struct rte_flow_item_ipv4);
		break;
	case RTE_FLOW_ITEM_TYPE_IPV6:
		mask_support = (const char *)&dpaa2_flow_item_ipv6_mask;
		size = sizeof(struct rte_flow_item_ipv6);
		break;
	case RTE_FLOW_ITEM_TYPE_ICMP:
		mask_support = (const char *)&dpaa2_flow_item_icmp_mask;
		size = sizeof(struct rte_flow_item_icmp);
		break;
	case RTE_FLOW_ITEM_TYPE_UDP:
		mask_support = (const char *)&dpaa2_flow_item_udp_mask;
		size = sizeof(struct rte_flow_item_udp);
		break;
	case RTE_FLOW_ITEM_TYPE_TCP:
		mask_support = (const char *)&dpaa2_flow_item_tcp_mask;
		size = sizeof(struct rte_flow_item_tcp);
		break;
	case RTE_FLOW_ITEM_TYPE_SCTP:
		mask_support = (const char *)&dpaa2_flow_item_sctp_mask;
		size = sizeof(struct rte_flow_item_sctp);
		break;
	case RTE_FLOW_ITEM_TYPE_GRE:
		mask_support = (const char *)&dpaa2_flow_item_gre_mask;
		size = sizeof(struct rte_flow_item_gre);
		break;
	default:
		return -1;
	}

	memcpy(mask, mask_support, size);

	for (i = 0; i < size; i++)
		mask[i] = (mask[i] | mask_src[i]);

	if (memcmp(mask, mask_support, size))
		return -1;

	return 0;
}

static int
dpaa2_configure_flow_eth(struct rte_flow *flow,
			 struct rte_eth_dev *dev,
			 const struct rte_flow_attr *attr,
			 const struct rte_flow_item *pattern,
			 const struct rte_flow_action actions[] __rte_unused,
			 struct rte_flow_error *error __rte_unused,
			 int *device_configured)
{
	int index, ret;
	int local_cfg = 0;
	uint32_t group;
	const struct rte_flow_item_eth *spec, *mask;

	/* TODO: Currently upper bound of range parameter is not implemented */
	const struct rte_flow_item_eth *last __rte_unused;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	const char zero_cmp[RTE_ETHER_ADDR_LEN] = {0};

	group = attr->group;

	/* Parse pattern list to get the matching parameters */
	spec    = (const struct rte_flow_item_eth *)pattern->spec;
	last    = (const struct rte_flow_item_eth *)pattern->last;
	mask    = (const struct rte_flow_item_eth *)
		(pattern->mask ? pattern->mask : &dpaa2_flow_item_eth_mask);
	if (!spec) {
		/* Don't care any field of eth header,
		 * only care eth protocol.
		 */
		DPAA2_PMD_WARN("No pattern spec for Eth flow, just skip");
		return 0;
	}

	/* Get traffic class index and flow id to be configured */
	flow->tc_id = group;
	flow->tc_index = attr->priority;

	if (dpaa2_flow_extract_support((const uint8_t *)mask,
		RTE_FLOW_ITEM_TYPE_ETH)) {
		DPAA2_PMD_WARN("Extract field(s) of ethernet not support.");

		return -1;
	}

	if (memcmp((const char *)&mask->src, zero_cmp, RTE_ETHER_ADDR_LEN)) {
		index = dpaa2_flow_extract_search(
				&priv->extract.qos_key_extract.dpkg,
				NET_PROT_ETH, NH_FLD_ETH_SA);
		if (index < 0) {
			ret = dpaa2_flow_extract_add(
					&priv->extract.qos_key_extract,
					NET_PROT_ETH, NH_FLD_ETH_SA,
					RTE_ETHER_ADDR_LEN);
			if (ret) {
				DPAA2_PMD_ERR("QoS Extract add ETH_SA failed.");

				return -1;
			}
			local_cfg |= DPAA2_QOS_TABLE_RECONFIGURE;
		}
		index = dpaa2_flow_extract_search(
				&priv->extract.tc_key_extract[group].dpkg,
				NET_PROT_ETH, NH_FLD_ETH_SA);
		if (index < 0) {
			ret = dpaa2_flow_extract_add(
					&priv->extract.tc_key_extract[group],
					NET_PROT_ETH, NH_FLD_ETH_SA,
					RTE_ETHER_ADDR_LEN);
			if (ret) {
				DPAA2_PMD_ERR("FS Extract add ETH_SA failed.");
				return -1;
			}
			local_cfg |= DPAA2_FS_TABLE_RECONFIGURE;
		}

		ret = dpaa2_flow_rule_move_ipaddr_tail(flow, priv, group);
		if (ret) {
			DPAA2_PMD_ERR(
				"Move ipaddr before ETH_SA rule set failed");
			return -1;
		}

		ret = dpaa2_flow_rule_data_set(
				&priv->extract.qos_key_extract,
				&flow->qos_rule,
				NET_PROT_ETH,
				NH_FLD_ETH_SA,
				&spec->src.addr_bytes,
				&mask->src.addr_bytes,
				sizeof(struct rte_ether_addr));
		if (ret) {
			DPAA2_PMD_ERR("QoS NH_FLD_ETH_SA rule data set failed");
			return -1;
		}

		ret = dpaa2_flow_rule_data_set(
				&priv->extract.tc_key_extract[group],
				&flow->fs_rule,
				NET_PROT_ETH,
				NH_FLD_ETH_SA,
				&spec->src.addr_bytes,
				&mask->src.addr_bytes,
				sizeof(struct rte_ether_addr));
		if (ret) {
			DPAA2_PMD_ERR("FS NH_FLD_ETH_SA rule data set failed");
			return -1;
		}
	}

	if (memcmp((const char *)&mask->dst, zero_cmp, RTE_ETHER_ADDR_LEN)) {
		index = dpaa2_flow_extract_search(
				&priv->extract.qos_key_extract.dpkg,
				NET_PROT_ETH, NH_FLD_ETH_DA);
		if (index < 0) {
			ret = dpaa2_flow_extract_add(
					&priv->extract.qos_key_extract,
					NET_PROT_ETH, NH_FLD_ETH_DA,
					RTE_ETHER_ADDR_LEN);
			if (ret) {
				DPAA2_PMD_ERR("QoS Extract add ETH_DA failed.");

				return -1;
			}
			local_cfg |= DPAA2_QOS_TABLE_RECONFIGURE;
		}

		index = dpaa2_flow_extract_search(
				&priv->extract.tc_key_extract[group].dpkg,
				NET_PROT_ETH, NH_FLD_ETH_DA);
		if (index < 0) {
			ret = dpaa2_flow_extract_add(
					&priv->extract.tc_key_extract[group],
					NET_PROT_ETH, NH_FLD_ETH_DA,
					RTE_ETHER_ADDR_LEN);
			if (ret) {
				DPAA2_PMD_ERR("FS Extract add ETH_DA failed.");

				return -1;
			}
			local_cfg |= DPAA2_FS_TABLE_RECONFIGURE;
		}

		ret = dpaa2_flow_rule_move_ipaddr_tail(flow, priv, group);
		if (ret) {
			DPAA2_PMD_ERR(
				"Move ipaddr before ETH DA rule set failed");
			return -1;
		}

		ret = dpaa2_flow_rule_data_set(
				&priv->extract.qos_key_extract,
				&flow->qos_rule,
				NET_PROT_ETH,
				NH_FLD_ETH_DA,
				&spec->dst.addr_bytes,
				&mask->dst.addr_bytes,
				sizeof(struct rte_ether_addr));
		if (ret) {
			DPAA2_PMD_ERR("QoS NH_FLD_ETH_DA rule data set failed");
			return -1;
		}

		ret = dpaa2_flow_rule_data_set(
				&priv->extract.tc_key_extract[group],
				&flow->fs_rule,
				NET_PROT_ETH,
				NH_FLD_ETH_DA,
				&spec->dst.addr_bytes,
				&mask->dst.addr_bytes,
				sizeof(struct rte_ether_addr));
		if (ret) {
			DPAA2_PMD_ERR("FS NH_FLD_ETH_DA rule data set failed");
			return -1;
		}
	}

	if (memcmp((const char *)&mask->type, zero_cmp, sizeof(rte_be16_t))) {
		index = dpaa2_flow_extract_search(
				&priv->extract.qos_key_extract.dpkg,
				NET_PROT_ETH, NH_FLD_ETH_TYPE);
		if (index < 0) {
			ret = dpaa2_flow_extract_add(
					&priv->extract.qos_key_extract,
					NET_PROT_ETH, NH_FLD_ETH_TYPE,
					RTE_ETHER_TYPE_LEN);
			if (ret) {
				DPAA2_PMD_ERR("QoS Extract add ETH_TYPE failed.");

				return -1;
			}
			local_cfg |= DPAA2_QOS_TABLE_RECONFIGURE;
		}
		index = dpaa2_flow_extract_search(
				&priv->extract.tc_key_extract[group].dpkg,
				NET_PROT_ETH, NH_FLD_ETH_TYPE);
		if (index < 0) {
			ret = dpaa2_flow_extract_add(
					&priv->extract.tc_key_extract[group],
					NET_PROT_ETH, NH_FLD_ETH_TYPE,
					RTE_ETHER_TYPE_LEN);
			if (ret) {
				DPAA2_PMD_ERR("FS Extract add ETH_TYPE failed.");

				return -1;
			}
			local_cfg |= DPAA2_FS_TABLE_RECONFIGURE;
		}

		ret = dpaa2_flow_rule_move_ipaddr_tail(flow, priv, group);
		if (ret) {
			DPAA2_PMD_ERR(
				"Move ipaddr before ETH TYPE rule set failed");
				return -1;
		}

		ret = dpaa2_flow_rule_data_set(
				&priv->extract.qos_key_extract,
				&flow->qos_rule,
				NET_PROT_ETH,
				NH_FLD_ETH_TYPE,
				&spec->type,
				&mask->type,
				sizeof(rte_be16_t));
		if (ret) {
			DPAA2_PMD_ERR("QoS NH_FLD_ETH_TYPE rule data set failed");
			return -1;
		}

		ret = dpaa2_flow_rule_data_set(
				&priv->extract.tc_key_extract[group],
				&flow->fs_rule,
				NET_PROT_ETH,
				NH_FLD_ETH_TYPE,
				&spec->type,
				&mask->type,
				sizeof(rte_be16_t));
		if (ret) {
			DPAA2_PMD_ERR("FS NH_FLD_ETH_TYPE rule data set failed");
			return -1;
		}
	}

	(*device_configured) |= local_cfg;

	return 0;
}

static int
dpaa2_configure_flow_vlan(struct rte_flow *flow,
			  struct rte_eth_dev *dev,
			  const struct rte_flow_attr *attr,
			  const struct rte_flow_item *pattern,
			  const struct rte_flow_action actions[] __rte_unused,
			  struct rte_flow_error *error __rte_unused,
			  int *device_configured)
{
	int index, ret;
	int local_cfg = 0;
	uint32_t group;
	const struct rte_flow_item_vlan *spec, *mask;

	const struct rte_flow_item_vlan *last __rte_unused;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;

	group = attr->group;

	/* Parse pattern list to get the matching parameters */
	spec    = (const struct rte_flow_item_vlan *)pattern->spec;
	last    = (const struct rte_flow_item_vlan *)pattern->last;
	mask    = (const struct rte_flow_item_vlan *)
		(pattern->mask ? pattern->mask : &dpaa2_flow_item_vlan_mask);

	/* Get traffic class index and flow id to be configured */
	flow->tc_id = group;
	flow->tc_index = attr->priority;

	if (!spec) {
		/* Don't care any field of vlan header,
		 * only care vlan protocol.
		 */
		/* Eth type is actually used for vLan classification.
		 */
		struct proto_discrimination proto;

		index = dpaa2_flow_extract_search(
				&priv->extract.qos_key_extract.dpkg,
				NET_PROT_ETH, NH_FLD_ETH_TYPE);
		if (index < 0) {
			ret = dpaa2_flow_proto_discrimination_extract(
						&priv->extract.qos_key_extract,
						RTE_FLOW_ITEM_TYPE_ETH);
			if (ret) {
				DPAA2_PMD_ERR(
				"QoS Ext ETH_TYPE to discriminate vLan failed");

				return -1;
			}
			local_cfg |= DPAA2_QOS_TABLE_RECONFIGURE;
		}

		index = dpaa2_flow_extract_search(
				&priv->extract.tc_key_extract[group].dpkg,
				NET_PROT_ETH, NH_FLD_ETH_TYPE);
		if (index < 0) {
			ret = dpaa2_flow_proto_discrimination_extract(
					&priv->extract.tc_key_extract[group],
					RTE_FLOW_ITEM_TYPE_ETH);
			if (ret) {
				DPAA2_PMD_ERR(
				"FS Ext ETH_TYPE to discriminate vLan failed.");

				return -1;
			}
			local_cfg |= DPAA2_FS_TABLE_RECONFIGURE;
		}

		ret = dpaa2_flow_rule_move_ipaddr_tail(flow, priv, group);
		if (ret) {
			DPAA2_PMD_ERR(
			"Move ipaddr before vLan discrimination set failed");
			return -1;
		}

		proto.type = RTE_FLOW_ITEM_TYPE_ETH;
		proto.eth_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN);
		ret = dpaa2_flow_proto_discrimination_rule(priv, flow, proto, group);
		if (ret) {
			DPAA2_PMD_ERR("vLan discrimination rule set failed");
			return -1;
		}

		(*device_configured) |= local_cfg;

		return 0;
	}

	if (dpaa2_flow_extract_support((const uint8_t *)mask,
		RTE_FLOW_ITEM_TYPE_VLAN)) {
		DPAA2_PMD_WARN("Extract field(s) of vlan not support.");

		return -1;
	}

	if (!mask->tci)
		return 0;

	index = dpaa2_flow_extract_search(
				&priv->extract.qos_key_extract.dpkg,
				NET_PROT_VLAN, NH_FLD_VLAN_TCI);
	if (index < 0) {
		ret = dpaa2_flow_extract_add(
						&priv->extract.qos_key_extract,
						NET_PROT_VLAN,
						NH_FLD_VLAN_TCI,
						sizeof(rte_be16_t));
		if (ret) {
			DPAA2_PMD_ERR("QoS Extract add VLAN_TCI failed.");

			return -1;
		}
		local_cfg |= DPAA2_QOS_TABLE_RECONFIGURE;
	}

	index = dpaa2_flow_extract_search(
			&priv->extract.tc_key_extract[group].dpkg,
			NET_PROT_VLAN, NH_FLD_VLAN_TCI);
	if (index < 0) {
		ret = dpaa2_flow_extract_add(
				&priv->extract.tc_key_extract[group],
				NET_PROT_VLAN,
				NH_FLD_VLAN_TCI,
				sizeof(rte_be16_t));
		if (ret) {
			DPAA2_PMD_ERR("FS Extract add VLAN_TCI failed.");

			return -1;
		}
		local_cfg |= DPAA2_FS_TABLE_RECONFIGURE;
	}

	ret = dpaa2_flow_rule_move_ipaddr_tail(flow, priv, group);
	if (ret) {
		DPAA2_PMD_ERR(
			"Move ipaddr before VLAN TCI rule set failed");
		return -1;
	}

	ret = dpaa2_flow_rule_data_set(&priv->extract.qos_key_extract,
				&flow->qos_rule,
				NET_PROT_VLAN,
				NH_FLD_VLAN_TCI,
				&spec->tci,
				&mask->tci,
				sizeof(rte_be16_t));
	if (ret) {
		DPAA2_PMD_ERR("QoS NH_FLD_VLAN_TCI rule data set failed");
		return -1;
	}

	ret = dpaa2_flow_rule_data_set(
			&priv->extract.tc_key_extract[group],
			&flow->fs_rule,
			NET_PROT_VLAN,
			NH_FLD_VLAN_TCI,
			&spec->tci,
			&mask->tci,
			sizeof(rte_be16_t));
	if (ret) {
		DPAA2_PMD_ERR("FS NH_FLD_VLAN_TCI rule data set failed");
		return -1;
	}

	(*device_configured) |= local_cfg;

	return 0;
}

static int
dpaa2_configure_flow_generic_ip(
	struct rte_flow *flow,
	struct rte_eth_dev *dev,
	const struct rte_flow_attr *attr,
	const struct rte_flow_item *pattern,
	const struct rte_flow_action actions[] __rte_unused,
	struct rte_flow_error *error __rte_unused,
	int *device_configured)
{
	int index, ret;
	int local_cfg = 0;
	uint32_t group;
	const struct rte_flow_item_ipv4 *spec_ipv4 = 0,
		*mask_ipv4 = 0;
	const struct rte_flow_item_ipv6 *spec_ipv6 = 0,
		*mask_ipv6 = 0;
	const void *key, *mask;
	enum net_prot prot;

	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	const char zero_cmp[NH_FLD_IPV6_ADDR_SIZE] = {0};
	int size;

	group = attr->group;

	/* Parse pattern list to get the matching parameters */
	if (pattern->type == RTE_FLOW_ITEM_TYPE_IPV4) {
		spec_ipv4 = (const struct rte_flow_item_ipv4 *)pattern->spec;
		mask_ipv4 = (const struct rte_flow_item_ipv4 *)
			(pattern->mask ? pattern->mask : &dpaa2_flow_item_ipv4_mask);
	} else {
		spec_ipv6 = (const struct rte_flow_item_ipv6 *)pattern->spec;
		mask_ipv6 = (const struct rte_flow_item_ipv6 *)
			(pattern->mask ? pattern->mask : &dpaa2_flow_item_ipv6_mask);
	}

	/* Get traffic class index and flow id to be configured */
	flow->tc_id = group;
	flow->tc_index = attr->priority;

	if (!spec_ipv4 && !spec_ipv6) {
		/* Don't care any field of IP header,
		 * only care IP protocol.
		 * Example: flow create 0 ingress pattern ipv6 /
		 */
		/* Eth type is actually used for IP identification.
		 */
		/* TODO: Current design only supports Eth + IP,
		 *  Eth + vLan + IP needs to add.
		 */
		struct proto_discrimination proto;

		index = dpaa2_flow_extract_search(
				&priv->extract.qos_key_extract.dpkg,
				NET_PROT_ETH, NH_FLD_ETH_TYPE);
		if (index < 0) {
			ret = dpaa2_flow_proto_discrimination_extract(
					&priv->extract.qos_key_extract,
					RTE_FLOW_ITEM_TYPE_ETH);
			if (ret) {
				DPAA2_PMD_ERR(
				"QoS Ext ETH_TYPE to discriminate IP failed.");

				return -1;
			}
			local_cfg |= DPAA2_QOS_TABLE_RECONFIGURE;
		}

		index = dpaa2_flow_extract_search(
				&priv->extract.tc_key_extract[group].dpkg,
				NET_PROT_ETH, NH_FLD_ETH_TYPE);
		if (index < 0) {
			ret = dpaa2_flow_proto_discrimination_extract(
					&priv->extract.tc_key_extract[group],
					RTE_FLOW_ITEM_TYPE_ETH);
			if (ret) {
				DPAA2_PMD_ERR(
				"FS Ext ETH_TYPE to discriminate IP failed");

				return -1;
			}
			local_cfg |= DPAA2_FS_TABLE_RECONFIGURE;
		}

		ret = dpaa2_flow_rule_move_ipaddr_tail(flow, priv, group);
		if (ret) {
			DPAA2_PMD_ERR(
			"Move ipaddr before IP discrimination set failed");
			return -1;
		}

		proto.type = RTE_FLOW_ITEM_TYPE_ETH;
		if (pattern->type == RTE_FLOW_ITEM_TYPE_IPV4)
			proto.eth_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
		else
			proto.eth_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);
		ret = dpaa2_flow_proto_discrimination_rule(priv, flow,
							proto, group);
		if (ret) {
			DPAA2_PMD_ERR("IP discrimination rule set failed");
			return -1;
		}

		(*device_configured) |= local_cfg;

		return 0;
	}

	if (mask_ipv4) {
		if (dpaa2_flow_extract_support((const uint8_t *)mask_ipv4,
			RTE_FLOW_ITEM_TYPE_IPV4)) {
			DPAA2_PMD_WARN("Extract field(s) of IPv4 not support.");

			return -1;
		}
	}

	if (mask_ipv6) {
		if (dpaa2_flow_extract_support((const uint8_t *)mask_ipv6,
			RTE_FLOW_ITEM_TYPE_IPV6)) {
			DPAA2_PMD_WARN("Extract field(s) of IPv6 not support.");

			return -1;
		}
	}

	if (mask_ipv4 && (mask_ipv4->hdr.src_addr ||
		mask_ipv4->hdr.dst_addr)) {
		flow->ipaddr_rule.ipaddr_type = FLOW_IPV4_ADDR;
	} else if (mask_ipv6 &&
		(memcmp((const char *)mask_ipv6->hdr.src_addr,
				zero_cmp, NH_FLD_IPV6_ADDR_SIZE) ||
		memcmp((const char *)mask_ipv6->hdr.dst_addr,
				zero_cmp, NH_FLD_IPV6_ADDR_SIZE))) {
		flow->ipaddr_rule.ipaddr_type = FLOW_IPV6_ADDR;
	}

	if ((mask_ipv4 && mask_ipv4->hdr.src_addr) ||
		(mask_ipv6 &&
			memcmp((const char *)mask_ipv6->hdr.src_addr,
				zero_cmp, NH_FLD_IPV6_ADDR_SIZE))) {
		index = dpaa2_flow_extract_search(
				&priv->extract.qos_key_extract.dpkg,
				NET_PROT_IP, NH_FLD_IP_SRC);
		if (index < 0) {
			ret = dpaa2_flow_extract_add(
							&priv->extract.qos_key_extract,
							NET_PROT_IP,
							NH_FLD_IP_SRC,
							0);
			if (ret) {
				DPAA2_PMD_ERR("QoS Extract add IP_SRC failed.");

				return -1;
			}
			local_cfg |= (DPAA2_QOS_TABLE_RECONFIGURE |
				DPAA2_QOS_TABLE_IPADDR_EXTRACT);
		}

		index = dpaa2_flow_extract_search(
				&priv->extract.tc_key_extract[group].dpkg,
				NET_PROT_IP, NH_FLD_IP_SRC);
		if (index < 0) {
			ret = dpaa2_flow_extract_add(
					&priv->extract.tc_key_extract[group],
					NET_PROT_IP,
					NH_FLD_IP_SRC,
					0);
			if (ret) {
				DPAA2_PMD_ERR("FS Extract add IP_SRC failed.");

				return -1;
			}
			local_cfg |= (DPAA2_FS_TABLE_RECONFIGURE |
				DPAA2_FS_TABLE_IPADDR_EXTRACT);
		}

		if (spec_ipv4)
			key = &spec_ipv4->hdr.src_addr;
		else
			key = &spec_ipv6->hdr.src_addr[0];
		if (mask_ipv4) {
			mask = &mask_ipv4->hdr.src_addr;
			size = NH_FLD_IPV4_ADDR_SIZE;
			prot = NET_PROT_IPV4;
		} else {
			mask = &mask_ipv6->hdr.src_addr[0];
			size = NH_FLD_IPV6_ADDR_SIZE;
			prot = NET_PROT_IPV6;
		}

		ret = dpaa2_flow_rule_data_set(
				&priv->extract.qos_key_extract,
				&flow->qos_rule,
				prot, NH_FLD_IP_SRC,
				key,	mask, size);
		if (ret) {
			DPAA2_PMD_ERR("QoS NH_FLD_IP_SRC rule data set failed");
			return -1;
		}

		ret = dpaa2_flow_rule_data_set(
				&priv->extract.tc_key_extract[group],
				&flow->fs_rule,
				prot, NH_FLD_IP_SRC,
				key,	mask, size);
		if (ret) {
			DPAA2_PMD_ERR("FS NH_FLD_IP_SRC rule data set failed");
			return -1;
		}

		flow->ipaddr_rule.qos_ipsrc_offset =
			dpaa2_flow_extract_key_offset(
				&priv->extract.qos_key_extract,
				prot, NH_FLD_IP_SRC);
		flow->ipaddr_rule.fs_ipsrc_offset =
			dpaa2_flow_extract_key_offset(
				&priv->extract.tc_key_extract[group],
				prot, NH_FLD_IP_SRC);
	}

	if ((mask_ipv4 && mask_ipv4->hdr.dst_addr) ||
		(mask_ipv6 &&
			memcmp((const char *)mask_ipv6->hdr.dst_addr,
				zero_cmp, NH_FLD_IPV6_ADDR_SIZE))) {
		index = dpaa2_flow_extract_search(
				&priv->extract.qos_key_extract.dpkg,
				NET_PROT_IP, NH_FLD_IP_DST);
		if (index < 0) {
			if (mask_ipv4)
				size = NH_FLD_IPV4_ADDR_SIZE;
			else
				size = NH_FLD_IPV6_ADDR_SIZE;
			ret = dpaa2_flow_extract_add(
							&priv->extract.qos_key_extract,
							NET_PROT_IP,
							NH_FLD_IP_DST,
							size);
			if (ret) {
				DPAA2_PMD_ERR("QoS Extract add IP_DST failed.");

				return -1;
			}
			local_cfg |= (DPAA2_QOS_TABLE_RECONFIGURE |
				DPAA2_QOS_TABLE_IPADDR_EXTRACT);
		}

		index = dpaa2_flow_extract_search(
				&priv->extract.tc_key_extract[group].dpkg,
				NET_PROT_IP, NH_FLD_IP_DST);
		if (index < 0) {
			if (mask_ipv4)
				size = NH_FLD_IPV4_ADDR_SIZE;
			else
				size = NH_FLD_IPV6_ADDR_SIZE;
			ret = dpaa2_flow_extract_add(
							&priv->extract.tc_key_extract[group],
							NET_PROT_IP,
							NH_FLD_IP_DST,
							size);
			if (ret) {
				DPAA2_PMD_ERR("FS Extract add IP_DST failed.");

				return -1;
			}
			local_cfg |= (DPAA2_FS_TABLE_RECONFIGURE |
				DPAA2_FS_TABLE_IPADDR_EXTRACT);
		}

		if (spec_ipv4)
			key = &spec_ipv4->hdr.dst_addr;
		else
			key = spec_ipv6->hdr.dst_addr;
		if (mask_ipv4) {
			mask = &mask_ipv4->hdr.dst_addr;
			size = NH_FLD_IPV4_ADDR_SIZE;
			prot = NET_PROT_IPV4;
		} else {
			mask = &mask_ipv6->hdr.dst_addr[0];
			size = NH_FLD_IPV6_ADDR_SIZE;
			prot = NET_PROT_IPV6;
		}

		ret = dpaa2_flow_rule_data_set(
				&priv->extract.qos_key_extract,
				&flow->qos_rule,
				prot, NH_FLD_IP_DST,
				key,	mask, size);
		if (ret) {
			DPAA2_PMD_ERR("QoS NH_FLD_IP_DST rule data set failed");
			return -1;
		}

		ret = dpaa2_flow_rule_data_set(
				&priv->extract.tc_key_extract[group],
				&flow->fs_rule,
				prot, NH_FLD_IP_DST,
				key,	mask, size);
		if (ret) {
			DPAA2_PMD_ERR("FS NH_FLD_IP_DST rule data set failed");
			return -1;
		}
		flow->ipaddr_rule.qos_ipdst_offset =
			dpaa2_flow_extract_key_offset(
				&priv->extract.qos_key_extract,
				prot, NH_FLD_IP_DST);
		flow->ipaddr_rule.fs_ipdst_offset =
			dpaa2_flow_extract_key_offset(
				&priv->extract.tc_key_extract[group],
				prot, NH_FLD_IP_DST);
	}

	if ((mask_ipv4 && mask_ipv4->hdr.next_proto_id) ||
		(mask_ipv6 && mask_ipv6->hdr.proto)) {
		index = dpaa2_flow_extract_search(
				&priv->extract.qos_key_extract.dpkg,
				NET_PROT_IP, NH_FLD_IP_PROTO);
		if (index < 0) {
			ret = dpaa2_flow_extract_add(
				&priv->extract.qos_key_extract,
				NET_PROT_IP,
				NH_FLD_IP_PROTO,
				NH_FLD_IP_PROTO_SIZE);
			if (ret) {
				DPAA2_PMD_ERR("QoS Extract add IP_DST failed.");

				return -1;
			}
			local_cfg |= DPAA2_QOS_TABLE_RECONFIGURE;
		}

		index = dpaa2_flow_extract_search(
				&priv->extract.tc_key_extract[group].dpkg,
				NET_PROT_IP, NH_FLD_IP_PROTO);
		if (index < 0) {
			ret = dpaa2_flow_extract_add(
					&priv->extract.tc_key_extract[group],
					NET_PROT_IP,
					NH_FLD_IP_PROTO,
					NH_FLD_IP_PROTO_SIZE);
			if (ret) {
				DPAA2_PMD_ERR("FS Extract add IP_DST failed.");

				return -1;
			}
			local_cfg |= DPAA2_FS_TABLE_RECONFIGURE;
		}

		ret = dpaa2_flow_rule_move_ipaddr_tail(flow, priv, group);
		if (ret) {
			DPAA2_PMD_ERR(
				"Move ipaddr after NH_FLD_IP_PROTO rule set failed");
			return -1;
		}

		if (spec_ipv4)
			key = &spec_ipv4->hdr.next_proto_id;
		else
			key = &spec_ipv6->hdr.proto;
		if (mask_ipv4)
			mask = &mask_ipv4->hdr.next_proto_id;
		else
			mask = &mask_ipv6->hdr.proto;

		ret = dpaa2_flow_rule_data_set(
				&priv->extract.qos_key_extract,
				&flow->qos_rule,
				NET_PROT_IP,
				NH_FLD_IP_PROTO,
				key,	mask, NH_FLD_IP_PROTO_SIZE);
		if (ret) {
			DPAA2_PMD_ERR("QoS NH_FLD_IP_PROTO rule data set failed");
			return -1;
		}

		ret = dpaa2_flow_rule_data_set(
				&priv->extract.tc_key_extract[group],
				&flow->fs_rule,
				NET_PROT_IP,
				NH_FLD_IP_PROTO,
				key,	mask, NH_FLD_IP_PROTO_SIZE);
		if (ret) {
			DPAA2_PMD_ERR("FS NH_FLD_IP_PROTO rule data set failed");
			return -1;
		}
	}

	(*device_configured) |= local_cfg;

	return 0;
}

static int
dpaa2_configure_flow_icmp(struct rte_flow *flow,
			  struct rte_eth_dev *dev,
			  const struct rte_flow_attr *attr,
			  const struct rte_flow_item *pattern,
			  const struct rte_flow_action actions[] __rte_unused,
			  struct rte_flow_error *error __rte_unused,
			  int *device_configured)
{
	int index, ret;
	int local_cfg = 0;
	uint32_t group;
	const struct rte_flow_item_icmp *spec, *mask;

	const struct rte_flow_item_icmp *last __rte_unused;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;

	group = attr->group;

	/* Parse pattern list to get the matching parameters */
	spec    = (const struct rte_flow_item_icmp *)pattern->spec;
	last    = (const struct rte_flow_item_icmp *)pattern->last;
	mask    = (const struct rte_flow_item_icmp *)
		(pattern->mask ? pattern->mask : &dpaa2_flow_item_icmp_mask);

	/* Get traffic class index and flow id to be configured */
	flow->tc_id = group;
	flow->tc_index = attr->priority;

	if (!spec) {
		/* Don't care any field of ICMP header,
		 * only care ICMP protocol.
		 * Example: flow create 0 ingress pattern icmp /
		 */
		/* Next proto of Generical IP is actually used
		 * for ICMP identification.
		 */
		struct proto_discrimination proto;

		index = dpaa2_flow_extract_search(
				&priv->extract.qos_key_extract.dpkg,
				NET_PROT_IP, NH_FLD_IP_PROTO);
		if (index < 0) {
			ret = dpaa2_flow_proto_discrimination_extract(
					&priv->extract.qos_key_extract,
					DPAA2_FLOW_ITEM_TYPE_GENERIC_IP);
			if (ret) {
				DPAA2_PMD_ERR(
					"QoS Extract IP protocol to discriminate ICMP failed.");

				return -1;
			}
			local_cfg |= DPAA2_QOS_TABLE_RECONFIGURE;
		}

		index = dpaa2_flow_extract_search(
				&priv->extract.tc_key_extract[group].dpkg,
				NET_PROT_IP, NH_FLD_IP_PROTO);
		if (index < 0) {
			ret = dpaa2_flow_proto_discrimination_extract(
					&priv->extract.tc_key_extract[group],
					DPAA2_FLOW_ITEM_TYPE_GENERIC_IP);
			if (ret) {
				DPAA2_PMD_ERR(
					"FS Extract IP protocol to discriminate ICMP failed.");

				return -1;
			}
			local_cfg |= DPAA2_FS_TABLE_RECONFIGURE;
		}

		ret = dpaa2_flow_rule_move_ipaddr_tail(flow, priv, group);
		if (ret) {
			DPAA2_PMD_ERR(
				"Move IP addr before ICMP discrimination set failed");
			return -1;
		}

		proto.type = DPAA2_FLOW_ITEM_TYPE_GENERIC_IP;
		proto.ip_proto = IPPROTO_ICMP;
		ret = dpaa2_flow_proto_discrimination_rule(priv, flow, proto, group);
		if (ret) {
			DPAA2_PMD_ERR("ICMP discrimination rule set failed");
			return -1;
		}

		(*device_configured) |= local_cfg;

		return 0;
	}

	if (dpaa2_flow_extract_support((const uint8_t *)mask,
		RTE_FLOW_ITEM_TYPE_ICMP)) {
		DPAA2_PMD_WARN("Extract field(s) of ICMP not support.");

		return -1;
	}

	if (mask->hdr.icmp_type) {
		index = dpaa2_flow_extract_search(
				&priv->extract.qos_key_extract.dpkg,
				NET_PROT_ICMP, NH_FLD_ICMP_TYPE);
		if (index < 0) {
			ret = dpaa2_flow_extract_add(
					&priv->extract.qos_key_extract,
					NET_PROT_ICMP,
					NH_FLD_ICMP_TYPE,
					NH_FLD_ICMP_TYPE_SIZE);
			if (ret) {
				DPAA2_PMD_ERR("QoS Extract add ICMP_TYPE failed.");

				return -1;
			}
			local_cfg |= DPAA2_QOS_TABLE_RECONFIGURE;
		}

		index = dpaa2_flow_extract_search(
				&priv->extract.tc_key_extract[group].dpkg,
				NET_PROT_ICMP, NH_FLD_ICMP_TYPE);
		if (index < 0) {
			ret = dpaa2_flow_extract_add(
					&priv->extract.tc_key_extract[group],
					NET_PROT_ICMP,
					NH_FLD_ICMP_TYPE,
					NH_FLD_ICMP_TYPE_SIZE);
			if (ret) {
				DPAA2_PMD_ERR("FS Extract add ICMP_TYPE failed.");

				return -1;
			}
			local_cfg |= DPAA2_FS_TABLE_RECONFIGURE;
		}

		ret = dpaa2_flow_rule_move_ipaddr_tail(flow, priv, group);
		if (ret) {
			DPAA2_PMD_ERR(
				"Move ipaddr before ICMP TYPE set failed");
			return -1;
		}

		ret = dpaa2_flow_rule_data_set(
				&priv->extract.qos_key_extract,
				&flow->qos_rule,
				NET_PROT_ICMP,
				NH_FLD_ICMP_TYPE,
				&spec->hdr.icmp_type,
				&mask->hdr.icmp_type,
				NH_FLD_ICMP_TYPE_SIZE);
		if (ret) {
			DPAA2_PMD_ERR("QoS NH_FLD_ICMP_TYPE rule data set failed");
			return -1;
		}

		ret = dpaa2_flow_rule_data_set(
				&priv->extract.tc_key_extract[group],
				&flow->fs_rule,
				NET_PROT_ICMP,
				NH_FLD_ICMP_TYPE,
				&spec->hdr.icmp_type,
				&mask->hdr.icmp_type,
				NH_FLD_ICMP_TYPE_SIZE);
		if (ret) {
			DPAA2_PMD_ERR("FS NH_FLD_ICMP_TYPE rule data set failed");
			return -1;
		}
	}

	if (mask->hdr.icmp_code) {
		index = dpaa2_flow_extract_search(
				&priv->extract.qos_key_extract.dpkg,
				NET_PROT_ICMP, NH_FLD_ICMP_CODE);
		if (index < 0) {
			ret = dpaa2_flow_extract_add(
					&priv->extract.qos_key_extract,
					NET_PROT_ICMP,
					NH_FLD_ICMP_CODE,
					NH_FLD_ICMP_CODE_SIZE);
			if (ret) {
				DPAA2_PMD_ERR("QoS Extract add ICMP_CODE failed.");

				return -1;
			}
			local_cfg |= DPAA2_QOS_TABLE_RECONFIGURE;
		}

		index = dpaa2_flow_extract_search(
				&priv->extract.tc_key_extract[group].dpkg,
				NET_PROT_ICMP, NH_FLD_ICMP_CODE);
		if (index < 0) {
			ret = dpaa2_flow_extract_add(
					&priv->extract.tc_key_extract[group],
					NET_PROT_ICMP,
					NH_FLD_ICMP_CODE,
					NH_FLD_ICMP_CODE_SIZE);
			if (ret) {
				DPAA2_PMD_ERR("FS Extract add ICMP_CODE failed.");

				return -1;
			}
			local_cfg |= DPAA2_FS_TABLE_RECONFIGURE;
		}

		ret = dpaa2_flow_rule_move_ipaddr_tail(flow, priv, group);
		if (ret) {
			DPAA2_PMD_ERR(
				"Move ipaddr after ICMP CODE set failed");
			return -1;
		}

		ret = dpaa2_flow_rule_data_set(
				&priv->extract.qos_key_extract,
				&flow->qos_rule,
				NET_PROT_ICMP,
				NH_FLD_ICMP_CODE,
				&spec->hdr.icmp_code,
				&mask->hdr.icmp_code,
				NH_FLD_ICMP_CODE_SIZE);
		if (ret) {
			DPAA2_PMD_ERR("QoS NH_FLD_ICMP_CODE rule data set failed");
			return -1;
		}

		ret = dpaa2_flow_rule_data_set(
				&priv->extract.tc_key_extract[group],
				&flow->fs_rule,
				NET_PROT_ICMP,
				NH_FLD_ICMP_CODE,
				&spec->hdr.icmp_code,
				&mask->hdr.icmp_code,
				NH_FLD_ICMP_CODE_SIZE);
		if (ret) {
			DPAA2_PMD_ERR("FS NH_FLD_ICMP_CODE rule data set failed");
			return -1;
		}
	}

	(*device_configured) |= local_cfg;

	return 0;
}

static int
dpaa2_configure_flow_udp(struct rte_flow *flow,
			 struct rte_eth_dev *dev,
			  const struct rte_flow_attr *attr,
			  const struct rte_flow_item *pattern,
			  const struct rte_flow_action actions[] __rte_unused,
			  struct rte_flow_error *error __rte_unused,
			  int *device_configured)
{
	int index, ret;
	int local_cfg = 0;
	uint32_t group;
	const struct rte_flow_item_udp *spec, *mask;

	const struct rte_flow_item_udp *last __rte_unused;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;

	group = attr->group;

	/* Parse pattern list to get the matching parameters */
	spec    = (const struct rte_flow_item_udp *)pattern->spec;
	last    = (const struct rte_flow_item_udp *)pattern->last;
	mask    = (const struct rte_flow_item_udp *)
		(pattern->mask ? pattern->mask : &dpaa2_flow_item_udp_mask);

	/* Get traffic class index and flow id to be configured */
	flow->tc_id = group;
	flow->tc_index = attr->priority;

	if (!spec || !mc_l4_port_identification) {
		struct proto_discrimination proto;

		index = dpaa2_flow_extract_search(
				&priv->extract.qos_key_extract.dpkg,
				NET_PROT_IP, NH_FLD_IP_PROTO);
		if (index < 0) {
			ret = dpaa2_flow_proto_discrimination_extract(
					&priv->extract.qos_key_extract,
					DPAA2_FLOW_ITEM_TYPE_GENERIC_IP);
			if (ret) {
				DPAA2_PMD_ERR(
					"QoS Extract IP protocol to discriminate UDP failed.");

				return -1;
			}
			local_cfg |= DPAA2_QOS_TABLE_RECONFIGURE;
		}

		index = dpaa2_flow_extract_search(
				&priv->extract.tc_key_extract[group].dpkg,
				NET_PROT_IP, NH_FLD_IP_PROTO);
		if (index < 0) {
			ret = dpaa2_flow_proto_discrimination_extract(
				&priv->extract.tc_key_extract[group],
				DPAA2_FLOW_ITEM_TYPE_GENERIC_IP);
			if (ret) {
				DPAA2_PMD_ERR(
					"FS Extract IP protocol to discriminate UDP failed.");

				return -1;
			}
			local_cfg |= DPAA2_FS_TABLE_RECONFIGURE;
		}

		ret = dpaa2_flow_rule_move_ipaddr_tail(flow, priv, group);
		if (ret) {
			DPAA2_PMD_ERR(
				"Move IP addr before UDP discrimination set failed");
			return -1;
		}

		proto.type = DPAA2_FLOW_ITEM_TYPE_GENERIC_IP;
		proto.ip_proto = IPPROTO_UDP;
		ret = dpaa2_flow_proto_discrimination_rule(priv, flow, proto, group);
		if (ret) {
			DPAA2_PMD_ERR("UDP discrimination rule set failed");
			return -1;
		}

		(*device_configured) |= local_cfg;

		if (!spec)
			return 0;
	}

	if (dpaa2_flow_extract_support((const uint8_t *)mask,
		RTE_FLOW_ITEM_TYPE_UDP)) {
		DPAA2_PMD_WARN("Extract field(s) of UDP not support.");

		return -1;
	}

	if (mask->hdr.src_port) {
		index = dpaa2_flow_extract_search(
				&priv->extract.qos_key_extract.dpkg,
				NET_PROT_UDP, NH_FLD_UDP_PORT_SRC);
		if (index < 0) {
			ret = dpaa2_flow_extract_add(&priv->extract.qos_key_extract,
				NET_PROT_UDP,
				NH_FLD_UDP_PORT_SRC,
				NH_FLD_UDP_PORT_SIZE);
			if (ret) {
				DPAA2_PMD_ERR("QoS Extract add UDP_SRC failed.");

				return -1;
			}
			local_cfg |= DPAA2_QOS_TABLE_RECONFIGURE;
		}

		index = dpaa2_flow_extract_search(
				&priv->extract.tc_key_extract[group].dpkg,
				NET_PROT_UDP, NH_FLD_UDP_PORT_SRC);
		if (index < 0) {
			ret = dpaa2_flow_extract_add(
					&priv->extract.tc_key_extract[group],
					NET_PROT_UDP,
					NH_FLD_UDP_PORT_SRC,
					NH_FLD_UDP_PORT_SIZE);
			if (ret) {
				DPAA2_PMD_ERR("FS Extract add UDP_SRC failed.");

				return -1;
			}
			local_cfg |= DPAA2_FS_TABLE_RECONFIGURE;
		}

		ret = dpaa2_flow_rule_move_ipaddr_tail(flow, priv, group);
		if (ret) {
			DPAA2_PMD_ERR(
				"Move ipaddr before UDP_PORT_SRC set failed");
			return -1;
		}

		ret = dpaa2_flow_rule_data_set(&priv->extract.qos_key_extract,
				&flow->qos_rule,
				NET_PROT_UDP,
				NH_FLD_UDP_PORT_SRC,
				&spec->hdr.src_port,
				&mask->hdr.src_port,
				NH_FLD_UDP_PORT_SIZE);
		if (ret) {
			DPAA2_PMD_ERR(
				"QoS NH_FLD_UDP_PORT_SRC rule data set failed");
			return -1;
		}

		ret = dpaa2_flow_rule_data_set(
				&priv->extract.tc_key_extract[group],
				&flow->fs_rule,
				NET_PROT_UDP,
				NH_FLD_UDP_PORT_SRC,
				&spec->hdr.src_port,
				&mask->hdr.src_port,
				NH_FLD_UDP_PORT_SIZE);
		if (ret) {
			DPAA2_PMD_ERR(
				"FS NH_FLD_UDP_PORT_SRC rule data set failed");
			return -1;
		}
	}

	if (mask->hdr.dst_port) {
		index = dpaa2_flow_extract_search(
				&priv->extract.qos_key_extract.dpkg,
				NET_PROT_UDP, NH_FLD_UDP_PORT_DST);
		if (index < 0) {
			ret = dpaa2_flow_extract_add(
					&priv->extract.qos_key_extract,
					NET_PROT_UDP,
					NH_FLD_UDP_PORT_DST,
					NH_FLD_UDP_PORT_SIZE);
			if (ret) {
				DPAA2_PMD_ERR("QoS Extract add UDP_DST failed.");

				return -1;
			}
			local_cfg |= DPAA2_QOS_TABLE_RECONFIGURE;
		}

		index = dpaa2_flow_extract_search(
				&priv->extract.tc_key_extract[group].dpkg,
				NET_PROT_UDP, NH_FLD_UDP_PORT_DST);
		if (index < 0) {
			ret = dpaa2_flow_extract_add(
					&priv->extract.tc_key_extract[group],
					NET_PROT_UDP,
					NH_FLD_UDP_PORT_DST,
					NH_FLD_UDP_PORT_SIZE);
			if (ret) {
				DPAA2_PMD_ERR("FS Extract add UDP_DST failed.");

				return -1;
			}
			local_cfg |= DPAA2_FS_TABLE_RECONFIGURE;
		}

		ret = dpaa2_flow_rule_move_ipaddr_tail(flow, priv, group);
		if (ret) {
			DPAA2_PMD_ERR(
				"Move ipaddr before UDP_PORT_DST set failed");
			return -1;
		}

		ret = dpaa2_flow_rule_data_set(
				&priv->extract.qos_key_extract,
				&flow->qos_rule,
				NET_PROT_UDP,
				NH_FLD_UDP_PORT_DST,
				&spec->hdr.dst_port,
				&mask->hdr.dst_port,
				NH_FLD_UDP_PORT_SIZE);
		if (ret) {
			DPAA2_PMD_ERR(
				"QoS NH_FLD_UDP_PORT_DST rule data set failed");
			return -1;
		}

		ret = dpaa2_flow_rule_data_set(
				&priv->extract.tc_key_extract[group],
				&flow->fs_rule,
				NET_PROT_UDP,
				NH_FLD_UDP_PORT_DST,
				&spec->hdr.dst_port,
				&mask->hdr.dst_port,
				NH_FLD_UDP_PORT_SIZE);
		if (ret) {
			DPAA2_PMD_ERR(
				"FS NH_FLD_UDP_PORT_DST rule data set failed");
			return -1;
		}
	}

	(*device_configured) |= local_cfg;

	return 0;
}

static int
dpaa2_configure_flow_tcp(struct rte_flow *flow,
			 struct rte_eth_dev *dev,
			 const struct rte_flow_attr *attr,
			 const struct rte_flow_item *pattern,
			 const struct rte_flow_action actions[] __rte_unused,
			 struct rte_flow_error *error __rte_unused,
			 int *device_configured)
{
	int index, ret;
	int local_cfg = 0;
	uint32_t group;
	const struct rte_flow_item_tcp *spec, *mask;

	const struct rte_flow_item_tcp *last __rte_unused;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;

	group = attr->group;

	/* Parse pattern list to get the matching parameters */
	spec    = (const struct rte_flow_item_tcp *)pattern->spec;
	last    = (const struct rte_flow_item_tcp *)pattern->last;
	mask    = (const struct rte_flow_item_tcp *)
		(pattern->mask ? pattern->mask : &dpaa2_flow_item_tcp_mask);

	/* Get traffic class index and flow id to be configured */
	flow->tc_id = group;
	flow->tc_index = attr->priority;

	if (!spec || !mc_l4_port_identification) {
		struct proto_discrimination proto;

		index = dpaa2_flow_extract_search(
				&priv->extract.qos_key_extract.dpkg,
				NET_PROT_IP, NH_FLD_IP_PROTO);
		if (index < 0) {
			ret = dpaa2_flow_proto_discrimination_extract(
					&priv->extract.qos_key_extract,
					DPAA2_FLOW_ITEM_TYPE_GENERIC_IP);
			if (ret) {
				DPAA2_PMD_ERR(
					"QoS Extract IP protocol to discriminate TCP failed.");

				return -1;
			}
			local_cfg |= DPAA2_QOS_TABLE_RECONFIGURE;
		}

		index = dpaa2_flow_extract_search(
				&priv->extract.tc_key_extract[group].dpkg,
				NET_PROT_IP, NH_FLD_IP_PROTO);
		if (index < 0) {
			ret = dpaa2_flow_proto_discrimination_extract(
				&priv->extract.tc_key_extract[group],
				DPAA2_FLOW_ITEM_TYPE_GENERIC_IP);
			if (ret) {
				DPAA2_PMD_ERR(
					"FS Extract IP protocol to discriminate TCP failed.");

				return -1;
			}
			local_cfg |= DPAA2_FS_TABLE_RECONFIGURE;
		}

		ret = dpaa2_flow_rule_move_ipaddr_tail(flow, priv, group);
		if (ret) {
			DPAA2_PMD_ERR(
				"Move IP addr before TCP discrimination set failed");
			return -1;
		}

		proto.type = DPAA2_FLOW_ITEM_TYPE_GENERIC_IP;
		proto.ip_proto = IPPROTO_TCP;
		ret = dpaa2_flow_proto_discrimination_rule(priv, flow, proto, group);
		if (ret) {
			DPAA2_PMD_ERR("TCP discrimination rule set failed");
			return -1;
		}

		(*device_configured) |= local_cfg;

		if (!spec)
			return 0;
	}

	if (dpaa2_flow_extract_support((const uint8_t *)mask,
		RTE_FLOW_ITEM_TYPE_TCP)) {
		DPAA2_PMD_WARN("Extract field(s) of TCP not support.");

		return -1;
	}

	if (mask->hdr.src_port) {
		index = dpaa2_flow_extract_search(
				&priv->extract.qos_key_extract.dpkg,
				NET_PROT_TCP, NH_FLD_TCP_PORT_SRC);
		if (index < 0) {
			ret = dpaa2_flow_extract_add(
					&priv->extract.qos_key_extract,
					NET_PROT_TCP,
					NH_FLD_TCP_PORT_SRC,
					NH_FLD_TCP_PORT_SIZE);
			if (ret) {
				DPAA2_PMD_ERR("QoS Extract add TCP_SRC failed.");

				return -1;
			}
			local_cfg |= DPAA2_QOS_TABLE_RECONFIGURE;
		}

		index = dpaa2_flow_extract_search(
				&priv->extract.tc_key_extract[group].dpkg,
				NET_PROT_TCP, NH_FLD_TCP_PORT_SRC);
		if (index < 0) {
			ret = dpaa2_flow_extract_add(
					&priv->extract.tc_key_extract[group],
					NET_PROT_TCP,
					NH_FLD_TCP_PORT_SRC,
					NH_FLD_TCP_PORT_SIZE);
			if (ret) {
				DPAA2_PMD_ERR("FS Extract add TCP_SRC failed.");

				return -1;
			}
			local_cfg |= DPAA2_FS_TABLE_RECONFIGURE;
		}

		ret = dpaa2_flow_rule_move_ipaddr_tail(flow, priv, group);
		if (ret) {
			DPAA2_PMD_ERR(
				"Move ipaddr before TCP_PORT_SRC set failed");
			return -1;
		}

		ret = dpaa2_flow_rule_data_set(
				&priv->extract.qos_key_extract,
				&flow->qos_rule,
				NET_PROT_TCP,
				NH_FLD_TCP_PORT_SRC,
				&spec->hdr.src_port,
				&mask->hdr.src_port,
				NH_FLD_TCP_PORT_SIZE);
		if (ret) {
			DPAA2_PMD_ERR(
				"QoS NH_FLD_TCP_PORT_SRC rule data set failed");
			return -1;
		}

		ret = dpaa2_flow_rule_data_set(
				&priv->extract.tc_key_extract[group],
				&flow->fs_rule,
				NET_PROT_TCP,
				NH_FLD_TCP_PORT_SRC,
				&spec->hdr.src_port,
				&mask->hdr.src_port,
				NH_FLD_TCP_PORT_SIZE);
		if (ret) {
			DPAA2_PMD_ERR(
				"FS NH_FLD_TCP_PORT_SRC rule data set failed");
			return -1;
		}
	}

	if (mask->hdr.dst_port) {
		index = dpaa2_flow_extract_search(
				&priv->extract.qos_key_extract.dpkg,
				NET_PROT_TCP, NH_FLD_TCP_PORT_DST);
		if (index < 0) {
			ret = dpaa2_flow_extract_add(
					&priv->extract.qos_key_extract,
					NET_PROT_TCP,
					NH_FLD_TCP_PORT_DST,
					NH_FLD_TCP_PORT_SIZE);
			if (ret) {
				DPAA2_PMD_ERR("QoS Extract add TCP_DST failed.");

				return -1;
			}
			local_cfg |= DPAA2_QOS_TABLE_RECONFIGURE;
		}

		index = dpaa2_flow_extract_search(
				&priv->extract.tc_key_extract[group].dpkg,
				NET_PROT_TCP, NH_FLD_TCP_PORT_DST);
		if (index < 0) {
			ret = dpaa2_flow_extract_add(
					&priv->extract.tc_key_extract[group],
					NET_PROT_TCP,
					NH_FLD_TCP_PORT_DST,
					NH_FLD_TCP_PORT_SIZE);
			if (ret) {
				DPAA2_PMD_ERR("FS Extract add TCP_DST failed.");

				return -1;
			}
			local_cfg |= DPAA2_FS_TABLE_RECONFIGURE;
		}

		ret = dpaa2_flow_rule_move_ipaddr_tail(flow, priv, group);
		if (ret) {
			DPAA2_PMD_ERR(
				"Move ipaddr before TCP_PORT_DST set failed");
			return -1;
		}

		ret = dpaa2_flow_rule_data_set(
				&priv->extract.qos_key_extract,
				&flow->qos_rule,
				NET_PROT_TCP,
				NH_FLD_TCP_PORT_DST,
				&spec->hdr.dst_port,
				&mask->hdr.dst_port,
				NH_FLD_TCP_PORT_SIZE);
		if (ret) {
			DPAA2_PMD_ERR(
				"QoS NH_FLD_TCP_PORT_DST rule data set failed");
			return -1;
		}

		ret = dpaa2_flow_rule_data_set(
				&priv->extract.tc_key_extract[group],
				&flow->fs_rule,
				NET_PROT_TCP,
				NH_FLD_TCP_PORT_DST,
				&spec->hdr.dst_port,
				&mask->hdr.dst_port,
				NH_FLD_TCP_PORT_SIZE);
		if (ret) {
			DPAA2_PMD_ERR(
				"FS NH_FLD_TCP_PORT_DST rule data set failed");
			return -1;
		}
	}

	(*device_configured) |= local_cfg;

	return 0;
}

static int
dpaa2_configure_flow_sctp(struct rte_flow *flow,
			  struct rte_eth_dev *dev,
			  const struct rte_flow_attr *attr,
			  const struct rte_flow_item *pattern,
			  const struct rte_flow_action actions[] __rte_unused,
			  struct rte_flow_error *error __rte_unused,
			  int *device_configured)
{
	int index, ret;
	int local_cfg = 0;
	uint32_t group;
	const struct rte_flow_item_sctp *spec, *mask;

	const struct rte_flow_item_sctp *last __rte_unused;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;

	group = attr->group;

	/* Parse pattern list to get the matching parameters */
	spec    = (const struct rte_flow_item_sctp *)pattern->spec;
	last    = (const struct rte_flow_item_sctp *)pattern->last;
	mask    = (const struct rte_flow_item_sctp *)
			(pattern->mask ? pattern->mask : &dpaa2_flow_item_sctp_mask);

	/* Get traffic class index and flow id to be configured */
	flow->tc_id = group;
	flow->tc_index = attr->priority;

	if (!spec || !mc_l4_port_identification) {
		struct proto_discrimination proto;

		index = dpaa2_flow_extract_search(
				&priv->extract.qos_key_extract.dpkg,
				NET_PROT_IP, NH_FLD_IP_PROTO);
		if (index < 0) {
			ret = dpaa2_flow_proto_discrimination_extract(
					&priv->extract.qos_key_extract,
					DPAA2_FLOW_ITEM_TYPE_GENERIC_IP);
			if (ret) {
				DPAA2_PMD_ERR(
					"QoS Extract IP protocol to discriminate SCTP failed.");

				return -1;
			}
			local_cfg |= DPAA2_QOS_TABLE_RECONFIGURE;
		}

		index = dpaa2_flow_extract_search(
				&priv->extract.tc_key_extract[group].dpkg,
				NET_PROT_IP, NH_FLD_IP_PROTO);
		if (index < 0) {
			ret = dpaa2_flow_proto_discrimination_extract(
					&priv->extract.tc_key_extract[group],
					DPAA2_FLOW_ITEM_TYPE_GENERIC_IP);
			if (ret) {
				DPAA2_PMD_ERR(
					"FS Extract IP protocol to discriminate SCTP failed.");

				return -1;
			}
			local_cfg |= DPAA2_FS_TABLE_RECONFIGURE;
		}

		ret = dpaa2_flow_rule_move_ipaddr_tail(flow, priv, group);
		if (ret) {
			DPAA2_PMD_ERR(
				"Move ipaddr before SCTP discrimination set failed");
			return -1;
		}

		proto.type = DPAA2_FLOW_ITEM_TYPE_GENERIC_IP;
		proto.ip_proto = IPPROTO_SCTP;
		ret = dpaa2_flow_proto_discrimination_rule(priv, flow, proto, group);
		if (ret) {
			DPAA2_PMD_ERR("SCTP discrimination rule set failed");
			return -1;
		}

		(*device_configured) |= local_cfg;

		if (!spec)
			return 0;
	}

	if (dpaa2_flow_extract_support((const uint8_t *)mask,
		RTE_FLOW_ITEM_TYPE_SCTP)) {
		DPAA2_PMD_WARN("Extract field(s) of SCTP not support.");

		return -1;
	}

	if (mask->hdr.src_port) {
		index = dpaa2_flow_extract_search(
				&priv->extract.qos_key_extract.dpkg,
				NET_PROT_SCTP, NH_FLD_SCTP_PORT_SRC);
		if (index < 0) {
			ret = dpaa2_flow_extract_add(
					&priv->extract.qos_key_extract,
					NET_PROT_SCTP,
					NH_FLD_SCTP_PORT_SRC,
					NH_FLD_SCTP_PORT_SIZE);
			if (ret) {
				DPAA2_PMD_ERR("QoS Extract add SCTP_SRC failed.");

				return -1;
			}
			local_cfg |= DPAA2_QOS_TABLE_RECONFIGURE;
		}

		index = dpaa2_flow_extract_search(
				&priv->extract.tc_key_extract[group].dpkg,
				NET_PROT_SCTP, NH_FLD_SCTP_PORT_SRC);
		if (index < 0) {
			ret = dpaa2_flow_extract_add(
					&priv->extract.tc_key_extract[group],
					NET_PROT_SCTP,
					NH_FLD_SCTP_PORT_SRC,
					NH_FLD_SCTP_PORT_SIZE);
			if (ret) {
				DPAA2_PMD_ERR("FS Extract add SCTP_SRC failed.");

				return -1;
			}
			local_cfg |= DPAA2_FS_TABLE_RECONFIGURE;
		}

		ret = dpaa2_flow_rule_move_ipaddr_tail(flow, priv, group);
		if (ret) {
			DPAA2_PMD_ERR(
				"Move ipaddr before SCTP_PORT_SRC set failed");
			return -1;
		}

		ret = dpaa2_flow_rule_data_set(
				&priv->extract.qos_key_extract,
				&flow->qos_rule,
				NET_PROT_SCTP,
				NH_FLD_SCTP_PORT_SRC,
				&spec->hdr.src_port,
				&mask->hdr.src_port,
				NH_FLD_SCTP_PORT_SIZE);
		if (ret) {
			DPAA2_PMD_ERR(
				"QoS NH_FLD_SCTP_PORT_SRC rule data set failed");
			return -1;
		}

		ret = dpaa2_flow_rule_data_set(
				&priv->extract.tc_key_extract[group],
				&flow->fs_rule,
				NET_PROT_SCTP,
				NH_FLD_SCTP_PORT_SRC,
				&spec->hdr.src_port,
				&mask->hdr.src_port,
				NH_FLD_SCTP_PORT_SIZE);
		if (ret) {
			DPAA2_PMD_ERR(
				"FS NH_FLD_SCTP_PORT_SRC rule data set failed");
			return -1;
		}
	}

	if (mask->hdr.dst_port) {
		index = dpaa2_flow_extract_search(
				&priv->extract.qos_key_extract.dpkg,
				NET_PROT_SCTP, NH_FLD_SCTP_PORT_DST);
		if (index < 0) {
			ret = dpaa2_flow_extract_add(
					&priv->extract.qos_key_extract,
					NET_PROT_SCTP,
					NH_FLD_SCTP_PORT_DST,
					NH_FLD_SCTP_PORT_SIZE);
			if (ret) {
				DPAA2_PMD_ERR("QoS Extract add SCTP_DST failed.");

				return -1;
			}
			local_cfg |= DPAA2_QOS_TABLE_RECONFIGURE;
		}

		index = dpaa2_flow_extract_search(
				&priv->extract.tc_key_extract[group].dpkg,
				NET_PROT_SCTP, NH_FLD_SCTP_PORT_DST);
		if (index < 0) {
			ret = dpaa2_flow_extract_add(
					&priv->extract.tc_key_extract[group],
					NET_PROT_SCTP,
					NH_FLD_SCTP_PORT_DST,
					NH_FLD_SCTP_PORT_SIZE);
			if (ret) {
				DPAA2_PMD_ERR("FS Extract add SCTP_DST failed.");

				return -1;
			}
			local_cfg |= DPAA2_FS_TABLE_RECONFIGURE;
		}

		ret = dpaa2_flow_rule_move_ipaddr_tail(flow, priv, group);
		if (ret) {
			DPAA2_PMD_ERR(
				"Move ipaddr before SCTP_PORT_DST set failed");
			return -1;
		}

		ret = dpaa2_flow_rule_data_set(
				&priv->extract.qos_key_extract,
				&flow->qos_rule,
				NET_PROT_SCTP,
				NH_FLD_SCTP_PORT_DST,
				&spec->hdr.dst_port,
				&mask->hdr.dst_port,
				NH_FLD_SCTP_PORT_SIZE);
		if (ret) {
			DPAA2_PMD_ERR(
				"QoS NH_FLD_SCTP_PORT_DST rule data set failed");
			return -1;
		}

		ret = dpaa2_flow_rule_data_set(
				&priv->extract.tc_key_extract[group],
				&flow->fs_rule,
				NET_PROT_SCTP,
				NH_FLD_SCTP_PORT_DST,
				&spec->hdr.dst_port,
				&mask->hdr.dst_port,
				NH_FLD_SCTP_PORT_SIZE);
		if (ret) {
			DPAA2_PMD_ERR(
				"FS NH_FLD_SCTP_PORT_DST rule data set failed");
			return -1;
		}
	}

	(*device_configured) |= local_cfg;

	return 0;
}

static int
dpaa2_configure_flow_gre(struct rte_flow *flow,
			 struct rte_eth_dev *dev,
			 const struct rte_flow_attr *attr,
			 const struct rte_flow_item *pattern,
			 const struct rte_flow_action actions[] __rte_unused,
			 struct rte_flow_error *error __rte_unused,
			 int *device_configured)
{
	int index, ret;
	int local_cfg = 0;
	uint32_t group;
	const struct rte_flow_item_gre *spec, *mask;

	const struct rte_flow_item_gre *last __rte_unused;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;

	group = attr->group;

	/* Parse pattern list to get the matching parameters */
	spec    = (const struct rte_flow_item_gre *)pattern->spec;
	last    = (const struct rte_flow_item_gre *)pattern->last;
	mask    = (const struct rte_flow_item_gre *)
		(pattern->mask ? pattern->mask : &dpaa2_flow_item_gre_mask);

	/* Get traffic class index and flow id to be configured */
	flow->tc_id = group;
	flow->tc_index = attr->priority;

	if (!spec) {
		struct proto_discrimination proto;

		index = dpaa2_flow_extract_search(
				&priv->extract.qos_key_extract.dpkg,
				NET_PROT_IP, NH_FLD_IP_PROTO);
		if (index < 0) {
			ret = dpaa2_flow_proto_discrimination_extract(
					&priv->extract.qos_key_extract,
					DPAA2_FLOW_ITEM_TYPE_GENERIC_IP);
			if (ret) {
				DPAA2_PMD_ERR(
					"QoS Extract IP protocol to discriminate GRE failed.");

				return -1;
			}
			local_cfg |= DPAA2_QOS_TABLE_RECONFIGURE;
		}

		index = dpaa2_flow_extract_search(
				&priv->extract.tc_key_extract[group].dpkg,
				NET_PROT_IP, NH_FLD_IP_PROTO);
		if (index < 0) {
			ret = dpaa2_flow_proto_discrimination_extract(
					&priv->extract.tc_key_extract[group],
					DPAA2_FLOW_ITEM_TYPE_GENERIC_IP);
			if (ret) {
				DPAA2_PMD_ERR(
					"FS Extract IP protocol to discriminate GRE failed.");

				return -1;
			}
			local_cfg |= DPAA2_FS_TABLE_RECONFIGURE;
		}

		ret = dpaa2_flow_rule_move_ipaddr_tail(flow, priv, group);
		if (ret) {
			DPAA2_PMD_ERR(
				"Move IP addr before GRE discrimination set failed");
			return -1;
		}

		proto.type = DPAA2_FLOW_ITEM_TYPE_GENERIC_IP;
		proto.ip_proto = IPPROTO_GRE;
		ret = dpaa2_flow_proto_discrimination_rule(priv, flow, proto, group);
		if (ret) {
			DPAA2_PMD_ERR("GRE discrimination rule set failed");
			return -1;
		}

		(*device_configured) |= local_cfg;

		return 0;
	}

	if (dpaa2_flow_extract_support((const uint8_t *)mask,
		RTE_FLOW_ITEM_TYPE_GRE)) {
		DPAA2_PMD_WARN("Extract field(s) of GRE not support.");

		return -1;
	}

	if (!mask->protocol)
		return 0;

	index = dpaa2_flow_extract_search(
			&priv->extract.qos_key_extract.dpkg,
			NET_PROT_GRE, NH_FLD_GRE_TYPE);
	if (index < 0) {
		ret = dpaa2_flow_extract_add(
				&priv->extract.qos_key_extract,
				NET_PROT_GRE,
				NH_FLD_GRE_TYPE,
				sizeof(rte_be16_t));
		if (ret) {
			DPAA2_PMD_ERR("QoS Extract add GRE_TYPE failed.");

			return -1;
		}
		local_cfg |= DPAA2_QOS_TABLE_RECONFIGURE;
	}

	index = dpaa2_flow_extract_search(
			&priv->extract.tc_key_extract[group].dpkg,
			NET_PROT_GRE, NH_FLD_GRE_TYPE);
	if (index < 0) {
		ret = dpaa2_flow_extract_add(
				&priv->extract.tc_key_extract[group],
				NET_PROT_GRE,
				NH_FLD_GRE_TYPE,
				sizeof(rte_be16_t));
		if (ret) {
			DPAA2_PMD_ERR("FS Extract add GRE_TYPE failed.");

			return -1;
		}
		local_cfg |= DPAA2_FS_TABLE_RECONFIGURE;
	}

	ret = dpaa2_flow_rule_move_ipaddr_tail(flow, priv, group);
	if (ret) {
		DPAA2_PMD_ERR(
			"Move ipaddr before GRE_TYPE set failed");
		return -1;
	}

	ret = dpaa2_flow_rule_data_set(
				&priv->extract.qos_key_extract,
				&flow->qos_rule,
				NET_PROT_GRE,
				NH_FLD_GRE_TYPE,
				&spec->protocol,
				&mask->protocol,
				sizeof(rte_be16_t));
	if (ret) {
		DPAA2_PMD_ERR(
			"QoS NH_FLD_GRE_TYPE rule data set failed");
		return -1;
	}

	ret = dpaa2_flow_rule_data_set(
			&priv->extract.tc_key_extract[group],
			&flow->fs_rule,
			NET_PROT_GRE,
			NH_FLD_GRE_TYPE,
			&spec->protocol,
			&mask->protocol,
			sizeof(rte_be16_t));
	if (ret) {
		DPAA2_PMD_ERR(
			"FS NH_FLD_GRE_TYPE rule data set failed");
		return -1;
	}

	(*device_configured) |= local_cfg;

	return 0;
}

/* The existing QoS/FS entry with IP address(es)
 * needs update after
 * new extract(s) are inserted before IP
 * address(es) extract(s).
 */
static int
dpaa2_flow_entry_update(
	struct dpaa2_dev_priv *priv, uint8_t tc_id)
{
	struct rte_flow *curr = LIST_FIRST(&priv->flows);
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)priv->hw;
	int ret;
	int qos_ipsrc_offset = -1, qos_ipdst_offset = -1;
	int fs_ipsrc_offset = -1, fs_ipdst_offset = -1;
	struct dpaa2_key_extract *qos_key_extract =
		&priv->extract.qos_key_extract;
	struct dpaa2_key_extract *tc_key_extract =
		&priv->extract.tc_key_extract[tc_id];
	char ipsrc_key[NH_FLD_IPV6_ADDR_SIZE];
	char ipdst_key[NH_FLD_IPV6_ADDR_SIZE];
	char ipsrc_mask[NH_FLD_IPV6_ADDR_SIZE];
	char ipdst_mask[NH_FLD_IPV6_ADDR_SIZE];
	int extend = -1, extend1, size;

	while (curr) {

		if (curr->ipaddr_rule.ipaddr_type ==
			FLOW_NONE_IPADDR) {
			curr = LIST_NEXT(curr, next);
			continue;
		}

		if (curr->ipaddr_rule.ipaddr_type ==
			FLOW_IPV4_ADDR) {
			qos_ipsrc_offset = qos_key_extract->key_info.ipv4_src_offset;
			qos_ipdst_offset = qos_key_extract->key_info.ipv4_dst_offset;
			fs_ipsrc_offset = tc_key_extract->key_info.ipv4_src_offset;
			fs_ipdst_offset = tc_key_extract->key_info.ipv4_dst_offset;
			size = NH_FLD_IPV4_ADDR_SIZE;
		} else {
			qos_ipsrc_offset = qos_key_extract->key_info.ipv6_src_offset;
			qos_ipdst_offset = qos_key_extract->key_info.ipv6_dst_offset;
			fs_ipsrc_offset = tc_key_extract->key_info.ipv6_src_offset;
			fs_ipdst_offset = tc_key_extract->key_info.ipv6_dst_offset;
			size = NH_FLD_IPV6_ADDR_SIZE;
		}

		ret = dpni_remove_qos_entry(dpni, CMD_PRI_LOW,
				priv->token, &curr->qos_rule);
		if (ret) {
			DPAA2_PMD_ERR("Qos entry remove failed.");
			return -1;
		}

		extend = -1;

		if (curr->ipaddr_rule.qos_ipsrc_offset >= 0) {
			RTE_ASSERT(qos_ipsrc_offset >=
				curr->ipaddr_rule.qos_ipsrc_offset);
			extend1 = qos_ipsrc_offset -
				curr->ipaddr_rule.qos_ipsrc_offset;
			if (extend >= 0)
				RTE_ASSERT(extend == extend1);
			else
				extend = extend1;

			memcpy(ipsrc_key,
				(char *)(size_t)curr->qos_rule.key_iova +
				curr->ipaddr_rule.qos_ipsrc_offset,
				size);
			memset((char *)(size_t)curr->qos_rule.key_iova +
				curr->ipaddr_rule.qos_ipsrc_offset,
				0, size);

			memcpy(ipsrc_mask,
				(char *)(size_t)curr->qos_rule.mask_iova +
				curr->ipaddr_rule.qos_ipsrc_offset,
				size);
			memset((char *)(size_t)curr->qos_rule.mask_iova +
				curr->ipaddr_rule.qos_ipsrc_offset,
				0, size);

			curr->ipaddr_rule.qos_ipsrc_offset = qos_ipsrc_offset;
		}

		if (curr->ipaddr_rule.qos_ipdst_offset >= 0) {
			RTE_ASSERT(qos_ipdst_offset >=
				curr->ipaddr_rule.qos_ipdst_offset);
			extend1 = qos_ipdst_offset -
				curr->ipaddr_rule.qos_ipdst_offset;
			if (extend >= 0)
				RTE_ASSERT(extend == extend1);
			else
				extend = extend1;

			memcpy(ipdst_key,
				(char *)(size_t)curr->qos_rule.key_iova +
				curr->ipaddr_rule.qos_ipdst_offset,
				size);
			memset((char *)(size_t)curr->qos_rule.key_iova +
				curr->ipaddr_rule.qos_ipdst_offset,
				0, size);

			memcpy(ipdst_mask,
				(char *)(size_t)curr->qos_rule.mask_iova +
				curr->ipaddr_rule.qos_ipdst_offset,
				size);
			memset((char *)(size_t)curr->qos_rule.mask_iova +
				curr->ipaddr_rule.qos_ipdst_offset,
				0, size);

			curr->ipaddr_rule.qos_ipdst_offset = qos_ipdst_offset;
		}

		if (curr->ipaddr_rule.qos_ipsrc_offset >= 0) {
			memcpy((char *)(size_t)curr->qos_rule.key_iova +
				curr->ipaddr_rule.qos_ipsrc_offset,
				ipsrc_key,
				size);
			memcpy((char *)(size_t)curr->qos_rule.mask_iova +
				curr->ipaddr_rule.qos_ipsrc_offset,
				ipsrc_mask,
				size);
		}
		if (curr->ipaddr_rule.qos_ipdst_offset >= 0) {
			memcpy((char *)(size_t)curr->qos_rule.key_iova +
				curr->ipaddr_rule.qos_ipdst_offset,
				ipdst_key,
				size);
			memcpy((char *)(size_t)curr->qos_rule.mask_iova +
				curr->ipaddr_rule.qos_ipdst_offset,
				ipdst_mask,
				size);
		}

		if (extend >= 0) {
			curr->qos_rule.key_size += extend;
		}

		ret = dpni_add_qos_entry(dpni, CMD_PRI_LOW,
				priv->token, &curr->qos_rule,
				curr->tc_id, curr->qos_index,
				0, 0);
		if (ret) {
			DPAA2_PMD_ERR("Qos entry update failed.");
			return -1;
		}

		if (curr->action != RTE_FLOW_ACTION_TYPE_QUEUE) {
			curr = LIST_NEXT(curr, next);
			continue;
		}

		extend = -1;

		ret = dpni_remove_fs_entry(dpni, CMD_PRI_LOW,
				priv->token, curr->tc_id, &curr->fs_rule);
		if (ret) {
			DPAA2_PMD_ERR("FS entry remove failed.");
			return -1;
		}

		if (curr->ipaddr_rule.fs_ipsrc_offset >= 0 &&
			tc_id == curr->tc_id) {
			RTE_ASSERT(fs_ipsrc_offset >=
				curr->ipaddr_rule.fs_ipsrc_offset);
			extend1 = fs_ipsrc_offset -
				curr->ipaddr_rule.fs_ipsrc_offset;
			if (extend >= 0)
				RTE_ASSERT(extend == extend1);
			else
				extend = extend1;

			memcpy(ipsrc_key,
				(char *)(size_t)curr->fs_rule.key_iova +
				curr->ipaddr_rule.fs_ipsrc_offset,
				size);
			memset((char *)(size_t)curr->fs_rule.key_iova +
				curr->ipaddr_rule.fs_ipsrc_offset,
				0, size);

			memcpy(ipsrc_mask,
				(char *)(size_t)curr->fs_rule.mask_iova +
				curr->ipaddr_rule.fs_ipsrc_offset,
				size);
			memset((char *)(size_t)curr->fs_rule.mask_iova +
				curr->ipaddr_rule.fs_ipsrc_offset,
				0, size);

			curr->ipaddr_rule.fs_ipsrc_offset = fs_ipsrc_offset;
		}

		if (curr->ipaddr_rule.fs_ipdst_offset >= 0 &&
			tc_id == curr->tc_id) {
			RTE_ASSERT(fs_ipdst_offset >=
				curr->ipaddr_rule.fs_ipdst_offset);
			extend1 = fs_ipdst_offset -
				curr->ipaddr_rule.fs_ipdst_offset;
			if (extend >= 0)
				RTE_ASSERT(extend == extend1);
			else
				extend = extend1;

			memcpy(ipdst_key,
				(char *)(size_t)curr->fs_rule.key_iova +
				curr->ipaddr_rule.fs_ipdst_offset,
				size);
			memset((char *)(size_t)curr->fs_rule.key_iova +
				curr->ipaddr_rule.fs_ipdst_offset,
				0, size);

			memcpy(ipdst_mask,
				(char *)(size_t)curr->fs_rule.mask_iova +
				curr->ipaddr_rule.fs_ipdst_offset,
				size);
			memset((char *)(size_t)curr->fs_rule.mask_iova +
				curr->ipaddr_rule.fs_ipdst_offset,
				0, size);

			curr->ipaddr_rule.fs_ipdst_offset = fs_ipdst_offset;
		}

		if (curr->ipaddr_rule.fs_ipsrc_offset >= 0) {
			memcpy((char *)(size_t)curr->fs_rule.key_iova +
				curr->ipaddr_rule.fs_ipsrc_offset,
				ipsrc_key,
				size);
			memcpy((char *)(size_t)curr->fs_rule.mask_iova +
				curr->ipaddr_rule.fs_ipsrc_offset,
				ipsrc_mask,
				size);
		}
		if (curr->ipaddr_rule.fs_ipdst_offset >= 0) {
			memcpy((char *)(size_t)curr->fs_rule.key_iova +
				curr->ipaddr_rule.fs_ipdst_offset,
				ipdst_key,
				size);
			memcpy((char *)(size_t)curr->fs_rule.mask_iova +
				curr->ipaddr_rule.fs_ipdst_offset,
				ipdst_mask,
				size);
		}

		if (extend >= 0)
			curr->fs_rule.key_size += extend;

		ret = dpni_add_fs_entry(dpni, CMD_PRI_LOW,
				priv->token, curr->tc_id, curr->fs_index,
				&curr->fs_rule, &curr->action_cfg);
		if (ret) {
			DPAA2_PMD_ERR("FS entry update failed.");
			return -1;
		}

		curr = LIST_NEXT(curr, next);
	}

	return 0;
}

static int
dpaa2_generic_flow_set(struct rte_flow *flow,
		       struct rte_eth_dev *dev,
		       const struct rte_flow_attr *attr,
		       const struct rte_flow_item pattern[],
		       const struct rte_flow_action actions[],
		       struct rte_flow_error *error)
{
	const struct rte_flow_action_queue *dest_queue;
	const struct rte_flow_action_rss *rss_conf;
	uint16_t index;
	int is_keycfg_configured = 0, end_of_list = 0;
	int ret = 0, i = 0, j = 0;
	struct dpni_attr nic_attr;
	struct dpni_rx_tc_dist_cfg tc_cfg;
	struct dpni_qos_tbl_cfg qos_cfg;
	struct dpni_fs_action_cfg action;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)priv->hw;
	size_t param;
	struct rte_flow *curr = LIST_FIRST(&priv->flows);

	/* Parse pattern list to get the matching parameters */
	while (!end_of_list) {
		switch (pattern[i].type) {
		case RTE_FLOW_ITEM_TYPE_ETH:
			ret = dpaa2_configure_flow_eth(flow,
					dev,	attr,	&pattern[i], actions, error,
					&is_keycfg_configured);
			if (ret) {
				DPAA2_PMD_ERR("ETH flow configuration failed!");
				return ret;
			}
			break;
		case RTE_FLOW_ITEM_TYPE_VLAN:
			ret = dpaa2_configure_flow_vlan(flow,
					dev,	attr,	&pattern[i], actions, error,
					&is_keycfg_configured);
			if (ret) {
				DPAA2_PMD_ERR("vLan flow configuration failed!");
				return ret;
			}
			break;
		case RTE_FLOW_ITEM_TYPE_IPV4:
		case RTE_FLOW_ITEM_TYPE_IPV6:
			ret = dpaa2_configure_flow_generic_ip(flow,
					dev, attr,	&pattern[i], actions, error,
					&is_keycfg_configured);
			if (ret) {
				DPAA2_PMD_ERR("IP flow configuration failed!");
				return ret;
			}
			break;
		case RTE_FLOW_ITEM_TYPE_ICMP:
			ret = dpaa2_configure_flow_icmp(flow,
					dev, attr, &pattern[i], actions, error,
					&is_keycfg_configured);
			if (ret) {
				DPAA2_PMD_ERR("ICMP flow configuration failed!");
				return ret;
			}
			break;
		case RTE_FLOW_ITEM_TYPE_UDP:
			ret = dpaa2_configure_flow_udp(flow,
					dev, attr, &pattern[i], actions, error,
					&is_keycfg_configured);
			if (ret) {
				DPAA2_PMD_ERR("UDP flow configuration failed!");
				return ret;
			}
			break;
		case RTE_FLOW_ITEM_TYPE_TCP:
			ret = dpaa2_configure_flow_tcp(flow,
					dev, attr, &pattern[i], actions, error,
					&is_keycfg_configured);
			if (ret) {
				DPAA2_PMD_ERR("TCP flow configuration failed!");
				return ret;
			}
			break;
		case RTE_FLOW_ITEM_TYPE_SCTP:
			ret = dpaa2_configure_flow_sctp(flow,
					dev, attr, &pattern[i], actions, error,
					&is_keycfg_configured);
			if (ret) {
				DPAA2_PMD_ERR("SCTP flow configuration failed!");
				return ret;
			}
			break;
		case RTE_FLOW_ITEM_TYPE_GRE:
			ret = dpaa2_configure_flow_gre(flow,
					dev, attr, &pattern[i], actions, error,
					&is_keycfg_configured);
			if (ret) {
				DPAA2_PMD_ERR("GRE flow configuration failed!");
				return ret;
			}
			break;
		case RTE_FLOW_ITEM_TYPE_END:
			end_of_list = 1;
			break; /*End of List*/
		default:
			DPAA2_PMD_ERR("Invalid action type");
			ret = -ENOTSUP;
			break;
		}
		i++;
	}

	/* Let's parse action on matching traffic */
	end_of_list = 0;
	while (!end_of_list) {
		switch (actions[j].type) {
		case RTE_FLOW_ACTION_TYPE_QUEUE:
			dest_queue = (const struct rte_flow_action_queue *)(actions[j].conf);
			flow->flow_id = dest_queue->index;
			flow->action = RTE_FLOW_ACTION_TYPE_QUEUE;
			memset(&action, 0, sizeof(struct dpni_fs_action_cfg));
			action.flow_id = flow->flow_id;
			if (is_keycfg_configured & DPAA2_QOS_TABLE_RECONFIGURE) {
				if (dpkg_prepare_key_cfg(&priv->extract.qos_key_extract.dpkg,
					(uint8_t *)(size_t)priv->extract.qos_extract_param) < 0) {
					DPAA2_PMD_ERR(
					"Unable to prepare extract parameters");
					return -1;
				}

				memset(&qos_cfg, 0, sizeof(struct dpni_qos_tbl_cfg));
				qos_cfg.discard_on_miss = true;
				qos_cfg.keep_entries = true;
				qos_cfg.key_cfg_iova = (size_t)priv->extract.qos_extract_param;
				ret = dpni_set_qos_table(dpni, CMD_PRI_LOW,
						priv->token, &qos_cfg);
				if (ret < 0) {
					DPAA2_PMD_ERR(
					"Distribution cannot be configured.(%d)"
					, ret);
					return -1;
				}
			}
			if (is_keycfg_configured & DPAA2_FS_TABLE_RECONFIGURE) {
				if (dpkg_prepare_key_cfg(
						&priv->extract.tc_key_extract[flow->tc_id].dpkg,
						(uint8_t *)(size_t)priv->extract
						.tc_extract_param[flow->tc_id]) < 0) {
					DPAA2_PMD_ERR(
					"Unable to prepare extract parameters");
					return -1;
				}

				memset(&tc_cfg, 0, sizeof(struct dpni_rx_tc_dist_cfg));
				tc_cfg.dist_size = priv->nb_rx_queues / priv->num_rx_tc;
				tc_cfg.dist_mode = DPNI_DIST_MODE_FS;
				tc_cfg.key_cfg_iova =
					(uint64_t)priv->extract.tc_extract_param[flow->tc_id];
				tc_cfg.fs_cfg.miss_action = DPNI_FS_MISS_DROP;
				tc_cfg.fs_cfg.keep_entries = true;
				ret = dpni_set_rx_tc_dist(dpni, CMD_PRI_LOW,
							 priv->token,
							 flow->tc_id, &tc_cfg);
				if (ret < 0) {
					DPAA2_PMD_ERR(
					"Distribution cannot be configured.(%d)"
					, ret);
					return -1;
				}
			}
			/* Configure QoS table first */
			memset(&nic_attr, 0, sizeof(struct dpni_attr));
			ret = dpni_get_attributes(dpni, CMD_PRI_LOW,
						 priv->token, &nic_attr);
			if (ret < 0) {
				DPAA2_PMD_ERR(
				"Failure to get attribute. dpni@%p err code(%d)\n",
				dpni, ret);
				return ret;
			}

			action.flow_id = action.flow_id % nic_attr.num_rx_tcs;

			if (!priv->qos_index) {
				priv->qos_index = rte_zmalloc(0,
								nic_attr.qos_entries, 64);
			}
			for (index = 0; index < nic_attr.qos_entries; index++) {
				if (!priv->qos_index[index]) {
					priv->qos_index[index] = 1;
					break;
				}
			}
			if (index >= nic_attr.qos_entries) {
				DPAA2_PMD_ERR("QoS table with %d entries full",
					nic_attr.qos_entries);
				return -1;
			}
			flow->qos_rule.key_size = priv->extract
				.qos_key_extract.key_info.key_total_size;
			if (flow->ipaddr_rule.ipaddr_type == FLOW_IPV4_ADDR) {
				if (flow->ipaddr_rule.qos_ipdst_offset >=
					flow->ipaddr_rule.qos_ipsrc_offset) {
					flow->qos_rule.key_size =
						flow->ipaddr_rule.qos_ipdst_offset +
						NH_FLD_IPV4_ADDR_SIZE;
				} else {
					flow->qos_rule.key_size =
						flow->ipaddr_rule.qos_ipsrc_offset +
						NH_FLD_IPV4_ADDR_SIZE;
				}
			} else if (flow->ipaddr_rule.ipaddr_type == FLOW_IPV6_ADDR) {
				if (flow->ipaddr_rule.qos_ipdst_offset >=
					flow->ipaddr_rule.qos_ipsrc_offset) {
					flow->qos_rule.key_size =
						flow->ipaddr_rule.qos_ipdst_offset +
						NH_FLD_IPV6_ADDR_SIZE;
				} else {
					flow->qos_rule.key_size =
						flow->ipaddr_rule.qos_ipsrc_offset +
						NH_FLD_IPV6_ADDR_SIZE;
				}
			}
			ret = dpni_add_qos_entry(dpni, CMD_PRI_LOW,
						priv->token, &flow->qos_rule,
						flow->tc_id, index,
						0, 0);
			if (ret < 0) {
				DPAA2_PMD_ERR(
				"Error in addnig entry to QoS table(%d)", ret);
				priv->qos_index[index] = 0;
				return ret;
			}
			flow->qos_index = index;

			/* Then Configure FS table */
			if (!priv->fs_index) {
				priv->fs_index = rte_zmalloc(0,
								nic_attr.fs_entries, 64);
			}
			for (index = 0; index < nic_attr.fs_entries; index++) {
				if (!priv->fs_index[index]) {
					priv->fs_index[index] = 1;
					break;
				}
			}
			if (index >= nic_attr.fs_entries) {
				DPAA2_PMD_ERR("FS table with %d entries full",
					nic_attr.fs_entries);
				return -1;
			}
			flow->fs_rule.key_size = priv->extract
					.tc_key_extract[attr->group].key_info.key_total_size;
			if (flow->ipaddr_rule.ipaddr_type ==
				FLOW_IPV4_ADDR) {
				if (flow->ipaddr_rule.fs_ipdst_offset >=
					flow->ipaddr_rule.fs_ipsrc_offset) {
					flow->fs_rule.key_size =
						flow->ipaddr_rule.fs_ipdst_offset +
						NH_FLD_IPV4_ADDR_SIZE;
				} else {
					flow->fs_rule.key_size =
						flow->ipaddr_rule.fs_ipsrc_offset +
						NH_FLD_IPV4_ADDR_SIZE;
				}
			} else if (flow->ipaddr_rule.ipaddr_type ==
				FLOW_IPV6_ADDR) {
				if (flow->ipaddr_rule.fs_ipdst_offset >=
					flow->ipaddr_rule.fs_ipsrc_offset) {
					flow->fs_rule.key_size =
						flow->ipaddr_rule.fs_ipdst_offset +
						NH_FLD_IPV6_ADDR_SIZE;
				} else {
					flow->fs_rule.key_size =
						flow->ipaddr_rule.fs_ipsrc_offset +
						NH_FLD_IPV6_ADDR_SIZE;
				}
			}
			ret = dpni_add_fs_entry(dpni, CMD_PRI_LOW, priv->token,
						flow->tc_id, index,
						&flow->fs_rule, &action);
			if (ret < 0) {
				DPAA2_PMD_ERR(
				"Error in adding entry to FS table(%d)", ret);
				priv->fs_index[index] = 0;
				return ret;
			}
			flow->fs_index = index;
			memcpy(&flow->action_cfg, &action,
				sizeof(struct dpni_fs_action_cfg));
			break;
		case RTE_FLOW_ACTION_TYPE_RSS:
			ret = dpni_get_attributes(dpni, CMD_PRI_LOW,
						 priv->token, &nic_attr);
			if (ret < 0) {
				DPAA2_PMD_ERR(
				"Failure to get attribute. dpni@%p err code(%d)\n",
				dpni, ret);
				return ret;
			}
			rss_conf = (const struct rte_flow_action_rss *)(actions[j].conf);
			for (i = 0; i < (int)rss_conf->queue_num; i++) {
				if (rss_conf->queue[i] < (attr->group * nic_attr.num_queues) ||
				    rss_conf->queue[i] >= ((attr->group + 1) * nic_attr.num_queues)) {
					DPAA2_PMD_ERR(
					"Queue/Group combination are not supported\n");
					return -ENOTSUP;
				}
			}

			flow->action = RTE_FLOW_ACTION_TYPE_RSS;
			ret = dpaa2_distset_to_dpkg_profile_cfg(rss_conf->types,
					&priv->extract.tc_key_extract[flow->tc_id].dpkg);
			if (ret < 0) {
				DPAA2_PMD_ERR(
				"unable to set flow distribution.please check queue config\n");
				return ret;
			}

			/* Allocate DMA'ble memory to write the rules */
			param = (size_t)rte_malloc(NULL, 256, 64);
			if (!param) {
				DPAA2_PMD_ERR("Memory allocation failure\n");
				return -1;
			}

			if (dpkg_prepare_key_cfg(
				&priv->extract.tc_key_extract[flow->tc_id].dpkg,
				(uint8_t *)param) < 0) {
				DPAA2_PMD_ERR(
				"Unable to prepare extract parameters");
				rte_free((void *)param);
				return -1;
			}

			memset(&tc_cfg, 0, sizeof(struct dpni_rx_tc_dist_cfg));
			tc_cfg.dist_size = rss_conf->queue_num;
			tc_cfg.dist_mode = DPNI_DIST_MODE_HASH;
			tc_cfg.key_cfg_iova = (size_t)param;
			tc_cfg.fs_cfg.miss_action = DPNI_FS_MISS_DROP;

			ret = dpni_set_rx_tc_dist(dpni, CMD_PRI_LOW,
						 priv->token, flow->tc_id,
						 &tc_cfg);
			if (ret < 0) {
				DPAA2_PMD_ERR(
				"Distribution cannot be configured: %d\n", ret);
				rte_free((void *)param);
				return -1;
			}

			rte_free((void *)param);
			if (is_keycfg_configured & DPAA2_QOS_TABLE_RECONFIGURE) {
				if (dpkg_prepare_key_cfg(
					&priv->extract.qos_key_extract.dpkg,
					(uint8_t *)(size_t)priv->extract.qos_extract_param) < 0) {
					DPAA2_PMD_ERR(
					"Unable to prepare extract parameters");
					return -1;
				}
				memset(&qos_cfg, 0,
					sizeof(struct dpni_qos_tbl_cfg));
				qos_cfg.discard_on_miss = true;
				qos_cfg.keep_entries = true;
				qos_cfg.key_cfg_iova =
					(size_t)priv->extract.qos_extract_param;
				ret = dpni_set_qos_table(dpni, CMD_PRI_LOW,
							 priv->token, &qos_cfg);
				if (ret < 0) {
					DPAA2_PMD_ERR(
					"Distribution can't be configured %d\n",
					ret);
					return -1;
				}
			}

			/* Add Rule into QoS table */
			if (!priv->qos_index) {
				priv->qos_index = rte_zmalloc(0,
						nic_attr.qos_entries, 64);
			}
			for (index = 0; index < nic_attr.qos_entries; index++) {
				if (!priv->qos_index[index]) {
					priv->qos_index[index] = 1;
					break;
				}
			}
			if (index >= nic_attr.qos_entries) {
				DPAA2_PMD_ERR("QoS table with %d entries full",
					nic_attr.qos_entries);
				return -1;
			}
			flow->qos_rule.key_size =
			  priv->extract.qos_key_extract.key_info.key_total_size;
			ret = dpni_add_qos_entry(dpni, CMD_PRI_LOW, priv->token,
						&flow->qos_rule, flow->tc_id,
						index, 0, 0);
			if (ret < 0) {
				DPAA2_PMD_ERR(
				"Error in entry addition in QoS table(%d)",
				ret);
				priv->qos_index[index] = 0;
				return ret;
			}
			flow->qos_index = index;
			break;
		case RTE_FLOW_ACTION_TYPE_END:
			end_of_list = 1;
			break;
		default:
			DPAA2_PMD_ERR("Invalid action type");
			ret = -ENOTSUP;
			break;
		}
		j++;
	}

	if (!ret) {
		ret = dpaa2_flow_entry_update(priv, flow->tc_id);
		if (ret) {
			DPAA2_PMD_ERR("Flow entry update failed.");

			return -1;
		}
		/* New rules are inserted. */
		if (!curr) {
			LIST_INSERT_HEAD(&priv->flows, flow, next);
		} else {
			while (LIST_NEXT(curr, next))
				curr = LIST_NEXT(curr, next);
			LIST_INSERT_AFTER(curr, flow, next);
		}
	}
	return ret;
}

static inline int
dpaa2_dev_verify_attr(struct dpni_attr *dpni_attr,
		      const struct rte_flow_attr *attr)
{
	int ret = 0;

	if (unlikely(attr->group >= dpni_attr->num_rx_tcs)) {
		DPAA2_PMD_ERR("Priority group is out of range\n");
		ret = -ENOTSUP;
	}
	if (unlikely(attr->priority >= dpni_attr->fs_entries)) {
		DPAA2_PMD_ERR("Priority within the group is out of range\n");
		ret = -ENOTSUP;
	}
	if (unlikely(attr->egress)) {
		DPAA2_PMD_ERR(
			"Flow configuration is not supported on egress side\n");
		ret = -ENOTSUP;
	}
	if (unlikely(!attr->ingress)) {
		DPAA2_PMD_ERR("Ingress flag must be configured\n");
		ret = -EINVAL;
	}
	return ret;
}

static inline int
dpaa2_dev_verify_patterns(const struct rte_flow_item pattern[])
{
	unsigned int i, j, is_found = 0;
	int ret = 0;

	for (j = 0; pattern[j].type != RTE_FLOW_ITEM_TYPE_END; j++) {
		for (i = 0; i < RTE_DIM(dpaa2_supported_pattern_type); i++) {
			if (dpaa2_supported_pattern_type[i]
					== pattern[j].type) {
				is_found = 1;
				break;
			}
		}
		if (!is_found) {
			ret = -ENOTSUP;
			break;
		}
	}
	/* Lets verify other combinations of given pattern rules */
	for (j = 0; pattern[j].type != RTE_FLOW_ITEM_TYPE_END; j++) {
		if (!pattern[j].spec) {
			ret = -EINVAL;
			break;
		}
	}

	return ret;
}

static inline int
dpaa2_dev_verify_actions(const struct rte_flow_action actions[])
{
	unsigned int i, j, is_found = 0;
	int ret = 0;

	for (j = 0; actions[j].type != RTE_FLOW_ACTION_TYPE_END; j++) {
		for (i = 0; i < RTE_DIM(dpaa2_supported_action_type); i++) {
			if (dpaa2_supported_action_type[i] == actions[j].type) {
				is_found = 1;
				break;
			}
		}
		if (!is_found) {
			ret = -ENOTSUP;
			break;
		}
	}
	for (j = 0; actions[j].type != RTE_FLOW_ACTION_TYPE_END; j++) {
		if ((actions[j].type
			!= RTE_FLOW_ACTION_TYPE_DROP) && (!actions[j].conf))
			ret = -EINVAL;
	}
	return ret;
}

static
int dpaa2_flow_validate(struct rte_eth_dev *dev,
			const struct rte_flow_attr *flow_attr,
			const struct rte_flow_item pattern[],
			const struct rte_flow_action actions[],
			struct rte_flow_error *error)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct dpni_attr dpni_attr;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)priv->hw;
	uint16_t token = priv->token;
	int ret = 0;

	memset(&dpni_attr, 0, sizeof(struct dpni_attr));
	ret = dpni_get_attributes(dpni, CMD_PRI_LOW, token, &dpni_attr);
	if (ret < 0) {
		DPAA2_PMD_ERR(
			"Failure to get dpni@%p attribute, err code  %d\n",
			dpni, ret);
		rte_flow_error_set(error, EPERM,
			   RTE_FLOW_ERROR_TYPE_ATTR,
			   flow_attr, "invalid");
		return ret;
	}

	/* Verify input attributes */
	ret = dpaa2_dev_verify_attr(&dpni_attr, flow_attr);
	if (ret < 0) {
		DPAA2_PMD_ERR(
			"Invalid attributes are given\n");
		rte_flow_error_set(error, EPERM,
			   RTE_FLOW_ERROR_TYPE_ATTR,
			   flow_attr, "invalid");
		goto not_valid_params;
	}
	/* Verify input pattern list */
	ret = dpaa2_dev_verify_patterns(pattern);
	if (ret < 0) {
		DPAA2_PMD_ERR(
			"Invalid pattern list is given\n");
		rte_flow_error_set(error, EPERM,
			   RTE_FLOW_ERROR_TYPE_ITEM,
			   pattern, "invalid");
		goto not_valid_params;
	}
	/* Verify input action list */
	ret = dpaa2_dev_verify_actions(actions);
	if (ret < 0) {
		DPAA2_PMD_ERR(
			"Invalid action list is given\n");
		rte_flow_error_set(error, EPERM,
			   RTE_FLOW_ERROR_TYPE_ACTION,
			   actions, "invalid");
		goto not_valid_params;
	}
not_valid_params:
	return ret;
}

static
struct rte_flow *dpaa2_flow_create(struct rte_eth_dev *dev,
				   const struct rte_flow_attr *attr,
				   const struct rte_flow_item pattern[],
				   const struct rte_flow_action actions[],
				   struct rte_flow_error *error)
{
	struct rte_flow *flow = NULL;
	size_t key_iova = 0, mask_iova = 0;
	int ret;

	flow = rte_zmalloc(NULL, sizeof(struct rte_flow), RTE_CACHE_LINE_SIZE);
	if (!flow) {
		DPAA2_PMD_ERR("Failure to allocate memory for flow");
		goto mem_failure;
	}
	/* Allocate DMA'ble memory to write the rules */
	key_iova = (size_t)rte_zmalloc(NULL, 256, 64);
	if (!key_iova) {
		DPAA2_PMD_ERR(
			"Memory allocation failure for rule configration\n");
		goto mem_failure;
	}
	mask_iova = (size_t)rte_zmalloc(NULL, 256, 64);
	if (!mask_iova) {
		DPAA2_PMD_ERR(
			"Memory allocation failure for rule configration\n");
		goto mem_failure;
	}

	flow->qos_rule.key_iova = key_iova;
	flow->qos_rule.mask_iova = mask_iova;

	/* Allocate DMA'ble memory to write the rules */
	key_iova = (size_t)rte_zmalloc(NULL, 256, 64);
	if (!key_iova) {
		DPAA2_PMD_ERR(
			"Memory allocation failure for rule configration\n");
		goto mem_failure;
	}
	mask_iova = (size_t)rte_zmalloc(NULL, 256, 64);
	if (!mask_iova) {
		DPAA2_PMD_ERR(
			"Memory allocation failure for rule configration\n");
		goto mem_failure;
	}

	flow->fs_rule.key_iova = key_iova;
	flow->fs_rule.mask_iova = mask_iova;

	flow->ipaddr_rule.ipaddr_type = FLOW_NONE_IPADDR;
	flow->ipaddr_rule.qos_ipsrc_offset =
		IP_ADDRESS_OFFSET_INVALID;
	flow->ipaddr_rule.qos_ipdst_offset =
		IP_ADDRESS_OFFSET_INVALID;
	flow->ipaddr_rule.fs_ipsrc_offset =
		IP_ADDRESS_OFFSET_INVALID;
	flow->ipaddr_rule.fs_ipdst_offset =
		IP_ADDRESS_OFFSET_INVALID;

	switch (dpaa2_filter_type) {
	case RTE_ETH_FILTER_GENERIC:
		ret = dpaa2_generic_flow_set(flow, dev, attr, pattern,
					     actions, error);
		if (ret < 0) {
			if (error->type > RTE_FLOW_ERROR_TYPE_ACTION)
				rte_flow_error_set(error, EPERM,
						RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
						attr, "unknown");
			DPAA2_PMD_ERR(
			"Failure to create flow, return code (%d)", ret);
			goto creation_error;
		}
		break;
	default:
		DPAA2_PMD_ERR("Filter type (%d) not supported",
		dpaa2_filter_type);
		break;
	}

	return flow;
mem_failure:
	rte_flow_error_set(error, EPERM,
			   RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
			   NULL, "memory alloc");
creation_error:
	rte_free((void *)flow);
	rte_free((void *)key_iova);
	rte_free((void *)mask_iova);

	return NULL;
}

static
int dpaa2_flow_destroy(struct rte_eth_dev *dev,
		       struct rte_flow *flow,
		       struct rte_flow_error *error)
{
	int ret = 0;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)priv->hw;

	switch (flow->action) {
	case RTE_FLOW_ACTION_TYPE_QUEUE:
		/* Remove entry from QoS table first */
		ret = dpni_remove_qos_entry(dpni, CMD_PRI_LOW, priv->token,
					   &flow->qos_rule);
		if (ret < 0) {
			DPAA2_PMD_ERR(
				"Error in adding entry to QoS table(%d)", ret);
			goto error;
		}
		priv->qos_index[flow->qos_index] = 0;

		/* Then remove entry from FS table */
		ret = dpni_remove_fs_entry(dpni, CMD_PRI_LOW, priv->token,
					   flow->tc_id, &flow->fs_rule);
		if (ret < 0) {
			DPAA2_PMD_ERR(
				"Error in entry addition in FS table(%d)", ret);
			goto error;
		}
		priv->fs_index[flow->fs_index] = 0;
		break;
	case RTE_FLOW_ACTION_TYPE_RSS:
		ret = dpni_remove_qos_entry(dpni, CMD_PRI_LOW, priv->token,
					   &flow->qos_rule);
		if (ret < 0) {
			DPAA2_PMD_ERR(
			"Error in entry addition in QoS table(%d)", ret);
			goto error;
		}
		break;
	default:
		DPAA2_PMD_ERR(
		"Action type (%d) is not supported", flow->action);
		ret = -ENOTSUP;
		break;
	}

	LIST_REMOVE(flow, next);
	/* Now free the flow */
	rte_free(flow);

error:
	if (ret)
		rte_flow_error_set(error, EPERM,
				   RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
				   NULL, "unknown");
	return ret;
}

/**
 * Destroy user-configured flow rules.
 *
 * This function skips internal flows rules.
 *
 * @see rte_flow_flush()
 * @see rte_flow_ops
 */
static int
dpaa2_flow_flush(struct rte_eth_dev *dev,
		struct rte_flow_error *error)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct rte_flow *flow = LIST_FIRST(&priv->flows);

	while (flow) {
		struct rte_flow *next = LIST_NEXT(flow, next);

		dpaa2_flow_destroy(dev, flow, error);
		flow = next;
	}
	return 0;
}

static int
dpaa2_flow_query(struct rte_eth_dev *dev __rte_unused,
		struct rte_flow *flow __rte_unused,
		const struct rte_flow_action *actions __rte_unused,
		void *data __rte_unused,
		struct rte_flow_error *error __rte_unused)
{
	return 0;
}

/**
 * Clean up all flow rules.
 *
 * Unlike dpaa2_flow_flush(), this function takes care of all remaining flow
 * rules regardless of whether they are internal or user-configured.
 *
 * @param priv
 *   Pointer to private structure.
 */
void
dpaa2_flow_clean(struct rte_eth_dev *dev)
{
	struct rte_flow *flow;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;

	while ((flow = LIST_FIRST(&priv->flows)))
		dpaa2_flow_destroy(dev, flow, NULL);
}

const struct rte_flow_ops dpaa2_flow_ops = {
	.create	= dpaa2_flow_create,
	.validate = dpaa2_flow_validate,
	.destroy = dpaa2_flow_destroy,
	.flush	= dpaa2_flow_flush,
	.query	= dpaa2_flow_query,
};
