/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018-2021 NXP
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

#include <rte_fslmc.h>
#include <fsl_dpdmux.h>
#include <fsl_dpkg.h>

#include <dpaa2_ethdev.h>
#include <dpaa2_pmd_logs.h>

struct dpaa2_dpdmux_dev {
	TAILQ_ENTRY(dpaa2_dpdmux_dev) next;
		/**< Pointer to Next device instance */
	struct fsl_mc_io dpdmux;  /** handle to DPDMUX portal object */
	uint16_t token;
	uint32_t dpdmux_id; /*HW ID for DPDMUX object */
	uint8_t num_ifs;   /* Number of interfaces in DPDMUX */
};

struct rte_flow {
	struct dpdmux_rule_cfg rule;
};

TAILQ_HEAD(dpdmux_dev_list, dpaa2_dpdmux_dev);
static struct dpdmux_dev_list dpdmux_dev_list =
	TAILQ_HEAD_INITIALIZER(dpdmux_dev_list); /*!< DPDMUX device list */

static struct dpaa2_dpdmux_dev *get_dpdmux_from_id(uint32_t dpdmux_id)
{
	struct dpaa2_dpdmux_dev *dpdmux_dev = NULL;

	/* Get DPDMUX dev handle from list using index */
	TAILQ_FOREACH(dpdmux_dev, &dpdmux_dev_list, next) {
		if (dpdmux_dev->dpdmux_id == dpdmux_id)
			break;
	}

	return dpdmux_dev;
}

struct rte_flow *
rte_pmd_dpaa2_mux_flow_create(uint32_t dpdmux_id,
			      struct rte_flow_item *pattern[],
			      struct rte_flow_action *actions[])
{
	struct dpaa2_dpdmux_dev *dpdmux_dev;
	struct dpkg_profile_cfg kg_cfg;
	const struct rte_flow_action_vf *vf_conf;
	struct dpdmux_cls_action dpdmux_action;
	struct rte_flow *flow = NULL;
	void *key_iova, *mask_iova, *key_cfg_iova = NULL;
	uint8_t key_size = 0;
	int ret;
	static int i;
	int num_rules = 1;
	uint64_t *masks = NULL, *keys = NULL;

	/* Find the DPDMUX from dpdmux_id in our list */
	dpdmux_dev = get_dpdmux_from_id(dpdmux_id);
	if (!dpdmux_dev) {
		DPAA2_PMD_ERR("Invalid dpdmux_id: %d", dpdmux_id);
		return NULL;
	}

	key_cfg_iova = rte_zmalloc(NULL, DIST_PARAM_IOVA_SIZE,
				   RTE_CACHE_LINE_SIZE);
	if (!key_cfg_iova) {
		DPAA2_PMD_ERR("Unable to allocate flow-dist parameters");
		return NULL;
	}
	flow = rte_zmalloc(NULL, sizeof(struct rte_flow) +
			   (2 * DIST_PARAM_IOVA_SIZE), RTE_CACHE_LINE_SIZE);
	if (!flow) {
		DPAA2_PMD_ERR(
			"Memory allocation failure for rule configuration\n");
		goto creation_error;
	}
	key_iova = (void *)((size_t)flow + sizeof(struct rte_flow));
	mask_iova = (void *)((size_t)key_iova + DIST_PARAM_IOVA_SIZE);

	/* Currently taking only IP protocol as an extract type.
	 * This can be exended to other fields using pattern->type.
	 */
	memset(&kg_cfg, 0, sizeof(struct dpkg_profile_cfg));

	switch (pattern[0]->type) {
	case RTE_FLOW_ITEM_TYPE_IPV4:
	{
		const struct rte_flow_item_ipv4 *spec;

		kg_cfg.extracts[0].extract.from_hdr.prot = NET_PROT_IP;
		kg_cfg.extracts[0].extract.from_hdr.field = NH_FLD_IP_PROTO;
		kg_cfg.extracts[0].type = DPKG_EXTRACT_FROM_HDR;
		kg_cfg.extracts[0].extract.from_hdr.type = DPKG_FULL_FIELD;
		kg_cfg.num_extracts = 1;

		spec = (const struct rte_flow_item_ipv4 *)pattern[0]->spec;
		memcpy(key_iova, (const void *)(&spec->hdr.next_proto_id),
			sizeof(uint8_t));
		memcpy(mask_iova, pattern[0]->mask, sizeof(uint8_t));
		key_size = sizeof(uint8_t);
	}
	break;

	case RTE_FLOW_ITEM_TYPE_IP_FRAG_UDP_AND_GTP:
	{
		/* The bit 50 and bit 87 in Parse Results signal the
		 * presence of an IP fragmented frame and GTP frame
		 * respectively. The following rule extracts the octet
		 * from 0xA containing bit 50 and from 0xE containing
		 * bit 87 from Parse Results. The arrays mask and key
		 * contain the cases for which the rules are created
		 * in this switch case ie. GTP traffic, and IP fragmented
		 * UDP traffic filled in this particular order in the arrays.
		 */

		uint64_t mask[] = {0x0001000000000000, 0x2000FF0000000000};
		uint64_t key[] = {0x0001000000000000, 0x2000110000000000};
		int j = 0;

		keys = rte_malloc(NULL, sizeof(uint64_t), 0);
		masks = rte_malloc(NULL, sizeof(uint64_t), 0);

		if (!keys)
			printf("Memory allocation failure for keys\n");

		if (!masks)
			printf("Memory allocation failure for masks\n");

		num_rules = 2;

		kg_cfg.extracts[j].type = DPKG_EXTRACT_FROM_PARSE;
		kg_cfg.extracts[j].extract.from_parse.offset = 0x0A;
		kg_cfg.extracts[j].extract.from_parse.size = 1;
		j++;

		kg_cfg.extracts[j].type = DPKG_EXTRACT_FROM_PARSE;
		kg_cfg.extracts[j].extract.from_parse.offset = 0x0E;
		kg_cfg.extracts[j].extract.from_parse.size = 1;
		j++;

		kg_cfg.extracts[j].type = DPKG_EXTRACT_FROM_HDR;
		kg_cfg.extracts[j].extract.from_hdr.type = DPKG_FULL_FIELD;
		kg_cfg.extracts[j].extract.from_hdr.prot = NET_PROT_IP;
		kg_cfg.extracts[j].extract.from_hdr.field = NH_FLD_IP_PROTO;
		j++;

		kg_cfg.num_extracts = j;
		masks = mask;
		keys = key;
		key_size = sizeof(uint8_t) * 3;
	}
	break;

	case RTE_FLOW_ITEM_TYPE_IP_FRAG_UDP_AND_GTP_AND_ESP:
	{
		/* The bit 50, bit 87 and bit 78 in Parse Results signal the
		 * presence of an IP fragmented frame, GTP frame or ESP frame
		 * respectively. The following rule extracts the octet from 0xA
		 * containing bit 50, from 0xE containing bit 87 and from 0xD of
		 * the Parse Results. The arrays mask and key contain the cases
		 * for which the rules are created in this switch case ie. GTP
		 * traffic, ESP traffic and IP fragmented UDP traffic filled in
		 * this particular order in the arrays.
		 */

		uint64_t mask[] = {0x0001000000000000, 0x0000020000000000,
				   0x200000FF00000000};
		uint64_t key[] = {0x0001000000000000, 0x0000020000000000,
				  0x2000001100000000};
		int j = 0;

		/* Mask/Key value needs to be exactly 256 bytes(16 digits). Zero
		 * bits can be added as padding if extracted bytes are less.
		 */

		/* 0x020102FF00000000
		 *    ^ ^ ^ ^ ^ ^ ^ ^
		 *    | | | | | | | |
		 *    1 2 3 4 Padding
		 *
		 * 02: 1st byte 0x0A
		 * 01: 2nd byte 0x0E
		 * 02: 3rd byte 0x0D
		 * FF: 4th byte NH_FLD_IP_PROTO
		 * Remaining bytes: Padding
		 */

		num_rules = 3;
		keys = rte_malloc(NULL, sizeof(uint64_t), 0);
		masks = rte_malloc(NULL, sizeof(uint64_t), 0);

		if (!keys)
			printf("Memory allocation failure for keys\n");

		if (!masks)
			printf("Memory allocation failure for masks\n");

		kg_cfg.extracts[j].type = DPKG_EXTRACT_FROM_PARSE;
		/* 0x0A Represents bits from 48-55 */
		kg_cfg.extracts[j].extract.from_parse.offset = 0x0A;
		kg_cfg.extracts[j].extract.from_parse.size = 1;
		j++;

		kg_cfg.extracts[j].type = DPKG_EXTRACT_FROM_PARSE;
		/* 0x0E Represents bits from 80-87 */
		kg_cfg.extracts[j].extract.from_parse.offset = 0x0E;
		kg_cfg.extracts[j].extract.from_parse.size = 1;
		j++;

		kg_cfg.extracts[j].type = DPKG_EXTRACT_FROM_PARSE;
		/* 0x0D Represents bits from 72-79 */
		kg_cfg.extracts[j].extract.from_parse.offset = 0x0D;
		kg_cfg.extracts[j].extract.from_parse.size = 1;
		j++;

		kg_cfg.extracts[j].type = DPKG_EXTRACT_FROM_HDR;
		kg_cfg.extracts[j].extract.from_hdr.type = DPKG_FULL_FIELD;
		kg_cfg.extracts[j].extract.from_hdr.prot = NET_PROT_IP;
		/* Size 1. Gets set automatically(NH_FLD_IP_PROTO_SIZE) */
		kg_cfg.extracts[j].extract.from_hdr.field = NH_FLD_IP_PROTO;
		j++;

		kg_cfg.num_extracts = j;
		masks = mask;
		keys = key;
		/* Four keys are extracted. */
		key_size = sizeof(uint8_t) * 4;
	}
	break;

	case RTE_FLOW_ITEM_TYPE_IP_FRAG_PROTO:
	{
		uint8_t key_val = 0x20;
		uint8_t mask_val = 0x20;
		int j = 0;

		kg_cfg.extracts[j].type = DPKG_EXTRACT_FROM_HDR;
		kg_cfg.extracts[j].extract.from_hdr.prot = NET_PROT_IP;
		kg_cfg.extracts[j].extract.from_hdr.type = DPKG_FULL_FIELD;
		kg_cfg.extracts[j].extract.from_hdr.field = NH_FLD_IP_PROTO;
		j++;

		kg_cfg.extracts[j].type = DPKG_EXTRACT_FROM_PARSE;
		kg_cfg.extracts[j].extract.from_parse.offset = 0x0A;
		kg_cfg.extracts[j].extract.from_parse.size = 1;
		j++;

		kg_cfg.num_extracts = j;
		const struct rte_flow_item_ipv4 *spec;

		spec = (const struct rte_flow_item_ipv4 *)pattern[0]->spec;
		memcpy(key_iova, (const void *)(&spec->hdr.next_proto_id),
			sizeof(uint8_t));
		memcpy(mask_iova, pattern[0]->mask, sizeof(uint8_t));
		memcpy((char *)key_iova + 1, &key_val, sizeof(uint8_t));
		memcpy((char *)mask_iova + 1, &mask_val, sizeof(uint8_t));
		key_size = sizeof(uint8_t) + sizeof(uint8_t);
	}
	break;

	case RTE_FLOW_ITEM_TYPE_UDP:
	{
		const struct rte_flow_item_udp *spec;
		uint16_t udp_dst_port;

		kg_cfg.extracts[0].extract.from_hdr.prot = NET_PROT_UDP;
		kg_cfg.extracts[0].extract.from_hdr.field = NH_FLD_UDP_PORT_DST;
		kg_cfg.extracts[0].type = DPKG_EXTRACT_FROM_HDR;
		kg_cfg.extracts[0].extract.from_hdr.type = DPKG_FULL_FIELD;
		kg_cfg.num_extracts = 1;

		spec = (const struct rte_flow_item_udp *)pattern[0]->spec;
		udp_dst_port = rte_constant_bswap16(spec->hdr.dst_port);
		memcpy((void *)key_iova, (const void *)&udp_dst_port,
							sizeof(rte_be16_t));
		memcpy(mask_iova, pattern[0]->mask, sizeof(uint16_t));
		key_size = sizeof(uint16_t);
	}
	break;

	case RTE_FLOW_ITEM_TYPE_ETH:
	{
		const struct rte_flow_item_eth *spec;
		uint16_t eth_type;

		kg_cfg.extracts[0].extract.from_hdr.prot = NET_PROT_ETH;
		kg_cfg.extracts[0].extract.from_hdr.field = NH_FLD_ETH_TYPE;
		kg_cfg.extracts[0].type = DPKG_EXTRACT_FROM_HDR;
		kg_cfg.extracts[0].extract.from_hdr.type = DPKG_FULL_FIELD;
		kg_cfg.num_extracts = 1;

		spec = (const struct rte_flow_item_eth *)pattern[0]->spec;
		eth_type = rte_constant_bswap16(spec->type);
		memcpy((void *)key_iova, (const void *)&eth_type,
							sizeof(rte_be16_t));
		memcpy(mask_iova, pattern[0]->mask, sizeof(uint16_t));
		key_size = sizeof(uint16_t);
	}
	break;

	case RTE_FLOW_ITEM_TYPE_RAW:
	{
		const struct rte_flow_item_raw *spec;

		spec = (const struct rte_flow_item_raw *)pattern[0]->spec;
		kg_cfg.extracts[0].extract.from_data.offset = spec->offset;
		kg_cfg.extracts[0].extract.from_data.size = spec->length;
		kg_cfg.extracts[0].type = DPKG_EXTRACT_FROM_DATA;
		kg_cfg.num_extracts = 1;
		memcpy((void *)key_iova, (const void *)spec->pattern,
							spec->length);
		memcpy(mask_iova, pattern[0]->mask, spec->length);

		key_size = spec->length;
	}
	break;

	default:
		DPAA2_PMD_ERR("Not supported pattern type: %d",
				pattern[0]->type);
		goto creation_error;
	}

	ret = dpkg_prepare_key_cfg(&kg_cfg, key_cfg_iova);
	if (ret) {
		DPAA2_PMD_ERR("dpkg_prepare_key_cfg failed: err(%d)", ret);
		goto creation_error;
	}

	/* Multiple rules with same DPKG extracts (kg_cfg.extracts) like same
	 * offset and length values in raw is supported right now. Different
	 * values of kg_cfg may not work.
	 */
	if (i == 0) {

		ret = dpdmux_set_custom_key(&dpdmux_dev->dpdmux, CMD_PRI_LOW,
					    dpdmux_dev->token,
				(uint64_t)(DPAA2_VADDR_TO_IOVA(key_cfg_iova)));
		if (ret) {
			DPAA2_PMD_ERR("dpdmux_set_custom_key failed: err(%d)",
					ret);
			goto creation_error;
		}
	}

	vf_conf = (const struct rte_flow_action_vf *)(actions[0]->conf);
	if (vf_conf->id == 0 || vf_conf->id > dpdmux_dev->num_ifs) {
		DPAA2_PMD_ERR("Invalid destination id\n");
		goto creation_error;
	}
	dpdmux_action.dest_if = vf_conf->id;

	/* As now our key extract parameters are set, let us configure
	 * the rule.
	 */
	for (int j = 0; j < num_rules; j++) {
		if (keys) {
			rte_be64_t key_val, mask_val;

			key_val = rte_bswap64(keys[j]);
			mask_val = rte_bswap64(masks[j]);
			memcpy(key_iova, &key_val, sizeof(rte_be64_t));
			memcpy(mask_iova, &mask_val, sizeof(rte_be64_t));
		}
		flow->rule.key_iova =
			(uint64_t)(DPAA2_VADDR_TO_IOVA(key_iova));
		flow->rule.mask_iova =
			(uint64_t)(DPAA2_VADDR_TO_IOVA(mask_iova));
		flow->rule.key_size = key_size;
		flow->rule.entry_index = i++;

		ret = dpdmux_add_custom_cls_entry(&dpdmux_dev->dpdmux,
					CMD_PRI_LOW, dpdmux_dev->token,
					&flow->rule, &dpdmux_action);

		if (ret) {
			DPAA2_PMD_ERR("dpdmux_add_custom_cls_entry failed:err(%d)"
					, ret);
			goto creation_error;
		}
	}

	return flow;

creation_error:
	rte_free((void *)key_cfg_iova);
	rte_free((void *)flow);
	return NULL;
}

/* dump the status of the dpaa2_mux counters on the console */
void
rte_pmd_dpaa2_mux_dump_counter(FILE *f, uint32_t dpdmux_id, int num_if)
{
	struct dpaa2_dpdmux_dev *dpdmux;
	uint64_t counter;
	int ret;
	int if_id;

	/* Find the DPDMUX from dpdmux_id in our list */
	dpdmux = get_dpdmux_from_id(dpdmux_id);
	if (!dpdmux) {
		DPAA2_PMD_ERR("Invalid dpdmux_id: %d", dpdmux_id);
		return;
	}

	for (if_id = 0; if_id < num_if; if_id++) {
		fprintf(f, "dpdmux.%d\n", if_id);

		ret = dpdmux_if_get_counter(&dpdmux->dpdmux, CMD_PRI_LOW,
			dpdmux->token, if_id, DPDMUX_CNT_ING_FRAME, &counter);
		if (!ret)
			fprintf(f, "DPDMUX_CNT_ING_FRAME %" PRIu64 "\n",
				counter);
		ret = dpdmux_if_get_counter(&dpdmux->dpdmux, CMD_PRI_LOW,
			dpdmux->token, if_id, DPDMUX_CNT_ING_BYTE, &counter);
		if (!ret)
			fprintf(f, "DPDMUX_CNT_ING_BYTE %" PRIu64 "\n",
				counter);
		ret = dpdmux_if_get_counter(&dpdmux->dpdmux, CMD_PRI_LOW,
			dpdmux->token, if_id, DPDMUX_CNT_ING_FLTR_FRAME,
			&counter);
		if (!ret)
			fprintf(f, "DPDMUX_CNT_ING_FLTR_FRAME %" PRIu64 "\n",
				counter);
		ret = dpdmux_if_get_counter(&dpdmux->dpdmux, CMD_PRI_LOW,
			dpdmux->token, if_id, DPDMUX_CNT_ING_FRAME_DISCARD,
			&counter);
		if (!ret)
			fprintf(f, "DPDMUX_CNT_ING_FRAME_DISCARD %" PRIu64 "\n",
				counter);
		ret = dpdmux_if_get_counter(&dpdmux->dpdmux, CMD_PRI_LOW,
			dpdmux->token, if_id, DPDMUX_CNT_ING_MCAST_FRAME,
			&counter);
		if (!ret)
			fprintf(f, "DPDMUX_CNT_ING_MCAST_FRAME %" PRIu64 "\n",
				counter);
		ret = dpdmux_if_get_counter(&dpdmux->dpdmux, CMD_PRI_LOW,
			dpdmux->token, if_id, DPDMUX_CNT_ING_MCAST_BYTE,
			&counter);
		if (!ret)
			fprintf(f, "DPDMUX_CNT_ING_MCAST_BYTE %" PRIu64 "\n",
				counter);
		ret = dpdmux_if_get_counter(&dpdmux->dpdmux, CMD_PRI_LOW,
			dpdmux->token, if_id, DPDMUX_CNT_ING_BCAST_FRAME,
			&counter);
		if (!ret)
			fprintf(f, "DPDMUX_CNT_ING_BCAST_FRAME %" PRIu64 "\n",
				counter);
		ret = dpdmux_if_get_counter(&dpdmux->dpdmux, CMD_PRI_LOW,
			dpdmux->token, if_id, DPDMUX_CNT_ING_BCAST_BYTES,
			&counter);
		if (!ret)
			fprintf(f, "DPDMUX_CNT_ING_BCAST_BYTES %" PRIu64 "\n",
				counter);
		ret = dpdmux_if_get_counter(&dpdmux->dpdmux, CMD_PRI_LOW,
			dpdmux->token, if_id, DPDMUX_CNT_EGR_FRAME, &counter);
		if (!ret)
			fprintf(f, "DPDMUX_CNT_EGR_FRAME %" PRIu64 "\n",
				counter);
		ret = dpdmux_if_get_counter(&dpdmux->dpdmux, CMD_PRI_LOW,
			dpdmux->token, if_id, DPDMUX_CNT_EGR_BYTE, &counter);
		if (!ret)
			fprintf(f, "DPDMUX_CNT_EGR_BYTE %" PRIu64 "\n",
				counter);
		ret = dpdmux_if_get_counter(&dpdmux->dpdmux, CMD_PRI_LOW,
			dpdmux->token, if_id, DPDMUX_CNT_EGR_FRAME_DISCARD,
			&counter);
		if (!ret)
			fprintf(f, "DPDMUX_CNT_EGR_FRAME_DISCARD %" PRIu64 "\n",
				counter);
	}
}

int
rte_pmd_dpaa2_mux_rx_frame_len(uint32_t dpdmux_id, uint16_t max_rx_frame_len)
{
	struct dpaa2_dpdmux_dev *dpdmux_dev;
	int ret;

	/* Find the DPDMUX from dpdmux_id in our list */
	dpdmux_dev = get_dpdmux_from_id(dpdmux_id);
	if (!dpdmux_dev) {
		DPAA2_PMD_ERR("Invalid dpdmux_id: %d", dpdmux_id);
		return -1;
	}

	ret = dpdmux_set_max_frame_length(&dpdmux_dev->dpdmux,
			CMD_PRI_LOW, dpdmux_dev->token, max_rx_frame_len);
	if (ret) {
		DPAA2_PMD_ERR("DPDMUX:Unable to set mtu. check config %d", ret);
		return ret;
	}

	DPAA2_PMD_INFO("dpdmux mtu set as %u",
			DPAA2_MAX_RX_PKT_LEN - RTE_ETHER_CRC_LEN);

	return ret;
}

static int
dpaa2_create_dpdmux_device(int vdev_fd __rte_unused,
			   struct vfio_device_info *obj_info __rte_unused,
			   int dpdmux_id)
{
	struct dpaa2_dpdmux_dev *dpdmux_dev;
	struct dpdmux_attr attr;
	int ret;
	uint16_t maj_ver;
	uint16_t min_ver;

	PMD_INIT_FUNC_TRACE();

	/* Allocate DPAA2 dpdmux handle */
	dpdmux_dev = rte_malloc(NULL, sizeof(struct dpaa2_dpdmux_dev), 0);
	if (!dpdmux_dev) {
		DPAA2_PMD_ERR("Memory allocation failed for DPDMUX Device");
		return -1;
	}

	/* Open the dpdmux object */
	dpdmux_dev->dpdmux.regs = dpaa2_get_mcp_ptr(MC_PORTAL_INDEX);
	ret = dpdmux_open(&dpdmux_dev->dpdmux, CMD_PRI_LOW, dpdmux_id,
			  &dpdmux_dev->token);
	if (ret) {
		DPAA2_PMD_ERR("Unable to open dpdmux object: err(%d)", ret);
		goto init_err;
	}

	ret = dpdmux_get_attributes(&dpdmux_dev->dpdmux, CMD_PRI_LOW,
				    dpdmux_dev->token, &attr);
	if (ret) {
		DPAA2_PMD_ERR("Unable to get dpdmux attr: err(%d)", ret);
		goto init_err;
	}

	ret = dpdmux_if_set_default(&dpdmux_dev->dpdmux, CMD_PRI_LOW,
				    dpdmux_dev->token, 1);
	if (ret) {
		DPAA2_PMD_ERR("setting default interface failed in %s",
			      __func__);
		goto init_err;
	}

	ret = dpdmux_get_api_version(&dpdmux_dev->dpdmux, CMD_PRI_LOW,
					&maj_ver, &min_ver);
	if (ret) {
		DPAA2_PMD_ERR("setting version failed in %s",
				__func__);
		goto init_err;
	}

	/* The new dpdmux_set/get_resetable() API are available starting with
	 * DPDMUX_VER_MAJOR==6 and DPDMUX_VER_MINOR==6
	 */
	if (maj_ver >= 6 && min_ver >= 6) {
		ret = dpdmux_set_resetable(&dpdmux_dev->dpdmux, CMD_PRI_LOW,
				dpdmux_dev->token,
				DPDMUX_SKIP_DEFAULT_INTERFACE |
				DPDMUX_SKIP_UNICAST_RULES |
				DPDMUX_SKIP_MULTICAST_RULES);
		if (ret) {
			DPAA2_PMD_ERR("setting default interface failed in %s",
				      __func__);
			goto init_err;
		}

		ret = dpdmux_set_max_frame_length(&dpdmux_dev->dpdmux,
				CMD_PRI_LOW, dpdmux_dev->token,
				DPAA2_MAX_RX_PKT_LEN - RTE_ETHER_CRC_LEN);
		if (ret) {
			DPAA2_PMD_ERR("DPDMUX:Unable to set mtu. check config");
			goto init_err;
		}
		DPAA2_PMD_INFO("dpdmux mtu set as %u",
				DPAA2_MAX_RX_PKT_LEN - RTE_ETHER_CRC_LEN);
	}

	if (maj_ver >= 6 && min_ver >= 9) {
		struct dpdmux_error_cfg mux_err_cfg;

		memset(&mux_err_cfg, 0, sizeof(mux_err_cfg));
		mux_err_cfg.error_action = DPDMUX_ERROR_ACTION_CONTINUE;
		mux_err_cfg.errors = DPDMUX_ERROR_DISC;

		ret = dpdmux_if_set_errors_behavior(&dpdmux_dev->dpdmux,
				CMD_PRI_LOW,
				dpdmux_dev->token, dpdmux_id,
				&mux_err_cfg);
		if (ret) {
			DPAA2_PMD_ERR("dpdmux_if_set_errors_behavior %s err %d",
				      __func__, ret);
			goto init_err;
		}
	}

	dpdmux_dev->dpdmux_id = dpdmux_id;
	dpdmux_dev->num_ifs = attr.num_ifs;

	TAILQ_INSERT_TAIL(&dpdmux_dev_list, dpdmux_dev, next);

	return 0;

init_err:
	if (dpdmux_dev)
		rte_free(dpdmux_dev);

	return -1;
}

static void
dpaa2_close_dpdmux_device(int object_id)
{
	struct dpaa2_dpdmux_dev *dpdmux_dev;

	dpdmux_dev = get_dpdmux_from_id((uint32_t)object_id);

	if (dpdmux_dev) {
		dpdmux_close(&dpdmux_dev->dpdmux, CMD_PRI_LOW,
			     dpdmux_dev->token);
		TAILQ_REMOVE(&dpdmux_dev_list, dpdmux_dev, next);
		rte_free(dpdmux_dev);
	}
}

static struct rte_dpaa2_object rte_dpaa2_dpdmux_obj = {
	.dev_type = DPAA2_MUX,
	.create = dpaa2_create_dpdmux_device,
	.close = dpaa2_close_dpdmux_device,
};

RTE_PMD_REGISTER_DPAA2_OBJECT(dpdmux, rte_dpaa2_dpdmux_obj);
