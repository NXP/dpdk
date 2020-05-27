/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2017-2020 NXP
 */

/* System headers */
#include <stdio.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/types.h>

#include <dpaa_ethdev.h>
#include <dpaa_flow.h>
#include <rte_dpaa_logs.h>
#include <fmlib/fm_port_ext.h>
#include <fmlib/fm_vsp_ext.h>

#define FMC_OUTPUT_FORMAT_VER 0x106

#define FMC_NAME_LEN             64
#define FMC_FMAN_NUM              2
#define FMC_PORTS_PER_FMAN       16
#define FMC_SCHEMES_NUM          32
#define FMC_SCHEME_PROTOCOLS_NUM 16
#define FMC_CC_NODES_NUM        512
#define FMC_REPLICATORS_NUM      16
#define FMC_PLC_NUM              64
#define MAX_SP_CODE_SIZE      0x7C0
#define FMC_MANIP_MAX            64
#define FMC_HMANIP_MAX          512
#define FMC_INSERT_MAX           56
#define FM_PCD_MAX_NUM_OF_REPS   64

typedef struct fmc_port_t {
	e_FmPortType type;
	unsigned int number;
	struct fm_pcd_net_env_params_t distinctionUnits;
	struct ioc_fm_port_pcd_params_t pcdParam;
	struct ioc_fm_port_pcd_prs_params_t prsParam;
	struct ioc_fm_port_pcd_kg_params_t kgParam;
	struct ioc_fm_port_pcd_cc_params_t ccParam;
	char name[FMC_NAME_LEN];
	char cctree_name[FMC_NAME_LEN];
	t_Handle handle;
	t_Handle env_id_handle;
	t_Handle env_id_devId;
	t_Handle cctree_handle;
	t_Handle cctree_devId;

	unsigned int schemes_count;
	unsigned int schemes[FMC_SCHEMES_NUM];
	unsigned int ccnodes_count;
	unsigned int ccnodes[FMC_CC_NODES_NUM];
	unsigned int htnodes_count;
	unsigned int htnodes[FMC_CC_NODES_NUM];

	unsigned int replicators_count;
	unsigned int replicators[FMC_REPLICATORS_NUM];
	ioc_fm_port_vsp_alloc_params_t vspParam;

	unsigned int ccroot_count;
	unsigned int ccroot[FMC_CC_NODES_NUM];
	enum ioc_fm_pcd_engine ccroot_type[FMC_CC_NODES_NUM];
	unsigned int ccroot_manip[FMC_CC_NODES_NUM];

	unsigned int reasm_index;
} fmc_port;

typedef struct fmc_fman_t {
	unsigned int number;
	unsigned int port_count;
	unsigned int ports[FMC_PORTS_PER_FMAN];
	char name[FMC_NAME_LEN];
	t_Handle handle;
	char pcd_name[FMC_NAME_LEN];
	t_Handle pcd_handle;
	unsigned int kg_payload_offset;

	unsigned int offload_support;

	unsigned int reasm_count;
	struct fm_pcd_manip_params_t reasm[FMC_MANIP_MAX];
	char reasm_name[FMC_MANIP_MAX][FMC_NAME_LEN];
	t_Handle reasm_handle[FMC_MANIP_MAX];
	t_Handle reasm_devId[FMC_MANIP_MAX];

	unsigned int frag_count;
	struct fm_pcd_manip_params_t frag[FMC_MANIP_MAX];
	char frag_name[FMC_MANIP_MAX][FMC_NAME_LEN];
	t_Handle frag_handle[FMC_MANIP_MAX];
	t_Handle frag_devId[FMC_MANIP_MAX];

	unsigned int hdr_count;
	struct fm_pcd_manip_params_t hdr[FMC_HMANIP_MAX];
	uint8_t insertData[FMC_HMANIP_MAX][FMC_INSERT_MAX];
	char hdr_name[FMC_HMANIP_MAX][FMC_NAME_LEN];
	t_Handle hdr_handle[FMC_HMANIP_MAX];
	t_Handle hdr_devId[FMC_HMANIP_MAX];
	unsigned int hdr_hasNext[FMC_HMANIP_MAX];
	unsigned int hdr_next[FMC_HMANIP_MAX];
} fmc_fman;

typedef enum fmc_apply_order_e {
	FMCEngineStart,
	FMCEngineEnd,
	FMCPortStart,
	FMCPortEnd,
	FMCScheme,
	FMCCCNode,
	FMCHTNode,
	FMCCCTree,
	FMCPolicer,
	FMCReplicator,
	FMCManipulation
} fmc_apply_order_e;

typedef struct fmc_apply_order_t {
	fmc_apply_order_e type;
	unsigned int index;
} fmc_apply_order;

struct fmc_model_t {
	unsigned int format_version;
	unsigned int sp_enable;
	t_FmPcdPrsSwParams sp;
	uint8_t spcode[MAX_SP_CODE_SIZE];

	unsigned int fman_count;
	fmc_fman fman[FMC_FMAN_NUM];

	unsigned int port_count;
	fmc_port port[FMC_FMAN_NUM * FMC_PORTS_PER_FMAN];

	unsigned int scheme_count;
	char scheme_name[FMC_SCHEMES_NUM][FMC_NAME_LEN];
	t_Handle scheme_handle[FMC_SCHEMES_NUM];
	t_Handle scheme_devId[FMC_SCHEMES_NUM];
	struct fm_pcd_kg_scheme_params_t scheme[FMC_SCHEMES_NUM];

	unsigned int ccnode_count;
	char ccnode_name[FMC_CC_NODES_NUM][FMC_NAME_LEN];
	t_Handle ccnode_handle[FMC_CC_NODES_NUM];
	t_Handle ccnode_devId[FMC_CC_NODES_NUM];
	struct fm_pcd_cc_node_params_t ccnode[FMC_CC_NODES_NUM];
	uint8_t cckeydata[FMC_CC_NODES_NUM][FM_PCD_MAX_NUM_OF_KEYS]
					[FM_PCD_MAX_SIZE_OF_KEY];
	unsigned char ccmask[FMC_CC_NODES_NUM][FM_PCD_MAX_NUM_OF_KEYS]
						[FM_PCD_MAX_SIZE_OF_KEY];
	unsigned int
		ccentry_action_index[FMC_CC_NODES_NUM][FM_PCD_MAX_NUM_OF_KEYS];
	enum ioc_fm_pcd_engine
		ccentry_action_type[FMC_CC_NODES_NUM][FM_PCD_MAX_NUM_OF_KEYS];
	unsigned char ccentry_frag[FMC_CC_NODES_NUM][FM_PCD_MAX_NUM_OF_KEYS];
	unsigned int ccentry_manip[FMC_CC_NODES_NUM][FM_PCD_MAX_NUM_OF_KEYS];
	unsigned int ccmiss_action_index[FMC_CC_NODES_NUM];
	enum ioc_fm_pcd_engine ccmiss_action_type[FMC_CC_NODES_NUM];
	unsigned char ccmiss_frag[FMC_CC_NODES_NUM];
	unsigned int ccmiss_manip[FMC_CC_NODES_NUM];

	unsigned int htnode_count;
	char htnode_name[FMC_CC_NODES_NUM][FMC_NAME_LEN];
	t_Handle htnode_handle[FMC_CC_NODES_NUM];
	t_Handle htnode_devId[FMC_CC_NODES_NUM];
	struct fm_pcd_hash_table_params_t htnode[FMC_CC_NODES_NUM];

	unsigned int htentry_count[FMC_CC_NODES_NUM];
	struct ioc_fm_pcd_cc_key_params_t
		htentry[FMC_CC_NODES_NUM][FM_PCD_MAX_NUM_OF_KEYS];
	uint8_t htkeydata[FMC_CC_NODES_NUM][FM_PCD_MAX_NUM_OF_KEYS]
					[FM_PCD_MAX_SIZE_OF_KEY];
	unsigned int
		htentry_action_index[FMC_CC_NODES_NUM][FM_PCD_MAX_NUM_OF_KEYS];
	enum ioc_fm_pcd_engine
		htentry_action_type[FMC_CC_NODES_NUM][FM_PCD_MAX_NUM_OF_KEYS];
	unsigned char htentry_frag[FMC_CC_NODES_NUM][FM_PCD_MAX_NUM_OF_KEYS];
	unsigned int htentry_manip[FMC_CC_NODES_NUM][FM_PCD_MAX_NUM_OF_KEYS];

	unsigned int htmiss_action_index[FMC_CC_NODES_NUM];
	enum ioc_fm_pcd_engine htmiss_action_type[FMC_CC_NODES_NUM];
	unsigned char htmiss_frag[FMC_CC_NODES_NUM];
	unsigned int htmiss_manip[FMC_CC_NODES_NUM];

	unsigned int replicator_count;
	char replicator_name[FMC_REPLICATORS_NUM][FMC_NAME_LEN];
	t_Handle replicator_handle[FMC_REPLICATORS_NUM];
	t_Handle replicator_devId[FMC_REPLICATORS_NUM];
	struct fm_pcd_frm_replic_group_params_t replicator[FMC_REPLICATORS_NUM];
	unsigned int
	 repentry_action_index[FMC_REPLICATORS_NUM][FM_PCD_MAX_NUM_OF_REPS];
	unsigned char repentry_frag[FMC_REPLICATORS_NUM][FM_PCD_MAX_NUM_OF_REPS];
	unsigned int repentry_manip[FMC_REPLICATORS_NUM][FM_PCD_MAX_NUM_OF_REPS];

	unsigned int policer_count;
	char policer_name[FMC_PLC_NUM][FMC_NAME_LEN];
	struct fm_pcd_plcr_profile_params_t policer[FMC_PLC_NUM];
	t_Handle policer_handle[FMC_PLC_NUM];
	t_Handle policer_devId[FMC_PLC_NUM];
	unsigned int policer_action_index[FMC_PLC_NUM][3];

	unsigned int apply_order_count;
	fmc_apply_order apply_order[FMC_FMAN_NUM *
		FMC_PORTS_PER_FMAN *
		(FMC_SCHEMES_NUM + FMC_CC_NODES_NUM)];
};

struct fmc_model_t *g_fmc_model;

static int dpaa_port_fmc_port_parse(
	struct fman_if *fif,
	const struct fmc_model_t *fmc_model,
	int apply_idx)
{
	int current_port = fmc_model->apply_order[apply_idx].index;
	const fmc_port *pport = &fmc_model->port[current_port];
	const uint8_t mac_idx[] = {-1, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1};
	const uint8_t mac_type[] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2};

	if (mac_idx[fif->mac_idx] != pport->number ||
		mac_type[fif->mac_idx] != pport->type)
		return -1;

	return current_port;
}

static int dpaa_port_fmc_scheme_parse(
	struct fman_if *fif,
	const struct fmc_model_t *fmc_model,
	int apply_idx,
	uint16_t *rxq_idx, int max_nb_rxq,
	uint32_t *fqids, int8_t *vspids)
{
	int scheme_idx = fmc_model->apply_order[apply_idx].index;
	uint32_t i;

	if (!fmc_model->scheme[scheme_idx].override_storage_profile &&
		fif->is_shared_mac) {
		DPAA_PMD_WARN("No VSP is assigned to sheme %d for sharemac %d!",
			scheme_idx, fif->mac_idx);
		DPAA_PMD_WARN("Risk to receive pkts from skb pool to CRASH!");
	}

	if (e_IOC_FM_PCD_DONE ==
		fmc_model->scheme[scheme_idx].next_engine) {
		for (i = 0; i < fmc_model->scheme[scheme_idx]
			.key_extract_and_hash_params.hash_distribution_num_of_fqids; i++) {
			uint32_t fqid = fmc_model->scheme[scheme_idx].base_fqid + i;
			int k, found = 0;

			if (fqid == fif->fqid_rx_def) {
				if (fif->is_shared_mac &&
				fmc_model->scheme[scheme_idx].override_storage_profile &&
				fmc_model->scheme[scheme_idx].storage_profile.direct &&
				fmc_model->scheme[scheme_idx].storage_profile
				.profile_select.direct_relative_profileId !=
				fif->base_profile_id) {
					DPAA_PMD_ERR(
					"Default RXQ must be associated"
					" with default VSP on sharemac!");

					return -1;
				}
				continue;
			}

			if (fif->is_shared_mac &&
			!fmc_model->scheme[scheme_idx].override_storage_profile) {
				DPAA_PMD_ERR(
					"RXQ to DPDK must be associated"
					" with VSP on sharemac!");
				return -1;
			}

			if (fif->is_shared_mac &&
			fmc_model->scheme[scheme_idx].override_storage_profile &&
			fmc_model->scheme[scheme_idx].storage_profile.direct &&
			fmc_model->scheme[scheme_idx].storage_profile
			.profile_select.direct_relative_profileId ==
			fif->base_profile_id) {
				DPAA_PMD_ERR(
					"RXQ can't be associated"
					" with default VSP on sharemac!");

				return -1;
			}

			if ((*rxq_idx) >= max_nb_rxq) {
				DPAA_PMD_DEBUG(
					"Too many queues in FMC policy"
					"%d overflow %d",
					(*rxq_idx), max_nb_rxq);

				continue;
			}

			for (k = 0; k < (*rxq_idx); k++) {
				if (fqids[k] == fqid) {
					found = 1;
					break;
				}
			}

			if (found)
				continue;
			fqids[(*rxq_idx)] = fqid;
			if (fmc_model->scheme[scheme_idx].override_storage_profile) {
				if (fmc_model->scheme[scheme_idx].storage_profile.direct) {
					vspids[(*rxq_idx)] =
						fmc_model->scheme[scheme_idx].storage_profile
							.profile_select.direct_relative_profileId;
				} else {
					vspids[(*rxq_idx)] = -1;
				}
			} else {
				vspids[(*rxq_idx)] = -1;
			}
			(*rxq_idx)++;
		}
	}

	return 0;
}

static int dpaa_port_fmc_ccnode_parse(
	struct fman_if *fif,
	const struct fmc_model_t *fmc_model,
	int apply_idx,
	uint16_t *rxq_idx, int max_nb_rxq,
	uint32_t *fqids, int8_t *vspids)
{
	uint16_t j, k, found = 0;
	const struct ioc_keys_params_t *keys_params;
	uint32_t fqid, cc_idx = fmc_model->apply_order[apply_idx].index;

	keys_params = &fmc_model->ccnode[cc_idx].keys_params;

	if ((*rxq_idx) >= max_nb_rxq) {
		DPAA_PMD_WARN(
			"Too many queues in FMC policy"
			"%d overflow %d",
			(*rxq_idx), max_nb_rxq);

		return 0;
	}

	for (j = 0; j < keys_params->num_of_keys; ++j) {
		found = 0;
		fqid = keys_params->key_params[j].cc_next_engine_params
			.params.enqueue_params.new_fqid;

		if (keys_params->key_params[j].cc_next_engine_params
			.next_engine != e_IOC_FM_PCD_DONE) {
			DPAA_PMD_WARN("FMC CC next engine not support");
			continue;
		}
		if (keys_params->key_params[j].cc_next_engine_params
			.params.enqueue_params.action !=
			e_IOC_FM_PCD_ENQ_FRAME)
			continue;
		for (k = 0; k < (*rxq_idx); k++) {
			if (fqids[k] == fqid) {
				found = 1;
				break;
			}
		}
		if (found)
			continue;

		if ((*rxq_idx) >= max_nb_rxq) {
			DPAA_PMD_WARN(
				"Too many queues in FMC policy"
				"%d overflow %d",
				(*rxq_idx), max_nb_rxq);

			return 0;
		}

		fqids[(*rxq_idx)] = fqid;
		vspids[(*rxq_idx)] =
			keys_params->key_params[j].cc_next_engine_params
				.params.enqueue_params
				.new_relative_storage_profile_id;

		if (vspids[(*rxq_idx)] == fif->base_profile_id &&
		    fif->is_shared_mac) {
			DPAA_PMD_ERR(
				"VSP %d can NOT be used on DPDK.",
				vspids[(*rxq_idx)]);
			DPAA_PMD_ERR(
			"It is associated to skb pool of shared interface.");

				return -1;
		}
		(*rxq_idx)++;
	}

	return 0;
}

int dpaa_port_fmc_init(struct fman_if *fif,
		       uint32_t *fqids, int8_t *vspids, int max_nb_rxq)
{
	int current_port = -1, ret;
	uint16_t rxq_idx = 0;
	const struct fmc_model_t *fmc_model;
	uint32_t i;

	if (!g_fmc_model) {
		size_t bytes_read;
		FILE *fp = fopen(FMC_FILE, "rb");

		if (!fp) {
			DPAA_PMD_ERR("%s not exists", FMC_FILE);
			return -1;
		}

		g_fmc_model = rte_malloc(NULL, sizeof(struct fmc_model_t), 64);
		if (!g_fmc_model) {
			DPAA_PMD_ERR("FMC memory alloc failed");
			fclose(fp);
			return -1;
		}

		bytes_read = fread(g_fmc_model,
					sizeof(struct fmc_model_t), 1, fp);
		if (!bytes_read) {
			DPAA_PMD_ERR("No bytes read");
			fclose(fp);
			rte_free(g_fmc_model);
			g_fmc_model = NULL;
			return -1;
		}
		fclose(fp);
	}

	fmc_model = g_fmc_model;

	if (fmc_model->format_version != FMC_OUTPUT_FORMAT_VER)
		return -1;

	for (i = 0; i < fmc_model->apply_order_count; i++) {
		switch (fmc_model->apply_order[i].type) {
		case FMCEngineStart:
			break;
		case FMCEngineEnd:
			break;
		case FMCPortStart:
			current_port = dpaa_port_fmc_port_parse(
				fif, fmc_model, i);
			break;
		case FMCPortEnd:
			break;
		case FMCScheme:
			if (current_port < 0)
				break;

			ret = dpaa_port_fmc_scheme_parse(
				fif, fmc_model,
				i, &rxq_idx, max_nb_rxq, fqids, vspids);
			if (ret)
				return ret;

			break;
		case FMCCCNode:
			if (current_port < 0)
				break;

			ret = dpaa_port_fmc_ccnode_parse(fif, fmc_model,
				i, &rxq_idx, max_nb_rxq, fqids, vspids);
			if (ret)
				return ret;

			break;
		case FMCHTNode:
			break;
		case FMCReplicator:
			break;
		case FMCCCTree:
			break;
		case FMCPolicer:
			break;
		case FMCManipulation:
			break;
		default:
			break;
		}
	}

	return rxq_idx;
}
