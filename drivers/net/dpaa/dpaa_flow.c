/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2017-2023 NXP
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
#include <rte_pmd_dpaa.h>

#define DPAA_MAX_NUM_ETH_DEV	8

#define SCH_EXT_ARR(scheme_params, hdr_idx) \
	scheme_params->param.key_extract_and_hash_params\
		.extract_array[hdr_idx]

#define SCH_EXT_HDR(scheme_params, hdr_idx) \
	SCH_EXT_ARR(scheme_params, hdr_idx).extract_params.extract_by_hdr

#define SCH_EXT_FULL_FLD(scheme_params, hdr_idx) \
	SCH_EXT_HDR(scheme_params, hdr_idx).extract_by_hdr_type.full_field

/* FMAN mac indexes mappings (0 is unused, first 8 are for 1G, next for 10G
 * ports).
 */
const uint8_t mac_idx[] = {-1, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1};

/* FM global info */
struct dpaa_fm_info {
	t_Handle fman_handle;
	t_Handle pcd_handle;
};

/*FM model to read and write from file */
struct dpaa_fm_model {
	uint32_t dev_count;
	uint8_t device_order[DPAA_MAX_NUM_ETH_DEV];
	t_FmPortParams fm_port_params[DPAA_MAX_NUM_ETH_DEV];
	t_Handle netenv_devid[DPAA_MAX_NUM_ETH_DEV];
	t_Handle scheme_devid[DPAA_MAX_NUM_ETH_DEV][2];
};

static struct dpaa_fm_info fm_info;
static struct dpaa_fm_model fm_model;
static const char *fm_log = "/tmp/fmdpdk.bin";

static void fm_prev_cleanup(void)
{
	uint32_t fman_id = 0, i = 0, devid;
	struct dpaa_if dpaa_intf = {0};
	t_FmPcdParams fmPcdParams = {0};
	PMD_INIT_FUNC_TRACE();

	fm_info.fman_handle = FM_Open(fman_id);
	if (!fm_info.fman_handle) {
		printf("\n%s- unable to open FMAN", __func__);
		return;
	}

	fmPcdParams.h_Fm = fm_info.fman_handle;
	fmPcdParams.prsSupport = true;
	fmPcdParams.kgSupport = true;
	/* FM PCD Open */
	fm_info.pcd_handle = FM_PCD_Open(&fmPcdParams);
	if (!fm_info.pcd_handle) {
		printf("\n%s- unable to open PCD", __func__);
		return;
	}

	while (i < fm_model.dev_count) {
		devid = fm_model.device_order[i];
		/* FM Port Open */
		fm_model.fm_port_params[devid].h_Fm = fm_info.fman_handle;
		dpaa_intf.port_handle =
				FM_PORT_Open(&fm_model.fm_port_params[devid]);
		dpaa_intf.scheme_handle[0] = CreateDevice(fm_info.pcd_handle,
					fm_model.scheme_devid[devid][0]);
		dpaa_intf.scheme_count = 1;
		if (fm_model.scheme_devid[devid][1]) {
			dpaa_intf.scheme_handle[1] =
				CreateDevice(fm_info.pcd_handle,
					fm_model.scheme_devid[devid][1]);
			if (dpaa_intf.scheme_handle[1])
				dpaa_intf.scheme_count++;
		}

		dpaa_intf.netenv_handle = CreateDevice(fm_info.pcd_handle,
					fm_model.netenv_devid[devid]);
		i++;
		if (!dpaa_intf.netenv_handle ||
			!dpaa_intf.scheme_handle[0] ||
			!dpaa_intf.port_handle)
			continue;

		if (dpaa_fm_deconfig(&dpaa_intf, NULL))
			printf("\nDPAA FM deconfig failed\n");
	}

	if (dpaa_fm_term())
		printf("\nDPAA FM term failed\n");

	memset(&fm_model, 0, sizeof(struct dpaa_fm_model));
}

void dpaa_write_fm_config_to_file(void)
{
	size_t bytes_write;
	FILE *fp = fopen(fm_log, "wb");
	PMD_INIT_FUNC_TRACE();

	if (!fp) {
		DPAA_PMD_ERR("File open failed");
		return;
	}
	bytes_write = fwrite(&fm_model, sizeof(struct dpaa_fm_model), 1, fp);
	if (!bytes_write) {
		DPAA_PMD_WARN("No bytes write");
		fclose(fp);
		return;
	}
	fclose(fp);
}

static void dpaa_read_fm_config_from_file(void)
{
	size_t bytes_read;
	FILE *fp = fopen(fm_log, "rb");
	PMD_INIT_FUNC_TRACE();

	if (!fp)
		return;
	DPAA_PMD_INFO("Previous DPDK-FM config instance present, cleaning up.");

	bytes_read = fread(&fm_model, sizeof(struct dpaa_fm_model), 1, fp);
	if (!bytes_read) {
		DPAA_PMD_WARN("No bytes read");
		fclose(fp);
		return;
	}
	fclose(fp);

	/*FM cleanup from previous configured app */
	fm_prev_cleanup();
}

static inline int set_hashParams_eth(
	ioc_fm_pcd_kg_scheme_params_t *scheme_params, int hdr_idx)
{
	int k;

	for (k = 0; k < 2; k++) {
		SCH_EXT_ARR(scheme_params, hdr_idx).type =
						e_IOC_FM_PCD_EXTRACT_BY_HDR;
		SCH_EXT_HDR(scheme_params, hdr_idx).hdr =
						HEADER_TYPE_ETH;
		SCH_EXT_HDR(scheme_params, hdr_idx).hdr_index =
						e_IOC_FM_PCD_HDR_INDEX_NONE;
		SCH_EXT_HDR(scheme_params, hdr_idx).type =
						e_IOC_FM_PCD_EXTRACT_FULL_FIELD;
		if (k == 0)
			SCH_EXT_FULL_FLD(scheme_params, hdr_idx).eth =
						IOC_NET_HEADER_FIELD_ETH_SA;
		else
			SCH_EXT_FULL_FLD(scheme_params, hdr_idx).eth =
						IOC_NET_HEADER_FIELD_ETH_DA;
		hdr_idx++;
	}
	return hdr_idx;
}

static inline int set_hashParams_ipv4(
	ioc_fm_pcd_kg_scheme_params_t *scheme_params, int hdr_idx)
{
	int k;

	for (k = 0; k < 2; k++) {
		SCH_EXT_ARR(scheme_params, hdr_idx).type =
						e_IOC_FM_PCD_EXTRACT_BY_HDR;
		SCH_EXT_HDR(scheme_params, hdr_idx).hdr =
						HEADER_TYPE_IPv4;
		SCH_EXT_HDR(scheme_params, hdr_idx).hdr_index =
						e_IOC_FM_PCD_HDR_INDEX_NONE;
		SCH_EXT_HDR(scheme_params, hdr_idx).type =
						e_IOC_FM_PCD_EXTRACT_FULL_FIELD;
		if (k == 0)
			SCH_EXT_FULL_FLD(scheme_params, hdr_idx).ipv4 =
					IOC_NET_HEADER_FIELD_IPv4_SRC_IP;
		else
			SCH_EXT_FULL_FLD(scheme_params, hdr_idx).ipv4 =
					IOC_NET_HEADER_FIELD_IPv4_DST_IP;
		hdr_idx++;
	}
	return hdr_idx;
}

static inline int set_hashParams_ipv6(
	ioc_fm_pcd_kg_scheme_params_t *scheme_params, int hdr_idx)
{
	int k;

	for (k = 0; k < 2; k++) {
		SCH_EXT_ARR(scheme_params, hdr_idx).type =
						e_IOC_FM_PCD_EXTRACT_BY_HDR;
		SCH_EXT_HDR(scheme_params, hdr_idx).hdr =
							HEADER_TYPE_IPv6;
		SCH_EXT_HDR(scheme_params, hdr_idx).hdr_index =
						e_IOC_FM_PCD_HDR_INDEX_NONE;
		SCH_EXT_HDR(scheme_params, hdr_idx).type =
						e_IOC_FM_PCD_EXTRACT_FULL_FIELD;
		if (k == 0)
			SCH_EXT_FULL_FLD(scheme_params, hdr_idx).ipv6 =
					IOC_NET_HEADER_FIELD_IPv6_SRC_IP;
		else
			SCH_EXT_FULL_FLD(scheme_params, hdr_idx).ipv6 =
					IOC_NET_HEADER_FIELD_IPv6_DST_IP;
		hdr_idx++;
	}
	return hdr_idx;
}

static inline int set_hashParams_udp(
	ioc_fm_pcd_kg_scheme_params_t *scheme_params, int hdr_idx)
{
	int k;

	for (k = 0; k < 2; k++) {
		SCH_EXT_ARR(scheme_params, hdr_idx).type =
						e_IOC_FM_PCD_EXTRACT_BY_HDR;
		SCH_EXT_HDR(scheme_params, hdr_idx).hdr =
						HEADER_TYPE_UDP;
		SCH_EXT_HDR(scheme_params, hdr_idx).hdr_index =
						e_IOC_FM_PCD_HDR_INDEX_NONE;
		SCH_EXT_HDR(scheme_params, hdr_idx).type =
						e_IOC_FM_PCD_EXTRACT_FULL_FIELD;
		if (k == 0)
			SCH_EXT_FULL_FLD(scheme_params, hdr_idx).udp =
					IOC_NET_HEADER_FIELD_UDP_PORT_SRC;
		else
			SCH_EXT_FULL_FLD(scheme_params, hdr_idx).udp =
					IOC_NET_HEADER_FIELD_UDP_PORT_DST;
		hdr_idx++;
	}
	return hdr_idx;
}

static inline int set_hashParams_tcp(
	ioc_fm_pcd_kg_scheme_params_t *scheme_params, int hdr_idx)
{
	int k;

	for (k = 0; k < 2; k++) {
		SCH_EXT_ARR(scheme_params, hdr_idx).type =
						e_IOC_FM_PCD_EXTRACT_BY_HDR;
		SCH_EXT_HDR(scheme_params, hdr_idx).hdr =
						HEADER_TYPE_TCP;
		SCH_EXT_HDR(scheme_params, hdr_idx).hdr_index =
						e_IOC_FM_PCD_HDR_INDEX_NONE;
		SCH_EXT_HDR(scheme_params, hdr_idx).type =
						e_IOC_FM_PCD_EXTRACT_FULL_FIELD;
		if (k == 0)
			SCH_EXT_FULL_FLD(scheme_params, hdr_idx).tcp =
					IOC_NET_HEADER_FIELD_TCP_PORT_SRC;
		else
			SCH_EXT_FULL_FLD(scheme_params, hdr_idx).tcp =
					IOC_NET_HEADER_FIELD_TCP_PORT_DST;
		hdr_idx++;
	}
	return hdr_idx;
}

static inline int set_hashParams_sctp(
	ioc_fm_pcd_kg_scheme_params_t *scheme_params, int hdr_idx)
{
	int k;

	for (k = 0; k < 2; k++) {
		SCH_EXT_ARR(scheme_params, hdr_idx).type =
						e_IOC_FM_PCD_EXTRACT_BY_HDR;
		SCH_EXT_HDR(scheme_params, hdr_idx).hdr =
						HEADER_TYPE_SCTP;
		SCH_EXT_HDR(scheme_params, hdr_idx).hdr_index =
						e_IOC_FM_PCD_HDR_INDEX_NONE;
		SCH_EXT_HDR(scheme_params, hdr_idx).type =
						e_IOC_FM_PCD_EXTRACT_FULL_FIELD;
		if (k == 0)
			SCH_EXT_FULL_FLD(scheme_params, hdr_idx).sctp =
					IOC_NET_HEADER_FIELD_SCTP_PORT_SRC;
		else
			SCH_EXT_FULL_FLD(scheme_params, hdr_idx).sctp =
					IOC_NET_HEADER_FIELD_SCTP_PORT_DST;
		hdr_idx++;
	}
	return hdr_idx;
}

/* Set scheme params for hash distribution */
static int set_scheme_params(
	ioc_fm_pcd_kg_scheme_params_t *scheme_params,
	ioc_fm_pcd_net_env_params_t *dist_units,
	struct dpaa_if *dpaa_intf,
	struct fman_if *fif)
{
	int dist_idx, hdr_idx = 0;
	PMD_INIT_FUNC_TRACE();

	if (fif->num_profiles) {
		scheme_params->param.override_storage_profile = true;
		scheme_params->param.storage_profile.direct = true;
		scheme_params->param.storage_profile.profile_select
			.direct_relative_profileId = fm_default_vsp_id(fif);
	}

	scheme_params->param.use_hash = 1;
	scheme_params->param.modify = false;
	scheme_params->param.always_direct = false;
	scheme_params->param.scheme_counter.update = 1;
	scheme_params->param.scheme_counter.value = 0;
	scheme_params->param.next_engine = e_IOC_FM_PCD_DONE;
	scheme_params->param.base_fqid = dpaa_intf->rx_queues[0].fqid;
	scheme_params->param.net_env_params.net_env_id =
		dpaa_intf->netenv_handle;
	scheme_params->param.net_env_params.num_of_distinction_units =
		dist_units->param.num_of_distinction_units;

	scheme_params->param.key_extract_and_hash_params
		.hash_distribution_num_of_fqids =
		dpaa_intf->nb_rx_queues;
	scheme_params->param.key_extract_and_hash_params
		.num_of_used_extracts =
		2 * dist_units->param.num_of_distinction_units;

	for (dist_idx = 0; dist_idx <
		dist_units->param.num_of_distinction_units;
		dist_idx++) {
		switch (dist_units->param.units[dist_idx].hdrs[0].hdr) {
		case HEADER_TYPE_ETH:
			hdr_idx = set_hashParams_eth(scheme_params, hdr_idx);
			break;

		case HEADER_TYPE_IPv4:
			hdr_idx = set_hashParams_ipv4(scheme_params, hdr_idx);
			break;

		case HEADER_TYPE_IPv6:
			hdr_idx = set_hashParams_ipv6(scheme_params, hdr_idx);
			break;

		case HEADER_TYPE_UDP:
			hdr_idx = set_hashParams_udp(scheme_params, hdr_idx);
			break;

		case HEADER_TYPE_TCP:
			hdr_idx = set_hashParams_tcp(scheme_params, hdr_idx);
			break;

		case HEADER_TYPE_SCTP:
			hdr_idx = set_hashParams_sctp(scheme_params, hdr_idx);
			break;

		default:
			DPAA_PMD_ERR("Invalid Distinction Unit");
			return -1;
		}
	}

	return 0;
}

static void set_dist_units(ioc_fm_pcd_net_env_params_t *dist_units,
			   uint64_t req_dist_set)
{
	uint32_t loop = 0, dist_idx = 0, dist_field = 0;
	int l2_configured = 0, ipv4_configured = 0, ipv6_configured = 0;
	int udp_configured = 0, tcp_configured = 0, sctp_configured = 0;
	PMD_INIT_FUNC_TRACE();

	if (!req_dist_set)
		dist_units->param.units[dist_idx++].hdrs[0].hdr =
			HEADER_TYPE_ETH;

	while (req_dist_set) {
		if (req_dist_set % 2 != 0) {
			dist_field = 1U << loop;
			switch (dist_field) {
			case ETH_RSS_L2_PAYLOAD:

				if (l2_configured)
					break;
				l2_configured = 1;

				dist_units->param.units[dist_idx++].hdrs[0].hdr =
								HEADER_TYPE_ETH;
				break;

			case ETH_RSS_IPV4:
			case ETH_RSS_FRAG_IPV4:
			case ETH_RSS_NONFRAG_IPV4_OTHER:

				if (ipv4_configured)
					break;
				ipv4_configured = 1;
				dist_units->param.units[dist_idx++].hdrs[0].hdr =
							HEADER_TYPE_IPv4;
				break;

			case ETH_RSS_IPV6:
			case ETH_RSS_FRAG_IPV6:
			case ETH_RSS_NONFRAG_IPV6_OTHER:
			case ETH_RSS_IPV6_EX:

				if (ipv6_configured)
					break;
				ipv6_configured = 1;
				dist_units->param.units[dist_idx++].hdrs[0].hdr =
							HEADER_TYPE_IPv6;
				break;

			case ETH_RSS_NONFRAG_IPV4_TCP:
			case ETH_RSS_NONFRAG_IPV6_TCP:
			case ETH_RSS_IPV6_TCP_EX:

				if (tcp_configured)
					break;
				tcp_configured = 1;
				dist_units->param.units[dist_idx++].hdrs[0].hdr =
							HEADER_TYPE_TCP;
				break;

			case ETH_RSS_NONFRAG_IPV4_UDP:
			case ETH_RSS_NONFRAG_IPV6_UDP:
			case ETH_RSS_IPV6_UDP_EX:

				if (udp_configured)
					break;
				udp_configured = 1;
				dist_units->param.units[dist_idx++].hdrs[0].hdr =
							HEADER_TYPE_UDP;
				break;

			case ETH_RSS_NONFRAG_IPV4_SCTP:
			case ETH_RSS_NONFRAG_IPV6_SCTP:

				if (sctp_configured)
					break;
				sctp_configured = 1;

				dist_units->param.units[dist_idx++].hdrs[0].hdr =
							HEADER_TYPE_SCTP;
				break;

			default:
				DPAA_PMD_ERR("Bad flow distribution option");
			}
		}
		req_dist_set = req_dist_set >> 1;
		loop++;
	}

	/* Dist units is set to dist_idx */
	dist_units->param.num_of_distinction_units = dist_idx;
}

/* Apply PCD configuration on interface */
static inline int set_port_pcd(struct dpaa_if *dpaa_intf)
{
	int ret = 0;
	unsigned int idx;
	ioc_fm_port_pcd_params_t pcd_param;
	ioc_fm_port_pcd_prs_params_t prs_param;
	ioc_fm_port_pcd_kg_params_t  kg_param;

	PMD_INIT_FUNC_TRACE();

	/* PCD support for hash distribution */
	uint8_t pcd_support = e_FM_PORT_PCD_SUPPORT_PRS_AND_KG;

	memset(&pcd_param, 0, sizeof(pcd_param));
	memset(&prs_param, 0, sizeof(prs_param));
	memset(&kg_param, 0, sizeof(kg_param));

	/* Set parse params */
	prs_param.first_prs_hdr = HEADER_TYPE_ETH;

	/* Set kg params */
	for (idx = 0; idx < dpaa_intf->scheme_count; idx++)
		kg_param.scheme_ids[idx] = dpaa_intf->scheme_handle[idx];
	kg_param.num_of_schemes = dpaa_intf->scheme_count;

	/* Set pcd params */
	pcd_param.net_env_id = dpaa_intf->netenv_handle;
	pcd_param.pcd_support = pcd_support;
	pcd_param.p_kg_params = &kg_param;
	pcd_param.p_prs_params = &prs_param;

	/* FM PORT Disable */
	ret = FM_PORT_Disable(dpaa_intf->port_handle);
	if (ret != E_OK) {
		DPAA_PMD_ERR("FM_PORT_Disable: Failed");
		return ret;
	}

	/* FM PORT SetPCD */
	ret = FM_PORT_SetPCD(dpaa_intf->port_handle, &pcd_param);
	if (ret != E_OK) {
		DPAA_PMD_ERR("FM_PORT_SetPCD: Failed");
		return ret;
	}

	/* FM PORT Enable */
	ret = FM_PORT_Enable(dpaa_intf->port_handle);
	if (ret != E_OK) {
		DPAA_PMD_ERR("FM_PORT_Enable: Failed");
		goto fm_port_delete_pcd;
	}

	return 0;

fm_port_delete_pcd:
	/* FM PORT DeletePCD */
	ret = FM_PORT_DeletePCD(dpaa_intf->port_handle);
	if (ret != E_OK) {
		DPAA_PMD_ERR("FM_PORT_DeletePCD: Failed\n");
		return ret;
	}
	return -1;
}

/* Unset PCD NerEnv and scheme */
static inline void unset_pcd_netenv_scheme(struct dpaa_if *dpaa_intf)
{
	int ret;
	PMD_INIT_FUNC_TRACE();

	/* reduce scheme count */
	if (dpaa_intf->scheme_count)
		dpaa_intf->scheme_count--;

	DPAA_PMD_DEBUG("KG SCHEME DEL %d handle =%p",
		dpaa_intf->scheme_count,
		dpaa_intf->scheme_handle[dpaa_intf->scheme_count]);

	ret = FM_PCD_KgSchemeDelete(
		dpaa_intf->scheme_handle[dpaa_intf->scheme_count]);
	if (ret != E_OK)
		DPAA_PMD_ERR("FM_PCD_KgSchemeDelete: Failed");

	dpaa_intf->scheme_handle[dpaa_intf->scheme_count] = NULL;
}

/* Set PCD NetEnv and Scheme and default scheme */
static inline int set_default_scheme(struct dpaa_if *dpaa_intf)
{
	ioc_fm_pcd_kg_scheme_params_t scheme_params;
	int idx = dpaa_intf->scheme_count;
	PMD_INIT_FUNC_TRACE();

	/* Set PCD NetEnvCharacteristics */
	memset(&scheme_params, 0, sizeof(scheme_params));

	/* Adding 10 to default schemes as the number of interface would be
	 * lesser than 10 and the relative scheme ids should be unique for
	 * every scheme.
	 */
	scheme_params.param.scm_id.relative_scheme_id =
		10 + dpaa_intf->ifid;
	scheme_params.param.use_hash = 0;
	scheme_params.param.next_engine = e_IOC_FM_PCD_DONE;
	scheme_params.param.net_env_params.num_of_distinction_units = 0;
	scheme_params.param.net_env_params.net_env_id =
		dpaa_intf->netenv_handle;
	scheme_params.param.base_fqid = dpaa_intf->rx_queues[0].fqid;
	scheme_params.param.key_extract_and_hash_params
		.hash_distribution_num_of_fqids = 1;
	scheme_params.param.key_extract_and_hash_params
		.num_of_used_extracts = 0;
	scheme_params.param.modify = false;
	scheme_params.param.always_direct = false;
	scheme_params.param.scheme_counter.update = 1;
	scheme_params.param.scheme_counter.value = 0;

	/* FM PCD KgSchemeSet */
	dpaa_intf->scheme_handle[idx] =
			FM_PCD_KgSchemeSet(fm_info.pcd_handle, &scheme_params);
	DPAA_PMD_DEBUG("KG SCHEME SET %d handle =%p",
		idx, dpaa_intf->scheme_handle[idx]);
	if (!dpaa_intf->scheme_handle[idx]) {
		DPAA_PMD_ERR("FM_PCD_KgSchemeSet: Failed");
		return -1;
	}

	fm_model.scheme_devid[dpaa_intf->ifid][idx] =
				GetDeviceId(dpaa_intf->scheme_handle[idx]);
	dpaa_intf->scheme_count++;
	return 0;
}


/* Set PCD NetEnv and Scheme and default scheme */
static inline int set_pcd_netenv_scheme(struct dpaa_if *dpaa_intf,
					uint64_t req_dist_set,
					struct fman_if *fif)
{
	int ret = -1;
	ioc_fm_pcd_net_env_params_t dist_units;
	ioc_fm_pcd_kg_scheme_params_t scheme_params;
	int idx = dpaa_intf->scheme_count;
	PMD_INIT_FUNC_TRACE();

	/* Set PCD NetEnvCharacteristics */
	memset(&dist_units, 0, sizeof(dist_units));
	memset(&scheme_params, 0, sizeof(scheme_params));

	/* Set dist unit header type */
	set_dist_units(&dist_units, req_dist_set);

	scheme_params.param.scm_id.relative_scheme_id = dpaa_intf->ifid;

	/* Set PCD Scheme params */
	ret = set_scheme_params(&scheme_params, &dist_units, dpaa_intf, fif);
	if (ret) {
		DPAA_PMD_ERR("Set scheme params: Failed");
		return -1;
	}

	/* FM PCD KgSchemeSet */
	dpaa_intf->scheme_handle[idx] =
			FM_PCD_KgSchemeSet(fm_info.pcd_handle, &scheme_params);
	DPAA_PMD_DEBUG("KG SCHEME SET %d handle =%p",
			idx, dpaa_intf->scheme_handle[idx]);
	if (!dpaa_intf->scheme_handle[idx]) {
		DPAA_PMD_ERR("FM_PCD_KgSchemeSet: Failed");
		return -1;
	}

	fm_model.scheme_devid[dpaa_intf->ifid][idx] =
				GetDeviceId(dpaa_intf->scheme_handle[idx]);
	dpaa_intf->scheme_count++;
	return 0;
}


static inline int get_rx_port_type(struct fman_if *fif)
{
	/* For onic ports, configure the VSP as offline ports so that
	 * kernel can configure correct port.
	 */
	if (fif->mac_type == fman_offline_internal ||
	    fif->mac_type == fman_onic)
		return e_FM_PORT_TYPE_OH_OFFLINE_PARSING;
	/* For 1G fm-mac9 and fm-mac10 ports, configure the VSP as 10G
	 * ports so that kernel can configure correct port.
	 */
	else if (fif->mac_type == fman_mac_1g &&
		fif->mac_idx >= DPAA_10G_MAC_START_IDX)
		return e_FM_PORT_TYPE_RX_10G;
	else if (fif->mac_type == fman_mac_1g)
		return e_FM_PORT_TYPE_RX;
	else if (fif->mac_type == fman_mac_2_5g)
		return e_FM_PORT_TYPE_RX_2_5G;
	else if (fif->mac_type == fman_mac_10g)
		return e_FM_PORT_TYPE_RX_10G;

	DPAA_PMD_ERR("MAC type unsupported");
	return e_FM_PORT_TYPE_DUMMY;
}

static inline int get_tx_port_type(struct fman_if *fif)
{
	if (fif->mac_type == fman_offline_internal ||
	    fif->mac_type == fman_onic)
		return e_FM_PORT_TYPE_OH_OFFLINE_PARSING;
	else if (fif->mac_type == fman_mac_1g)
		return e_FM_PORT_TYPE_TX;
	else if (fif->mac_type == fman_mac_2_5g)
		return e_FM_PORT_TYPE_TX_2_5G;
	else if (fif->mac_type == fman_mac_10g)
		return e_FM_PORT_TYPE_TX_10G;

	DPAA_PMD_ERR("MAC type unsupported");
	return e_FM_PORT_TYPE_DUMMY;
}

static inline int set_fm_port_handle(struct dpaa_if *dpaa_intf,
				     uint64_t req_dist_set,
				     struct fman_if *fif)
{
	t_FmPortParams	fm_port_params;
	ioc_fm_pcd_net_env_params_t dist_units;
	PMD_INIT_FUNC_TRACE();

	/* Memset FM port params */
	memset(&fm_port_params, 0, sizeof(fm_port_params));

	/* Set FM port params */
	fm_port_params.h_Fm = fm_info.fman_handle;
	fm_port_params.portType = get_rx_port_type(fif);
	fm_port_params.portId = mac_idx[fif->mac_idx];

	/* FM PORT Open */
	dpaa_intf->port_handle = FM_PORT_Open(&fm_port_params);
	if (!dpaa_intf->port_handle) {
		DPAA_PMD_ERR("FM_PORT_Open: Failed\n");
		return -1;
	}

	fm_model.fm_port_params[dpaa_intf->ifid] = fm_port_params;

	/* Set PCD NetEnvCharacteristics */
	memset(&dist_units, 0, sizeof(dist_units));

	/* Set dist unit header type */
	set_dist_units(&dist_units, req_dist_set);

	/* FM PCD NetEnvCharacteristicsSet */
	dpaa_intf->netenv_handle = FM_PCD_NetEnvCharacteristicsSet(
					fm_info.pcd_handle, &dist_units);
	if (!dpaa_intf->netenv_handle) {
		DPAA_PMD_ERR("FM_PCD_NetEnvCharacteristicsSet: Failed");
		return -1;
	}

	fm_model.netenv_devid[dpaa_intf->ifid] =
				GetDeviceId(dpaa_intf->netenv_handle);

	return 0;
}

/* De-Configure DPAA FM */
int dpaa_fm_deconfig(struct dpaa_if *dpaa_intf,
			struct fman_if *fif __rte_unused)
{
	int ret;
	unsigned int idx;

	PMD_INIT_FUNC_TRACE();

	/* FM PORT Disable */
	ret = FM_PORT_Disable(dpaa_intf->port_handle);
	if (ret != E_OK) {
		DPAA_PMD_ERR("FM_PORT_Disable: Failed");
		return ret;
	}

	/* FM PORT DeletePCD */
	ret = FM_PORT_DeletePCD(dpaa_intf->port_handle);
	if (ret != E_OK) {
		DPAA_PMD_ERR("FM_PORT_DeletePCD: Failed");
		return ret;
	}

	for (idx = 0; idx < dpaa_intf->scheme_count; idx++) {
		DPAA_PMD_DEBUG("KG SCHEME DEL %d, handle =%p",
			idx, dpaa_intf->scheme_handle[idx]);
		/* FM PCD KgSchemeDelete */
		ret = FM_PCD_KgSchemeDelete(dpaa_intf->scheme_handle[idx]);
		if (ret != E_OK) {
			DPAA_PMD_ERR("FM_PCD_KgSchemeDelete: Failed");
			return ret;
		}
		dpaa_intf->scheme_handle[idx] = NULL;
	}
	/* FM PCD NetEnvCharacteristicsDelete */
	ret = FM_PCD_NetEnvCharacteristicsDelete(dpaa_intf->netenv_handle);
	if (ret != E_OK) {
		DPAA_PMD_ERR("FM_PCD_NetEnvCharacteristicsDelete: Failed");
		return ret;
	}
	dpaa_intf->netenv_handle = NULL;

	if (fif && fif->is_shared_mac) {
		ret = FM_PORT_Enable(dpaa_intf->port_handle);
		if (ret != E_OK) {
			DPAA_PMD_ERR("shared mac re-enable failed");
			return ret;
		}
	}

	/* FM PORT Close */
	FM_PORT_Close(dpaa_intf->port_handle);
	dpaa_intf->port_handle = NULL;

	/* Set scheme count to 0 */
	dpaa_intf->scheme_count = 0;

	return 0;
}

int dpaa_fm_config(struct rte_eth_dev *dev, uint64_t req_dist_set)
{
	struct dpaa_if *dpaa_intf = dev->data->dev_private;
	struct fman_if *fif = dev->process_private;
	int ret;
	unsigned int i = 0;
	PMD_INIT_FUNC_TRACE();

	if (dpaa_intf->port_handle) {
		if (dpaa_fm_deconfig(dpaa_intf, fif))
			DPAA_PMD_ERR("DPAA FM deconfig failed");
	}

	if (!dev->data->nb_rx_queues)
		return 0;

	if (dev->data->nb_rx_queues & (dev->data->nb_rx_queues - 1)) {
		DPAA_PMD_ERR("No of queues should be power of 2");
		return -1;
	}

	dpaa_intf->nb_rx_queues = dev->data->nb_rx_queues;

	/* Open FM Port and set it in port info */
	ret = set_fm_port_handle(dpaa_intf, req_dist_set, fif);
	if (ret) {
		DPAA_PMD_ERR("Set FM Port handle: Failed");
		return -1;
	}

	if (fif->num_profiles) {
		for (i = 0; i < dpaa_intf->nb_rx_queues; i++)
			dpaa_intf->rx_queues[i].vsp_id =
				fm_default_vsp_id(fif);

		i = 0;
	}

	/* Set PCD netenv and scheme */
	if (req_dist_set) {
		ret = set_pcd_netenv_scheme(dpaa_intf, req_dist_set, fif);
		if (ret) {
			DPAA_PMD_ERR("Set PCD NetEnv and Scheme dist: Failed");
			goto unset_fm_port_handle;
		}
	}
	/* Set default netenv and scheme */
	if (!fif->is_shared_mac) {
		ret = set_default_scheme(dpaa_intf);
		if (ret) {
			DPAA_PMD_ERR("Set PCD NetEnv and Scheme: Failed");
			goto unset_pcd_netenv_scheme1;
		}
	}

	/* Set Port PCD */
	ret = set_port_pcd(dpaa_intf);
	if (ret) {
		DPAA_PMD_ERR("Set Port PCD: Failed");
		goto unset_pcd_netenv_scheme;
	}

	for (; i < fm_model.dev_count; i++)
		if (fm_model.device_order[i] == dpaa_intf->ifid)
			return 0;

	fm_model.device_order[fm_model.dev_count] = dpaa_intf->ifid;
	fm_model.dev_count++;

	return 0;

unset_pcd_netenv_scheme:
	unset_pcd_netenv_scheme(dpaa_intf);

unset_pcd_netenv_scheme1:
	unset_pcd_netenv_scheme(dpaa_intf);

unset_fm_port_handle:
	/* FM PORT Close */
	FM_PORT_Close(dpaa_intf->port_handle);
	dpaa_intf->port_handle = NULL;
	return -1;
}

int dpaa_fm_init(void)
{
	t_Handle fman_handle;
	t_Handle pcd_handle;
	t_FmPcdParams fmPcdParams = {0};
	/* Hard-coded : fman id 0 since one fman is present in LS104x */
	int fman_id = 0, ret;
	PMD_INIT_FUNC_TRACE();

	dpaa_read_fm_config_from_file();

	/* FM Open */
	fman_handle = FM_Open(fman_id);
	if (!fman_handle) {
		DPAA_PMD_ERR("FM_Open: Failed");
		return -1;
	}

	/* FM PCD Open */
	fmPcdParams.h_Fm = fman_handle;
	fmPcdParams.prsSupport = true;
	fmPcdParams.kgSupport = true;
	pcd_handle = FM_PCD_Open(&fmPcdParams);
	if (!pcd_handle) {
		FM_Close(fman_handle);
		DPAA_PMD_ERR("FM_PCD_Open: Failed");
		return -1;
	}

	/* FM PCD Enable */
	ret = FM_PCD_Enable(pcd_handle);
	if (ret) {
		FM_Close(fman_handle);
		FM_PCD_Close(pcd_handle);
		DPAA_PMD_ERR("FM_PCD_Enable: Failed");
		return -1;
	}

	/* Set fman and pcd handle in fm info */
	fm_info.fman_handle = fman_handle;
	fm_info.pcd_handle = pcd_handle;

	return 0;
}


/* De-initialization of FM */
int dpaa_fm_term(void)
{
	int ret;

	PMD_INIT_FUNC_TRACE();

	if (fm_info.pcd_handle && fm_info.fman_handle) {
		/* FM PCD Disable */
		ret = FM_PCD_Disable(fm_info.pcd_handle);
		if (ret) {
			DPAA_PMD_ERR("FM_PCD_Disable: Failed");
			return -1;
		}

		/* FM PCD Close */
		FM_PCD_Close(fm_info.pcd_handle);
		fm_info.pcd_handle = NULL;
	}

	if (fm_info.fman_handle) {
		/* FM Close */
		FM_Close(fm_info.fman_handle);
		fm_info.fman_handle = NULL;
	}

	if (access(fm_log, F_OK) != -1) {
		ret = remove(fm_log);
		if (ret)
			DPAA_PMD_ERR("File remove: Failed");
	}
	return 0;
}

static int dpaa_port_vsp_configure(struct dpaa_if *dpaa_intf,
		uint8_t vsp_id, t_Handle fman_handle,
		struct fman_if *fif, u32 mbuf_data_room_size)
{
	t_FmVspParams vsp_params;
	t_FmBufferPrefixContent buf_prefix_cont;
	uint8_t idx = mac_idx[fif->mac_idx];
	int ret;

	if (vsp_id == fif->base_profile_id && fif->is_shared_mac) {
		/* For shared interface, VSP of base
		 * profile is default pool located in kernel.
		 */
		dpaa_intf->vsp_bpid[vsp_id] = 0;
		return 0;
	}

	if (vsp_id >= DPAA_VSP_PROFILE_MAX_NUM) {
		DPAA_PMD_ERR("VSP ID %d exceeds MAX number %d",
			vsp_id, DPAA_VSP_PROFILE_MAX_NUM);
		return -1;
	}

	memset(&vsp_params, 0, sizeof(vsp_params));
	vsp_params.h_Fm = fman_handle;
	vsp_params.relativeProfileId = vsp_id;
	if (fif->mac_type == fman_offline_internal ||
	    fif->mac_type == fman_onic)
		vsp_params.portParams.portId = fif->mac_idx;
	else
		vsp_params.portParams.portId = idx;

	vsp_params.portParams.portType = get_rx_port_type(fif);
	if (vsp_params.portParams.portType == e_FM_PORT_TYPE_DUMMY) {
		DPAA_PMD_ERR("Mac type %d error", fif->mac_type);
		return -1;
	}

	vsp_params.extBufPools.numOfPoolsUsed = 1;
	vsp_params.extBufPools.extBufPool[0].id = dpaa_intf->vsp_bpid[vsp_id];
	vsp_params.extBufPools.extBufPool[0].size = mbuf_data_room_size;

	dpaa_intf->vsp_handle[vsp_id] = FM_VSP_Config(&vsp_params);
	if (!dpaa_intf->vsp_handle[vsp_id]) {
		DPAA_PMD_ERR("FM_VSP_Config error for profile %d", vsp_id);
		return -EINVAL;
	}

	/* configure the application buffer (structure, size and
	 * content)
	 */

	memset(&buf_prefix_cont, 0, sizeof(buf_prefix_cont));

	buf_prefix_cont.privDataSize = 16;
	buf_prefix_cont.dataAlign = 64;
	buf_prefix_cont.passPrsResult = true;
	buf_prefix_cont.passTimeStamp = true;
	buf_prefix_cont.passHashResult = false;
	buf_prefix_cont.passAllOtherPCDInfo = false;
	buf_prefix_cont.manipExtraSpace =
		RTE_PKTMBUF_HEADROOM - DPAA_MBUF_HW_ANNOTATION;

	ret = FM_VSP_ConfigBufferPrefixContent(dpaa_intf->vsp_handle[vsp_id],
					       &buf_prefix_cont);
	if (ret != E_OK) {
		DPAA_PMD_ERR("FM_VSP_ConfigBufferPrefixContent error for profile %d err: %d",
			     vsp_id, ret);
		return ret;
	}

	/* initialize the FM VSP module */
	ret = FM_VSP_Init(dpaa_intf->vsp_handle[vsp_id]);
	if (ret != E_OK) {
		DPAA_PMD_ERR("FM_VSP_Init error for profile %d err:%d",
			 vsp_id, ret);
		return ret;
	}

	return 0;
}

int dpaa_port_vsp_update(struct dpaa_if *dpaa_intf,
		bool fmc_mode, uint8_t vsp_id, uint32_t bpid,
		struct fman_if *fif, u32 mbuf_data_room_size)
{
	int ret = 0;
	t_Handle fman_handle;

	if (!fif->num_profiles)
		return 0;

	if (vsp_id >= fif->num_profiles)
		return 0;

	if (dpaa_intf->vsp_bpid[vsp_id] == bpid)
		return 0;

	if (dpaa_intf->vsp_handle[vsp_id]) {
		ret = FM_VSP_Free(dpaa_intf->vsp_handle[vsp_id]);
		if (ret != E_OK) {
			DPAA_PMD_ERR(
				"Error FM_VSP_Free: "
				"err %d vsp_handle[%d]",
				ret, vsp_id);
			return ret;
		}
		dpaa_intf->vsp_handle[vsp_id] = 0;
	}

	if (fmc_mode)
		fman_handle = FM_Open(0);
	else
		fman_handle = fm_info.fman_handle;

	dpaa_intf->vsp_bpid[vsp_id] = bpid;

	return dpaa_port_vsp_configure(dpaa_intf, vsp_id, fman_handle, fif,
				       mbuf_data_room_size);
}

int dpaa_port_vsp_cleanup(struct dpaa_if *dpaa_intf, struct fman_if *fif)
{
	int idx, ret;

	for (idx = 0; idx < (uint8_t)fif->num_profiles; idx++) {
		if (dpaa_intf->vsp_handle[idx]) {
			ret = FM_VSP_Free(dpaa_intf->vsp_handle[idx]);
			if (ret != E_OK) {
				DPAA_PMD_ERR("Error FM_VSP_Free: err %d vsp_handle[%d]",
					ret, idx);
				return ret;
			}
		}
	}

	return E_OK;
}

int rte_pmd_dpaa_port_set_rate_limit(uint16_t port_id, uint16_t burst,
				     uint32_t rate)
{
	t_FmPortRateLimit port_rate_limit;
	bool port_handle_exists = true;
	void *handle;
	uint32_t ret;
	struct rte_eth_dev *dev;
	struct dpaa_if *dpaa_intf;
	struct fman_if *fif;

	RTE_ETH_VALID_PORTID_OR_ERR_RET(port_id, -ENODEV);
	dev = &rte_eth_devices[port_id];
	dpaa_intf = dev->data->dev_private;
	fif = dev->process_private;

	memset(&port_rate_limit, 0, sizeof(port_rate_limit));
	port_rate_limit.maxBurstSize = burst;
	port_rate_limit.rateLimit = rate;

	DPAA_PMD_DEBUG("Setting Rate Limiter for port:%s  Max Burst =%u Max Rate =%u \n",
		       dpaa_intf->name, burst, rate);

	if (!dpaa_intf->port_handle) {

		t_FmPortParams fm_port_params;

		/* Memset FM port params */
		memset(&fm_port_params, 0, sizeof(fm_port_params));

		/* Set FM port params */
		fm_port_params.h_Fm = FM_Open(0);
		fm_port_params.portType = get_tx_port_type(fif);
		fm_port_params.portId = mac_idx[fif->mac_idx];

		/* FM PORT Open */
		handle = FM_PORT_Open(&fm_port_params);
		FM_Close(fm_port_params.h_Fm);
		if (!handle) {
			DPAA_PMD_ERR("%s: Can't open handle %p \n",
				     __FUNCTION__, fm_info.fman_handle);
			return -ENODEV;
		}

		port_handle_exists = false;
	} else
		handle = dpaa_intf->port_handle;

	if (burst == 0 || rate == 0)
		ret = FM_PORT_DeleteRateLimit(handle);
	else
		ret = FM_PORT_SetRateLimit(handle, &port_rate_limit);

	if (ret) {
		DPAA_PMD_ERR("%s: Failed to set rate limit ret = %#x\n",
			     __FUNCTION__, -ret);

		if (!port_handle_exists)
			FM_PORT_Close(handle);

		return -ret;
	}

	DPAA_PMD_DEBUG("%s: FM_PORT_SetRateLimit ret = %#x\n",
		       __FUNCTION__, -ret);

	if (!port_handle_exists)
		FM_PORT_Close(handle);

	return 0;
}
