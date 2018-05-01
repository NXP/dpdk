/*-
 *   BSD LICENSE
 *
 *   Copyright 2017 NXP
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
 *     * Neither the name of NXP nor the names of its
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
/* System headers */
#include <stdio.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/types.h>

#include <dpaa_ethdev.h>
#include <dpaa_flow.h>
#include <rte_dpaa_logs.h>
#include <fm_port_ext.h>

#define DPAA_MAX_NUM_ETH_DEV	8

#define SCH_EXT_ARR(scheme_params, hdr_idx) \
	scheme_params->key_extract_and_hash_params.extract_array[hdr_idx]

#define SCH_EXT_HDR(scheme_params, hdr_idx) \
	SCH_EXT_ARR(scheme_params, hdr_idx).extract_params.extract_by_hdr

#define SCH_EXT_FULL_FLD(scheme_params, hdr_idx) \
	SCH_EXT_HDR(scheme_params, hdr_idx).extract_by_hdr_type.full_field

/* FM global info */
struct dpaa_fm_info {
	t_Handle fman_handle;
	t_Handle pcd_handle;
};

/*FM model to read and write from file */
struct dpaa_fm_model {
	uint32_t dev_count;
	t_FmPortParams fm_port_params[DPAA_MAX_NUM_ETH_DEV];
	t_Handle scheme_devid[DPAA_MAX_NUM_ETH_DEV];
	t_Handle netenv_devid[DPAA_MAX_NUM_ETH_DEV];
};

struct dpaa_fm_info fm_info;
struct dpaa_fm_model fm_model;
const char *fm_log = "/tmp/fm.bin";

static void fm_prev_cleanup(void)
{
	uint32_t fman_id = 0, i = 0;
	struct dpaa_if dpaa_intf;
	t_FmPcdParams fmPcdParams = {0};

	fm_info.fman_handle = FM_Open(fman_id);
	if (!fm_info.fman_handle)
		return;

	fmPcdParams.h_Fm = fm_info.fman_handle;
	fmPcdParams.prsSupport = true;
	fmPcdParams.kgSupport = true;
	/* FM PCD Open */
	fm_info.pcd_handle = FM_PCD_Open(&fmPcdParams);
	if (!fm_info.pcd_handle)
		return;

	while (i < fm_model.dev_count) {
		/* FM Port Open */
		fm_model.fm_port_params[i].h_Fm = fm_info.fman_handle;
		dpaa_intf.port_handle =
				FM_PORT_Open(&fm_model.fm_port_params[i]);

		dpaa_intf.scheme_handle = CreateDevice
				(fm_info.pcd_handle, fm_model.scheme_devid[i]);

		dpaa_intf.netenv_handle = CreateDevice
				(fm_info.pcd_handle, fm_model.netenv_devid[i]);

		i++;
		if (!dpaa_intf.netenv_handle || !dpaa_intf.scheme_handle ||
							!dpaa_intf.port_handle)
			continue;

		if (dpaa_fm_deconfig(&dpaa_intf))
			DPAA_PMD_ERR("DPAA FM deconfig failed\n");
	}

	if (dpaa_fm_term())
		DPAA_PMD_WARN("DPAA FM term failed\n");

	memset(&fm_model, 0, sizeof(struct dpaa_fm_model));
}

void dpaa_write_fm_config_to_file(void)
{
	size_t bytes_write;
	FILE *fp = fopen(fm_log, "wb");
	if (!fp) {
		DPAA_PMD_ERR("File open failed\n");
		return;
	}
	bytes_write = fwrite(&fm_model, sizeof(struct dpaa_fm_model), 1, fp);
	if (!bytes_write) {
		DPAA_PMD_WARN("No bytes write\n");
		fclose(fp);
		return;
	}
	fclose(fp);
}

static void dpaa_read_fm_config_from_file(void)
{
	size_t bytes_read;
	FILE *fp = fopen(fm_log, "rb");
	if (!fp)
		return;
	bytes_read = fread(&fm_model, sizeof(struct dpaa_fm_model), 1, fp);
	if (!bytes_read) {
		DPAA_PMD_WARN("No bytes read\n");
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
	struct dpaa_if *dpaa_intf)
{
	int dist_idx, hdr_idx = 0;

	scheme_params->use_hash = 1;
	scheme_params->modify = false;
	scheme_params->always_direct = false;
	scheme_params->scheme_counter.update = 1;
	scheme_params->scheme_counter.value = 0;
	scheme_params->next_engine = e_IOC_FM_PCD_DONE;
	scheme_params->base_fqid = DPAA_PCD_FQID_START + (dpaa_intf->ifid *
						DPAA_PCD_FQID_MULTIPLIER);
	scheme_params->net_env_params.net_env_id = dpaa_intf->netenv_handle;
	scheme_params->net_env_params.num_of_distinction_units =
					dist_units->num_of_distinction_units;

	scheme_params->key_extract_and_hash_params.
		hash_distribution_num_of_fqids = dpaa_intf->nb_rx_queues;
	scheme_params->key_extract_and_hash_params.
		num_of_used_extracts = 2 * dist_units->num_of_distinction_units;

	for (dist_idx = 0; dist_idx < dist_units->num_of_distinction_units;
	     dist_idx++) {

		switch (dist_units->units[dist_idx].hdrs[0].hdr) {
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
			DPAA_PMD_ERR("Invalid Distinction Unit\n");
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

	if (!req_dist_set)
		dist_units->units[dist_idx++].hdrs[0].hdr = HEADER_TYPE_IPv4;

	while (req_dist_set) {
		if (req_dist_set % 2 != 0) {
			dist_field = 1U << loop;
			switch (dist_field) {
			case ETH_RSS_L2_PAYLOAD:

				if (l2_configured)
					break;
				l2_configured = 1;

				dist_units->units[dist_idx++].hdrs[0].hdr =
								HEADER_TYPE_ETH;
				break;

			case ETH_RSS_IPV4:
			case ETH_RSS_FRAG_IPV4:
			case ETH_RSS_NONFRAG_IPV4_OTHER:

				if (ipv4_configured)
					break;
				ipv4_configured = 1;
				dist_units->units[dist_idx++].hdrs[0].hdr =
							HEADER_TYPE_IPv4;
				break;

			case ETH_RSS_IPV6:
			case ETH_RSS_FRAG_IPV6:
			case ETH_RSS_NONFRAG_IPV6_OTHER:
			case ETH_RSS_IPV6_EX:

				if (ipv6_configured)
					break;
				ipv6_configured = 1;
				dist_units->units[dist_idx++].hdrs[0].hdr =
							HEADER_TYPE_IPv6;
				break;

			case ETH_RSS_NONFRAG_IPV4_TCP:
			case ETH_RSS_NONFRAG_IPV6_TCP:
			case ETH_RSS_IPV6_TCP_EX:

				if (tcp_configured)
					break;
				tcp_configured = 1;
				dist_units->units[dist_idx++].hdrs[0].hdr =
							HEADER_TYPE_TCP;
				break;

			case ETH_RSS_NONFRAG_IPV4_UDP:
			case ETH_RSS_NONFRAG_IPV6_UDP:
			case ETH_RSS_IPV6_UDP_EX:

				if (udp_configured)
					break;
				udp_configured = 1;
				dist_units->units[dist_idx++].hdrs[0].hdr =
							HEADER_TYPE_UDP;
				break;

			case ETH_RSS_NONFRAG_IPV4_SCTP:
			case ETH_RSS_NONFRAG_IPV6_SCTP:

				if (sctp_configured)
					break;
				sctp_configured = 1;

				dist_units->units[dist_idx++].hdrs[0].hdr =
							HEADER_TYPE_SCTP;
				break;

			default:
				DPAA_PMD_ERR("Bad flow distribution"
					    " option\n");
			}
		}
		req_dist_set = req_dist_set >> 1;
		loop++;
	}

	/* Dist units is set to dist_idx */
	dist_units->num_of_distinction_units = dist_idx;
}

/* De-Configure DPAA FM */
int dpaa_fm_deconfig(struct dpaa_if *dpaa_intf)
{
	int ret;

	/* FM PORT Disable */
	ret = FM_PORT_Disable(dpaa_intf->port_handle);
	if (ret != E_OK) {
		DPAA_PMD_ERR("FM_PORT_Disable: Failed\n");
		return ret;
	}

	/* FM PORT DeletePCD */
	ret = FM_PORT_DeletePCD(dpaa_intf->port_handle);
	if (ret != E_OK) {
		DPAA_PMD_ERR("FM_PORT_DeletePCD: Failed\n");
		return ret;
	}

	/* FM PCD KgSchemeDelete */
	ret = FM_PCD_KgSchemeDelete(dpaa_intf->scheme_handle);
	if (ret != E_OK) {
		DPAA_PMD_ERR("FM_PCD_KgSchemeDelete: Failed\n");
		return ret;
	}
	dpaa_intf->scheme_handle = NULL;

	/* FM PCD NetEnvCharacteristicsDelete */
	ret = FM_PCD_NetEnvCharacteristicsDelete(dpaa_intf->netenv_handle);
	if (ret != E_OK) {
		DPAA_PMD_ERR("FM_PCD_NetEnvCharacteristicsDelete: Failed\n");
		return ret;
	}
	dpaa_intf->netenv_handle = NULL;

	/* FM PORT Close */
	FM_PORT_Close(dpaa_intf->port_handle);
	dpaa_intf->port_handle = NULL;

	/* Set scheme count to 0 */
	dpaa_intf->scheme_count = 0;

	return 0;
}

int dpaa_fm_init(void)
{
	t_Handle fman_handle;
	t_Handle pcd_handle;
	t_FmPcdParams fmPcdParams = {0};
	/* Hard-coded : fman id 0 since one fman is present in LS104x */
	int fman_id = 0, ret;

	dpaa_read_fm_config_from_file();

	/* FM Open */
	fman_handle = FM_Open(fman_id);
	if (!fman_handle) {
		DPAA_PMD_ERR("FM_Open: Failed\n");
		return -1;
	}

	/* FM PCD Open */
	fmPcdParams.h_Fm = fman_handle;
	fmPcdParams.prsSupport = true;
	fmPcdParams.kgSupport = true;
	pcd_handle = FM_PCD_Open(&fmPcdParams);
	if (!pcd_handle) {
		DPAA_PMD_ERR("FM_PCD_Open: Failed\n");
		return -1;
	}

	/* FM PCD Enable */
	ret = FM_PCD_Enable(pcd_handle);
	if (ret) {
		DPAA_PMD_ERR("FM_PCD_Enable: Failed\n");
		return -1;
	}

	/* Set fman and pcd handle in fm info */
	fm_info.fman_handle = fman_handle;
	fm_info.pcd_handle = pcd_handle;

	return 0;
}

/* Apply PCD configuration on interface */
static inline int set_port_pcd(struct dpaa_if *dpaa_intf)
{
	int ret = 0;
	ioc_fm_port_pcd_params_t pcd_param;
	ioc_fm_port_pcd_prs_params_t prs_param;
	ioc_fm_port_pcd_kg_params_t  kg_param;
	/* PCD support for hash distribution */
	uint8_t pcd_support = e_FM_PORT_PCD_SUPPORT_PRS_AND_KG;

	memset(&pcd_param, 0, sizeof(pcd_param));
	memset(&prs_param, 0, sizeof(prs_param));
	memset(&kg_param, 0, sizeof(kg_param));

	/* Set parse params */
	prs_param.first_prs_hdr = HEADER_TYPE_ETH;

	/* Set kg params */
	kg_param.scheme_ids[0] = dpaa_intf->scheme_handle;
	kg_param.num_of_schemes = dpaa_intf->scheme_count;

	/* Set pcd params */
	pcd_param.net_env_id = dpaa_intf->netenv_handle;
	pcd_param.pcd_support = pcd_support;
	pcd_param.p_kg_params = &kg_param;
	pcd_param.p_prs_params = &prs_param;

	/* FM PORT Disable */
	ret = FM_PORT_Disable(dpaa_intf->port_handle);
	if (ret != E_OK) {
		DPAA_PMD_ERR("FM_PORT_Disable: Failed\n");
		return ret;
	}

	/* FM PORT SetPCD */
	ret = FM_PORT_SetPCD(dpaa_intf->port_handle, &pcd_param);
	if (ret != E_OK) {
		DPAA_PMD_ERR("FM_PORT_SetPCD: Failed\n");
		return ret;
	}

	/* FM PORT Enable */
	ret = FM_PORT_Enable(dpaa_intf->port_handle);
	if (ret != E_OK) {
		DPAA_PMD_ERR("FM_PORT_Enable: Failed\n");
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
	ret = FM_PCD_KgSchemeDelete(dpaa_intf->scheme_handle);
	if (ret != E_OK)
		DPAA_PMD_ERR("FM_PCD_KgSchemeDelete: Failed\n");

	dpaa_intf->scheme_handle = NULL;

	/* FM PCD NetEnvCharacteristicsDelete */
	ret = FM_PCD_NetEnvCharacteristicsDelete(dpaa_intf->netenv_handle);
	if (ret != E_OK)
		DPAA_PMD_ERR("FM_PCD_NetEnvCharacteristicsDelete: Failed\n");

	dpaa_intf->netenv_handle = NULL;

	/* Set scheme count to 0 */
	dpaa_intf->scheme_count = 0;
}

/* Set PCD NetEnv and Scheme */
static inline int set_pcd_netenv_scheme(struct dpaa_if *dpaa_intf,
					uint64_t req_dist_set)
{
	int ret = -1;
	ioc_fm_pcd_net_env_params_t dist_units;
	ioc_fm_pcd_kg_scheme_params_t scheme_params;

	/* Set PCD NetEnvCharacteristics */
	memset(&dist_units, 0, sizeof(dist_units));
	memset(&scheme_params, 0, sizeof(scheme_params));

	/* Set dist unit header type */
	set_dist_units(&dist_units, req_dist_set);

	/* FM PCD NetEnvCharacteristicsSet */
	dpaa_intf->netenv_handle = FM_PCD_NetEnvCharacteristicsSet(
					fm_info.pcd_handle, &dist_units);
	if (!dpaa_intf->netenv_handle) {
		DPAA_PMD_ERR("FM_PCD_NetEnvCharacteristicsSet: Failed\n");
		return -1;
	}

	fm_model.netenv_devid[dpaa_intf->ifid] =
					GetDeviceId(dpaa_intf->netenv_handle);
	scheme_params.scm_id.relative_scheme_id = dpaa_intf->ifid;

	/* Set PCD Scheme params */
	ret = set_scheme_params(&scheme_params, &dist_units, dpaa_intf);
	if (ret) {
		DPAA_PMD_ERR("Set scheme params: Failed\n");
		goto net_env_char_delete;
	}

	/* FM PCD KgSchemeSet */
	dpaa_intf->scheme_handle = FM_PCD_KgSchemeSet(
					fm_info.pcd_handle, &scheme_params);
	if (!dpaa_intf->scheme_handle) {
		DPAA_PMD_ERR("FM_PCD_KgSchemeSet: Failed\n");
		goto net_env_char_delete;
	}

	fm_model.scheme_devid[dpaa_intf->ifid] =
					GetDeviceId(dpaa_intf->scheme_handle);
	dpaa_intf->scheme_count++;
	return 0;

net_env_char_delete:
	/* FM PCD NetEnvCharacteristicsDelete */
	ret = FM_PCD_NetEnvCharacteristicsDelete(dpaa_intf->netenv_handle);
	if (ret != E_OK) {
		DPAA_PMD_ERR("FM_PCD_NetEnvCharacteristicsDelete: Failed\n");
		return ret;
	}
	dpaa_intf->netenv_handle = NULL;
	return -1;
}


static inline int get_port_type(struct fman_if *fif)
{
	if (fif->mac_type == fman_mac_1g) {
		return e_FM_PORT_TYPE_RX;
	} else if (fif->mac_type == fman_mac_10g) {
		return e_FM_PORT_TYPE_RX_10G;
	} else {
		DPAA_PMD_ERR("MAC type unsupported\n");
		return -1;
	}
}

static inline int set_fm_port_handle(struct dpaa_if *dpaa_intf)
{
	t_FmPortParams	fm_port_params;

	/* FMAN mac indexes mappings */
	uint8_t mac_idx[] = {-1, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1};

	/* Memset FM port params */
	memset(&fm_port_params, 0, sizeof(fm_port_params));

	/* Set FM port params */
	fm_port_params.h_Fm = fm_info.fman_handle;
	fm_port_params.portType = get_port_type(dpaa_intf->fif);
	fm_port_params.portId = mac_idx[dpaa_intf->fif->mac_idx];

	/* FM PORT Open */
	dpaa_intf->port_handle = FM_PORT_Open(&fm_port_params);
	if (!dpaa_intf->port_handle) {
		DPAA_PMD_ERR("FM_PORT_Open: Failed\n");
		return -1;
	}

	fm_model.fm_port_params[dpaa_intf->ifid] = fm_port_params;

	return 0;
}

int dpaa_fm_config(struct rte_eth_dev *dev, uint64_t req_dist_set)
{
	struct dpaa_if *dpaa_intf = dev->data->dev_private;
	int ret;

	if (dpaa_intf->port_handle) {
		if (dpaa_fm_deconfig(dpaa_intf))
			DPAA_PMD_ERR("DPAA FM deconfig failed\n");
	}

	if (!dev->data->nb_rx_queues)
		return 0;

	if (dev->data->nb_rx_queues & (dev->data->nb_rx_queues - 1)) {
		DPAA_PMD_ERR("No of queues should be power of 2\n");
		return -1;
	}

	dpaa_intf->nb_rx_queues = dev->data->nb_rx_queues;

	/* Open FM Port and set it in port info */
	ret = set_fm_port_handle(dpaa_intf);
	if (ret) {
		DPAA_PMD_ERR("Set FM Port handle: Failed\n");
		return -1;
	}

	/* Set PCD netenv and scheme */
	ret = set_pcd_netenv_scheme(dpaa_intf, req_dist_set);
	if (ret) {
		DPAA_PMD_ERR("Set PCD NetEnv and Scheme: Failed\n");
		goto unset_fm_port_handle;
	}

	/* Set Port PCD */
	ret = set_port_pcd(dpaa_intf);
	if (ret) {
		DPAA_PMD_ERR("Set Port PCD: Failed\n");
		goto unset_pcd_netenv_scheme;
	}

	fm_model.dev_count++;

	return 0;

unset_pcd_netenv_scheme:
	unset_pcd_netenv_scheme(dpaa_intf);

unset_fm_port_handle:
	/* FM PORT Close */
	FM_PORT_Close(dpaa_intf->port_handle);
	dpaa_intf->port_handle = NULL;
	return -1;
}

/* De-initialization of FM */
int dpaa_fm_term(void)
{
	t_Handle fman_handle = NULL;
	t_Handle pcd_handle = NULL;
	int ret;

	fman_handle = fm_info.fman_handle;
	pcd_handle = fm_info.pcd_handle;

	/* FM PCD Disable */
	ret = FM_PCD_Disable(pcd_handle);
	if (ret) {
		DPAA_PMD_ERR("FM_PCD_Disable: Failed\n");
		return -1;
	}

	/* FM PCD Close */
	FM_PCD_Close(pcd_handle);

	/* FM Close */
	FM_Close(fman_handle);

	ret = remove(fm_log);
	if (ret)
		DPAA_PMD_ERR("File remove: Failed\n");

	return 0;
}
