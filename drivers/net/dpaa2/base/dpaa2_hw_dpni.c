/*-
 *   BSD LICENSE
 *
 *   Copyright (c) 2016 Freescale Semiconductor, Inc. All rights reserved.
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
 *     * Neither the name of Freescale Semiconductor, Inc nor the names of its
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

#include <time.h>
#include <net/if.h>

#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_string_fns.h>
#include <rte_cycles.h>
#include <rte_kvargs.h>
#include <rte_dev.h>
#include <rte_ethdev.h>

/* DPAA2 Global constants */
#include <dpaa2_hw_pvt.h>
#include "dpaa2_logs.h"

/* DPAA2 Base interface files */
#include <dpaa2_hw_dpbp.h>
#include <dpaa2_hw_dpni.h>
#include <dpaa2_hw_dpio.h>

static void
dpaa2_distset_to_dpkg_profile_cfg(
		uint32_t req_dist_set,
		struct dpkg_profile_cfg *kg_cfg);

int
dpaa2_setup_flow_distribution(struct rte_eth_dev *eth_dev,
			      uint32_t req_dist_set)
{
	struct dpaa2_dev_priv *priv = eth_dev->data->dev_private;
	struct fsl_mc_io *dpni = priv->hw;
	struct dpni_rx_tc_dist_cfg tc_cfg;
	struct dpkg_profile_cfg kg_cfg;
	void *p_params;
	int ret, tc_index = 0;

	p_params = rte_malloc(
		NULL, DIST_PARAM_IOVA_SIZE, RTE_CACHE_LINE_SIZE);
	if (!p_params) {
		PMD_DRV_LOG(ERR, "Memory unavaialble\n");
		return -ENOMEM;
	}
	memset(p_params, 0, DIST_PARAM_IOVA_SIZE);
	memset(&tc_cfg, 0, sizeof(struct dpni_rx_tc_dist_cfg));

	dpaa2_distset_to_dpkg_profile_cfg(req_dist_set, &kg_cfg);
	tc_cfg.key_cfg_iova = (uint64_t)(DPAA2_VADDR_TO_IOVA(p_params));
	tc_cfg.dist_size = eth_dev->data->nb_rx_queues;
	tc_cfg.dist_mode = DPNI_DIST_MODE_HASH;

	ret = dpni_prepare_key_cfg(&kg_cfg, p_params);
	if (ret) {
		PMD_DRV_LOG(ERR, "Unable to prepare extract parameters\n");
		rte_free(p_params);
		return ret;
	}

	ret = dpni_set_rx_tc_dist(dpni, CMD_PRI_LOW, priv->token, tc_index,
				  &tc_cfg);
	rte_free(p_params);
	if (ret) {
		PMD_DRV_LOG(ERR, "Setting distribution for Rx failed with"
			"err code: %d\n", ret);
		return ret;
	}

	return 0;
}

int
dpaa2_remove_flow_distribution(
	struct rte_eth_dev *eth_dev,
	uint8_t tc_index)
{
	struct dpaa2_dev_priv *priv = eth_dev->data->dev_private;
	struct fsl_mc_io *dpni = priv->hw;
	struct dpni_rx_tc_dist_cfg tc_cfg;
	struct dpkg_profile_cfg kg_cfg;
	void *p_params;
	int ret;

	p_params = rte_malloc(
		NULL, DIST_PARAM_IOVA_SIZE, RTE_CACHE_LINE_SIZE);
	if (!p_params) {
		PMD_DRV_LOG(ERR, "Memory unavaialble\n");
		return -ENOMEM;
	}
	memset(p_params, 0, DIST_PARAM_IOVA_SIZE);
	memset(&tc_cfg, 0, sizeof(struct dpni_rx_tc_dist_cfg));

	tc_cfg.key_cfg_iova = (uint64_t)(DPAA2_VADDR_TO_IOVA(p_params));
	tc_cfg.dist_size = 0;
	tc_cfg.dist_mode = DPNI_DIST_MODE_NONE;

	ret = dpni_prepare_key_cfg(&kg_cfg, p_params);
	if (ret) {
		PMD_DRV_LOG(ERR, "Unable to prepare extract parameters\n");
		rte_free(p_params);
		return ret;
	}

	ret = dpni_set_rx_tc_dist(dpni, CMD_PRI_LOW, priv->token, tc_index,
				  &tc_cfg);
	rte_free(p_params);
	if (ret) {
		PMD_DRV_LOG(ERR, "Setting distribution for Rx failed with"
			"err code: %d\n", ret);
		return ret;
	}
	return ret;
}

static void
dpaa2_distset_to_dpkg_profile_cfg(
		uint32_t req_dist_set,
		struct dpkg_profile_cfg *kg_cfg)
{
	uint32_t loop = 0, i = 0, dist_field = 0;
	int l2_configured = 0, l3_configured = 0;
	int l4_configured = 0, sctp_configured = 0;

	memset(kg_cfg, 0, sizeof(struct dpkg_profile_cfg));
	while (req_dist_set) {
		if (req_dist_set % 2 != 0) {
			dist_field = 1U << loop;
			switch (dist_field) {
			case ETH_RSS_L2_PAYLOAD:

				if (l2_configured)
					break;
				l2_configured = 1;

				kg_cfg->extracts[i].extract.from_hdr.prot =
					NET_PROT_ETH;
				kg_cfg->extracts[i].extract.from_hdr.field =
					NH_FLD_ETH_TYPE;
				kg_cfg->extracts[i].type = DPKG_EXTRACT_FROM_HDR;
				kg_cfg->extracts[i].extract.from_hdr.type =
					DPKG_FULL_FIELD;
				i++;
			break;

			case ETH_RSS_IPV4:
			case ETH_RSS_FRAG_IPV4:
			case ETH_RSS_NONFRAG_IPV4_OTHER:
			case ETH_RSS_IPV6:
			case ETH_RSS_FRAG_IPV6:
			case ETH_RSS_NONFRAG_IPV6_OTHER:
			case ETH_RSS_IPV6_EX:

				if (l3_configured)
					break;
				l3_configured = 1;

				kg_cfg->extracts[i].extract.from_hdr.prot =
					NET_PROT_IP;
				kg_cfg->extracts[i].extract.from_hdr.field =
					NH_FLD_IP_SRC;
				kg_cfg->extracts[i].type = DPKG_EXTRACT_FROM_HDR;
				kg_cfg->extracts[i].extract.from_hdr.type =
					DPKG_FULL_FIELD;
				i++;

				kg_cfg->extracts[i].extract.from_hdr.prot =
					NET_PROT_IP;
				kg_cfg->extracts[i].extract.from_hdr.field =
					NH_FLD_IP_DST;
				kg_cfg->extracts[i].type = DPKG_EXTRACT_FROM_HDR;
				kg_cfg->extracts[i].extract.from_hdr.type =
					DPKG_FULL_FIELD;
				i++;

				kg_cfg->extracts[i].extract.from_hdr.prot =
					NET_PROT_IP;
				kg_cfg->extracts[i].extract.from_hdr.field =
					NH_FLD_IP_PROTO;
				kg_cfg->extracts[i].type = DPKG_EXTRACT_FROM_HDR;
				kg_cfg->extracts[i].extract.from_hdr.type =
					DPKG_FULL_FIELD;
				kg_cfg->num_extracts++;
				i++;
			break;

			case ETH_RSS_NONFRAG_IPV4_TCP:
			case ETH_RSS_NONFRAG_IPV6_TCP:
			case ETH_RSS_NONFRAG_IPV4_UDP:
			case ETH_RSS_NONFRAG_IPV6_UDP:

				if (l4_configured)
					break;
				l4_configured = 1;

				kg_cfg->extracts[i].extract.from_hdr.prot =
					NET_PROT_TCP;
				kg_cfg->extracts[i].extract.from_hdr.field =
					NH_FLD_TCP_PORT_SRC;
				kg_cfg->extracts[i].type = DPKG_EXTRACT_FROM_HDR;
				kg_cfg->extracts[i].extract.from_hdr.type =
					DPKG_FULL_FIELD;
				i++;

				kg_cfg->extracts[i].extract.from_hdr.prot =
					NET_PROT_TCP;
				kg_cfg->extracts[i].extract.from_hdr.field =
					NH_FLD_TCP_PORT_SRC;
				kg_cfg->extracts[i].type = DPKG_EXTRACT_FROM_HDR;
				kg_cfg->extracts[i].extract.from_hdr.type =
					DPKG_FULL_FIELD;
				i++;
				break;

			case ETH_RSS_NONFRAG_IPV4_SCTP:
			case ETH_RSS_NONFRAG_IPV6_SCTP:

				if (sctp_configured)
					break;
				sctp_configured = 1;

				kg_cfg->extracts[i].extract.from_hdr.prot =
					NET_PROT_SCTP;
				kg_cfg->extracts[i].extract.from_hdr.field =
					NH_FLD_SCTP_PORT_SRC;
				kg_cfg->extracts[i].type = DPKG_EXTRACT_FROM_HDR;
				kg_cfg->extracts[i].extract.from_hdr.type =
					DPKG_FULL_FIELD;
				i++;

				kg_cfg->extracts[i].extract.from_hdr.prot =
					NET_PROT_SCTP;
				kg_cfg->extracts[i].extract.from_hdr.field =
					NH_FLD_SCTP_PORT_DST;
				kg_cfg->extracts[i].type = DPKG_EXTRACT_FROM_HDR;
				kg_cfg->extracts[i].extract.from_hdr.type =
					DPKG_FULL_FIELD;
				i++;
				break;

			default:
				PMD_DRV_LOG(WARNING, "Bad flow distribution option %x\n",
							dist_field);
			}
		}
		req_dist_set = req_dist_set >> 1;
		loop++;
	}
	kg_cfg->num_extracts = i;
}

void
dpaa2_free_dq_storage(struct queue_storage_info_t *q_storage)
{
	int i = 0;

	for (i = 0; i < NUM_DQS_PER_QUEUE; i++) {
		if (q_storage->dq_storage[i])
			rte_free(q_storage->dq_storage[i]);
	}
}

int
dpaa2_alloc_dq_storage(struct queue_storage_info_t *q_storage)
{
	int i = 0;

	for (i = 0; i < NUM_DQS_PER_QUEUE; i++) {
		q_storage->dq_storage[i] = rte_malloc(NULL,
			NUM_MAX_RECV_FRAMES * sizeof(struct qbman_result),
			RTE_CACHE_LINE_SIZE);
		if (!q_storage->dq_storage[i])
			goto fail;
		/*setting toggle for initial condition*/
		q_storage->toggle = -1;
	}
	return 0;
fail:
	i -= 1;
	while (i >= 0)
		rte_free(q_storage->dq_storage[i]);

	return -1;
}

int
dpaa2_attach_bp_list(struct dpaa2_dev_priv *priv,
		     void *blist)
{
	/* Function to attach a DPNI with a buffer pool list. Buffer pool list
	 * handle is passed in blist.
	 */
	int32_t retcode;
	struct fsl_mc_io *dpni = priv->hw;
	struct dpni_pools_cfg bpool_cfg;
	struct dpaa2_bp_list *bp_list = (struct dpaa2_bp_list *)blist;
	struct dpni_buffer_layout layout;
	int tot_size;

	/* ... rx buffer layout .
	Check alignment for buffer layouts first*/

	/* ... rx buffer layout ... */
	tot_size = DPAA2_HW_BUF_RESERVE + RTE_PKTMBUF_HEADROOM;
	tot_size = RTE_ALIGN_CEIL(tot_size,
				  DPAA2_PACKET_LAYOUT_ALIGN);

	memset(&layout, 0, sizeof(struct dpni_buffer_layout));
	layout.options = DPNI_BUF_LAYOUT_OPT_DATA_HEAD_ROOM;

	layout.data_head_room =
		tot_size - DPAA2_FD_PTA_SIZE - DPAA2_MBUF_HW_ANNOTATION;
	retcode = dpni_set_rx_buffer_layout(dpni, CMD_PRI_LOW, priv->token,
					    &layout);
	if (retcode) {
		PMD_DRV_LOG(ERR, "Err(%d) in setting rx buffer layout\n",
					retcode);
		return retcode;
	}

	/*Attach buffer pool to the network interface as described by the user*/
	bpool_cfg.num_dpbp = 1;
	bpool_cfg.pools[0].dpbp_id = bp_list->buf_pool.dpbp_node->dpbp_id;
	bpool_cfg.pools[0].backup_pool = 0;
	bpool_cfg.pools[0].buffer_size =
		RTE_ALIGN_CEIL(bp_list->buf_pool.size,
			       256 /*DPAA2_PACKET_LAYOUT_ALIGN*/);

	retcode = dpni_set_pools(dpni, CMD_PRI_LOW, priv->token, &bpool_cfg);
	if (retcode != 0) {
		PMD_DRV_LOG(ERR, "Error in attaching the buffer pool list"
				"bpid = %d Error code = %d\n",
				bpool_cfg.pools[0].dpbp_id, retcode);
		return retcode;
	}

	priv->bp_list = bp_list;
	return 0;
}

void
dpaa2_dev_print_stats(struct rte_eth_dev *dev)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)priv->hw;
	uint64_t value;

	dpni_get_counter(dpni, CMD_PRI_LOW,
					 priv->token, DPNI_CNT_ING_FRAME, &value);
	printf("Rx packets: %ld\n", value);
	dpni_get_counter(dpni, CMD_PRI_LOW,
					 priv->token, DPNI_CNT_ING_BYTE, &value);
	printf("Rx bytes: %ld\n", value);
	dpni_get_counter(dpni, CMD_PRI_LOW,
					 priv->token, DPNI_CNT_ING_MCAST_FRAME, &value);
	printf("Rx Multicast: %ld\n", value);
	dpni_get_counter(dpni, CMD_PRI_LOW,
					 priv->token, DPNI_CNT_ING_FRAME_DROP, &value);
	printf("Rx dropped: %ld\n", value);
	dpni_get_counter(dpni, CMD_PRI_LOW,
					 priv->token, DPNI_CNT_ING_FRAME_DISCARD, &value);
	printf("Rx discarded: %ld\n", value);
	dpni_get_counter(dpni, CMD_PRI_LOW,
					 priv->token, DPNI_CNT_EGR_FRAME, &value);
	printf("Tx packets: %ld\n", value);
	dpni_get_counter(dpni, CMD_PRI_LOW,
					 priv->token, DPNI_CNT_EGR_BYTE, &value);
	printf("Tx bytes: %ld\n", value);
	dpni_get_counter(dpni, CMD_PRI_LOW,
					 priv->token, DPNI_CNT_EGR_FRAME_DISCARD, &value);
	printf("Tx dropped: %ld\n", value);
}
