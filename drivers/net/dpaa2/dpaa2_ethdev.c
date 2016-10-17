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
#include <dpaa2_logs.h>
#include <dpaa2_hw_pvt.h>

/* DPAA2 Base interface files */
#include <dpaa2_hw_dpbp.h>
#include <dpaa2_hw_dpni.h>
#include <dpaa2_hw_dpio.h>

/* DPDK Interfaces */
#include <dpaa2_ethdev.h>

/* Name of the DPAA2 Net PMD */
static const char *drivername = "DPNI PMD";

/**
 * Atomically reads the link status information from global
 * structure rte_eth_dev.
 *
 * @param dev
 *   - Pointer to the structure rte_eth_dev to read from.
 *   - Pointer to the buffer to be saved with the link status.
 *
 * @return
 *   - On success, zero.
 *   - On failure, negative value.
 */
static inline int
dpaa2_dev_atomic_read_link_status(struct rte_eth_dev *dev,
				  struct rte_eth_link *link)
{
	struct rte_eth_link *dst = link;
	struct rte_eth_link *src = &dev->data->dev_link;

	if (rte_atomic64_cmpset((uint64_t *)dst, *(uint64_t *)dst,
				*(uint64_t *)src) == 0)
		return -1;

	return 0;
}

/**
 * Atomically writes the link status information into global
 * structure rte_eth_dev.
 *
 * @param dev
 *   - Pointer to the structure rte_eth_dev to read from.
 *   - Pointer to the buffer to be saved with the link status.
 *
 * @return
 *   - On success, zero.
 *   - On failure, negative value.
 */
static inline int
dpaa2_dev_atomic_write_link_status(struct rte_eth_dev *dev,
				   struct rte_eth_link *link)
{
	struct rte_eth_link *dst = &dev->data->dev_link;
	struct rte_eth_link *src = link;

	if (rte_atomic64_cmpset((uint64_t *)dst, *(uint64_t *)dst,
				*(uint64_t *)src) == 0)
		return -1;

	return 0;
}

static int
dpaa2_vlan_stripping_set(struct rte_eth_dev *dev, int on)
{
	int ret;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)priv->hw;

	PMD_INIT_FUNC_TRACE();

	if (dpni == NULL) {
		PMD_DRV_LOG(ERR, "dpni is NULL");
		return -1;
	}

	ret = dpni_set_vlan_removal(dpni, CMD_PRI_LOW, priv->token, on);
	if (ret < 0)
		PMD_DRV_LOG(ERR, "Unable to dpni_set_vlan_removal hwid =%d",
			    priv->hw_id);
	return ret;
}

static int
dpaa2_vlan_filter_set(struct rte_eth_dev *dev, uint16_t vlan_id, int on)
{
	int ret;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)priv->hw;

	if (dpni == NULL) {
		PMD_DRV_LOG(ERR, "dpni is NULL");
		return -1;
	}

	if (on)
		ret = dpni_add_vlan_id(dpni, CMD_PRI_LOW, priv->token, vlan_id);
	else
		ret = dpni_remove_vlan_id(dpni, CMD_PRI_LOW, priv->token, vlan_id);

	if (ret < 0)
		PMD_DRV_LOG(ERR, "ret = %d Unable to add/rem vlan %d  hwid =%d",
			    ret, vlan_id, priv->hw_id);

	/*todo this should on global basis */
/*	ret = dpni_set_vlan_filters(dpni, CMD_PRI_LOW, priv->token, on);
	if (ret < 0)
		PMD_DRV_LOG(ERR, "Unable to set vlan filter");
*/	return ret;
}

static void
dpaa2_vlan_offload_set(struct rte_eth_dev *dev, int mask)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)priv->hw;
	int ret;

	if (mask & ETH_VLAN_FILTER_MASK) {
		if (dev->data->dev_conf.rxmode.hw_vlan_filter)
			ret = dpni_set_vlan_filters(dpni, CMD_PRI_LOW, priv->token, TRUE);
		else
			ret = dpni_set_vlan_filters(dpni, CMD_PRI_LOW, priv->token, FALSE);
		if (ret < 0)
			PMD_DRV_LOG(ERR, "ret = %d Unable to set vlan filter", ret);
	}

	if (mask & ETH_VLAN_STRIP_MASK) {
		/* Enable or disable VLAN stripping */
		if (dev->data->dev_conf.rxmode.hw_vlan_strip)
			dpaa2_vlan_stripping_set(dev, TRUE);
		else
			dpaa2_vlan_stripping_set(dev, FALSE);
	}

	if (mask & ETH_VLAN_EXTEND_MASK) {
		PMD_INIT_FUNC_TRACE();
/*		if (dev->data->dev_conf.rxmode.hw_vlan_extend)
			i40e_vsi_config_double_vlan(vsi, TRUE);
		else
			i40e_vsi_config_double_vlan(vsi, FALSE);
*/	}
}

static void
dpaa2_dev_info_get(struct rte_eth_dev *dev, struct rte_eth_dev_info *dev_info)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;

	dev_info->driver_name = drivername;
	dev_info->if_index = priv->hw_id;
	dev_info->max_mac_addrs = priv->max_unicast_filters;
	dev_info->max_rx_pktlen = DPAA2_MAX_RX_PKT_LEN;
	dev_info->max_rx_queues = (uint16_t)priv->nb_rx_queues;
	dev_info->max_tx_queues = (uint16_t)priv->nb_tx_queues;
	dev_info->min_rx_bufsize = DPAA2_MIN_RX_BUF_SIZE;
	dev_info->pci_dev = dev->pci_dev;
	dev_info->rx_offload_capa =
		DEV_RX_OFFLOAD_IPV4_CKSUM |
		DEV_RX_OFFLOAD_UDP_CKSUM |
		DEV_RX_OFFLOAD_TCP_CKSUM;
	dev_info->tx_offload_capa =
		DEV_TX_OFFLOAD_IPV4_CKSUM |
		DEV_TX_OFFLOAD_UDP_CKSUM |
		DEV_TX_OFFLOAD_TCP_CKSUM |
		DEV_TX_OFFLOAD_SCTP_CKSUM;
	dev_info->speed_capa = ETH_LINK_SPEED_1G | ETH_LINK_SPEED_10G;
}

static int
dpaa2_alloc_rx_tx_queues(struct rte_eth_dev *dev)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	uint16_t dist_idx;
	uint32_t vq_id;
	struct dpaa2_queue *mc_q, *mcq;
	uint32_t tot_queues;
	int i;
	struct dpaa2_queue *dpaa2_q;

	tot_queues = priv->nb_rx_queues + priv->nb_tx_queues;
	mc_q = rte_malloc(NULL, sizeof(struct dpaa2_queue) * tot_queues,
			  RTE_CACHE_LINE_SIZE);
	if (!mc_q) {
		PMD_DRV_LOG(ERR, "malloc failed for rx/tx queues\n");
		return -1;
	}

	for (i = 0; i < priv->nb_rx_queues; i++) {
		mc_q->dev = dev;
		priv->rx_vq[i] = mc_q++;
		dpaa2_q = (struct dpaa2_queue *)priv->rx_vq[i];
		dpaa2_q->q_storage = rte_malloc("dq_storage",
			sizeof(struct queue_storage_info_t),
			RTE_CACHE_LINE_SIZE);
		if (!dpaa2_q->q_storage)
			goto fail;

		memset(dpaa2_q->q_storage, 0, sizeof(struct queue_storage_info_t));
	}

	for (i = 0; i < priv->nb_tx_queues; i++) {
		mc_q->dev = dev;
		mc_q->flow_id = DPNI_NEW_FLOW_ID;
		priv->tx_vq[i] = mc_q++;
	}

	vq_id = 0;
	for (dist_idx = 0; dist_idx < priv->num_dist_per_tc[DPAA2_DEF_TC];
	     dist_idx++) {
		mcq = (struct dpaa2_queue *)priv->rx_vq[vq_id];
		mcq->tc_index = DPAA2_DEF_TC;
		mcq->flow_id = dist_idx;
		vq_id++;
	}

	return 0;
fail:
	 i -= 1;
	while (i >= 0) {
		dpaa2_q = (struct dpaa2_queue *)priv->rx_vq[i];
		rte_free(dpaa2_q->q_storage);
	}
	return -1;
}

static int
dpaa2_eth_dev_configure(struct rte_eth_dev *dev)
{
	struct rte_eth_dev_data *data = dev->data;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct rte_eth_conf *eth_conf = &data->dev_conf;
	struct dpaa2_queue *dpaa2_q;
	int i, ret;

	for (i = 0; i < data->nb_rx_queues; i++) {
		 data->rx_queues[i] = priv->rx_vq[i];
		 dpaa2_q = (struct dpaa2_queue *)data->rx_queues[i];
		 if (dpaa2_alloc_dq_storage(dpaa2_q->q_storage))
			 return -1;
	}

	for (i = 0; i < data->nb_tx_queues; i++) {
		 data->tx_queues[i] = priv->tx_vq[i];
		 dpaa2_q = (struct dpaa2_queue *)data->tx_queues[i];
		 dpaa2_q->cscn = rte_malloc(NULL, sizeof(struct qbman_result), 16);
		 if (!dpaa2_q->cscn)
			 goto fail_tx_queue;
	}

	/* Check for correct configuration */
	if (eth_conf->rxmode.mq_mode != ETH_MQ_RX_RSS &&
	    data->nb_rx_queues > 1) {
		PMD_DRV_LOG(ERR, "Distribution is not enabled, "
			"but Rx queues more than 1\n");
		return -1;
	}

	if (eth_conf->rxmode.mq_mode == ETH_MQ_RX_RSS) {
		/* Return in case number of Rx queues is 1 */
		if (data->nb_rx_queues == 1)
			return 0;
		ret = dpaa2_setup_flow_distribution(dev,
						    eth_conf->rx_adv_conf.rss_conf.rss_hf);
		if (ret) {
			PMD_DRV_LOG(ERR, "dpaa2_setup_flow_distribution failed\n");
			return ret;
		}
	}

	return 0;
 fail_tx_queue:
	i -= 1;
	while (i >= 0) {
		dpaa2_q = (struct dpaa2_queue *)data->tx_queues[i];
		rte_free(dpaa2_q->cscn);
	}
	return -1;
}

/* Function to setup RX flow information. It contains traffic class ID,
 * flow ID, destination configuration etc.
 */
static int
dpaa2_dev_rx_queue_setup(struct rte_eth_dev *dev,
			 uint16_t rx_queue_id,
			 uint16_t nb_rx_desc __rte_unused,
			 unsigned int socket_id __rte_unused,
			 const struct rte_eth_rxconf *rx_conf __rte_unused,
			 struct rte_mempool *mb_pool)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)priv->hw;
	struct dpaa2_queue *dpaa2_q;
	struct dpni_queue_cfg cfg;
	uint8_t flow_id;
	uint32_t bpid;
	int ret;

	PMD_DRV_LOG(INFO, "dev =%p, queue =%d, pool = %p, conf =%p",
		    dev, rx_queue_id, mb_pool, rx_conf);

	if (!priv->bp_list || priv->bp_list->mp != mb_pool) {
		bpid = mempool_to_bpid(mb_pool);
		ret = dpaa2_attach_bp_list(priv,
					   bpid_info[bpid].bp_list);
		if (ret)
			return ret;
	}
	dpaa2_q = (struct dpaa2_queue *)dev->data->rx_queues[rx_queue_id];

	/*Get the tc id and flow id from given VQ id*/
	flow_id = rx_queue_id % priv->num_dist_per_tc[dpaa2_q->tc_index];
	memset(&cfg, 0, sizeof(struct dpni_queue_cfg));

	cfg.options = cfg.options | DPNI_QUEUE_OPT_USER_CTX;
	cfg.user_ctx = (uint64_t)(dpaa2_q);

	if (!(priv->flags & DPAA2_PER_TC_RX_TAILDROP) &&
	    !(priv->flags & DPAA2_NO_CGR_SUPPORT)) {
		/*enabling per queue congestion control */
		cfg.options = cfg.options | DPNI_QUEUE_OPT_TAILDROP_THRESHOLD;
		cfg.tail_drop_threshold = CONG_THRESHOLD_RX_Q;
		PMD_DRV_LOG(INFO, "Enabling Early Drop on queue = %d",
			    rx_queue_id);
	}

	/*if ls2088 or rev2 device, enable the stashing */
	if ((qbman_get_version() & 0xFFFF0000) > QMAN_REV_4000) {
		cfg.options = cfg.options | DPNI_QUEUE_OPT_FLC;
		cfg.flc_cfg.flc_type = DPNI_FLC_STASH;
		cfg.flc_cfg.frame_data_size = DPNI_STASH_SIZE_64B;

		/* Enabling Annotation stashing */
		cfg.options |= DPNI_FLC_STASH_FRAME_ANNOTATION;
		cfg.flc_cfg.options = DPNI_FLC_STASH_FRAME_ANNOTATION;
	}
	ret = dpni_set_rx_flow(dpni, CMD_PRI_LOW, priv->token,
			       dpaa2_q->tc_index, flow_id, &cfg);
	if (ret) {
		PMD_DRV_LOG(ERR, "Error in setting the rx flow: = %d\n", ret);
		return -1;
	}

	return 0;
}

static int
dpaa2_dev_tx_queue_setup(struct rte_eth_dev *dev,
			 uint16_t tx_queue_id,
			 uint16_t nb_tx_desc __rte_unused,
			 unsigned int socket_id __rte_unused,
			 const struct rte_eth_txconf *tx_conf __rte_unused)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct dpaa2_queue *dpaa2_q = (struct dpaa2_queue *)
		dev->data->tx_queues[tx_queue_id];
	struct fsl_mc_io *dpni = priv->hw;
	struct dpni_tx_flow_cfg cfg;
	struct dpni_tx_conf_cfg tx_conf_cfg;
	uint32_t tc_id;
	int ret;

	PMD_INIT_FUNC_TRACE();

	/* Return if queue already configured */
	if (dpaa2_q->flow_id != DPNI_NEW_FLOW_ID)
		return 0;

	memset(&cfg, 0, sizeof(struct dpni_tx_flow_cfg));
	cfg.l3_chksum_gen = 1;
	cfg.options = DPNI_TX_FLOW_OPT_L3_CHKSUM_GEN;
	cfg.l4_chksum_gen = 1;
	cfg.options |= DPNI_TX_FLOW_OPT_L4_CHKSUM_GEN;
	memset(&tx_conf_cfg, 0, sizeof(struct dpni_tx_conf_cfg));
	tx_conf_cfg.errors_only = TRUE;

	/*
	if (action & DPAA2BUF_TX_CONF_REQUIRED) {
		cfg.options = DPNI_TX_FLOW_OPT_TX_CONF_ERROR;
		cfg.use_common_tx_conf_queue =
				((action & DPAA2BUF_TX_CONF_ERR_ON_COMMON_Q) ?
								TRUE : FALSE);
		tx_conf_cfg.errors_only = FALSE;
	}*/

	if (priv->num_tc == 1)
		tc_id = 0;
	else
		tc_id = tx_queue_id;

	ret = dpni_set_tx_flow(dpni, CMD_PRI_LOW, priv->token,
			       &dpaa2_q->flow_id, &cfg);
	if (ret) {
		PMD_DRV_LOG(ERR, "Error in setting the tx flow:"
					"ErrorCode = %x\n", ret);
			return -1;
	}
	/*Set tx-conf and error configuration*/
	ret = dpni_set_tx_conf(dpni, CMD_PRI_LOW, priv->token,
			       dpaa2_q->flow_id, &tx_conf_cfg);
	if (ret) {
		PMD_DRV_LOG(ERR, "Error in setting tx conf settings: "
					"ErrorCode = %x", ret);
		return -1;
	}

	if (tx_queue_id == 0) {
		/*Set tx-conf and error configuration*/
		ret = dpni_set_tx_conf(dpni, CMD_PRI_LOW, priv->token,
				       DPNI_COMMON_TX_CONF, &tx_conf_cfg);
		if (ret) {
			PMD_DRV_LOG(ERR, "Error in setting tx conf settings: "
						"ErrorCode = %x", ret);
			return -1;
		}
	}
	dpaa2_q->tc_index = tc_id;

	if (!(priv->flags & DPAA2_NO_CGR_SUPPORT)) {
		struct dpni_congestion_notification_cfg cong_notif_cfg;
		cong_notif_cfg.units = DPNI_CONGESTION_UNIT_FRAMES;
		/*Notify about congestion when the queue size is 128 frames */
		cong_notif_cfg.threshold_entry = CONG_ENTER_TX_THRESHOLD;
		/*Notify that the queue is not congested when the number of frames in \
		  the queue is below this thershold.
		  TODO: Check if this value is the optimum value for better performance*/
		cong_notif_cfg.threshold_exit = CONG_EXIT_TX_THRESHOLD;
		cong_notif_cfg.message_ctx = 0;
		cong_notif_cfg.message_iova = (uint64_t)dpaa2_q->cscn;
		cong_notif_cfg.dest_cfg.dest_type = DPNI_DEST_NONE;
		cong_notif_cfg.options = DPNI_CONG_OPT_WRITE_MEM_ON_ENTER |
					 DPNI_CONG_OPT_WRITE_MEM_ON_EXIT |
					 DPNI_CONG_OPT_COHERENT_WRITE;

		ret = dpni_set_tx_tc_congestion_notification(dpni, CMD_PRI_LOW,
							     priv->token,
							     tc_id,
							     &cong_notif_cfg);
		if (ret) {
			PMD_DRV_LOG(ERR, "Error in setting tx congestion"
				    "notification: ErrorCode = %d", -ret);
			return -ret;
		}
	}
	return 0;
}

static void
dpaa2_dev_rx_queue_release(void *q __rte_unused)
{
	PMD_DRV_LOG(INFO, "Not implemented");
	return;
}

static void
dpaa2_dev_tx_queue_release(void *q __rte_unused)
{
	PMD_DRV_LOG(INFO, "Not implemented");
	return;
}

static const uint32_t *
dpaa2_supported_ptypes_get(struct rte_eth_dev *dev)
{
	static const uint32_t ptypes[] = {
		/*todo -= add more types */
		RTE_PTYPE_L2_ETHER,
		RTE_PTYPE_L3_IPV4,
		RTE_PTYPE_L3_IPV4_EXT,
		RTE_PTYPE_L3_IPV6,
		RTE_PTYPE_L3_IPV6_EXT,
		RTE_PTYPE_L4_TCP,
		RTE_PTYPE_L4_UDP,
		RTE_PTYPE_L4_SCTP,
		RTE_PTYPE_L4_ICMP,
		RTE_PTYPE_UNKNOWN
	};

	if (dev->rx_pkt_burst == dpaa2_dev_prefetch_rx ||
	    dev->rx_pkt_burst == dpaa2_dev_rx)
		return ptypes;
	return NULL;
}

static int
dpaa2_dev_start(struct rte_eth_dev *dev)
{
	struct rte_eth_dev_data *data = dev->data;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)priv->hw;
	struct dpni_queue_attr cfg;
	struct dpni_error_cfg	err_cfg;
	uint16_t qdid;
	struct dpaa2_queue *dpaa2_q;
	int ret, i, mask = 0;

	PMD_INIT_FUNC_TRACE();

	dev->data->dev_link.link_status = 1;

	ret = dpni_enable(dpni, CMD_PRI_LOW, priv->token);
	if (ret) {
		PMD_DRV_LOG(ERR, "Failure %d in enabling dpni %d device\n",
			    ret, priv->hw_id);
		return ret;
	}

	ret = dpni_get_qdid(dpni, CMD_PRI_LOW, priv->token, &qdid);
	if (ret) {
		PMD_DRV_LOG(ERR, "Error to get qdid:ErrorCode = %d\n", ret);
		return ret;
	}
	priv->qdid = qdid;

	for (i = 0; i < data->nb_rx_queues; i++) {
		dpaa2_q = (struct dpaa2_queue *)data->rx_queues[i];
		ret = dpni_get_rx_flow(dpni, CMD_PRI_LOW, priv->token,
				       dpaa2_q->tc_index,
				       dpaa2_q->flow_id, &cfg);
		if (ret) {
			PMD_DRV_LOG(ERR, "Error to get flow "
				"information Error code = %d\n", ret);
			return ret;
		}
		dpaa2_q->fqid = cfg.fqid;
	}

	if (priv->max_congestion_ctrl &&
	    (priv->flags & DPAA2_PER_TC_RX_TAILDROP) &&
	    !(priv->flags & DPAA2_NO_CGR_SUPPORT)) {

		struct dpni_early_drop_cfg tailcfg = {0};
		uint8_t *early_drop_buf;
		/* Note - doing it only for the first queue  - as we are only
			using 1 TC for the time being */
		dpaa2_q = (struct dpaa2_queue *)data->rx_queues[DPAA2_DEF_TC];

		early_drop_buf = rte_malloc(NULL, 256, 1);
		if (!early_drop_buf) {
			PMD_DRV_LOG(ERR, "No data memory\n");
			return -1;
		}
		tailcfg.mode = DPNI_EARLY_DROP_MODE_TAIL;
		tailcfg.units = DPNI_CONGESTION_UNIT_FRAMES;
		tailcfg.tail_drop_threshold = DPAA2_DEF_TC_THRESHOLD;

		dpni_prepare_early_drop(&tailcfg, early_drop_buf);

		ret = dpni_set_rx_tc_early_drop(dpni,
						CMD_PRI_LOW,
						priv->token,
						dpaa2_q->tc_index,
						(uint64_t)early_drop_buf);
		if (ret) {
			PMD_DRV_LOG(ERR,"Error in setting rx_tc_early_drop"
				    " ErrCode = %d", -ret);
			return -ret;
		}
		PMD_DRV_LOG(INFO, "Enabling Early Drop on TC = %d",
			dpaa2_q->tc_index);
	}

	ret = dpni_set_l3_chksum_validation(dpni, CMD_PRI_LOW,
					    priv->token, TRUE);
	if (ret) {
		PMD_DRV_LOG(ERR, "Error to get l3 csum:ErrorCode = %d\n", ret);
		return ret;
	}

	ret = dpni_set_l4_chksum_validation(dpni, CMD_PRI_LOW,
					    priv->token, TRUE);
	if (ret) {
		PMD_DRV_LOG(ERR, "Error to get l4 csum:ErrorCode = %d\n", ret);
		return ret;
	}

	/*for checksum issue, send them to normal path and set it in annotation */
	err_cfg.errors = DPNI_ERROR_L3CE | DPNI_ERROR_L4CE;

	err_cfg.error_action = DPNI_ERROR_ACTION_CONTINUE;
	err_cfg.set_frame_annotation = TRUE;

	ret = dpni_set_errors_behavior(dpni, CMD_PRI_LOW,
				       priv->token, &err_cfg);
	if (ret) {
		PMD_DRV_LOG(ERR, "Error to dpni_set_errors_behavior:"
				"code = %d\n", ret);
		return ret;
	}
	/*
	 * VLAN Offload Settings
	 */
	if (priv->options & DPNI_OPT_VLAN_FILTER)
		mask = ETH_VLAN_FILTER_MASK;

	if (priv->options & DPNI_OPT_VLAN_MANIPULATION)
		mask = ETH_VLAN_STRIP_MASK;

	if (mask)
		dpaa2_vlan_offload_set(dev, mask);

	return 0;
}

/*********************************************************************
 *
 *  This routine disables all traffic on the adapter by issuing a
 *  global reset on the MAC.
 *
 **********************************************************************/
static void
dpaa2_dev_stop(struct rte_eth_dev *dev)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)priv->hw;
	int ret;
	struct rte_eth_link link;

	dev->data->dev_link.link_status = 0;

	ret = dpni_disable(dpni, CMD_PRI_LOW, priv->token);
	if (ret) {
		PMD_DRV_LOG(ERR, "Failure in disabling dpni %d device\n", priv->hw_id);
		return;
	}

	/* clear the recorded link status */
	memset(&link, 0, sizeof(link));
	dpaa2_dev_atomic_write_link_status(dev, &link);
}

static void
dpaa2_dev_close(struct rte_eth_dev *dev)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)priv->hw;
	int ret;
	struct rte_eth_link link;

	/*Function is reverse of dpaa2_dev_init.
	 * It does the following:
	 * 1. Detach a DPNI from attached resources i.e. buffer pools, dpbp_id.
	 * 2. Close the DPNI device
	 * 3. Free the allocated reqources.
	 */

	/* Clean the device first */
	ret = dpni_reset(dpni, CMD_PRI_LOW, priv->token);
	if (ret) {
		PMD_DRV_LOG(ERR, "Failure cleaning dpni device with"
			"error code %d\n", ret);
		return;
	}

	/*Close the device at underlying layer*/
	ret = dpni_close(dpni, CMD_PRI_LOW, priv->token);
	if (ret) {
		PMD_DRV_LOG(ERR, "Failure closing dpni device with"
			"error code %d\n", ret);
		return;
	}

	/*Free the allocated memory for ethernet private data and dpni*/
	priv->hw = NULL;
	free(dpni);

	memset(&link, 0, sizeof(link));
	dpaa2_dev_atomic_write_link_status(dev, &link);
}

static void
dpaa2_dev_promiscuous_enable(
		struct rte_eth_dev *dev)
{
	int ret;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)priv->hw;

	if (dpni == NULL) {
		PMD_DRV_LOG(ERR, "dpni is NULL");
		return;
	}

	ret = dpni_set_unicast_promisc(dpni, CMD_PRI_LOW, priv->token, TRUE);
	if (ret < 0)
		PMD_DRV_LOG(ERR, "Unable to enable promiscuous mode");
	return;
}

static void
dpaa2_dev_promiscuous_disable(
		struct rte_eth_dev *dev)
{
	int ret;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)priv->hw;

	if (dpni == NULL) {
		PMD_DRV_LOG(ERR, "dpni is NULL");
		return;
	}

	ret = dpni_set_unicast_promisc(dpni, CMD_PRI_LOW, priv->token, FALSE);
	if (ret < 0)
		PMD_DRV_LOG(ERR, "Unable to disable promiscuous mode");
	return;
}

static void
dpaa2_dev_allmulticast_enable(
		struct rte_eth_dev *dev)
{
	int ret;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)priv->hw;

	if (dpni == NULL) {
		PMD_DRV_LOG(ERR, "dpni is NULL");
		return;
	}

	ret = dpni_set_multicast_promisc(dpni, CMD_PRI_LOW, priv->token, true);
	if (ret < 0)
		PMD_DRV_LOG(ERR, "Unable to enable promiscuous mode");
	return;
}

static void
dpaa2_dev_allmulticast_disable(struct rte_eth_dev *dev)
{
	int ret;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)priv->hw;

	if (dpni == NULL) {
		PMD_DRV_LOG(ERR, "dpni is NULL");
		return;
	}

	ret = dpni_set_multicast_promisc(dpni, CMD_PRI_LOW, priv->token, false);
	if (ret < 0)
		PMD_DRV_LOG(ERR, "Unable to enable promiscuous mode");
	return;
}

static int
dpaa2_dev_mtu_set(struct rte_eth_dev *dev, uint16_t mtu)
{
	int ret;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)priv->hw;
	uint32_t frame_size = mtu + ETHER_HDR_LEN + ETHER_CRC_LEN;

	if (dpni == NULL) {
		PMD_DRV_LOG(ERR, "dpni is NULL");
		return -EINVAL;
	}

	/* check that mtu is within the allowed range */
	if ((mtu < ETHER_MIN_MTU) || (frame_size > DPAA2_MAX_RX_PKT_LEN))
		return -EINVAL;

	/* Set the Max Rx frame length as 'mtu' +
	 * Maximum Ethernet header length */
	ret = dpni_set_max_frame_length(dpni, CMD_PRI_LOW, priv->token,
					mtu + ETH_VLAN_HLEN);
	if (ret) {
		PMD_DRV_LOG(ERR, "setting the max frame length failed");
		return -1;
	}
	if (priv->options & DPNI_OPT_IPF) {
		ret = dpni_set_mtu(dpni, CMD_PRI_LOW, priv->token, mtu);
		if (ret) {
			PMD_DRV_LOG(ERR, "Setting the MTU failed");
			return -1;
		}
	}

	PMD_DRV_LOG(INFO, "MTU is configured %d for the device\n", mtu);
	return 0;
}

static int
dpaa2_dev_flow_ctrl_set(struct rte_eth_dev *dev  __rte_unused,
			struct rte_eth_fc_conf *fc_conf  __rte_unused)
{
	return 0;
}

static void
dpaa2_dev_add_mac_addr(struct rte_eth_dev *dev,
		       struct ether_addr *addr,
		 __rte_unused uint32_t index,
		 __rte_unused uint32_t pool)
{
	int ret;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)priv->hw;

	if (dpni == NULL) {
		PMD_DRV_LOG(ERR, "dpni is NULL");
		return;
	}

	ret = dpni_add_mac_addr(dpni, CMD_PRI_LOW,
				priv->token, addr->addr_bytes);
	if (ret) {
		PMD_DRV_LOG(ERR, "Adding the MAC ADDR failed");
	}

	return;
}

static void
dpaa2_dev_remove_mac_addr(struct rte_eth_dev *dev,
			  uint32_t index)
{
	int ret;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)priv->hw;
	struct rte_eth_dev_data *data = dev->data;
	struct ether_addr *macaddr;

	macaddr = &data->mac_addrs[index];

	if (dpni == NULL) {
		PMD_DRV_LOG(ERR, "dpni is NULL");
		return;
	}

	ret = dpni_remove_mac_addr(dpni, CMD_PRI_LOW,
				   priv->token, macaddr->addr_bytes);
	if (ret) {
		PMD_DRV_LOG(ERR, "Removing the MAC ADDR failed");
	}

	return;
}

static void
dpaa2_dev_set_mac_addr(struct rte_eth_dev *dev,
		       struct ether_addr *addr)
{
	int ret;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)priv->hw;

	if (dpni == NULL) {
		PMD_DRV_LOG(ERR, "dpni is NULL");
		return;
	}

	ret = dpni_set_primary_mac_addr(dpni, CMD_PRI_LOW,
					priv->token, addr->addr_bytes);

	if (ret) {
		PMD_DRV_LOG(ERR, "Setting the MAC ADDR failed");
	}

	return;
}

static int
dpaa2_dev_get_mac_addr(struct rte_eth_dev *dev,
		       struct ether_addr *addr)
{
	int ret;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)priv->hw;

	if (dpni == NULL) {
		PMD_DRV_LOG(ERR, "dpni is NULL");
		return -EINVAL;
	}

	ret = dpni_get_primary_mac_addr(dpni, CMD_PRI_LOW,
					priv->token, addr->addr_bytes);

	if (ret) {
		PMD_DRV_LOG(ERR, "Getting the MAC ADDR failed");
	}

	return ret;
}

static int
dpaa2_dev_timestamp_enable(struct rte_eth_dev *dev)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)priv->hw;

	struct dpni_buffer_layout layout;
	int ret;

	layout.options = DPNI_BUF_LAYOUT_OPT_TIMESTAMP;
	layout.pass_timestamp = TRUE;

	ret = dpni_set_rx_buffer_layout(dpni, CMD_PRI_LOW, priv->token, &layout);
	if (ret) {
		PMD_DRV_LOG(ERR, "Enabling timestamp for Rx failed with"
			"err code: %d", ret);
		return ret;
	}

	ret = dpni_set_tx_buffer_layout(dpni, CMD_PRI_LOW, priv->token, &layout);
	if (ret) {
		PMD_DRV_LOG(ERR, "Enabling timestamp failed for Tx with"
			"err code: %d", ret);
		return ret;
	}

	ret = dpni_set_tx_conf_buffer_layout(dpni, CMD_PRI_LOW,
					     priv->token, &layout);
	if (ret) {
		PMD_DRV_LOG(ERR, "Enabling timestamp failed for Tx-conf with"
			"err code: %d", ret);
		return ret;
	}

	return 0;
}

static int
dpaa2_dev_timestamp_disable(struct rte_eth_dev *dev)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)priv->hw;
	struct dpni_buffer_layout layout;
	int ret;

	layout.options = DPNI_BUF_LAYOUT_OPT_TIMESTAMP;
	layout.pass_timestamp = FALSE;

	ret = dpni_set_rx_buffer_layout(dpni, CMD_PRI_LOW, priv->token, &layout);
	if (ret) {
		PMD_DRV_LOG(ERR, "Disabling timestamp failed for Rx with"
			"err code: %d", ret);
		return ret;
	}

	ret = dpni_set_tx_buffer_layout(dpni, CMD_PRI_LOW, priv->token, &layout);
	if (ret) {
		PMD_DRV_LOG(ERR, "Disabling timestamp failed for Tx with"
			"err code: %d", ret);
		return ret;
	}

	ret = dpni_set_tx_conf_buffer_layout(dpni, CMD_PRI_LOW,
					     priv->token, &layout);
	if (ret) {
		PMD_DRV_LOG(ERR, "Disabling timestamp failed for Tx-conf with"
			"err code: %d", ret);
		return ret;
	}

	return ret;
}

/* return 0 means link status changed, -1 means not changed */
static int
dpaa2_dev_get_link_info(struct rte_eth_dev *dev,
			int wait_to_complete __rte_unused)
{
	int ret;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)priv->hw;
	struct rte_eth_link link, old;
	struct dpni_link_state state = {0};

	if (dpni == NULL) {
		PMD_DRV_LOG(ERR, "dpni is NULL");
		return 0;
	}
	memset(&old, 0, sizeof(old));
	dpaa2_dev_atomic_read_link_status(dev, &old);

	ret = dpni_get_link_state(dpni, CMD_PRI_LOW, priv->token, &state);
	if (ret < 0) {
		PMD_DRV_LOG(ERR, "dpni_get_link_state");
		return 0;
	}

	if (state.up == 0) {
		dpaa2_dev_atomic_write_link_status(dev, &link);
		if (state.up == old.link_status)
			return -1;
		return 0;
	}
	link.link_status = state.up;
	link.link_speed = state.rate;

	if (state.options & DPNI_LINK_OPT_HALF_DUPLEX)
		link.link_duplex = ETH_LINK_HALF_DUPLEX;
	else
		link.link_duplex = ETH_LINK_FULL_DUPLEX;

	dpaa2_dev_atomic_write_link_status(dev, &link);

	if (link.link_status == old.link_status)
		return -1;

	return 0;
}

static
void dpaa2_dev_stats_get(struct rte_eth_dev *dev,
			 struct rte_eth_stats *stats)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)priv->hw;

	int32_t  retcode;
	uint64_t value;

	if (dpni == NULL) {
		PMD_DRV_LOG(ERR, "dpni is NULL");
		return;
	}

	if (!stats) {
		PMD_DRV_LOG(ERR, "stats is NULL");
		return;
	}

	retcode = dpni_get_counter(dpni, CMD_PRI_LOW, priv->token,
				   DPNI_CNT_ING_FRAME, &value);
	if (retcode)
		goto error;
	stats->ipackets = value;
	retcode =  dpni_get_counter(dpni, CMD_PRI_LOW, priv->token,
				    DPNI_CNT_ING_BYTE, &value);
	if (retcode)
		goto error;
	stats->ibytes = value;
	retcode =  dpni_get_counter(dpni, CMD_PRI_LOW, priv->token,
				    DPNI_CNT_ING_FRAME_DROP, &value);
	if (retcode)
		goto error;
	stats->ierrors = value;
	retcode =  dpni_get_counter(dpni, CMD_PRI_LOW, priv->token,
				    DPNI_CNT_ING_FRAME_DISCARD, &value);
	if (retcode)
		goto error;
	stats->ierrors = stats->ierrors + value;
	retcode =  dpni_get_counter(dpni, CMD_PRI_LOW, priv->token,
				    DPNI_CNT_EGR_FRAME, &value);
	if (retcode)
		goto error;
	stats->opackets = value;
	dpni_get_counter(dpni, CMD_PRI_LOW, priv->token,
			 DPNI_CNT_EGR_BYTE, &value);
	if (retcode)
		goto error;
	stats->obytes = value;
	retcode =  dpni_get_counter(dpni, CMD_PRI_LOW, priv->token,
				    DPNI_CNT_EGR_FRAME_DISCARD, &value);
	if (retcode)
		goto error;
	stats->oerrors = value;

	return;

error:
	PMD_DRV_LOG(ERR, "Operation not completed:Error Code = %d\n", retcode);
	return;
};

static
void dpaa2_dev_stats_reset(struct rte_eth_dev *dev)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)priv->hw;

	int32_t  retcode;

	if (dpni == NULL) {
		PMD_DRV_LOG(ERR, "dpni is NULL");
		return;
	}

	retcode =  dpni_set_counter(dpni, CMD_PRI_LOW, priv->token,
				    DPNI_CNT_ING_FRAME, 0);
	if (retcode)
		goto error;
	retcode =  dpni_set_counter(dpni, CMD_PRI_LOW, priv->token,
				    DPNI_CNT_ING_BYTE, 0);
	if (retcode)
		goto error;
	retcode =  dpni_set_counter(dpni, CMD_PRI_LOW, priv->token,
				    DPNI_CNT_ING_BCAST_FRAME, 0);
	if (retcode)
		goto error;
	retcode =  dpni_set_counter(dpni, CMD_PRI_LOW, priv->token,
				    DPNI_CNT_ING_BCAST_BYTES, 0);
	if (retcode)
		goto error;
	retcode =  dpni_set_counter(dpni, CMD_PRI_LOW, priv->token,
				    DPNI_CNT_ING_MCAST_FRAME, 0);
	if (retcode)
		goto error;
	retcode =  dpni_set_counter(dpni, CMD_PRI_LOW, priv->token,
				    DPNI_CNT_ING_MCAST_BYTE, 0);
	if (retcode)
		goto error;
	retcode =  dpni_set_counter(dpni, CMD_PRI_LOW, priv->token,
				    DPNI_CNT_ING_FRAME_DROP, 0);
	if (retcode)
		goto error;
	retcode =  dpni_set_counter(dpni, CMD_PRI_LOW, priv->token,
				    DPNI_CNT_ING_FRAME_DISCARD, 0);
	if (retcode)
		goto error;
	retcode =  dpni_set_counter(dpni, CMD_PRI_LOW, priv->token,
				    DPNI_CNT_EGR_FRAME, 0);
	if (retcode)
		goto error;
	retcode =  dpni_set_counter(dpni, CMD_PRI_LOW, priv->token,
				    DPNI_CNT_EGR_BYTE, 0);
	if (retcode)
		goto error;
	retcode =  dpni_set_counter(dpni, CMD_PRI_LOW, priv->token,
				    DPNI_CNT_EGR_FRAME_DISCARD, 0);
	if (retcode)
		goto error;

	return;

error:
	PMD_DRV_LOG(ERR, "Operation not completed:Error Code = %d\n", retcode);
	return;
};

static struct eth_dev_ops dpaa2_ethdev_ops = {
	.dev_configure	      = dpaa2_eth_dev_configure,
	.dev_start	      = dpaa2_dev_start,
	.dev_stop	      = dpaa2_dev_stop,
	.dev_close	      = dpaa2_dev_close,
	.promiscuous_enable   = dpaa2_dev_promiscuous_enable,
	.promiscuous_disable  = dpaa2_dev_promiscuous_disable,
	.allmulticast_enable  = dpaa2_dev_allmulticast_enable,
	.allmulticast_disable = dpaa2_dev_allmulticast_disable,
	.dev_set_link_up      = NULL,
	.dev_set_link_down    = NULL,
	.link_update	      = dpaa2_dev_get_link_info,
	.stats_get	      = dpaa2_dev_stats_get,
	.stats_reset	      = dpaa2_dev_stats_reset,
	.dev_infos_get	      = dpaa2_dev_info_get,
	.dev_supported_ptypes_get = dpaa2_supported_ptypes_get,
	.mtu_set	      = dpaa2_dev_mtu_set,
	.vlan_filter_set      = dpaa2_vlan_filter_set,
	.vlan_tpid_set        = NULL,
	.vlan_offload_set     = dpaa2_vlan_offload_set,
	.vlan_strip_queue_set = NULL,
	.vlan_pvid_set        = NULL,
	.rx_queue_setup	      = dpaa2_dev_rx_queue_setup,
	.rx_queue_release      = dpaa2_dev_rx_queue_release,
	.tx_queue_setup	      = dpaa2_dev_tx_queue_setup,
	.tx_queue_release      = dpaa2_dev_tx_queue_release,
	.dev_led_on           = NULL,
	.dev_led_off          = NULL,
	.set_queue_rate_limit = NULL,
	.flow_ctrl_get	      = NULL,
	.flow_ctrl_set	      = dpaa2_dev_flow_ctrl_set,
	.priority_flow_ctrl_set = NULL,
	.mac_addr_add         = dpaa2_dev_add_mac_addr,
	.mac_addr_remove      = dpaa2_dev_remove_mac_addr,
	.rxq_info_get         = NULL,
	.txq_info_get         = NULL,
	.timesync_enable      = dpaa2_dev_timestamp_enable,
	.timesync_disable     = dpaa2_dev_timestamp_disable,
	.mac_addr_set         = dpaa2_dev_set_mac_addr,
};

static int
dpaa2_dev_init(struct rte_eth_dev *eth_dev)
{
	struct fsl_mc_io *dpni_dev;
	struct dpni_attr attr;
	struct dpaa2_dev_priv *priv = eth_dev->data->dev_private;
	struct dpni_buffer_layout layout;
	int i, ret, hw_id;
	struct dpni_extended_cfg *ext_cfg = NULL;
	int tot_size;

	PMD_INIT_FUNC_TRACE();

	hw_id = eth_dev->pci_dev->addr.devid;

	dpni_dev = (struct fsl_mc_io *)malloc(sizeof(struct fsl_mc_io));
	if (!dpni_dev) {
		PMD_DRV_LOG(ERR, "malloc failed for dpni device\n");
		return -1;
	}

	dpni_dev->regs = mcp_ptr_list[0];
	ret = dpni_open(dpni_dev, CMD_PRI_LOW, hw_id, &priv->token);
	if (ret) {
		PMD_DRV_LOG(ERR, "Failure in opening dpni@%d device with"
			"error code %d\n", hw_id, ret);
		return -1;
	}

	/* Clean the device first */
	ret = dpni_reset(dpni_dev, CMD_PRI_LOW, priv->token);
	if (ret) {
		PMD_DRV_LOG(ERR, "Failure cleaning dpni@%d device with"
			"error code %d\n", hw_id, ret);
		return -1;
	}

	ext_cfg = (struct dpni_extended_cfg *)rte_malloc(NULL, 256,
							RTE_CACHE_LINE_SIZE);
	if (!ext_cfg) {
		PMD_DRV_LOG(ERR, "No data memory\n");
		return -1;
	}
	attr.ext_cfg_iova = (uint64_t)(DPAA2_VADDR_TO_IOVA(ext_cfg));

	ret = dpni_get_attributes(dpni_dev, CMD_PRI_LOW, priv->token, &attr);
	if (ret) {
		PMD_DRV_LOG(ERR, "Failure in getting dpni@%d attribute, "
			"error code %d\n", hw_id, ret);
		return -1;
	}

	priv->num_tc = attr.max_tcs;
	for (i = 0; i < attr.max_tcs; i++) {
		priv->num_dist_per_tc[i] = ext_cfg->tc_cfg[i].max_dist;
		break;
	}

	/* Distribution is per Tc only, so choosing RX queues from default TC only */
	priv->nb_rx_queues = priv->num_dist_per_tc[DPAA2_DEF_TC];

	if (attr.max_tcs == 1)
		priv->nb_tx_queues = attr.max_senders;
	else
		priv->nb_tx_queues = attr.max_tcs;
	PMD_DRV_LOG(INFO, "num_tc %d", priv->num_tc);
	PMD_DRV_LOG(INFO, "nb_rx_queues %d", priv->nb_rx_queues);

	eth_dev->data->nb_rx_queues = priv->nb_rx_queues;
	eth_dev->data->nb_tx_queues = priv->nb_tx_queues;

	priv->hw = dpni_dev;
	priv->hw_id = hw_id;
	priv->options = attr.options;

	priv->max_unicast_filters = attr.max_unicast_filters;
	priv->max_multicast_filters = attr.max_multicast_filters;
	priv->max_congestion_ctrl = attr.max_congestion_ctrl;

	if (attr.options & DPNI_OPT_VLAN_FILTER)
		priv->max_vlan_filters = attr.max_vlan_filters;
	else
		priv->max_vlan_filters = 0;

	priv->flags = 0;

	/*If congestion control support is not required */
	if(getenv("DPAA2_NO_CGR_SUPPORT")) {
		priv->flags |= DPAA2_NO_CGR_SUPPORT;
		PMD_DRV_LOG(INFO, "Disabling the congestion control support");
	}

	/*Tail drop to be configured on per TC instead of per queue */
	if(getenv("DPAA2_PER_TC_RX_TAILDROP")) {
		priv->flags |= DPAA2_PER_TC_RX_TAILDROP;
		PMD_DRV_LOG(INFO, "Enabling per TC tail drop on RX");
	}

	ret = dpaa2_alloc_rx_tx_queues(eth_dev);
	if (ret) {
		PMD_DRV_LOG(ERR, "dpaa2_alloc_rx_tx_queuesFailed\n");
		return -ret;
	}

	/* Allocate memory for storing MAC addresses */
	eth_dev->data->mac_addrs = rte_zmalloc("dpni",
		ETHER_ADDR_LEN * attr.max_unicast_filters, 0);
	if (eth_dev->data->mac_addrs == NULL) {
		PMD_DRV_LOG(ERR, "Failed to allocate %d bytes needed to "
						"store MAC addresses",
				ETHER_ADDR_LEN * attr.max_unicast_filters);
		return -ENOMEM;
	}

	ret = dpni_get_primary_mac_addr(dpni_dev, CMD_PRI_LOW,
					priv->token,
				(uint8_t *)(eth_dev->data->mac_addrs[0].addr_bytes));
	if (ret) {
		PMD_DRV_LOG(ERR, "DPNI get mac address failed:"
					" Error Code = %d\n", ret);
		return -ret;
	}

	/* ... rx buffer layout ... */
	tot_size = DPAA2_HW_BUF_RESERVE + RTE_PKTMBUF_HEADROOM;
	tot_size = RTE_ALIGN_CEIL(tot_size,
				  DPAA2_PACKET_LAYOUT_ALIGN);

	memset(&layout, 0, sizeof(struct dpni_buffer_layout));
	layout.options = DPNI_BUF_LAYOUT_OPT_FRAME_STATUS |
				DPNI_BUF_LAYOUT_OPT_TIMESTAMP |
				DPNI_BUF_LAYOUT_OPT_PARSER_RESULT |
				DPNI_BUF_LAYOUT_OPT_DATA_HEAD_ROOM |
				DPNI_BUF_LAYOUT_OPT_PRIVATE_DATA_SIZE;

	layout.pass_frame_status = 1;
	layout.data_head_room = tot_size
		- DPAA2_FD_PTA_SIZE - DPAA2_MBUF_HW_ANNOTATION;
	layout.private_data_size = DPAA2_FD_PTA_SIZE;
	layout.pass_timestamp = 1;
	layout.pass_parser_result = 1;
	PMD_DRV_LOG(INFO, "Tot_size = %d, head room = %d, private = %d",
		    tot_size, layout.data_head_room, layout.private_data_size);
	ret = dpni_set_rx_buffer_layout(dpni_dev, CMD_PRI_LOW, priv->token,
					&layout);
	if (ret) {
		PMD_DRV_LOG(ERR, "Err(%d) in setting rx buffer layout\n", ret);
		return -1;
	}

	/* ... tx buffer layout ... */
	memset(&layout, 0, sizeof(struct dpni_buffer_layout));
	layout.options = DPNI_BUF_LAYOUT_OPT_FRAME_STATUS |
				DPNI_BUF_LAYOUT_OPT_TIMESTAMP;
	layout.pass_frame_status = 1;
	layout.pass_timestamp = 1;
	ret = dpni_set_tx_buffer_layout(dpni_dev, CMD_PRI_LOW, priv->token, &layout);
	if (ret) {
		PMD_DRV_LOG(ERR, "Error (%d) in setting tx buffer layout\n", ret);
		return -1;
	}

	/* ... tx-conf and error buffer layout ... */
	memset(&layout, 0, sizeof(struct dpni_buffer_layout));
	layout.options = DPNI_BUF_LAYOUT_OPT_FRAME_STATUS |
				DPNI_BUF_LAYOUT_OPT_TIMESTAMP;
	layout.pass_frame_status = 1;
	layout.pass_timestamp = 1;
	ret = dpni_set_tx_conf_buffer_layout(dpni_dev, CMD_PRI_LOW, priv->token, &layout);
	if (ret) {
		PMD_DRV_LOG(ERR, "Error (%d) in setting tx-conf buffer layout\n", ret);
		return -1;
	}

	/* TODO - Set the MTU if required */

	eth_dev->dev_ops = &dpaa2_ethdev_ops;
	eth_dev->rx_pkt_burst = dpaa2_dev_prefetch_rx;/*dpaa2_dev_rx;*/
	eth_dev->tx_pkt_burst = dpaa2_dev_tx;

	rte_free(ext_cfg);

	return 0;
}

static struct rte_pci_id pci_id_dpaa2_map[] = {
	{RTE_PCI_DEVICE(FSL_VENDOR_ID, FSL_MC_DPNI_DEVID)},
};

static struct eth_driver rte_dpaa2_dpni = {
	{
		.name = "rte_dpaa2_dpni",
		.id_table = pci_id_dpaa2_map,
	},
	.eth_dev_init = dpaa2_dev_init,
	.dev_private_size = sizeof(struct dpaa2_dev_priv),
};

static int
rte_pmd_dpaa2_devinit(
		const char *name __rte_unused,
		const char *params __rte_unused)
{
	int ret = 0;

	ret = rte_eal_dpaa2_dmamap();
	if (!ret) {
		/* DMA Mapping has been completed*/
	}

	PMD_DRV_LOG(INFO, "Initializing dpaa2_pmd for %s\n", name);
	rte_eth_driver_register(&rte_dpaa2_dpni);

	return 0;
}

static struct rte_driver pmd_dpaa2_drv = {
	.name = "dpaa2_pmd",
	.type = PMD_PDEV,
	.init = rte_pmd_dpaa2_devinit,
};

PMD_REGISTER_DRIVER(pmd_dpaa2_drv, dpaa2);
