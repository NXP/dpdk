/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 NXP
 */

#include <stdio.h>
#include <sys/ioctl.h>

#include <rte_dpaa_bus.h>
#include <rte_dpaa_logs.h>
#include <dpaa_ethdev.h>
#include <dpaa_rxtx.h>
#include <dpaa_mempool.h>

#include <fsl_fman.h>

/* The ol device is a tx are queue pair, which is provided to the kernel through
 * ioctl calls. It is exposed as a virtual port to the application.
 * This ASK Device provides IOCTL calls to driver for communicating fqid's,
 * buffer pool id's and channel id's with kernel.
 */
#define ASK_PATH            "/dev/cdx_ctrl"
#define CDX_IOC_MAGIC 'c'


static int fd = -1;
static pthread_mutex_t fd_init_lock = PTHREAD_MUTEX_INITIALIZER;

struct ask_ctrl_offline_channel {
	uint32_t channel_id;
};

struct ask_ctrl_set_dpdk_info {
	uint32_t dpdk_tx_fq_id;	/* DPDK transmits GTP packets using FQ ID */
	uint32_t dpdk_rx_fq_id;	/* DPDK receives packets from FMAN */
	uint16_t gtp_udp_port;	/* DPDK app listens on this GTP port */
	uint8_t  dpdk_bp_id;	/* DPDK buffer pool id */
};

#define ASK_CTRL_GET_OFFLINE_CHANNEL_INFO \
	_IOWR(CDX_IOC_MAGIC, 8, struct ask_ctrl_offline_channel)
#define ASK_CTRL_SET_DPDK_INFO \
	_IOWR(CDX_IOC_MAGIC, 9, struct ask_ctrl_set_dpdk_info)

static int check_fd(void)
{
	int ret;

	if (fd >= 0)
		return 0;
	ret = pthread_mutex_lock(&fd_init_lock);
	assert(!ret);
	/* check again with the lock held */
	if (fd < 0)
		fd = open(ASK_PATH, O_RDWR);
	ret = pthread_mutex_unlock(&fd_init_lock);
	assert(!ret);
	return (fd >= 0) ? 0 : -ENODEV;
}

static uint32_t ask_get_channel_id(void)
{
	return 0;

	struct ask_ctrl_offline_channel ch_info;
	int ret = check_fd();

	if (ret)
		return ret;

	ret = ioctl(fd, ASK_CTRL_GET_OFFLINE_CHANNEL_INFO, &ch_info);
	if (ret) {
		perror("ioctl(ASK_CTRL_GET_OFFLINE_CHANNEL_INFO)");
		return ret;
	}
	return ch_info.channel_id;
}

static int ask_set_dpdk_info(uint32_t tx_fqid, uint32_t rx_fqid,
			     uint16_t gtp_udp_port, uint8_t bpid)
{
	return 0;

	struct ask_ctrl_set_dpdk_info dpdk_info;
	int ret = check_fd();

	if (ret)
		return ret;

	dpdk_info.dpdk_tx_fq_id = tx_fqid;
	dpdk_info.dpdk_rx_fq_id = rx_fqid;
	dpdk_info.gtp_udp_port = gtp_udp_port;
	dpdk_info.dpdk_bp_id = bpid;

	ret = ioctl(fd, ASK_CTRL_SET_DPDK_INFO, &dpdk_info);
	if (ret) {
		perror("ioctl(ASK_CTRL_SET_DPDK_INFO)");
		return ret;
	}

	return 0;
}

static int
dpaa_ol_dev_configure(__rte_unused struct rte_eth_dev *dev)
{
	printf("OL Port Configuring....\n");
	return 0;
}

static int dpaa_ol_dev_info(struct rte_eth_dev *dev,
			    struct rte_eth_dev_info *dev_info)
{
	struct dpaa_if *dpaa_intf = dev->data->dev_private;

	dev_info->max_rx_queues = dpaa_intf->nb_rx_queues;
	dev_info->max_tx_queues = dpaa_intf->nb_tx_queues;
	dev_info->max_rx_pktlen = DPAA_MAX_RX_PKT_LEN;
	dev_info->max_mac_addrs = DPAA_MAX_MAC_FILTER;
	dev_info->max_hash_mac_addrs = 0;
	dev_info->max_vfs = 0;

	dev_info->speed_capa = ETH_LINK_SPEED_10M_HD | ETH_LINK_SPEED_10M |
			       ETH_LINK_SPEED_100M_HD | ETH_LINK_SPEED_100M |
			       ETH_LINK_SPEED_1G | ETH_LINK_SPEED_2_5G |
			       ETH_LINK_SPEED_10G;

	return 0;
}

static int dpaa_ol_dev_start(struct rte_eth_dev *dev)
{
	PMD_INIT_FUNC_TRACE();

	printf("Starting device...\n");

	dev->tx_pkt_burst = dpaa_eth_queue_tx;

	return 0;
}

static void dpaa_ol_dev_stop(struct rte_eth_dev *dev)
{
	PMD_INIT_FUNC_TRACE();

	dev->tx_pkt_burst = dpaa_eth_tx_drop_all;
}

static void dpaa_ol_dev_close(__rte_unused struct rte_eth_dev *dev)
{
	return;
}

static inline void
dpaa_poll_queue_default_config(struct qm_mcc_initfq *opts)
{
	memset(opts, 0, sizeof(struct qm_mcc_initfq));
	opts->we_mask = QM_INITFQ_WE_FQCTRL | QM_INITFQ_WE_CONTEXTA;
	opts->fqd.fq_ctrl = QM_FQCTRL_AVOIDBLOCK | QM_FQCTRL_CTXASTASHING |
			    QM_FQCTRL_PREFERINCACHE;
	opts->fqd.context_a.stashing.exclusive = 0;
	if (dpaa_svr_family != SVR_LS1046A_FAMILY)
		opts->fqd.context_a.stashing.annotation_cl =
				DPAA_IF_RX_ANNOTATION_STASH;
	opts->fqd.context_a.stashing.data_cl = DPAA_IF_RX_DATA_STASH;
	opts->fqd.context_a.stashing.context_cl = DPAA_IF_RX_CONTEXT_STASH;
}

static
int dpaa_ol_rx_queue_setup(struct rte_eth_dev *dev, uint16_t queue_idx,
			    __rte_unused uint16_t nb_desc,
			    unsigned int socket_id __rte_unused,
			    __rte_unused const struct rte_eth_rxconf *rx_conf,
			    struct rte_mempool *mp)
{
	struct dpaa_if *dpaa_intf = dev->data->dev_private;
	struct qman_fq *rxq = &dpaa_intf->rx_queues[queue_idx];
	struct qman_fq *txq = &dpaa_intf->tx_queues[queue_idx];
	struct qm_mcc_initfq opts = {0};
	u32 flags = 0;
	struct qman_portal *qp;
	int q_fd, ret;
	uint32_t bp_id;

	PMD_INIT_FUNC_TRACE();

	if (queue_idx >= dev->data->nb_rx_queues) {
		rte_errno = EOVERFLOW;
		DPAA_PMD_ERR("%p: queue index out of range (%u >= %u)",
			     (void *)dev, queue_idx, dev->data->nb_rx_queues);
		return -rte_errno;
	}

	dpaa_intf->bp_info = DPAA_MEMPOOL_TO_POOL_INFO(mp);
	dpaa_intf->valid = 1;

	/*Create a channel and associate given queue with the channel*/
	qman_alloc_pool_range((u32 *)&rxq->ch_id, 1, 1, 0);
	opts.we_mask = opts.we_mask | QM_INITFQ_WE_DESTWQ;
	opts.fqd.dest.channel = rxq->ch_id;
	opts.fqd.dest.wq = DPAA_IF_RX_PRIORITY;
	flags = QMAN_INITFQ_FLAG_SCHED;

	ret = qman_init_fq(rxq, flags, &opts);
	if (ret) {
		DPAA_PMD_ERR("Channel/Q association failed. fqid 0x%x "
			     "ret:%d(%s)", rxq->fqid, ret, strerror(ret));
		return ret;
	}

	rxq->cb.dqrr_dpdk_pull_cb = dpaa_rx_cb;
	rxq->cb.dqrr_prepare = dpaa_rx_cb_prepare;

	rxq->is_static = true;

	qp = fsl_qman_fq_portal_create(&q_fd);
	if (!qp) {
		DPAA_PMD_ERR("Unable to alloc fq portal");
		return -1;
	}
	rxq->qp = qp;
	rxq->q_fd = q_fd;

	rxq->bp_array = rte_dpaa_bpid_info;
	dev->data->rx_queues[queue_idx] = rxq;

	if (dpaa_intf->bp_info == NULL || txq == NULL)
		return 0;

	bp_id = dpaa_intf->bp_info->bpid;
	ret = ask_set_dpdk_info(txq->fqid, rxq->fqid, 0, bp_id);
	if (ret < 0) {
		DPAA_PMD_ERR("set dpdk info failed with ret: %d", ret);
		return ret;
	}

	return 0;
}

static
int dpaa_ol_tx_queue_setup(struct rte_eth_dev *dev, uint16_t queue_idx,
			   uint16_t nb_desc __rte_unused,
			   unsigned int socket_id __rte_unused,
			   const struct rte_eth_txconf *tx_conf __rte_unused)
{
	struct dpaa_if *dpaa_intf = dev->data->dev_private;
	struct qman_fq *txq = &dpaa_intf->tx_queues[queue_idx];
	struct qman_fq *rxq = &dpaa_intf->tx_queues[queue_idx];
	uint32_t bp_id;
	int ret;

	PMD_INIT_FUNC_TRACE();

	dev->data->tx_queues[queue_idx] = txq;

	if (dpaa_intf->bp_info == NULL || rxq == NULL)
		return 0;

	bp_id = dpaa_intf->bp_info->bpid;
	ret = ask_set_dpdk_info(txq->fqid, rxq->fqid, 0, bp_id);
	if (ret < 0) {
		DPAA_PMD_ERR("set dpdk info failed with ret: %d", ret);
		return ret;
	}

	return 0;
}

static int dpaa_ol_link_update(struct rte_eth_dev *dev,
			       __rte_unused int wait_to_complete)
{
	struct dpaa_if *dpaa_intf = dev->data->dev_private;
	struct rte_eth_link *link = &dev->data->dev_link;

	link->link_status = dpaa_intf->valid;
	link->link_speed = ETH_SPEED_NUM_1G;
	link->link_duplex = ETH_LINK_FULL_DUPLEX;
	link->link_autoneg = ETH_LINK_AUTONEG;

	return 0;
}

static int dpaa_ol_promiscuous_enable(__rte_unused struct rte_eth_dev *dev)
{
	return 0;
}

static int dpaa_ol_rx_queue_init(struct qman_fq *fq, uint32_t fqid)
{
	int ret;
	struct qm_mcc_initfq opts = {0};
	u32 flags = QMAN_FQ_FLAG_DYNAMIC_FQID | QMAN_FQ_FLAG_NO_ENQUEUE;

	ret = qman_create_fq(fqid, flags, fq);
	if (ret) {
		DPAA_PMD_ERR("create rx fqid 0x%x failed with ret: %d", fqid,
			     ret);
		return ret;
	}
	fq->is_static = false;

	dpaa_poll_queue_default_config(&opts);

	ret = qman_init_fq(fq, 0, &opts);
	if (ret)
		DPAA_PMD_ERR("init rx fqid 0x%x failed with ret:%d", fqid, ret);
	return ret;
}

static int dpaa_ol_tx_queue_init(struct qman_fq *fq, uint32_t fqid)
{
	int ret;
	struct qm_mcc_initfq opts = {0};
	u32 flags = QMAN_FQ_FLAG_DYNAMIC_FQID | QMAN_FQ_FLAG_TO_DCPORTAL;

	ret = qman_create_fq(fqid, flags, fq);
	if (ret) {
		DPAA_PMD_ERR("create tx fq failed with ret: %d", ret);
		return ret;
	}

	opts.we_mask = QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL |
		       QM_INITFQ_WE_CONTEXTB | QM_INITFQ_WE_CONTEXTA;

	ret = ask_get_channel_id();
	if (ret < 0) {
		DPAA_PMD_ERR("get channel id failed with ret: %d", ret);
		return ret;
	}
	opts.fqd.dest.channel = ret;

	opts.fqd.dest.wq = DPAA_IF_TX_PRIORITY;
	opts.fqd.fq_ctrl = QM_FQCTRL_PREFERINCACHE;
	opts.fqd.context_b = 0;
	/* no tx-confirmation */
	opts.fqd.context_a.hi = 0x80000000 | fman_dealloc_bufs_mask_hi;
	opts.fqd.context_a.lo = 0 | fman_dealloc_bufs_mask_lo;

	ret = qman_init_fq(fq, QMAN_INITFQ_FLAG_SCHED, &opts);
	if (ret)
		DPAA_PMD_ERR("init tx fqid 0x%x failed %d", fq->fqid, ret);
	return ret;
}

static struct eth_dev_ops dpaa_ol_devops = {
		.dev_configure            = dpaa_ol_dev_configure,
		.dev_start                = dpaa_ol_dev_start,
		.dev_stop                 = dpaa_ol_dev_stop,
		.dev_close                = dpaa_ol_dev_close,
		.dev_infos_get            = dpaa_ol_dev_info,

		.rx_queue_setup           = dpaa_ol_rx_queue_setup,
		.tx_queue_setup           = dpaa_ol_tx_queue_setup,

		.link_update              = dpaa_ol_link_update,
		.promiscuous_enable       = dpaa_ol_promiscuous_enable,
};

static int dpaa_oldev_init(struct rte_eth_dev *eth_dev)
{
	int num_fqs, ret;
	struct dpaa_if *dpaa_intf;

	PMD_INIT_FUNC_TRACE();

	num_fqs = DPAA_DEFAULT_NUM_PCD_QUEUES;
	dpaa_intf = eth_dev->data->dev_private;

	dpaa_intf->rx_queues = rte_zmalloc(NULL,
					   sizeof(struct qman_fq) * num_fqs,
					   MAX_CACHELINE);
	if (!dpaa_intf->rx_queues) {
		DPAA_PMD_ERR("Failed to alloc mem for RX queues\n");
		return -ENOMEM;
	}

	ret = dpaa_ol_rx_queue_init(&dpaa_intf->rx_queues[0], 0);
	if (ret)
		goto free_rx;
	dpaa_intf->rx_queues[0].dpaa_intf = dpaa_intf;

	dpaa_intf->nb_rx_queues = num_fqs;

	dpaa_intf->tx_queues = rte_zmalloc(NULL,
					   sizeof(struct qman_fq) * num_fqs,
					   MAX_CACHELINE);
	if (!dpaa_intf->tx_queues) {
		DPAA_PMD_ERR("Failed to alloc mem for TX queues\n");
		ret = -ENOMEM;
		goto free_rx;
	}

	ret = dpaa_ol_tx_queue_init(&dpaa_intf->tx_queues[0], 0);
	if (ret)
		goto free_tx;

	dpaa_intf->nb_tx_queues = num_fqs;

	eth_dev->dev_ops = &dpaa_ol_devops;
	eth_dev->rx_pkt_burst = dpaa_eth_queue_rx;
	eth_dev->tx_pkt_burst = dpaa_eth_tx_drop_all;

	/* Allocate memory for storing MAC addresses */
	eth_dev->data->mac_addrs = rte_zmalloc("mac_addr",
			RTE_ETHER_ADDR_LEN * DPAA_MAX_MAC_FILTER, 0);
	if (eth_dev->data->mac_addrs == NULL) {
		DPAA_PMD_ERR("Failed to allocate %d bytes needed to "
			     "store MAC addresses",
			     RTE_ETHER_ADDR_LEN * DPAA_MAX_MAC_FILTER);
		ret = -ENOMEM;
		goto free_tx;
	}

	return 0;

free_tx:
	rte_free(dpaa_intf->tx_queues);
	dpaa_intf->tx_queues = NULL;
	dpaa_intf->nb_tx_queues = 0;
free_rx:
	rte_free(dpaa_intf->rx_queues);
	dpaa_intf->rx_queues = NULL;
	dpaa_intf->nb_rx_queues = 0;
	return ret;
}

static int rte_dpaa_probe(__rte_unused struct rte_dpaa_driver *dpaa_drv,
			  __rte_unused struct rte_dpaa_device *dpaa_dev)
{
	int ret;
	struct rte_eth_dev *eth_dev;

	PMD_INIT_FUNC_TRACE();

	eth_dev = rte_eth_dev_allocate(dpaa_dev->name);
	if (!eth_dev)
		return -ENOMEM;
	eth_dev->data->dev_private = rte_zmalloc("ethdev private structure",
						 sizeof(struct dpaa_if),
						 RTE_CACHE_LINE_SIZE);
	if (!eth_dev->data->dev_private) {
		DPAA_PMD_ERR("Cannot allocate memzone for port data");
		rte_eth_dev_release_port(eth_dev);
		return -ENOMEM;
	}

	eth_dev->device = &dpaa_dev->device;
	dpaa_dev->eth_dev = eth_dev;

	ret = dpaa_oldev_init(eth_dev);
	if (ret == 0) {
		rte_eth_dev_probing_finish(eth_dev);
		printf("OL Device Probed\n");
		return 0;
	}

	rte_eth_dev_release_port(eth_dev);
	return ret;
}

static int rte_dpaa_remove(__rte_unused struct rte_dpaa_device *dpaa_dev)
{
	printf("OL Device Removed\n");
	return 0;
}

static struct rte_dpaa_driver rte_dpaa_ol_pmd = {
		.drv_type = FSL_DPAA_OL,
		.probe = rte_dpaa_probe,
		.remove = rte_dpaa_remove,
};

RTE_PMD_REGISTER_DPAA(ol_dpaa, rte_dpaa_ol_pmd);
