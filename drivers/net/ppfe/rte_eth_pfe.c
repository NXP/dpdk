/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018 NXP
 */

#include <rte_cycles.h>
#include <rte_devargs.h>
#include <rte_dev.h>
#include <rte_kvargs.h>
#include <rte_ethdev.h>
#include <rte_ethdev_vdev.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_bus_vdev.h>
#include <of.h>
#include "pfe_logs.h"
#include "pfe_mod.h"

#define PPFE_MAX_MACS 1 /*we can support upto 4 MACs per IF*/
#define PPFE_VDEV_MAX_PORT 2
#define PPFE_VDEV_GEM_ID_ARG	("intf")

static void *cbus_emac_base[3];
static void *cbus_gpi_base[3];
struct pfe *g_pfe;

unsigned int pfe_svr = SVR_LS1012A_REV1;

static void
pfe_dev_set_mac_addr(struct rte_eth_dev *dev, struct ether_addr *addr);
static void
pfe_eth_exit(struct rte_eth_dev *dev, struct pfe *pfe);
static uint16_t
pfe_dummy_xmit_pkts(__rte_unused void *tx_queue,
		__rte_unused struct rte_mbuf **tx_pkts,
		__rte_unused uint16_t nb_pkts);
static uint16_t
pfe_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts, uint16_t nb_pkts);

struct pfe_vdev_init_params {
	int8_t	gem_id;
};

/* pfe_gemac_init
 */
static int pfe_gemac_init(struct pfe_eth_priv_s *priv)
{
	struct gemac_cfg cfg;

	cfg.speed = SPEED_1000M;
	cfg.duplex = DUPLEX_FULL;

	gemac_set_config(priv->EMAC_baseaddr, &cfg);
	gemac_allow_broadcast(priv->EMAC_baseaddr);
	gemac_enable_1536_rx(priv->EMAC_baseaddr);
	gemac_enable_stacked_vlan(priv->EMAC_baseaddr);
	gemac_enable_pause_rx(priv->EMAC_baseaddr);
	gemac_set_bus_width(priv->EMAC_baseaddr, 64);
	gemac_enable_rx_checksum_offload(priv->EMAC_baseaddr);

	return 0;
}

static void
pfe_soc_version_get(void)
{
	FILE *svr_file = NULL;
	unsigned int svr_ver = 0;

	PMD_INIT_FUNC_TRACE();

	svr_file = fopen(PFE_SOC_ID_FILE, "r");
	if (!svr_file) {
		PFE_PMD_ERR("Unable to open SoC device");
		return; /* Not supported on this infra */
	}
	if (fscanf(svr_file, "svr:%x", &svr_ver) > 0)
		pfe_svr = svr_ver;
	else
		PFE_PMD_ERR("Unable to read SoC device");

	fclose(svr_file);
}

/* pfe_eth_start
 */
static int pfe_eth_start(struct pfe_eth_priv_s *priv)
{
	gpi_enable(priv->GPI_baseaddr);
	gemac_enable(priv->EMAC_baseaddr);

	return 0;
}

/* pfe_eth_flush_txQ
 */
static void pfe_eth_flush_txQ(struct pfe_eth_priv_s *priv, int tx_q_num, int
				__rte_unused from_tx, __rte_unused int n_desc)
{
	struct rte_mbuf *mbuf;
	unsigned int flags;

	/* Clean HIF and client queue */
	while ((mbuf = hif_lib_tx_get_next_complete(&priv->client,
						   tx_q_num, &flags,
						   HIF_TX_DESC_NT))) {
		if (mbuf) {
			if (flags & HIF_DATA_VALID)
				rte_pktmbuf_free(mbuf);
		}
	}
}


/* pfe_eth_flush_tx
 */
static void pfe_eth_flush_tx(struct pfe_eth_priv_s *priv)
{
	unsigned int ii;

	for (ii = 0; ii < emac_txq_cnt; ii++)
		pfe_eth_flush_txQ(priv, ii, 0, 0);
}

/* pfe_eth_event_handler
 */
static int pfe_eth_event_handler(void *data, int event, __rte_unused int qno)
{
	struct pfe_eth_priv_s *priv = data;

	switch (event) {
	case EVENT_TXDONE_IND:
		pfe_eth_flush_tx(priv);
		hif_lib_event_handler_start(&priv->client, EVENT_TXDONE_IND, 0);
		break;
	case EVENT_HIGH_RX_WM:
	default:
		break;
	}

	return 0;
}

static uint16_t
pfe_recv_pkts(void *rxq, struct rte_mbuf **rx_pkts, uint16_t nb_pkts)
{
	struct hif_client_rx_queue *queue = rxq;
	struct pfe_eth_priv_s *priv = queue->priv;
	struct rte_mempool *pool;

	/*TODO can we remove this cleanup from here?*/
	pfe_tx_do_cleanup(priv->pfe);
	pfe_hif_rx_process(&priv->pfe->hif, nb_pkts);
	pool = priv->pfe->hif.shm->pool;

	return hif_lib_receive_pkt(rxq, pool, rx_pkts, nb_pkts);
}

static uint16_t
pfe_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	struct hif_client_tx_queue *queue = tx_queue;
	struct pfe_eth_priv_s *priv = queue->priv;
	struct rte_eth_stats *stats = &priv->stats;
	int i;

	for (i = 0; i < nb_pkts; i++) {
		hif_lib_xmit_pkt(&priv->client, queue->queue_id,
			(void *)rte_pktmbuf_iova(tx_pkts[i]),
			tx_pkts[i]->buf_addr + tx_pkts[i]->data_off ,
			tx_pkts[i]->pkt_len, 0 /*ctrl*/,
			HIF_FIRST_BUFFER | HIF_LAST_BUFFER | HIF_DATA_VALID,
			tx_pkts[i]);
		stats->obytes += tx_pkts[i]->pkt_len;
		hif_tx_dma_start();
	}
	stats->opackets += nb_pkts;
	pfe_tx_do_cleanup(priv->pfe);

	return nb_pkts;
}

static uint16_t
pfe_dummy_xmit_pkts(__rte_unused void *tx_queue,
		__rte_unused struct rte_mbuf **tx_pkts,
		__rte_unused uint16_t nb_pkts)
{
	return 0;
}

static uint16_t
pfe_dummy_recv_pkts(__rte_unused void *rxq,
		__rte_unused struct rte_mbuf **rx_pkts,
		__rte_unused uint16_t nb_pkts)
{
	return 0;
}


/* pfe_eth_open
 */
static int pfe_eth_open(struct rte_eth_dev *dev)
{
	struct pfe_eth_priv_s *priv = dev->data->dev_private;
	struct hif_client_s *client;
	struct hif_shm *hif_shm;
	int rc;

	/* Register client driver with HIF */
	client = &priv->client;

	if (client->pfe) {
		hif_shm = client->pfe->hif.shm;
		/* TODO please remove the below code of if block, once we add
		 * the proper cleanup in eth_close */
		if (!test_bit(PFE_CL_GEM0 + priv->id, &hif_shm->g_client_status[0])) {
			/* Register client driver with HIF */
			memset(client, 0, sizeof(*client));
			client->id = PFE_CL_GEM0 + priv->id;
			client->tx_qn = emac_txq_cnt;
			client->rx_qn = EMAC_RXQ_CNT;
			client->priv = priv;
			client->pfe = priv->pfe;
			client->port_id = dev->data->port_id;
			client->event_handler = pfe_eth_event_handler;

			client->tx_qsize = EMAC_TXQ_DEPTH;
			client->rx_qsize = EMAC_RXQ_DEPTH;

			rc = hif_lib_client_register(client);
			if (rc) {
				PFE_PMD_ERR("hif_lib_client_register(%d) failed", client->id);
				goto err0;
			}
		} else {
			/* Freeing the packets if already exists */
			int ret = 0;
			struct rte_mbuf *rx_pkts[32];
			/* TODO multiqueue support */
			ret = hif_lib_receive_pkt(&client->rx_q[0], hif_shm->pool, rx_pkts, 32);
			while (ret) {
				for (int i = 0; i < ret; i++)
					rte_pktmbuf_free(rx_pkts[i]);
				ret = hif_lib_receive_pkt(&client->rx_q[0], hif_shm->pool, rx_pkts, 32);
			}
		}
	} else {
		/* Register client driver with HIF */
		memset(client, 0, sizeof(*client));
		client->id = PFE_CL_GEM0 + priv->id;
		client->tx_qn = emac_txq_cnt;
		client->rx_qn = EMAC_RXQ_CNT;
		client->priv = priv;
		client->pfe = priv->pfe;
		client->port_id = dev->data->port_id;
		client->event_handler = pfe_eth_event_handler;

		client->tx_qsize = EMAC_TXQ_DEPTH;
		client->rx_qsize = EMAC_RXQ_DEPTH;

		rc = hif_lib_client_register(client);
		if (rc) {
			PFE_PMD_ERR("hif_lib_client_register(%d) failed", client->id);
			goto err0;
		}
	}
	rc = pfe_eth_start(priv);
	dev->rx_pkt_burst = &pfe_recv_pkts;
	dev->tx_pkt_burst = &pfe_xmit_pkts;
err0:
	return rc;
}

/* pfe_eth_stop
 */
static void pfe_eth_stop(struct rte_eth_dev *dev/*, int wake*/)
{
	struct pfe_eth_priv_s *priv = dev->data->dev_private;

	gemac_disable(priv->EMAC_baseaddr);
	gpi_disable(priv->GPI_baseaddr);

	dev->rx_pkt_burst = &pfe_dummy_recv_pkts;
	dev->tx_pkt_burst = &pfe_dummy_xmit_pkts;
}

/* pfe_eth_close
 *
 */
static void pfe_eth_close(struct rte_eth_dev *dev)
{
	if (!dev)
		return;

	if (!g_pfe)
		return;

	pfe_eth_exit(dev, g_pfe);

	if (g_pfe->nb_devs == 0) {
		pfe_hif_exit(g_pfe);
		pfe_hif_lib_exit(g_pfe);
		rte_free(g_pfe);
		g_pfe = NULL;
	}
}

static int
pfe_eth_configure(struct rte_eth_dev *dev __rte_unused)
{
	return 0;
}

static void
pfe_eth_info(struct rte_eth_dev *dev,
		struct rte_eth_dev_info *dev_info)
{
	struct pfe_eth_priv_s *internals = dev->data->dev_private;

	dev_info->if_index = internals->id;
	dev_info->max_mac_addrs = PPFE_MAX_MACS;
	dev_info->max_rx_pktlen = JUMBO_FRAME_SIZE;
	dev_info->max_rx_queues = dev->data->nb_rx_queues;
	dev_info->max_tx_queues = dev->data->nb_tx_queues;
	dev_info->min_rx_bufsize = HIF_RX_PKT_MIN_SIZE;
}

/* Only first mb_pool given on first call of this API will be used
 * in whole system, also nb_rx_desc and rx_conf are unused params
 */
static int pfe_rx_queue_setup(struct rte_eth_dev *dev, uint16_t queue_idx,
		__rte_unused uint16_t nb_rx_desc,
		__rte_unused unsigned int socket_id,
		__rte_unused const struct rte_eth_rxconf *rx_conf,
		struct rte_mempool *mb_pool)
{
	int rc = 0;
	struct pfe *pfe;
	struct pfe_eth_priv_s *priv = dev->data->dev_private;

	pfe = priv->pfe;

	if (queue_idx >= EMAC_RXQ_CNT) {
		PFE_PMD_ERR("Invalid queue idx = %d, Max queues = %d",
				queue_idx, EMAC_RXQ_CNT);
		return -1;
	}

	if (!pfe->hif.setuped) {
		rc = pfe_hif_shm_init(pfe->hif.shm, mb_pool);
		if (rc) {
			PFE_PMD_ERR("Could not allocate buffer descriptors");
			return -1;
		}

		pfe->hif.shm->pool = mb_pool;
		if (pfe_hif_init_buffers(&pfe->hif)) {
			PFE_PMD_ERR("Could not initialize buffer descriptors");
			return -1;
		}
		hif_init();
		hif_rx_enable();
		hif_tx_enable();
		pfe->hif.setuped = 1;
	}
	dev->data->rx_queues[queue_idx] = &priv->client.rx_q[queue_idx];
	priv->client.rx_q[queue_idx].queue_id = queue_idx;

	return 0;
}

static void
pfe_rx_queue_release(void *q __rte_unused)
{
	PMD_INIT_FUNC_TRACE();
}

static void
pfe_tx_queue_release(void *q __rte_unused)
{
	PMD_INIT_FUNC_TRACE();
}

static int
pfe_tx_queue_setup(struct rte_eth_dev *dev,
		   uint16_t queue_idx,
		   __rte_unused uint16_t nb_desc,
		   __rte_unused unsigned int socket_id,
		   __rte_unused const struct rte_eth_txconf *tx_conf)
{
	struct pfe_eth_priv_s *priv = dev->data->dev_private;

	if (queue_idx >= emac_txq_cnt) {
		PFE_PMD_ERR("Invalid queue idx = %d, Max queues = %d",
				queue_idx, emac_txq_cnt);
		return -1;
	}
	dev->data->tx_queues[queue_idx] = &priv->client.tx_q[queue_idx];
	priv->client.tx_q[queue_idx].queue_id = queue_idx;
	return 0;
}

static const uint32_t *
pfe_supported_ptypes_get(struct rte_eth_dev *dev)
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
		RTE_PTYPE_L4_SCTP
	};

	if (dev->rx_pkt_burst == pfe_recv_pkts)
		return ptypes;
	return NULL;
}

static int pfe_eth_link_update(struct rte_eth_dev *dev,
				int wait_to_complete __rte_unused)
{
	struct rte_eth_link *link = &dev->data->dev_link;


	link->link_speed = 1000;

	link->link_status = 1;
	link->link_duplex = ETH_LINK_FULL_DUPLEX;
	link->link_autoneg = ETH_LINK_AUTONEG;
	return 0;
}

static void
pfe_promiscuous_enable(struct rte_eth_dev *dev)
{
	struct pfe_eth_priv_s *priv = dev->data->dev_private;

	priv->promisc = 1;
	dev->data->promiscuous = 1;
	gemac_enable_copy_all(priv->EMAC_baseaddr);
}

static void
pfe_promiscuous_disable(struct rte_eth_dev *dev)
{
	struct pfe_eth_priv_s *priv = dev->data->dev_private;

	priv->promisc = 0;
	dev->data->promiscuous = 0;
	gemac_disable_copy_all(priv->EMAC_baseaddr);
}

static void
pfe_allmulticast_enable(struct rte_eth_dev *dev)
{
	struct pfe_eth_priv_s *priv = dev->data->dev_private;
	struct pfe_mac_addr    hash_addr; /* hash register structure */

	/* Set the hash to rx all multicast frames */
	hash_addr.bottom = 0xFFFFFFFF;
	hash_addr.top = 0xFFFFFFFF;
	gemac_set_hash(priv->EMAC_baseaddr, &hash_addr);
	dev->data->all_multicast = 1;
}

static void
pfe_allmulticast_disable(__rte_unused struct rte_eth_dev *dev)
{
}

static int pfe_link_down(struct rte_eth_dev *dev)
{
	pfe_eth_stop(dev);
	return 0;
}

static int pfe_link_up(struct rte_eth_dev *dev)
{
	struct pfe_eth_priv_s *priv = dev->data->dev_private;

	pfe_eth_start(priv);
	return 0;
}

static int
pfe_mtu_set(struct rte_eth_dev *dev, uint16_t mtu)
{
	int ret;
	struct pfe_eth_priv_s *priv = dev->data->dev_private;
	uint16_t frame_size = mtu + ETHER_HDR_LEN + ETHER_CRC_LEN;

	/*TODO Support VLAN*/
	ret = gemac_set_rx(priv->EMAC_baseaddr, frame_size);
	if (!ret) {
		dev->data->mtu = mtu;
	}

	return ret;
}

/* pfe_eth_enet_addr_byte_mac
 */
static int pfe_eth_enet_addr_byte_mac(u8 *enet_byte_addr,
			       struct pfe_mac_addr *enet_addr)
{
	if (!enet_byte_addr || !enet_addr) {
		return -1;

	} else {
		enet_addr->bottom = enet_byte_addr[0] |
			(enet_byte_addr[1] << 8) |
			(enet_byte_addr[2] << 16) |
			(enet_byte_addr[3] << 24);
		enet_addr->top = enet_byte_addr[4] |
			(enet_byte_addr[5] << 8);
		return 0;
	}
}


static int
pfe_dev_add_mac_addr(struct rte_eth_dev *dev,
			     struct ether_addr *addr,
			     uint32_t index,
			     __rte_unused uint32_t pool)
{
	struct pfe_eth_priv_s *priv = dev->data->dev_private;
	struct pfe_mac_addr spec_addr;

	pfe_eth_enet_addr_byte_mac(addr->addr_bytes, &spec_addr);
	gemac_set_laddrN(priv->EMAC_baseaddr,
			 (struct pfe_mac_addr *)&spec_addr, index);
	/*TODO first allocate memory to dev->data->mac_addrs during init*/
	//ether_addr_copy(&addr->addr_bytes, &dev->data->mac_addrs[index]);
	return 0;
}

static void
pfe_dev_set_mac_addr(struct rte_eth_dev *dev,
		       struct ether_addr *addr)
{
	struct pfe_eth_priv_s *priv = dev->data->dev_private;
	struct pfe_mac_addr spec_addr;

	pfe_eth_enet_addr_byte_mac(addr->addr_bytes, &spec_addr);
	gemac_set_laddrN(priv->EMAC_baseaddr,
			 (struct pfe_mac_addr *)&spec_addr, 1);
	ether_addr_copy(addr, &dev->data->mac_addrs[0]);
}

static
int pfe_stats_get(struct rte_eth_dev *dev,
			 struct rte_eth_stats *stats)
{
	struct pfe_eth_priv_s *priv = dev->data->dev_private;
	struct rte_eth_stats *eth_stats = &priv->stats;

	if (stats == NULL)
		return -1;

	memset(stats, 0, sizeof(struct rte_eth_stats));

	stats->ipackets = eth_stats->ipackets;
	stats->ibytes = eth_stats->ibytes;
	stats->opackets = eth_stats->opackets;
	stats->obytes = eth_stats->obytes;

	return 0;
}


static const struct eth_dev_ops ops = {
	.dev_start = pfe_eth_open,
	.dev_stop = pfe_eth_stop,
	.dev_close = pfe_eth_close,
	.dev_configure = pfe_eth_configure,
	.dev_infos_get = pfe_eth_info,
	.rx_queue_setup = pfe_rx_queue_setup,
	.rx_queue_release  = pfe_rx_queue_release,
	.tx_queue_setup = pfe_tx_queue_setup,
	.tx_queue_release  = pfe_tx_queue_release,
	.dev_supported_ptypes_get = pfe_supported_ptypes_get,
	.link_update  = pfe_eth_link_update,
	.promiscuous_enable   = pfe_promiscuous_enable,
	.promiscuous_disable  = pfe_promiscuous_disable,
	.allmulticast_enable  = pfe_allmulticast_enable,
	.allmulticast_disable = pfe_allmulticast_disable,
	.dev_set_link_down    = pfe_link_down,
	.dev_set_link_up      = pfe_link_up,
	.mtu_set              = pfe_mtu_set,
	.mac_addr_set	      = pfe_dev_set_mac_addr,
	.mac_addr_add	      = pfe_dev_add_mac_addr,
	.stats_get            = pfe_stats_get,
};

/* pfe_eth_exit
 */
static void
pfe_eth_exit(struct rte_eth_dev *dev, struct pfe *pfe)
{
	PMD_INIT_FUNC_TRACE();

	rte_eth_dev_release_port(dev);
	pfe->nb_devs--;
}

/* pfe_eth_init_one
 */
static int pfe_eth_init(struct rte_vdev_device *vdev, struct pfe *pfe, int id)
{
	struct rte_eth_dev_data *data = NULL;
	struct rte_eth_dev *eth_dev = NULL;
	struct pfe_eth_priv_s *priv = NULL;
	struct ls1012a_eth_platform_data *einfo;
	struct ls1012a_pfe_platform_data *pfe_info;
	struct ether_addr addr;
	int err;

	if (id >= pfe->max_intf) {
		PFE_PMD_ERR("Requested intf (gemid) %d not supported Max is %d",
			id, pfe->max_intf);
		return -EINVAL;
	}

	data = rte_zmalloc(NULL, sizeof(*data), 64);
	if (data == NULL)
		return -ENOMEM;

	/* reserve an ethdev entry */
	eth_dev = rte_eth_vdev_allocate(vdev, sizeof(*priv));
	if (eth_dev == NULL) {
		rte_free(data);
		return -ENOMEM;
	}
	/* Extract pltform data */
	pfe_info = (struct ls1012a_pfe_platform_data *)&pfe->platform_data;
	if (!pfe_info) {
		PFE_PMD_ERR("pfe missing additional platform data");
		err = -ENODEV;
		goto err0;
	}

	einfo = (struct ls1012a_eth_platform_data *)pfe_info->ls1012a_eth_pdata;

	/* einfo never be NULL, but no harm in having this check */
	if (!einfo) {
		PFE_PMD_ERR("pfe missing additional gemacs platform data");
		err = -ENODEV;
		goto err0;
	}

	priv = eth_dev->data->dev_private;
	rte_memcpy(data, eth_dev->data, sizeof(*data));

	priv->ndev = eth_dev;
	priv->id = einfo[id].gem_id;
	priv->pfe = pfe;

	pfe->eth.eth_priv[id] = priv;

	/* Set the info in the priv to the current info */
	priv->einfo = &einfo[id];
	priv->EMAC_baseaddr = cbus_emac_base[id];
	priv->PHY_baseaddr = cbus_emac_base[id];
	priv->GPI_baseaddr = cbus_gpi_base[id];

#define HIF_GEMAC_TMUQ_BASE	6
	priv->low_tmu_q = HIF_GEMAC_TMUQ_BASE + (id * 2);
	priv->high_tmu_q = priv->low_tmu_q + 1;

	rte_spinlock_init(&priv->lock);

	/* Copy the station address into the dev structure, */
	eth_dev->data->mac_addrs = rte_zmalloc("mac_addr",
			ETHER_ADDR_LEN * PPFE_MAX_MACS, 0);
	if (eth_dev->data->mac_addrs == NULL) {
		PFE_PMD_ERR("Failed to allocate mem %d to store MAC addresses",
			ETHER_ADDR_LEN * PPFE_MAX_MACS);
		err = -ENOMEM;
		goto err0;
	}

	memcpy(addr.addr_bytes, priv->einfo->mac_addr,
		       ETH_ALEN);

	pfe_dev_set_mac_addr(eth_dev, &addr);
	ether_addr_copy(&addr, &eth_dev->data->mac_addrs[0]);

	eth_dev->data->mtu = 1500;
	eth_dev->dev_ops = &ops;
	pfe_eth_stop(eth_dev);
	pfe_gemac_init(priv);

	eth_dev->data->nb_rx_queues = 1;
	eth_dev->data->nb_tx_queues = 1;

	return 0;
err0:
	rte_free(data);
	return err;
}

static int pfe_get_gemac_if_proprties(struct pfe *pfe,
		__rte_unused const struct device_node *parent,
		unsigned int port, unsigned int if_cnt,
		struct ls1012a_pfe_platform_data *pdata)
{
	const struct device_node *gem = NULL, *phy = NULL;
	size_t size;
	unsigned int ii = 0, phy_id = 0;
	const u32 *addr;
	const void *mac_addr;

	for (ii = 0; ii < if_cnt; ii++) {
		gem = of_get_next_child(parent, gem);
		if (!gem)
			goto err;
		addr = of_get_property(gem, "reg", &size);
		if (addr && (rte_be_to_cpu_32((unsigned int)*addr) == port))
			break;
	}

	if (ii >= if_cnt) {
		PFE_PMD_ERR("Failed to find interface = %d", if_cnt);
		goto err;
	}

	pdata->ls1012a_eth_pdata[port].gem_id = port;

	mac_addr = of_get_mac_address(gem);

	if (mac_addr) {
		memcpy(pdata->ls1012a_eth_pdata[port].mac_addr, mac_addr,
		       ETH_ALEN);
	}

	addr = of_get_property(gem, "fsl,gemac-bus-id", &size);
	if (!addr)
		PFE_PMD_ERR("Invalid gemac-bus-id....");
	else
		pdata->ls1012a_eth_pdata[port].bus_id =
			rte_be_to_cpu_32((unsigned int)*addr);

	addr = of_get_property(gem, "fsl,gemac-phy-id", &size);
	if (!addr) {
		PFE_PMD_ERR("Invalid gemac-phy-id....");
	} else {
		phy_id = rte_be_to_cpu_32((unsigned int)*addr);
		pdata->ls1012a_eth_pdata[port].phy_id = phy_id;
		pdata->ls1012a_mdio_pdata[0].phy_mask &= ~(1 << phy_id);
	}

	addr = of_get_property(gem, "fsl,mdio-mux-val", &size);
	if (!addr) {
		PFE_PMD_ERR("Invalid mdio-mux-val....");
	} else {
		phy_id = rte_be_to_cpu_32((unsigned int)*addr);
		pdata->ls1012a_eth_pdata[port].mdio_muxval = phy_id;
	}
	if (pdata->ls1012a_eth_pdata[port].phy_id < 32)
		pfe->mdio_muxval[pdata->ls1012a_eth_pdata[port].phy_id] =
			 pdata->ls1012a_eth_pdata[port].mdio_muxval;

	addr = of_get_property(gem, "fsl,pfe-phy-if-flags", &size);
	if (!addr)
		PFE_PMD_ERR("Invalid pfe-phy-if-flags....");
	else
		pdata->ls1012a_eth_pdata[port].phy_flags =
			rte_be_to_cpu_32((unsigned int)*addr);

	/* If PHY is enabled, read mdio properties */
	if (pdata->ls1012a_eth_pdata[port].phy_flags & GEMAC_NO_PHY)
		goto done;

	phy = of_get_next_child(gem, NULL);

	addr = of_get_property(phy, "reg", &size);

	if (!addr)
		PFE_PMD_ERR("Invalid phy enable flag....");
	else
		pdata->ls1012a_mdio_pdata[port].enabled =
				rte_be_to_cpu_32((unsigned int)*addr);

done:

	return 0;

err:
	return -1;
}

/* Parse integer from integer argument */
static int
parse_integer_arg(const char *key __rte_unused,
		const char *value, void *extra_args)
{
	int *i = (int *)extra_args;

	*i = atoi(value);
	if (*i < 0) {
		PFE_PMD_ERR("argument has to be positive.");
		return -1;
	}

	return 0;
}

static int
pfe_parse_vdev_init_params(struct pfe_vdev_init_params *params,
				struct rte_vdev_device *dev)
{
	struct rte_kvargs *kvlist = NULL;
	int ret = 0;

	static const char * const pfe_vdev_valid_params[] = {
		PPFE_VDEV_GEM_ID_ARG,
		NULL
	};

	const char *input_args = rte_vdev_device_args(dev);
	if (params == NULL)
		return -EINVAL;


	if (input_args) {
		kvlist = rte_kvargs_parse(input_args, pfe_vdev_valid_params);
		if (kvlist == NULL)
			return -1;

		ret = rte_kvargs_process(kvlist,
					PPFE_VDEV_GEM_ID_ARG,
					&parse_integer_arg,
					&params->gem_id);
		if (ret < 0)
			goto free_kvlist;
	}

free_kvlist:
	rte_kvargs_free(kvlist);
	return ret;
}

static int
pmd_pfe_probe(struct rte_vdev_device *vdev)
{
	const u32 *prop;
	const struct device_node *np;
	const char *name;
	const uint32_t *addr;
	uint64_t cbus_addr, ddr_size, cbus_size;
	int rc = -1, fd = -1, gem_id;
	unsigned int ii, interface_count = 0;
	size_t size = 0;
	struct pfe_vdev_init_params init_params = {
		-1
	};

	name = rte_vdev_device_name(vdev);
	rc = pfe_parse_vdev_init_params(&init_params, vdev);
	if (rc < 0)
		return -EINVAL;

	RTE_LOG(INFO, PMD, "Initializing pmd_pfe for %s Given gem-id %d\n",
		name, init_params.gem_id);

	if (g_pfe) {
		if (g_pfe->nb_devs >= g_pfe->max_intf) {
			PFE_PMD_ERR("PPFE %d dev already created Max is %d",
				g_pfe->nb_devs, g_pfe->max_intf);
			return -EINVAL;
		}
		goto eth_init;
	}

	g_pfe = rte_zmalloc(NULL, sizeof(*g_pfe), 64);
	if (g_pfe == NULL)
		return  -EINVAL;

	/* Load the device-tree driver */
	rc = of_init();
	if (rc) {
		PFE_PMD_ERR("of_init failed with ret: %d", rc);
		goto err;
	}

	np = of_find_compatible_node(NULL, NULL, "fsl,pfe");
	if (!np) {
		PFE_PMD_ERR("Invalid device node");
		rc = -EINVAL;
		goto err;
	}

	addr = of_get_address(np, 0, &cbus_size, NULL);
	if (!addr) {
		PFE_PMD_ERR("of_get_address cannot return qman address\n");
		goto err;
	}
	cbus_addr = of_translate_address(np, addr);
	if (!cbus_addr) {
		PFE_PMD_ERR("of_translate_address failed\n");
		goto err;
	}

	addr = of_get_address(np, 1, &ddr_size, NULL);
	if (!addr) {
		PFE_PMD_ERR("of_get_address cannot return qman address\n");
		goto err;
	}

	g_pfe->ddr_phys_baseaddr = of_translate_address(np, addr);
	if (!g_pfe->ddr_phys_baseaddr) {
		PFE_PMD_ERR("of_translate_address failed\n");
		goto err;
	}

	g_pfe->ddr_baseaddr = pfe_mem_ptov(g_pfe->ddr_phys_baseaddr);
	g_pfe->ddr_size = ddr_size;

	fd = open("/dev/mem", O_RDWR);
	g_pfe->cbus_baseaddr = mmap(NULL, cbus_size, PROT_READ | PROT_WRITE,
					MAP_SHARED, fd, cbus_addr);
	if (g_pfe->cbus_baseaddr == MAP_FAILED) {
		PFE_PMD_ERR("Can not map cbus base");
		rc = -EINVAL;
		goto err;
	}

	/* Read interface count */
	prop = of_get_property(np, "fsl,pfe-num-interfaces", &size);
	if (!prop) {
		PFE_PMD_ERR("Failed to read number of interfaces");
		rc = -ENXIO;
		goto err_prop;
	}

	interface_count = rte_be_to_cpu_32((unsigned int)*prop);
	if (interface_count <= 0) {
		PFE_PMD_ERR("No ethernet interface count : %d",
				interface_count);
		rc = -ENXIO;
		goto err_prop;
	}
	PFE_PMD_INFO("num interfaces = %d ", interface_count);

	g_pfe->max_intf  = interface_count;
	g_pfe->platform_data.ls1012a_mdio_pdata[0].phy_mask = 0xffffffff;

	for (ii = 0; ii < interface_count; ii++) {
		pfe_get_gemac_if_proprties(g_pfe, np, ii, interface_count,
					   &g_pfe->platform_data);
	}

	pfe_lib_init(g_pfe->cbus_baseaddr, g_pfe->ddr_baseaddr,
		     g_pfe->ddr_phys_baseaddr, g_pfe->ddr_size);

	PFE_PMD_INFO("CLASS version: %x", readl(CLASS_VERSION));
	PFE_PMD_INFO("TMU version: %x", readl(TMU_VERSION));

	PFE_PMD_INFO("BMU1 version: %x", readl(BMU1_BASE_ADDR + BMU_VERSION));
	PFE_PMD_INFO("BMU2 version: %x", readl(BMU2_BASE_ADDR + BMU_VERSION));

	PFE_PMD_INFO("EGPI1 version: %x", readl(EGPI1_BASE_ADDR + GPI_VERSION));
	PFE_PMD_INFO("EGPI2 version: %x", readl(EGPI2_BASE_ADDR + GPI_VERSION));
	PFE_PMD_INFO("HGPI version: %x", readl(HGPI_BASE_ADDR + GPI_VERSION));

	PFE_PMD_INFO("HIF version: %x", readl(HIF_VERSION));
	PFE_PMD_INFO("HIF NOPCY version: %x", readl(HIF_NOCPY_VERSION));

	cbus_emac_base[0] = EMAC1_BASE_ADDR;
	cbus_emac_base[1] = EMAC2_BASE_ADDR;

	cbus_gpi_base[0] = EGPI1_BASE_ADDR;
	cbus_gpi_base[1] = EGPI2_BASE_ADDR;

	rc = pfe_hif_lib_init(g_pfe);
	if (rc < 0)
		goto err_hif_lib;

	rc = pfe_hif_init(g_pfe);
	if (rc < 0)
		goto err_hif;
	pfe_soc_version_get();
eth_init:
	if (init_params.gem_id < 0)
		gem_id = g_pfe->nb_devs;
	else
		gem_id = init_params.gem_id;

	RTE_LOG(INFO, PMD, "Init pmd_pfe for %s gem-id %d(given =%d)\n",
		name, gem_id, init_params.gem_id);

	rc = pfe_eth_init(vdev, g_pfe, gem_id);
	if (rc < 0)
		goto err_eth;
	else
		g_pfe->nb_devs++;

	return 0;

err_eth:
	pfe_hif_exit(g_pfe);

err_hif:
	pfe_hif_lib_exit(g_pfe);

err_hif_lib:
err_prop:
err:
	rte_free(g_pfe);
	return rc;
}

static int
pmd_pfe_remove(struct rte_vdev_device *vdev)
{
	const char *name;
	struct rte_eth_dev *eth_dev = NULL;

	name = rte_vdev_device_name(vdev);
	if (name == NULL)
		return -EINVAL;

	PFE_PMD_INFO("Closing eventdev sw device %s", name);

	if (!g_pfe)
		return 0;

	eth_dev = rte_eth_dev_allocated(name);
	if (eth_dev == NULL)
		return -ENODEV;

	pfe_eth_exit(eth_dev, g_pfe);

	if (g_pfe->nb_devs == 0) {
		pfe_hif_exit(g_pfe);
		pfe_hif_lib_exit(g_pfe);
		rte_free(g_pfe);
		g_pfe = NULL;
	}
	return 0;
}

static struct rte_vdev_driver pmd_pfe_drv = {
	.probe = pmd_pfe_probe,
	.remove = pmd_pfe_remove,
};

RTE_PMD_REGISTER_VDEV(PFE_PMD, pmd_pfe_drv);
RTE_PMD_REGISTER_ALIAS(PFE_PMD, eth_pfe);
RTE_PMD_REGISTER_PARAM_STRING(PFE_PMD, "intf=<int> ");
