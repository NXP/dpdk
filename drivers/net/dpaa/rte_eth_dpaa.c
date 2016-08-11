/*-
 *   BSD LICENSE
 *
 *   Copyright (c) 2014 Freescale Semiconductor, Inc. All rights reserved.
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
 *     * Neither the name of  Freescale Semiconductor, Inc nor the names of its
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
#include <stdio.h>
#include <limits.h>

#include <rte_config.h>
#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_interrupts.h>
#include <rte_log.h>
#include <rte_debug.h>
#include <rte_pci.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_tailq.h>
#include <rte_eal.h>
#include <rte_alarm.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_atomic.h>
#include <rte_malloc.h>
#include <rte_ring.h>

#include "rte_eth_dpaa.h"
#include "dpaa_logs.h"

/* #define DPAAETHDRV_DEBUG  1 */

#define FSL_VENDOR_ID		0x1957
#define FSL_DEVICE_ID		0x410	 /* custom */
#define FSL_FMAN_ETH_CLASS	0x020000 /* ethernet */
#define FSL_SUBSYSTEM_VENDOR	0
#define FSL_SUBSYSTEM_DEVICE	0

#define FSL_USDPAA_DOMAIN	2
#define FSL_USDPAA_BUSID	16
#define FSL_USDPAA_FUNC		0
#define USDPAA_DRV_NAME		"usdpaa_pci_driver"

#define FSL_USDPAA_MAX_RXS	8
#define FSL_USDPAA_MAX_TXS	RTE_MAX_LCORE

#define DPAA_MIN_RX_BUF_SIZE 512
#define DPAA_MAX_RX_PKT_LEN  9600 /* FMAN support*/

#define DPAA_RSS_OFFLOAD_ALL ( \
	ETH_RSS_FRAG_IPV4 | \
	ETH_RSS_NONFRAG_IPV4_TCP | \
	ETH_RSS_NONFRAG_IPV4_UDP | \
	ETH_RSS_NONFRAG_IPV4_SCTP | \
	ETH_RSS_FRAG_IPV6 | \
	ETH_RSS_NONFRAG_IPV6_TCP | \
	ETH_RSS_NONFRAG_IPV6_UDP | \
	ETH_RSS_NONFRAG_IPV6_SCTP)

#define QBMAN_MULTI_TX

static int usdpaa_pci_devinit(struct rte_pci_driver *,
			      struct rte_pci_device *);

static uint16_t usdpaa_eth_tx_drop_all(void *q,
				       struct rte_mbuf **bufs,
			uint16_t nb_bufs);

static struct rte_pci_id usdpaa_pci_id[2] = {
	{0, FSL_VENDOR_ID, FSL_DEVICE_ID, FSL_SUBSYSTEM_VENDOR,
		FSL_SUBSYSTEM_DEVICE},
	{0, 0, 0, 0}
};

static struct rte_pci_driver usdpaa_pci_driver = {
	.name = USDPAA_DRV_NAME,
	.id_table = usdpaa_pci_id,
	.devinit = usdpaa_pci_devinit
};

#define PCI_DEV_ADDR(dev) \
		((dev->addr.domain << 24) | (dev->addr.bus << 16) | \
		 (dev->addr.devid << 8) | (dev->addr.function))

static int
usdpaa_eth_dev_configure(struct rte_eth_dev *dev __rte_unused)
{
	return 0;
}

static const uint32_t *
usdpaa_supported_ptypes_get(struct rte_eth_dev *dev)
{
	static const uint32_t ptypes[] = {
		/*todo -= add more types */
		RTE_PTYPE_L2_ETHER,
		RTE_PTYPE_L3_IPV4,
		RTE_PTYPE_L3_IPV6,
		RTE_PTYPE_L3_IPV6_EXT,
		RTE_PTYPE_L4_TCP,
		RTE_PTYPE_L4_UDP,
		RTE_PTYPE_L4_SCTP
	};

	if (dev->rx_pkt_burst == usdpaa_eth_queue_rx)
		return ptypes;
	return NULL;
}

static int usdpaa_eth_dev_start(struct rte_eth_dev *dev)
{
	uint32_t port_id;
	int ret = 0;

	if (!thread_portal_init) {
		ret = usdpaa_portal_init((void *)0);
		if (ret) {
			printf("Failure in affining portal\n");
			return ret;
		}
	}

	port_id = dev->data->port_id;

	/* Change tx callback to the real one */
	dev->tx_pkt_burst = usdpaa_eth_queue_tx;

	usdpaa_port_control(port_id, ENABLE_OP);
	return ret;
}

static void usdpaa_eth_dev_stop(struct rte_eth_dev *dev)
{
	uint32_t port_id;

	port_id = dev->data->port_id;
	usdpaa_port_control(port_id, DISABLE_OP);
	dev->tx_pkt_burst = usdpaa_eth_tx_drop_all;
}

static void usdpaa_eth_dev_close(struct rte_eth_dev *dev)
{
	usdpaa_eth_dev_stop(dev);
}

static void usdpaa_eth_dev_info(struct rte_eth_dev *dev,
				struct rte_eth_dev_info *dev_info)
{
	dev_info->max_rx_queues = usdpaa_get_num_rx_queue(dev->data->port_id);
	dev_info->max_tx_queues = FSL_USDPAA_MAX_TXS/* iface->nb_tx_queues*/;
	dev_info->min_rx_bufsize = DPAA_MIN_RX_BUF_SIZE;
	dev_info->max_rx_pktlen = DPAA_MAX_RX_PKT_LEN;
	dev_info->max_mac_addrs = 0;
	dev_info->max_hash_mac_addrs = 0;
	dev_info->max_vfs = dev->pci_dev->max_vfs;
	dev_info->max_vmdq_pools = ETH_16_POOLS;
	dev_info->flow_type_rss_offloads = DPAA_RSS_OFFLOAD_ALL;
	dev_info->rx_offload_capa =
		(DEV_RX_OFFLOAD_IPV4_CKSUM |
		DEV_RX_OFFLOAD_UDP_CKSUM  |
		DEV_RX_OFFLOAD_TCP_CKSUM);
	dev_info->tx_offload_capa =
		(DEV_TX_OFFLOAD_IPV4_CKSUM  |
		DEV_TX_OFFLOAD_UDP_CKSUM   |
		DEV_TX_OFFLOAD_TCP_CKSUM);
}

static int usdpaa_eth_link_update(struct rte_eth_dev *dev,
				  int wait_to_complete __rte_unused)
{
	struct rte_eth_link *link = &dev->data->dev_link;
	struct usdpaa_eth_link arg;

	usdpaa_get_iface_link(dev->data->port_id, &arg);
	link->link_speed = arg.link_speed;
	link->link_duplex = arg.link_duplex;
	link->link_status = arg.link_status;

	return 0;
}

static void usdpaa_eth_stats_get(struct rte_eth_dev *dev,
				 struct rte_eth_stats *stats)
{
	struct usdpaa_eth_stats mystats;

	usdpaa_get_iface_stats(dev->data->port_id, &mystats);
	stats->ipackets = mystats.ipackets;
	stats->opackets = mystats.opackets;
	stats->ibytes = mystats.ibytes;
	stats->obytes = mystats.obytes;
}

static void usdpaa_eth_stats_reset(struct rte_eth_dev *dev)
{
	printf("%s::needs implementation dev %p\n", __func__, dev);
}

static void usdpaa_eth_promiscuous_enable(struct rte_eth_dev *dev)
{
	uint32_t port_id;

	port_id = dev->data->port_id;
	usdpaa_set_promisc_mode(port_id, ENABLE_OP);
}

static void usdpaa_eth_promiscuous_disable(struct rte_eth_dev *dev)
{
	uint32_t port_id;

	port_id = dev->data->port_id;
	usdpaa_set_promisc_mode(port_id, DISABLE_OP);
}

static uint16_t usdpaa_eth_tx_drop_all(void *q  __rte_unused,
				       struct rte_mbuf **bufs __rte_unused,
				uint16_t nb_bufs __rte_unused)
{
	/* Drop all incoming packets. No need to free packets here
	 * because the rte_eth f/w frees up the packets through tx_buffer
	 * callback in case this functions returns count less than nb_bufs
	 */
	return 0;
}

int usdpaa_eth_rx_queue_setup(struct rte_eth_dev *dev, uint16_t queue_idx,
			      uint16_t nb_desc __rte_unused,
			      unsigned int socket_id __rte_unused,
			      const struct rte_eth_rxconf *rx_conf __rte_unused,
			      struct rte_mempool *mp)
{
	return usdpaa_set_rx_queue(dev->data->port_id, queue_idx,
			     dev->data->rx_queues, mp);
}

void usdpaa_eth_rx_queue_release(void *rxq)
{
	printf("\n(%s) called for 1=%p\n", __func__, rxq);
	return;
}

int usdpaa_eth_tx_queue_setup(struct rte_eth_dev *dev, uint16_t queue_idx,
			      uint16_t nb_desc __rte_unused,
			      unsigned int socket_id __rte_unused,
			      const struct rte_eth_txconf *tx_conf __rte_unused)
{
	return usdpaa_set_tx_queue(dev->data->port_id, queue_idx,
			     dev->data->tx_queues);
}

void usdpaa_eth_tx_queue_release(void *txq)
{
	printf("\n(%s) called for 1=%p\n", __func__, txq);
}

int usdpaa_mtu_set(struct rte_eth_dev *dev __rte_unused,
		   uint16_t mtu __rte_unused)
{
	/* Currently we don't need to set anything specefic
	 * in hardware for MTU (to be checked again). So just return zero in
	 * order to make sure that setting mtu from Applicaiton doesn't return
	 * any error
	 */
	return 0;
}

int usdpaa_link_down(struct rte_eth_dev *dev)
{
	usdpaa_eth_dev_stop(dev);
	return 0;
}

int usdpaa_link_up(struct rte_eth_dev *dev)
{
	usdpaa_eth_dev_start(dev);
	return 0;
}

static int
usdpaa_flow_ctrl_set(struct rte_eth_dev *dev  __rte_unused,
		     struct rte_eth_fc_conf *fc_conf  __rte_unused)
{
	/*TBD:XXX: to be implemented*/
	PMD_DRV_LOG(NOTICE, "%s:: Empty place holder, no action taken\n",
		    __func__);

	return 0;
}

static struct eth_dev_ops usdpaa_devops = {
	.dev_configure		  = usdpaa_eth_dev_configure,
	.dev_start		  = usdpaa_eth_dev_start,
	.dev_stop		  = usdpaa_eth_dev_stop,
	.dev_close		  = usdpaa_eth_dev_close,
	.dev_infos_get		  = usdpaa_eth_dev_info,
	.dev_supported_ptypes_get = usdpaa_supported_ptypes_get,

	.rx_queue_setup		  = usdpaa_eth_rx_queue_setup,
	.tx_queue_setup		  = usdpaa_eth_tx_queue_setup,
	.rx_queue_release	  = usdpaa_eth_rx_queue_release,
	.tx_queue_release	  = usdpaa_eth_tx_queue_release,

	.flow_ctrl_set		  = usdpaa_flow_ctrl_set,

	.link_update		  = usdpaa_eth_link_update,
	.stats_get		  = usdpaa_eth_stats_get,
	.stats_reset		  = usdpaa_eth_stats_reset,
	.promiscuous_enable	  = usdpaa_eth_promiscuous_enable,
	.promiscuous_disable	  = usdpaa_eth_promiscuous_disable,
	.mtu_set		  = usdpaa_mtu_set,
	.dev_set_link_down	  = usdpaa_link_down,
	.dev_set_link_up	  = usdpaa_link_up,
};

static int usdpaa_pci_devinit(struct rte_pci_driver *pci_drv __rte_unused,
			      struct rte_pci_device *pci_dev)
{
	struct rte_eth_dev *ethdev;
	char devname[MAX_ETHDEV_NAME];
	char *mac_addr;

	PMD_DRV_LOG(DEBUG, "%s::drv %p, dev %p\n", __func__, pci_drv, pci_dev);

	/* alloc ethdev entry */
	sprintf(devname, "%s%d\n", ETHDEV_NAME_PREFIX, pci_dev->addr.devid);
	ethdev = rte_eth_dev_allocate(devname, RTE_ETH_DEV_VIRTUAL);
	if (!ethdev) {
		printf("%s::unable to allocate ethdev\n", __func__);
		return -1;
	}

	PMD_DRV_LOG(DEBUG, "%s::allocated eth device port id %d\n", __func__,
		    ethdev->data->port_id);

	ethdev->dev_ops = &usdpaa_devops;
	ethdev->pci_dev = pci_dev;

	/* assign rx and tx ops */
	ethdev->rx_pkt_burst = usdpaa_eth_queue_rx;
	ethdev->tx_pkt_burst = usdpaa_eth_tx_drop_all;

	mac_addr = usdpaa_get_iface_macaddr(ethdev->data->port_id);
	ethdev->data->mac_addrs = (struct ether_addr *)mac_addr;

	return 0;
}

static inline void insert_devices_into_pcilist(struct rte_pci_device *dev)
{
	uint32_t devaddr;
	uint32_t newdevaddr;
	struct rte_pci_device *dev2 = NULL;

	if (!(TAILQ_EMPTY(&pci_device_list))) {
		newdevaddr = PCI_DEV_ADDR(dev);
		TAILQ_FOREACH(dev2, &pci_device_list, next) {
			devaddr = PCI_DEV_ADDR(dev2);

			if (newdevaddr < devaddr) {
				TAILQ_INSERT_BEFORE(dev2, dev, next);
				return;
			}
		}
	}
	TAILQ_INSERT_TAIL(&pci_device_list, dev, next);
}

int add_usdpaa_devices_to_pcilist(int num_ethports)
{
	int ii;
	struct rte_pci_device *dev;

	for (ii = 0; ii < num_ethports; ii++) {
		dev = calloc(1, sizeof(struct rte_pci_device));
		if (!dev) {
			printf("%s::unable to allocate dev for %d\n",
			       __func__, ii);
			return -1;
		}
		dev->addr.domain = FSL_USDPAA_DOMAIN;
		dev->addr.bus = FSL_USDPAA_BUSID;
		dev->addr.devid = ii;
		dev->id.class_id = 0;
		dev->id.vendor_id = FSL_VENDOR_ID;
		dev->id.device_id = FSL_DEVICE_ID;
		dev->id.subsystem_vendor_id = FSL_SUBSYSTEM_VENDOR;
		dev->id.subsystem_device_id = FSL_SUBSYSTEM_DEVICE;
		dev->numa_node = 0;

		/* device is valid, add in list (sorted) */
		insert_devices_into_pcilist(dev);
	}
	printf("%s::%d devices added to pci list\n", __func__, ii);
	rte_eal_pci_register(&usdpaa_pci_driver);

	return 0;
}
