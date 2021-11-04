// SPDX-License-Identifier: BSD-3-Clause
/* Copyright 2020-2021 NXP  */

#include <time.h>
#include <net/if.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <stdarg.h>
#include <inttypes.h>
#include <rte_byteorder.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/queue.h>
#include <pthread.h>
#include <fcntl.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <signal.h>
#include <stdbool.h>

#include <rte_common.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_string_fns.h>
#include <rte_cycles.h>
#include <rte_kvargs.h>
#include <rte_dev.h>

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
#include <rte_ethdev_pci.h>
#include <rte_tcp.h>
#include <rte_atomic.h>
#include <rte_errno.h>
#include <rte_version.h>
#include <rte_eal_memconfig.h>
#include <rte_net.h>
#include <rte_bus_vdev.h>
#include <rte_ethdev_vdev.h>
#include <rte_fslmc.h>

#include <dpaa2_hw_pvt.h>
#include <rte_lsx_pciep_bus.h>

#include "lsxinic_common_pmd.h"
#include "lsxinic_common_helper.h"
#include "lsxinic_vio.h"
#include "lsxinic_vio_common.h"
#include "lsxinic_vio_net.h"
#include "lsxinic_vio_rxtx.h"
#include "lsxinic_ep_dma.h"
#include "lsxinic_ep_tool.h"

static int lsxvio_dev_configure(struct rte_eth_dev *dev);
static int lsxvio_dev_start(struct rte_eth_dev *dev);
static void lsxvio_dev_stop(struct rte_eth_dev *dev);
static void lsxvio_dev_close(struct rte_eth_dev *dev);
static void lsxvio_dev_reset(struct rte_eth_dev *dev);
static int
lsxvio_dev_info_get(struct rte_eth_dev *dev,
	struct rte_eth_dev_info *dev_info);

static int lsxvio_dev_mtu_set(struct rte_eth_dev *dev, uint16_t mtu);

static int
lsxvio_dev_link_update(struct rte_eth_dev *dev,
	int wait_to_complete);

static int lsxvio_dev_promiscuous_enable(struct rte_eth_dev *dev);
static int lsxvio_dev_promiscuous_disable(struct rte_eth_dev *dev);
static int lsxvio_dev_allmulticast_enable(struct rte_eth_dev *dev);
static int lsxvio_dev_allmulticast_disable(struct rte_eth_dev *dev);
static int
lsxvio_dev_stats_get(struct rte_eth_dev *dev,
	struct rte_eth_stats *stats);

static int lsxvio_dev_stats_reset(struct rte_eth_dev *dev);
static int is_valid_ether_addr(uint8_t *addr);

static const struct rte_eth_desc_lim rx_desc_lim = {
	.nb_max = LSINIC_BD_ENTRY_COUNT,
	.nb_min = LSINIC_BD_ENTRY_COUNT,
	.nb_align = 8,
};

static const struct rte_eth_desc_lim tx_desc_lim = {
	.nb_max = LSINIC_BD_ENTRY_COUNT,
	.nb_min = LSINIC_BD_ENTRY_COUNT,
	.nb_align = 8,
};

static int
is_valid_ether_addr(uint8_t *addr)
{
	const char zaddr[6] = { 0, };

	return !(addr[0] & 1) && memcmp(addr, zaddr, 6);
}

static struct eth_dev_ops lsxvio_eth_dev_ops = {
	.dev_configure        = lsxvio_dev_configure,
	.dev_start            = lsxvio_dev_start,
	.dev_stop             = lsxvio_dev_stop,
	.dev_close            = lsxvio_dev_close,
	.dev_infos_get        = lsxvio_dev_info_get,
	.mtu_set	      = lsxvio_dev_mtu_set,
	.rx_queue_setup       = lsxvio_dev_rx_queue_setup,
	.rx_queue_release     = lsxvio_dev_rx_queue_release,
	.tx_queue_setup       = lsxvio_dev_tx_queue_setup,
	.tx_queue_release     = lsxvio_dev_tx_queue_release,
	.link_update          = lsxvio_dev_link_update,
	.promiscuous_enable   = lsxvio_dev_promiscuous_enable,
	.promiscuous_disable  = lsxvio_dev_promiscuous_disable,
	.allmulticast_enable  = lsxvio_dev_allmulticast_enable,
	.allmulticast_disable = lsxvio_dev_allmulticast_disable,
	.stats_get            = lsxvio_dev_stats_get,
	.stats_reset          = lsxvio_dev_stats_reset,
};

static int
lsxvio_init_bar_addr(struct rte_lsx_pciep_device *lsx_dev)
{
	struct rte_eth_dev *eth_dev = lsx_dev->eth_dev;
	struct lsxvio_adapter *adapter = (struct lsxvio_adapter *)
		eth_dev->data->dev_private;
	uint16_t device_id;
	enum lsx_pcie_pf_idx pf_idx = lsx_dev->pf;

	adapter->lsx_dev = lsx_dev;
	/* Get queue config.*/

	lsx_pciep_set_ib_win(lsx_dev,
		LSXVIO_CONFIG_BAR_IDX,
		LSXVIO_CONFIG_BAR_MAX_SIZE);
	lsx_pciep_set_ib_win(lsx_dev,
		LSXVIO_RING_BAR_IDX,
		LSXVIO_RING_BAR_MAX_SIZE);

	adapter->cfg_base =
		(uint64_t)lsx_dev->virt_addr[LSXVIO_CONFIG_BAR_IDX];
	adapter->ring_base =
		(uint64_t)lsx_dev->virt_addr[LSXVIO_RING_BAR_IDX];
	adapter->ob_base = lsx_dev->ob_phy_base;
	adapter->ob_virt_base = (uint8_t *)lsx_dev->ob_virt_base;
	adapter->pf_idx = lsx_dev->pf;
	adapter->is_vf = lsx_dev->is_vf;
	if (lsx_dev->is_vf)
		adapter->vf_idx = lsx_dev->vf;
	adapter->pcie_idx = lsx_dev->pcie_id;
	adapter->num_queues = 0;
	adapter->num_descs = LSXVIO_MAX_RING_DESC;
#if (LSX_VIRTIO_NET_FEATURES & (1ULL << VIRTIO_F_VERSION_1))
	adapter->vtnet_hdr_size = sizeof(struct virtio_net_hdr_mrg_rxbuf);
#else
	adapter->vtnet_hdr_size = sizeof(struct virtio_net_hdr);
#endif
	device_id = lsx_pciep_ctl_get_device_id(lsx_dev->pcie_id, pf_idx);
	lsxvio_virtio_init(adapter->cfg_base, device_id);

	return 0;
}

static int
lsxvio_uninit_bar_addr(struct rte_lsx_pciep_device *lsx_dev)
{
	struct rte_eth_dev *eth_dev = lsx_dev->eth_dev;
	struct lsxvio_adapter *adapter = (struct lsxvio_adapter *)
		eth_dev->data->dev_private;

	adapter->cfg_base = 0;
	adapter->ring_base = 0;
	adapter->pf_idx = 0;
	adapter->is_vf = 0;
	adapter->vf_idx = 0;
	adapter->pcie_idx = 0;

	return 0;
}

static void
lsxvio_child_mac_init(struct lsxvio_adapter *adapter)
{
	int pf_idx = adapter->pf_idx;
	int vf_idx = adapter->vf_idx;
	int is_vf = adapter->is_vf;

	/* 00:e0:0c:fm_idx-mac_idx:mac_type-PF index: VF index */
	adapter->mac_addr[0] = 0x00;
	adapter->mac_addr[1] = 0xe0;
	adapter->mac_addr[2] = 0x0c;
	adapter->mac_addr[3] = pf_idx + 1;
	adapter->mac_addr[4] = is_vf;
	adapter->mac_addr[5] = vf_idx;

	adapter->port_mac_addr[0] = 0x00;
	adapter->port_mac_addr[1] = 0x00;
	adapter->port_mac_addr[2] = 0x00;
	adapter->port_mac_addr[3] = pf_idx + 1;
	adapter->port_mac_addr[4] = is_vf;
	adapter->port_mac_addr[5] = vf_idx;
}

static inline unsigned long ilog2(unsigned long n)
{
	unsigned int e = 0;

	while (n) {
		if (n & ~((1 << 8) - 1)) {
			e += 8;
			n >>= 8;
			continue;
		}

		if (n & ~((1 << 4) - 1)) {
			e += 4;
			n >>= 4;
		}

		for (;;) {
			n >>= 1;
			if (n == 0)
				break;
			e++;
		}
	}

	return e;
}

static void
lsxvio_netdev_reg_init(struct lsxvio_adapter *adapter)
{
	/* initialize mac addr */
	lsxvio_child_mac_init(adapter);
}

/* rte_lsxvio_probe:
 *
 * Interrupt is used only for link status notification on dpdk.
 * we don't think about the interrupt handlle situation right now.
 * we can port our MSIX interrupt in iNIC host driver to dpdk,
 * need to test the performance.
 */

static int
rte_lsxvio_probe(struct rte_lsx_pciep_driver *lsx_drv,
	struct rte_lsx_pciep_device *lsx_dev)
{
	struct rte_eth_dev *eth_dev = NULL;
	struct lsxvio_adapter *adapter = NULL;
	uint16_t device_id, class_id;
	int ret, rbp;
	char env_name[128];

	device_id = VIRTIO_ID_DEVICE_ID_BASE + VIRTIO_ID_NETWORK;
	class_id = PCI_CLASS_NETWORK_ETHERNET;
	sprintf(env_name, "LSINIC_PCIE%d_PF%d_VIO_STORAGE",
		lsx_dev->pcie_id, lsx_dev->pf);
	if (getenv(env_name)) {
		device_id = VIRTIO_ID_DEVICE_ID_BASE + VIRTIO_ID_BLOCK;
		class_id = PCI_CLASS_STORAGE_SCSI;
	}

	if (lsx_dev->init_flag) {
		LSXINIC_PMD_ERR("pf:%d vf:%d has been initialized!",
			lsx_dev->pf, lsx_dev->vf);
		return 0;
	}

	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
		eth_dev = rte_eth_dev_allocate(lsx_dev->device.name);
		if (!eth_dev) {
			LSXINIC_PMD_ERR("Cannot allocate eth_dev");
			return -ENODEV;
		}
		LSXINIC_PMD_INFO("Create eth_dev %s",
			lsx_dev->device.name);

		adapter = rte_zmalloc("ethdev private netdev_adapter",
					sizeof(struct lsxvio_adapter),
					RTE_CACHE_LINE_SIZE);
		if (!adapter) {
			LSXINIC_PMD_ERR("Cannot allocate memzone for priv");
			rte_eth_dev_release_port(eth_dev);
			return -ENOMEM;
		}
		eth_dev->data->dev_private = adapter;
	} else {
		eth_dev = rte_eth_dev_attach_secondary(lsx_dev->device.name);
		if (!eth_dev)
			return -ENODEV;

		adapter = eth_dev->data->dev_private;
	}

	if (!lsx_dev->is_vf) {
		ret = lsx_pciep_ctl_dev_set(VIRTIO_PCI_VENDORID,
			device_id, class_id,
			lsx_dev->pcie_id, lsx_dev->pf);
		if (ret)
			return ret;
	}

	eth_dev->device = &lsx_dev->device;
	eth_dev->device->driver = &lsx_drv->driver;
	lsx_dev->driver = lsx_drv;
	lsx_dev->eth_dev = eth_dev;
	lsx_dev->chk_eth_status = lsxvio_dev_chk_eth_status;
	eth_dev->data->rx_mbuf_alloc_failed = 0;

	eth_dev->dev_ops = &lsxvio_eth_dev_ops;
	eth_dev->rx_pkt_burst = &lsxvio_recv_pkts;
	eth_dev->tx_pkt_burst = &lsxvio_xmit_pkts;

	lsxvio_init_bar_addr(lsx_dev);
	if (lsx_pciep_hw_sim_get(lsx_dev->pcie_id) &&
		!lsx_dev->is_vf) {
		lsx_pciep_sim_dev_map_inbound(lsx_dev);
	}
	lsxvio_netdev_reg_init(adapter);

	adapter->qdma_dev_id = lsinic_dma_init();
	if (adapter->qdma_dev_id < 0)
		return -ENODEV;

	rbp = lsx_pciep_hw_rbp_get(lsx_dev->pcie_id);
	if (rbp)
		adapter->rbp_enable = 1;
	else
		adapter->rbp_enable = 0;

	if (!is_valid_ether_addr(adapter->mac_addr)) {
		LSXINIC_PMD_ERR("Invalid MAC address");
		return -EINVAL;
	}

	/* Allocate memory for storing MAC addresses */
	eth_dev->data->mac_addrs =
		rte_zmalloc("lsx", RTE_ETHER_ADDR_LEN, 0);
	if (!eth_dev->data->mac_addrs) {
		LSXINIC_PMD_ERR("Failed to allocate mac addr mem");
		return -ENOMEM;
	}
	/* Copy the permanent MAC address */
	rte_ether_addr_copy((struct rte_ether_addr *)adapter->port_mac_addr,
		&eth_dev->data->mac_addrs[0]);

	lsx_dev->init_flag = 1;
	rte_eth_dev_probing_finish(eth_dev);
	return 0;
}

int
lsxvio_dev_chk_eth_status(struct rte_eth_dev *dev)
{
	struct lsxvio_adapter *adapter = dev->data->dev_private;

	if (adapter->status & VIRTIO_CONFIG_STATUS_DRIVER_OK)
		return 1;

	return 0;
}

#define DEBUG_PRINT_INTERVAL 4
#define	LSX_CMD_POLLING_INTERVAL 2

static void lsxvio_print_ep_status(void)
{
	static int debug_interval;
	struct rte_lsx_pciep_device *dev;
	struct rte_eth_dev *eth_dev;
	struct lsxvio_adapter *adapter;
	uint64_t core_mask = 0;

	if (debug_interval < DEBUG_PRINT_INTERVAL) {
		debug_interval++;
		return;
	}

	debug_interval = 0;
	dev = lsx_pciep_first_dev();

	while (dev) {
		eth_dev = dev->eth_dev;
		adapter = eth_dev->data->dev_private;

		if (!(adapter->status & VIRTIO_CONFIG_STATUS_DRIVER_OK))
			continue;

		printf("\n\nPF%d", dev->pf);
		if (dev->vf >= 0)
			printf("-VF%d", dev->vf);
		printf("-Port%d -- statistics:\n", eth_dev->data->port_id);

		print_port_status(eth_dev, &core_mask,
			(DEBUG_PRINT_INTERVAL + 1) * LSX_CMD_POLLING_INTERVAL,
			1, 1);

		printf("\r\n\r\n");
		dev = (struct rte_lsx_pciep_device *)TAILQ_NEXT(dev, next);
	}
}

static void *lsxvio_poll_dev(void *arg __rte_unused)
{
	struct rte_lsx_pciep_device *dev;
	struct lsxvio_adapter *adapter;
	struct lsxvio_common_cfg *common;
	uint8_t status;
	char *penv = getenv("LSINIC_EP_PRINT_STATUS");
	int print_status = 0;

	if (penv)
		print_status = atoi(penv);

	while (1) {
		dev = lsx_pciep_first_dev();
		while (dev) {
			adapter = dev->eth_dev->data->dev_private;
			common = BASE_TO_COMMON(adapter->cfg_base);
			status = common->device_status;

			if (status == adapter->status) {
				dev = (struct rte_lsx_pciep_device *)TAILQ_NEXT(dev, next);
				continue;
			}

			if (status == VIRTIO_CONFIG_STATUS_SEND_RESET) {
				if (adapter->status
					& VIRTIO_CONFIG_STATUS_DRIVER_OK) {
					if (adapter->is_vf)
						LSXINIC_PMD_INFO("pcie%d:pf%d:vf:%d link down",
							adapter->pcie_idx,
							adapter->pf_idx,
							adapter->vf_idx);
					else
						LSXINIC_PMD_INFO("pcie%d:pf%d link down",
							adapter->pcie_idx,
							adapter->pf_idx);
				}
				lsxvio_dev_reset(dev->eth_dev);
				dev = (struct rte_lsx_pciep_device *)TAILQ_NEXT(dev, next);
				continue;
			}

			if ((adapter->status &
				VIRTIO_CONFIG_STATUS_DRIVER_OK) &&
				(status & VIRTIO_CONFIG_STATUS_NEEDS_RESET)) {
				/* Wait for the driver to reset the device*/
				lsx_pciep_msix_cmd_send(adapter->msix_cfg_addr,
					adapter->msix_cfg_cmd);
			}

			if (status & VIRTIO_CONFIG_STATUS_FEATURES_OK) {
				/* ??? */
				if (!lsxvio_virtio_check_driver_feature(common))
					common->device_status &=
					~VIRTIO_CONFIG_STATUS_FEATURES_OK;
			}
			if ((status & VIRTIO_CONFIG_STATUS_DRIVER_OK) &&
				!(adapter->status &
				VIRTIO_CONFIG_STATUS_DRIVER_OK)) {
				lsxvio_virtio_config_fromrc(dev);
				if (adapter->is_vf)
					LSXINIC_PMD_INFO("pcie%d:pf%d:vf%d link up",
						adapter->pcie_idx,
						adapter->pf_idx,
						adapter->vf_idx);
				else
					LSXINIC_PMD_INFO("pcie%d:pf%d link up",
						adapter->pcie_idx,
						adapter->pf_idx);
			}

			adapter->status = status;

			dev = (struct rte_lsx_pciep_device *)TAILQ_NEXT(dev, next);
		}

		if (print_status)
			lsxvio_print_ep_status();

		sleep(LSX_CMD_POLLING_INTERVAL);
	}

	return NULL;
}

static int
lsxvio_dev_configure(struct rte_eth_dev *dev __rte_unused)
{
	LSXINIC_PMD_DBG("\nConfigured Physical Function port id: %d",
		dev->data->port_id);

	return 0;
}

/* lsxvio_dev_start
 *
 * Configure device link speed and setup link.
 * It returns 0 on success.
 */
static int
lsxvio_dev_start(struct rte_eth_dev *eth_dev)
{
	int err;
	pthread_t thread;
	static uint32_t thread_init_flag;
	struct lsxvio_adapter *adapter = eth_dev->data->dev_private;

	/* stop adapter */
	adapter->adapter_stopped = false;
	adapter->status = VIRTIO_CONFIG_STATUS_NEEDS_RESET;

	/* initialize transmission unit */
	lsxvio_dev_tx_init(eth_dev);

	/* This can fail when allocating mbufs for descriptor rings */
	err = lsxvio_dev_rx_init(eth_dev);
	if (err) {
		LSXINIC_PMD_ERR("Unable to initialize RX hardware");
		lsxvio_dev_clear_queues(eth_dev);
		return -EIO;
	}

	lsxvio_dev_rx_tx_bind(eth_dev);

	if (!thread_init_flag) {
		if (pthread_create(&thread, NULL, lsxvio_poll_dev, NULL)) {
			LSXINIC_PMD_ERR("Could not create pol pthread");
			return -1;
		}

		thread_init_flag = 1;
	}

	return 0;
}

/* Stop device: disable rx and tx functions to allow for reconfiguring. */
static void
lsxvio_dev_stop(struct rte_eth_dev *dev)
{
	struct lsxvio_adapter *adapter = dev->data->dev_private;

	/* disable all enabled rx & tx queues */
	lsxvio_dev_rx_stop(dev);
	lsxvio_dev_tx_stop(dev);

	/* reset the NIC */
	adapter->adapter_stopped = true;

	lsxvio_dev_clear_queues(dev);
}

static void lsxvio_dev_reset(struct rte_eth_dev *dev)
{
	lsxvio_dev_stop(dev);

	lsxvio_dev_start(dev);

	lsxvio_virtio_reset_dev(dev);
}

/* Reest and stop device. */
static void
lsxvio_dev_close(struct rte_eth_dev *dev)
{
	struct lsxvio_adapter *adapter = dev->data->dev_private;

	lsxvio_dev_stop(dev);
	adapter->adapter_stopped = true;
}

static int
lsxvio_dev_info_get(struct rte_eth_dev *dev __rte_unused,
	struct rte_eth_dev_info *dev_info)
{
	dev_info->max_rx_queues = (uint16_t)512;
	dev_info->max_tx_queues = (uint16_t)512;
	dev_info->min_rx_bufsize = 1024; /* cf BSIZEPACKET in SRRCTL register */
	dev_info->max_rx_pktlen = 15872; /* includes CRC, cf MAXFRS register */
	dev_info->max_vfs = 32;

	dev_info->rx_desc_lim = rx_desc_lim;
	dev_info->tx_desc_lim = tx_desc_lim;
	dev_info->rx_offload_capa = DEV_RX_OFFLOAD_CHECKSUM;

	return 0;
}

static int
lsxvio_dev_mtu_set(struct rte_eth_dev *dev, uint16_t mtu)
{
	/* TODO: Add proper implementation */

	RTE_SET_USED(dev);
	RTE_SET_USED(mtu);

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
rte_lsxvio_dev_atomic_write_link_status(struct rte_eth_dev *dev,
	struct rte_eth_link *link)
{
	struct rte_eth_link *dst = &dev->data->dev_link;
	struct rte_eth_link *src = link;

	if (rte_atomic64_cmpset((uint64_t *)dst, *(uint64_t *)dst,
		*(uint64_t *)src) == 0)
		return -1;

	return 0;
}

/* return 0 means link status changed, -1 means not changed */
static int
lsxvio_dev_link_update(struct rte_eth_dev *dev,
	int wait_to_complete __rte_unused)
{
	struct rte_eth_link link;
	struct rte_eth_link *src, *dst;
	struct lsxvio_adapter *adapter =
		(struct lsxvio_adapter *)dev->data->dev_private;

	if (adapter->status & VIRTIO_CONFIG_STATUS_DRIVER_OK) {
		link.link_status = ETH_LINK_UP;
		link.link_duplex = ETH_LINK_FULL_DUPLEX;
		link.link_speed = ETH_SPEED_NUM_25G;
	} else {
		link.link_status = ETH_LINK_DOWN;
		link.link_duplex = ETH_LINK_HALF_DUPLEX;
		link.link_speed = ETH_SPEED_NUM_NONE;
	}

	src = &(link);
	dst = &dev->data->dev_link;
	if (rte_atomic64_cmpset((uint64_t *)dst, *(uint64_t *)dst,
		*((uint64_t *)src)) == 0)
		return -1;

	return 0;
}

static int
lsxvio_dev_promiscuous_enable(struct rte_eth_dev *dev __rte_unused)
{
	return 0;
}

static int
lsxvio_dev_promiscuous_disable(struct rte_eth_dev *dev __rte_unused)
{
	return 0;
}

static int
lsxvio_dev_allmulticast_enable(struct rte_eth_dev *dev __rte_unused)
{
	return 0;
}

static int
lsxvio_dev_allmulticast_disable(struct rte_eth_dev *dev __rte_unused)
{
	return 0;
}

/* Staticstic related function */
static int
lsxvio_dev_stats_get(struct rte_eth_dev *dev,
	struct rte_eth_stats *stats)
{
	uint64_t total_ipackets, total_ibytes, total_ierrors;
	uint64_t total_opackets, total_obytes, total_oerrors;
	struct lsxvio_tx_queue *txq, *txtmp;
	struct lsxvio_rx_queue *rxq, *rxtmp;
	uint32_t i, j;

	total_ipackets = 0;
	total_ibytes = 0;
	total_ierrors = 0;
	total_opackets = 0;
	total_obytes = 0;
	total_oerrors = 0;

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		txq = dev->data->tx_queues[i];
		txtmp = txq;
		for (j = 0; j < txq->nb_q; j++) {
			total_opackets += txtmp->packets;
			total_obytes += txtmp->bytes;
			total_oerrors += txtmp->errors;
			txtmp = txtmp->sibling;
		}
	}

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		rxq = dev->data->rx_queues[i];
		rxtmp = rxq;
		for (j = 0; j < rxq->nb_q; j++) {
			total_ipackets += rxtmp->packets;
			total_ibytes += rxtmp->bytes;
			total_ierrors += rxtmp->errors;
			rxtmp = rxtmp->sibling;
		}
	}

	stats->ipackets = total_ipackets;
	stats->opackets = total_opackets;
	stats->ibytes = total_ibytes;
	stats->obytes = total_obytes;
	stats->ierrors = total_ierrors;
	stats->oerrors = total_oerrors;

	return 0;
}

static int
lsxvio_dev_stats_reset(struct rte_eth_dev *dev)
{
	struct lsxvio_tx_queue *txq;
	struct lsxvio_rx_queue *rxq;
	uint32_t i, j;

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		txq = dev->data->tx_queues[i];
		for (j = 0; j < txq->nb_q; j++) {
			txq->packets = 0;
			txq->bytes = 0;
			txq->errors = 0;
			txq = txq->sibling;
		}
	}

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		rxq = dev->data->rx_queues[i];
		for (j = 0; j < rxq->nb_q; j++) {
			rxq->packets = 0;
			rxq->bytes = 0;
			rxq->errors = 0;
			rxq = rxq->sibling;
		}
	}

	return 0;
}

static int
lsxvio_dev_uninit(struct rte_eth_dev *eth_dev)
{
	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return 0;

	/* free memory for storing MAC addresses */
	if (eth_dev->data->mac_addrs) {
		rte_free(eth_dev->data->mac_addrs);
		eth_dev->data->mac_addrs = NULL;
	}

	eth_dev->dev_ops = NULL;
	eth_dev->rx_pkt_burst = NULL;
	eth_dev->tx_pkt_burst = NULL;

	LSXINIC_PMD_INFO("%s: netdev destroyed", eth_dev->data->name);

	return 0;
}

static int
rte_lsxvio_remove(struct rte_lsx_pciep_device *lsx_dev)
{
	struct rte_eth_dev *eth_dev;

	eth_dev = lsx_dev->eth_dev;

	lsxvio_dev_uninit(eth_dev);

	lsxvio_uninit_bar_addr(lsx_dev);

	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
		rte_free(eth_dev->data->dev_private);
		lsinic_dma_uninit();
	}
	rte_eth_dev_release_port(eth_dev);
	lsx_dev->init_flag = 0;

	return 0;
}

static struct rte_lsx_pciep_driver rte_lsxvio_pmd = {
	.drv_type = 0,
	.name = LSX_PCIEP_VIRT_NAME_PREFIX "_driver",
	.probe = rte_lsxvio_probe,
	.remove = rte_lsxvio_remove,
};

RTE_PMD_REGISTER_LSX_PCIEP(net_lsx, rte_lsxvio_pmd);
