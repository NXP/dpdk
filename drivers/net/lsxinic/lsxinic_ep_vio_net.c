// SPDX-License-Identifier: BSD-3-Clause
/* Copyright 2020-2026 NXP  */

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
#include <rte_tcp.h>
#include <rte_atomic.h>
#include <rte_errno.h>
#include <rte_version.h>
#include <rte_eal_memconfig.h>
#include <rte_net.h>
#include <rte_bus_vdev.h>
#include <rte_lsx_pciep_bus.h>

#include <virtio_pci.h>
#include "virtqueue.h"

#include "lsxinic_common_pmd.h"
#include "lsxinic_ep_vio.h"
#include "lsxinic_vio_common.h"
#include "lsxinic_ep_vio_net.h"
#include "lsxinic_ep_vio_rxtx.h"
#include "lsxinic_ep_dma.h"
#include "lsxinic_common_helper.h"

#define EP2RC_RING_DMA_ERR(ring_type, notify) \
	"%s %s %s %s ring", \
	"EP2RC DMA", notify, \
	"should be supported with", ring_type

static int lsxvio_dev_configure(struct rte_eth_dev *dev);
static int lsxvio_dev_start(struct rte_eth_dev *dev);
static int lsxvio_dev_stop(struct rte_eth_dev *dev);
static int lsxvio_dev_close(struct rte_eth_dev *dev);
static void lsxvio_dev_reset(struct rte_eth_dev *dev);
static int
lsxvio_dev_info_get(struct rte_eth_dev *dev,
	struct rte_eth_dev_info *dev_info);

static int lsxvio_dev_mtu_set(struct rte_eth_dev *dev, uint16_t mtu);

static int lsxvio_dev_promiscuous_enable(struct rte_eth_dev *dev);
static int lsxvio_dev_promiscuous_disable(struct rte_eth_dev *dev);
static int lsxvio_dev_allmulticast_enable(struct rte_eth_dev *dev);
static int lsxvio_dev_allmulticast_disable(struct rte_eth_dev *dev);

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

static uint64_t
lsxvio_xstats_get_ipackets(struct rte_eth_dev *dev)
{
	return lsxinic_common_get_ipackets(dev, struct lsxvio_queue *);
}

static uint64_t
lsxvio_xstats_get_ibytes(struct rte_eth_dev *dev)
{
	return lsxinic_common_get_ibytes(dev, struct lsxvio_queue *);
}

static uint64_t
lsxvio_xstats_get_epackets(struct rte_eth_dev *dev)
{
	return lsxinic_common_get_epackets(dev, struct lsxvio_queue *);
}

static uint64_t
lsxvio_xstats_get_ebytes(struct rte_eth_dev *dev)
{
	return lsxinic_common_get_ebytes(dev, struct lsxvio_queue *);
}

static uint64_t
lsxvio_xstats_get_ierrs(struct rte_eth_dev *dev)
{
	return lsxinic_common_get_ierrs(dev, struct lsxvio_queue *);
}

static uint64_t
lsxvio_xstats_get_eerrs(struct rte_eth_dev *dev)
{
	return lsxinic_common_get_eerrs(dev, struct lsxvio_queue *);
}

static uint64_t
lsxvio_xstats_get_ibd_errs(struct rte_eth_dev *dev)
{
	return lsxinic_common_get_ibd_errs(dev, struct lsxvio_queue *);
}

static uint64_t
lsxvio_xstats_get_efulls(struct rte_eth_dev *dev)
{
	return lsxinic_common_get_efulls(dev, struct lsxvio_queue *);
}

static uint64_t
lsxvio_xstats_get_edrops(struct rte_eth_dev *dev)
{
	return lsxinic_common_get_edrops(dev, struct lsxvio_queue *);
}

static const lsxinic_common_xstats_count s_lsxvio_xstat_cbs[] = {
	lsxvio_xstats_get_ipackets,
	lsxvio_xstats_get_ibytes,
	lsxvio_xstats_get_epackets,
	lsxvio_xstats_get_ebytes,
	lsxvio_xstats_get_ierrs,
	lsxvio_xstats_get_eerrs,
	lsxvio_xstats_get_ibd_errs,
	lsxvio_xstats_get_efulls,
	lsxvio_xstats_get_edrops
};

/* Staticstic related function */
static int
lsxvio_dev_stats_get(struct rte_eth_dev *dev,
	struct rte_eth_stats *stats, __rte_unused struct eth_queue_stats *qstats)
{
	stats->ipackets = lsxinic_common_get_ipackets(dev, struct lsxvio_queue *);
	stats->ibytes = lsxinic_common_get_ibytes(dev, struct lsxvio_queue *);
	stats->ierrors = lsxinic_common_get_ierrs(dev, struct lsxvio_queue *);

	stats->opackets = lsxinic_common_get_epackets(dev, struct lsxvio_queue *);
	stats->obytes = lsxinic_common_get_ebytes(dev, struct lsxvio_queue *);
	stats->oerrors = lsxinic_common_get_eerrs(dev, struct lsxvio_queue *);

	return 0;
}

static int
lsxvio_dev_stats_reset(struct rte_eth_dev *dev)
{
	lsxinic_common_q_reset(dev, struct lsxvio_queue *);

	return 0;
}

static int
lsxvio_dev_xstats_reset(struct rte_eth_dev *dev)
{
	return lsxvio_dev_stats_reset(dev);
}

static int
lsxvio_dev_link_update(struct rte_eth_dev *dev,
	int wait_to_complete __rte_unused)
{
	struct lsxvio_adapter *adapter = LSINIC_DEV_PRIVATE(dev);

	return lsxinic_common_link_update(dev,
		adapter->status & VIRTIO_CONFIG_STATUS_DRIVER_OK);
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
	.xstats_get	       = lsxinic_common_xstats_get,
	.xstats_get_by_id     = lsinic_common_xstats_get_by_id,
	.xstats_get_names_by_id = lsinic_common_xstats_get_names_by_id,
	.xstats_get_names      = lsxinic_common_xstats_get_names,
	.xstats_reset          = lsxvio_dev_xstats_reset,
};

static int
lsxvio_init_bar_addr(struct rte_lsx_pciep_device *lsx_dev,
	uint64_t lsx_feature)
{
	struct rte_eth_dev *eth_dev = lsx_dev->eth_dev;
	struct lsxvio_adapter *adapter = LSINIC_DEV_PRIVATE(eth_dev);
	uint16_t device_id;
	enum lsx_pcie_pf_idx pf_idx = lsx_dev->pf;
	uint64_t mask, size;
	int ret;

	adapter->lsx_dev = lsx_dev;
	/* Get queue config.*/

	mask = rte_lsx_pciep_bus_win_mask(lsx_dev);

	size = LSXVIO_CONFIG_BAR_MAX_SIZE;
	while (mask && (size & mask))
		size++;
	ret = rte_lsx_pciep_set_ib_win(lsx_dev, LSXVIO_CONFIG_BAR_IDX, size);
	if (ret) {
		LSXINIC_PMD_ERR("%s: IB win[%d] size(0x%lx) set failed",
			lsx_dev->name, LSXVIO_CONFIG_BAR_IDX, size);

		return ret;
	}
	/**Always mark reg bar noncache.*/
	rte_lsx_pciep_ib_cache_mark(lsx_dev, LSXVIO_CONFIG_BAR_IDX, 0);

	size = LSXVIO_RING_BAR_MAX_SIZE;
	while (mask && (size & mask))
		size++;
	ret = rte_lsx_pciep_set_ib_win(lsx_dev, LSXVIO_RING_BAR_IDX, size);
	if (ret) {
		LSXINIC_PMD_ERR("%s: IB win[%d] size(0x%lx) set failed",
			lsx_dev->name, LSXVIO_RING_BAR_IDX, size);

		return ret;
	}

	adapter->cfg_base = lsx_dev->virt_addr[LSXVIO_CONFIG_BAR_IDX];
	adapter->ring_base = lsx_dev->virt_addr[LSXVIO_RING_BAR_IDX];
	adapter->ring_phy_base = lsx_dev->iov_addr[LSXVIO_RING_BAR_IDX];
	adapter->num_queues = 0;
	adapter->num_descs = LSXVIO_MAX_RING_DESC;
#if (LSX_VIRTIO_NET_FEATURES & (1ULL << VIRTIO_F_VERSION_1))
	adapter->vtnet_hdr_size = sizeof(struct virtio_net_hdr_mrg_rxbuf);
#else
	adapter->vtnet_hdr_size = sizeof(struct virtio_net_hdr);
#endif

	device_id = rte_lsx_pciep_ctl_get_device_id(lsx_dev->pcie_id, pf_idx);
	ret = lsxvio_virtio_init((uint64_t)adapter->cfg_base,
		device_id, lsx_feature);
	if (ret) {
		LSXINIC_PMD_ERR("%s: vio init dev(%d) failed(%d)",
			lsx_dev->name, device_id, ret);

		return ret;
	}

	return 0;
}

static int
lsxvio_uninit_bar_addr(struct rte_lsx_pciep_device *lsx_dev)
{
	struct rte_eth_dev *eth_dev = lsx_dev->eth_dev;
	struct lsxvio_adapter *adapter = LSINIC_DEV_PRIVATE(eth_dev);

	adapter->cfg_base = NULL;
	adapter->ring_base = NULL;
	adapter->pf_idx = 0;
	adapter->is_vf = 0;
	adapter->vf_idx = 0;
	adapter->pcie_idx = 0;

	return 0;
}

static int
lsxvio_release_dma(struct rte_lsx_pciep_device *lsx_dev)
{
	struct rte_eth_dev *eth_dev = lsx_dev->eth_dev;
	struct lsxvio_adapter *adapter = LSINIC_DEV_PRIVATE(eth_dev);
	int ret;

	ret = lsinic_dma_release(adapter->txq_dma_id);
	if (ret)
		return ret;
	adapter->txq_dma_id = -1;

	ret = lsinic_dma_release(adapter->rxq_dma_id);
	if (ret)
		return ret;
	adapter->rxq_dma_id = -1;

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

static int
lsxvio_dev_priv_feature_configure(struct lsxvio_adapter *adapter,
	uint64_t *pfeature)
{
	uint64_t lsx_feature = 0;
	int env_val;
	char *penv;
	enum PEX_TYPE pex_type = rte_lsx_pciep_type_get(adapter->pcie_idx);

	lsx_feature |= LSX_VIO_EP2RC_DMA_NORSP;
	lsx_feature |= LSX_VIO_RC2EP_IN_ORDER;
	lsx_feature |= LSX_VIO_EP2RC_PACKED;
	lsx_feature |= LSX_VIO_RC2EP_DMA_BD_NOTIFY;
	lsx_feature |= LSX_VIO_EP2RC_DMA_ADDR_NOTIFY;
	lsx_feature |= LSX_VIO_EP2RC_DMA_BD_NOTIFY;
	lsx_feature |= LSX_VIO_EP2RC_DMA_SG_ENABLE;
	lsx_feature |= LSX_VIO_RC2EP_DMA_SG_ENABLE;

	penv = getenv("LSXVIO_QDMA_SG_ENABLE");
	if (penv) {
		env_val = atoi(penv);
		if (!env_val) {
			lsx_feature &= (~LSX_VIO_EP2RC_DMA_SG_ENABLE);
			lsx_feature &= (~LSX_VIO_RC2EP_DMA_SG_ENABLE);
		}
	}

	penv = getenv("LSXVIO_RXQ_QDMA_NO_RESPONSE");
	if (penv) {
		env_val = atoi(penv);
		if (env_val)
			lsx_feature |= LSX_VIO_RC2EP_DMA_NORSP;
	}

	penv = getenv("LSXVIO_TXQ_QDMA_NO_RESPONSE");
	if (penv) {
		env_val = atoi(penv);
		if (!env_val)
			lsx_feature &= (~LSX_VIO_EP2RC_DMA_NORSP);
	}

	penv = getenv("LSXVIO_RXQ_IN_ORDER");
	if (penv) {
		env_val = atoi(penv);
		if (!env_val)
			lsx_feature &= (~LSX_VIO_RC2EP_IN_ORDER);
	}

	penv = getenv("LSXVIO_TXQ_PACKED");
	if (penv) {
		env_val = atoi(penv);
		if (!env_val)
			lsx_feature &= (~LSX_VIO_EP2RC_PACKED);
	}

	penv = getenv("LSXVIO_RXQ_DMA_BD_NOTIFY");
	if (penv) {
		env_val = atoi(penv);
		if (!env_val)
			lsx_feature &= (~LSX_VIO_RC2EP_DMA_BD_NOTIFY);
	}

	penv = getenv("LSXVIO_TXQ_DMA_ADDR_NOTIFY");
	if (penv) {
		env_val = atoi(penv);
		if (!env_val)
			lsx_feature &= (~LSX_VIO_EP2RC_DMA_ADDR_NOTIFY);
	}

	penv = getenv("LSXVIO_TXQ_DMA_BD_NOTIFY");
	if (penv) {
		env_val = atoi(penv);
		if (!env_val)
			lsx_feature &= (~LSX_VIO_EP2RC_DMA_BD_NOTIFY);
	}

	if (lsx_feature & LSX_VIO_EP2RC_DMA_NORSP)
		lsx_feature |= LSX_VIO_EP2RC_DMA_SG_ENABLE;

	if (adapter->rbp_enable && pex_type == PEX_LX2160_REV1 &&
		(lsx_feature &
		(LSX_VIO_EP2RC_DMA_SG_ENABLE |
		LSX_VIO_RC2EP_DMA_SG_ENABLE))) {
		LSXINIC_PMD_ERR("LX2160A REV1 PEX not support SG with rbp");

		return -ENOTSUP;
	}

	if (pfeature)
		*pfeature = lsx_feature;

	return 0;
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
	uint64_t lsx_feature = 0;

	device_id = VIRTIO_PCI_MODERN_DEVICEID_NET;
	class_id = PCI_CLASS_NETWORK_ETHERNET;
	sprintf(env_name, "LSINIC_PCIE%d_PF%d_VIO_STORAGE",
		lsx_dev->pcie_id, lsx_dev->pf);
	if (getenv(env_name))
		lsxvio_virtio_get_blk_id(&device_id, &class_id);

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
	eth_dev->process_private = lsx_dev;

	adapter->dev_type = LSINIC_VIRTIO_DEV;

	ret = rte_lsx_pciep_fun_config(VIRTIO_PCI_VENDORID,
		device_id, class_id,
		VIRTIO_PCI_VENDORID, device_id,
		lsx_dev->pcie_id, lsx_dev->pf,
		lsx_dev->is_vf, lsx_dev->vf);
	if (ret)
		return ret;

	eth_dev->device = &lsx_dev->device;
	eth_dev->device->driver = &lsx_drv->driver;
	lsx_dev->driver = lsx_drv;
	lsx_dev->eth_dev = eth_dev;
	lsx_dev->chk_eth_status = lsxvio_dev_chk_eth_status;

	eth_dev->dev_ops = &lsxvio_eth_dev_ops;
	eth_dev->rx_pkt_burst = lsxvio_recv_pkts;
	eth_dev->tx_pkt_burst = lsxvio_xmit_pkts;
	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		goto end_probe;

	eth_dev->data->rx_mbuf_alloc_failed = 0;
	rbp = rte_lsx_pciep_hw_rbp_get(lsx_dev->pcie_id);
	if (rbp)
		adapter->rbp_enable = 1;
	else
		adapter->rbp_enable = 0;

	adapter->pf_idx = lsx_dev->pf;
	adapter->is_vf = lsx_dev->is_vf;
	if (lsx_dev->is_vf)
		adapter->vf_idx = lsx_dev->vf;
	adapter->pcie_idx = lsx_dev->pcie_id;

	ret = lsxvio_dev_priv_feature_configure(adapter,
		&lsx_feature);
	if (ret)
		return ret;

	if ((lsx_feature & LSX_VIO_RC2EP_DMA_BD_NOTIFY) &&
		(lsx_feature & LSX_VIO_RC2EP_DMA_NORSP)) {
		/* TBD*/
		LSXINIC_PMD_ERR("RC2EP DMA NORSP/BD notify TBD");

		return -EINVAL;
	}

	if ((lsx_feature & LSX_VIO_RC2EP_DMA_BD_NOTIFY) &&
		!(lsx_feature & LSX_VIO_RC2EP_IN_ORDER)) {
		/* TBD*/
		LSXINIC_PMD_ERR("RC2EP DMA-BD is NOT order ring");

		return -EINVAL;
	}

	if ((lsx_feature & LSX_VIO_EP2RC_DMA_BD_NOTIFY) &&
		!(lsx_feature & LSX_VIO_EP2RC_PACKED)) {
		LSXINIC_PMD_ERR(EP2RC_RING_DMA_ERR("PACKED",
			"BD update"));

		return -EINVAL;
	}

	if ((lsx_feature & LSX_VIO_EP2RC_DMA_ADDR_NOTIFY) &&
		!(lsx_feature & LSX_VIO_EP2RC_PACKED)) {
		LSXINIC_PMD_ERR(EP2RC_RING_DMA_ERR("PACKED",
			"address notify"));

		return -EINVAL;
	}

	if ((lsx_feature & LSX_VIO_EP2RC_DMA_BD_NOTIFY) &&
		!(lsx_feature & LSX_VIO_EP2RC_DMA_SG_ENABLE)) {
		LSXINIC_PMD_ERR("EP2RC DMA-BD is NOT SG enabled");

		return -EINVAL;
	}

	if ((lsx_feature & LSX_VIO_RC2EP_IN_ORDER) &&
		!(lsx_feature & LSX_VIO_RC2EP_DMA_SG_ENABLE)) {
		LSXINIC_PMD_ERR("RC2EP order ring is NOT SG enabled");

		return -EINVAL;
	}

	lsxvio_init_bar_addr(lsx_dev, lsx_feature);
	if (rte_lsx_pciep_hw_sim_get(lsx_dev->pcie_id) &&
		!lsx_dev->is_vf) {
		rte_lsx_pciep_sim_dev_map_inbound(lsx_dev);
	}
	lsxvio_netdev_reg_init(adapter);

	adapter->txq_dma_id = -1;
	adapter->rxq_dma_id = -1;
	adapter->txq_dma_vchan_used = 0;
	adapter->rxq_dma_vchan_used = 0;
	rte_spinlock_init(&adapter->txq_dma_start_lock);
	rte_spinlock_init(&adapter->rxq_dma_start_lock);

	if (!is_valid_ether_addr(adapter->mac_addr)) {
		LSXINIC_PMD_ERR("Invalid MAC address");
		return -EINVAL;
	}

	/* Allocate memory for storing MAC addresses */
	eth_dev->data->mac_addrs = rte_zmalloc("lsx", RTE_ETHER_ADDR_LEN, 0);
	if (!eth_dev->data->mac_addrs) {
		LSXINIC_PMD_ERR("Failed to allocate mac addr mem");
		return -ENOMEM;
	}
	/* Copy the permanent MAC address */
	rte_ether_addr_copy((struct rte_ether_addr *)adapter->port_mac_addr,
		&eth_dev->data->mac_addrs[0]);

end_probe:
	lsx_dev->init_flag = 1;
	rte_eth_dev_probing_finish(eth_dev);
	return 0;
}

int
lsxvio_dev_chk_eth_status(struct rte_eth_dev *dev)
{
	struct lsxvio_adapter *adapter = LSINIC_DEV_PRIVATE(dev);

	if (adapter->status & VIRTIO_CONFIG_STATUS_DRIVER_OK)
		return 1;

	return 0;
}

#define	LSX_CMD_POLLING_INTERVAL 2

static inline void
lsxvio_dev_print_link_status(int pcie_idx,
	int pf_idx, int vf_idx, int is_vf,
	const char *link_status)
{
	if (is_vf) {
		LSXINIC_PMD_INFO("pcie%d:pf%d:vf%d link %s",
			pcie_idx, pf_idx, vf_idx,
			link_status);
	} else {
		LSXINIC_PMD_INFO("pcie%d:pf%d link %s",
			pcie_idx, pf_idx,
			link_status);
	}
}

static void *lsxvio_poll_dev(void *arg)
{
	struct rte_eth_dev *eth_dev = arg;
	struct rte_lsx_pciep_device *dev = eth_dev->process_private;
	struct lsxvio_adapter *adapter = LSINIC_DEV_PRIVATE(eth_dev);
	struct lsxvio_common_cfg *common;
	uint8_t status;
	char *penv = getenv("LSINIC_EP_PRINT_STATUS");
	int print_status = 0, ret;

	adapter->cycs = rte_get_timer_cycles();

	if (penv)
		print_status = atoi(penv);

	while (1) {
		if (adapter->poll_stat != LSINIC_POLL_START) {
			adapter->poll_stat = LSINIC_POLL_INIT;
			return arg;
		}
		common = BASE_TO_COMMON(adapter->cfg_base);
		status = common->device_status;

		if (status == adapter->status)
			goto next_loop;

		if (status == VIRTIO_CONFIG_STATUS_SEND_RESET) {
			lsxvio_dev_reset(eth_dev);
			if (!(adapter->status & VIRTIO_CONFIG_STATUS_DRIVER_OK))
				continue;
			lsxvio_dev_print_link_status(adapter->pcie_idx,
				adapter->pf_idx, adapter->vf_idx,
				adapter->is_vf, "down");
			continue;
		}

		if ((adapter->status & VIRTIO_CONFIG_STATUS_DRIVER_OK) &&
			(status & VIRTIO_CONFIG_STATUS_NEEDS_RESET)) {
			/* Wait for the driver to reset the device*/
			rte_lsx_pciep_start_msix(adapter->msix_cfg_addr,
				adapter->msix_cfg_cmd);
		}

		if (status & VIRTIO_CONFIG_STATUS_FEATURES_OK) {
			/* ??? */
			if (!lsxvio_virtio_check_driver_feature(common))
				common->device_status &= ~VIRTIO_CONFIG_STATUS_FEATURES_OK;
		}
		if ((status & VIRTIO_CONFIG_STATUS_DRIVER_OK) &&
			!(adapter->status & VIRTIO_CONFIG_STATUS_DRIVER_OK)) {
			lsxvio_dev_print_link_status(adapter->pcie_idx,
				adapter->pf_idx, adapter->vf_idx,
				adapter->is_vf, "ok");
		}
		if ((status & VIRTIO_CONFIG_STATUS_START) &&
			!(adapter->status & VIRTIO_CONFIG_STATUS_START)) {
			ret = lsxvio_virtio_config_fromrc(dev);
			if (ret) {
				LSXINIC_PMD_ERR("%s link failed", eth_dev->data->name);
				continue;
			}

			lsxvio_dev_print_link_status(adapter->pcie_idx,
				adapter->pf_idx, adapter->vf_idx,
				adapter->is_vf, "up");
		}

		adapter->status = status;

next_loop:
		if (print_status)
			print_port_status_cycle(eth_dev, &adapter->cycs, LSINIC_EPVIO_PORT);

		sleep(LSX_CMD_POLLING_INTERVAL);
	}

	return arg;
}

static int
lsxvio_dev_configure(struct rte_eth_dev *dev)
{
	struct lsxvio_adapter *adapter = LSINIC_DEV_PRIVATE(dev);
	int dma_silent, err;
	struct lsxvio_common_cfg *common = BASE_TO_COMMON(adapter->cfg_base);

	if (common->lsx_feature & LSX_VIO_EP2RC_DMA_NORSP)
		dma_silent = 1;
	else
		dma_silent = 0;
	err = lsinic_dma_acquire(dma_silent,
		LSXVIO_MAX_QUEUE_PAIRS,
		LSXVIO_BD_DMA_MAX_COUNT,
		LSINIC_DMA_MEM_TO_PCIE,
		&adapter->txq_dma_id);
	if (err)
		return err;
	adapter->txq_dma_silent = dma_silent;

	if (common->lsx_feature & LSX_VIO_RC2EP_DMA_NORSP)
		dma_silent = 1;
	else
		dma_silent = 0;
	err = lsinic_dma_acquire(dma_silent,
		LSXVIO_MAX_QUEUE_PAIRS,
		LSXVIO_BD_DMA_MAX_COUNT,
		LSINIC_DMA_PCIE_TO_MEM,
		&adapter->rxq_dma_id);
	if (err)
		return err;
	adapter->rxq_dma_silent = dma_silent;

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
	struct lsxvio_adapter *adapter = LSINIC_DEV_PRIVATE(eth_dev);

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

	adapter->poll_stat = LSINIC_POLL_START;

	if (pthread_create(&thread, NULL, lsxvio_poll_dev, eth_dev)) {
		LSXINIC_PMD_ERR("Could not create pol pthread");
		return -1;
	}

	return 0;
}

/* Stop device: disable rx and tx functions to allow for reconfiguring. */
static int
lsxvio_dev_stop(struct rte_eth_dev *dev)
{
	/* disable all enabled rx & tx queues */
	lsxvio_dev_rx_stop(dev);
	lsxvio_dev_tx_stop(dev);

	lsxvio_dev_clear_queues(dev);

	return 0;
}

static void lsxvio_dev_reset(struct rte_eth_dev *dev)
{
	lsxvio_dev_stop(dev);

	lsxvio_dev_start(dev);

	lsxvio_virtio_reset_dev(dev);
}

/* Reest and stop device. */
static int
lsxvio_dev_close(struct rte_eth_dev *dev)
{
	int ret;

	ret = lsxvio_dev_stop(dev);
	if (ret)
		return ret;

	return 0;
}

static int
lsxvio_dev_info_get(struct rte_eth_dev *dev __rte_unused,
	struct rte_eth_dev_info *dev_info)
{
	dev_info->max_rx_queues = LSXVIO_MAX_QUEUE_PAIRS;
	dev_info->max_tx_queues = LSXVIO_MAX_QUEUE_PAIRS;
	dev_info->min_rx_bufsize = 1024; /* cf BSIZEPACKET in SRRCTL register */
	dev_info->max_rx_pktlen = 15872; /* includes CRC, cf MAXFRS register */
	dev_info->max_vfs = 32;

	dev_info->rx_desc_lim = rx_desc_lim;
	dev_info->tx_desc_lim = tx_desc_lim;
	dev_info->rx_offload_capa = RTE_ETH_RX_OFFLOAD_CHECKSUM;

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
		lsxvio_release_dma(lsx_dev);
		rte_free(eth_dev->data->dev_private);
	}
	rte_eth_dev_release_port(eth_dev);
	lsx_dev->init_flag = 0;

	return 0;
}

static void
lsxvio_xstat_cb_init(void)
{
	lsxinic_common_xstats_add_cb(s_lsxvio_xstat_cbs);
}

static struct rte_lsx_pciep_driver rte_lsxvio_pmd = {
	.drv_type = 0,
	.name = LSX_PCIEP_VIRT_NAME_PREFIX "_driver",
	.probe = rte_lsxvio_probe,
	.remove = rte_lsxvio_remove,
};

RTE_INIT(lsxvio_xstat_cb_init);
RTE_PMD_REGISTER_LSX_PCIEP(net_lsx, rte_lsxvio_pmd);
