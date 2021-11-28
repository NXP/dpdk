/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2021 NXP
 */

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
#include "lsxinic_common_reg.h"
#include "lsxinic_common_helper.h"
#include "lsxinic_ep_tool.h"
#include "lsxinic_ep_ethdev.h"
#include "lsxinic_ep_rxtx.h"
#include "lsxinic_ep_dma.h"
#include "lsxinic_ep_ethtool.h"
#include <dpaa2_ethdev.h>

static int
lsinic_dev_configure(struct rte_eth_dev *dev);
static int
lsinic_dev_start(struct rte_eth_dev *dev);
static void
lsinic_dev_stop(struct rte_eth_dev *dev);
static void
lsinic_dev_close(struct rte_eth_dev *dev);
static int
lsinic_dev_info_get(struct rte_eth_dev *dev,
	struct rte_eth_dev_info *dev_info);
static int
lsinic_dev_mtu_set(struct rte_eth_dev *dev, uint16_t mtu);
static int
lsinic_dev_link_update(struct rte_eth_dev *dev,
	int wait_to_complete);
static int
lsinic_dev_promiscuous_enable(struct rte_eth_dev *dev);
static int
lsinic_dev_promiscuous_disable(struct rte_eth_dev *dev);
static int
lsinic_dev_allmulticast_enable(struct rte_eth_dev *dev);
static int
lsinic_dev_allmulticast_disable(struct rte_eth_dev *dev);
static int
lsinic_dev_stats_get(struct rte_eth_dev *dev,
	struct rte_eth_stats *stats);
static int
lsinic_dev_stats_reset(struct rte_eth_dev *dev);

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

static struct eth_dev_ops lsinic_eth_dev_ops = {
	.dev_configure        = lsinic_dev_configure,
	.dev_start            = lsinic_dev_start,
	.dev_stop             = lsinic_dev_stop,
	.dev_close            = lsinic_dev_close,
	.dev_infos_get        = lsinic_dev_info_get,
	.mtu_set	      = lsinic_dev_mtu_set,
	.rx_queue_setup       = lsinic_dev_rx_queue_setup,
	.rx_queue_release     = lsinic_dev_rx_queue_release,
	.tx_queue_setup       = lsinic_dev_tx_queue_setup,
	.tx_queue_release     = lsinic_dev_tx_queue_release,
	.link_update          = lsinic_dev_link_update,
	.promiscuous_enable   = lsinic_dev_promiscuous_enable,
	.promiscuous_disable  = lsinic_dev_promiscuous_disable,
	.allmulticast_enable  = lsinic_dev_allmulticast_enable,
	.allmulticast_disable = lsinic_dev_allmulticast_disable,
	.stats_get            = lsinic_dev_stats_get,
	.stats_reset          = lsinic_dev_stats_reset,
};

/**
 * lsinic_sw_init - Initialize general software structures
 *                   (struct lsinic_adapter)
 * @adapter: board private structure to initialize
 *
 * lsinic_sw_init initializes the Adapter private data structure.
 * Fields are initialized based on PCI device information and
 * OS network device settings (MTU size).
 **/
static int
lsinic_sw_init(struct lsinic_adapter *adapter)
{
	struct lsinic_eth_reg *eth_reg =
		LSINIC_REG_OFFSET(adapter->hw_addr, LSINIC_ETH_REG_OFFSET);

	/* get ring setting */
	adapter->tx_ring_bd_count = LSINIC_READ_REG(&eth_reg->tx_entry_num);
	adapter->rx_ring_bd_count = LSINIC_READ_REG(&eth_reg->rx_entry_num);

	adapter->num_tx_queues = 0;
	adapter->num_rx_queues = 0;

	return 0;
}

static int
lsinic_txrx_queues_create(struct lsinic_adapter *adapter)
{
	adapter->txqs = rte_zmalloc_socket("ethdev queue",
					sizeof(struct lsinic_queue) *
					LSINIC_MAX_NUM_TX_QUEUES,
					RTE_CACHE_LINE_SIZE, 0);
	adapter->rxqs = rte_zmalloc_socket("ethdev queue",
					sizeof(struct lsinic_queue) *
					LSINIC_MAX_NUM_RX_QUEUES,
					RTE_CACHE_LINE_SIZE, 0);
	if (!adapter->txqs || !adapter->rxqs) {
		LSXINIC_PMD_ERR("Cannot allocate txqs/rxqs");
		return -ENODEV;
	}

	return 0;
}

/* lsinic_set_netdev
 *
 * Send command to netdev to init/start/stop/remove device
 */
static int
lsinic_set_netdev(struct lsinic_adapter *adapter, int cmd)
{
	struct lsinic_dev_reg *reg =
		LSINIC_REG_OFFSET(adapter->hw_addr, LSINIC_DEV_REG_OFFSET);

	switch (cmd) {
	case PCIDEV_COMMAND_START:
		adapter->ep_state = LSINIC_DEV_UP;
		break;
	case PCIDEV_COMMAND_STOP:
		adapter->ep_state = LSINIC_DEV_DOWN;
		break;
	case PCIDEV_COMMAND_REMOVE:
		adapter->ep_state = LSINIC_DEV_REMOVED;
		break;
	case PCIDEV_COMMAND_INIT:
		adapter->ep_state = LSINIC_DEV_INITED;
		break;
	default:
		break;
	}

	LSINIC_WRITE_REG(&reg->ep_state, adapter->ep_state);

	/* To Do notify Host driver that the status has been changed */

	return 0;
}

static int
lsinic_set_init_flag(struct lsinic_adapter *adapter)
{
	struct lsinic_dev_reg *reg =
		LSINIC_REG_OFFSET(adapter->hw_addr, LSINIC_DEV_REG_OFFSET);

	LSINIC_WRITE_REG(&reg->init_flag, LSINIC_INIT_FLAG);

	return 0;
}

static int
lsinic_init_bar_addr(struct rte_lsx_pciep_device *lsinic_dev)
{
	struct rte_eth_dev *eth_dev = lsinic_dev->eth_dev;
	struct lsinic_adapter *adapter = (struct lsinic_adapter *)
		eth_dev->process_private;
	int sim, rbp;

	adapter->pf_idx = lsinic_dev->pf;
	adapter->is_vf = lsinic_dev->is_vf;
	if (lsinic_dev->is_vf)
		adapter->vf_idx = lsinic_dev->vf;
	adapter->pcie_idx = lsinic_dev->pcie_id;

	sim = lsx_pciep_hw_sim_get(adapter->pcie_idx);
	if (adapter->is_vf)
		rbp = lsx_pciep_hw_rbp_get(adapter->pcie_idx);
	else
		rbp = lsx_pciep_hw_rbp_get(adapter->pcie_idx);

	if (!rbp && !sim) {
		/* OB setting does NOT depend on RC for NORBP.*/
		lsx_pciep_set_ob_win(lsinic_dev, 0, 0);
	}

	lsx_pciep_set_ib_win(lsinic_dev,
		LSX_PCIEP_REG_BAR_IDX,
		LSINIC_REG_BAR_MAX_SIZE);
	lsx_pciep_set_ib_win(lsinic_dev,
		LSX_PCIEP_RING_BAR_IDX,
		LSINIC_RING_BAR_MAX_SIZE);
	if (sim && !lsinic_dev->is_vf &&
		!(adapter->cap & LSINIC_CAP_XFER_HOST_ACCESS_EP_MEM))
		lsx_pciep_sim_dev_map_inbound(lsinic_dev);

	adapter->hw_addr =
		lsinic_dev->virt_addr[LSX_PCIEP_REG_BAR_IDX];
	adapter->ep_ring_virt_base =
		lsinic_dev->virt_addr[LSX_PCIEP_RING_BAR_IDX];
	adapter->bd_desc_base =
		(uint8_t *)adapter->ep_ring_virt_base +
		LSINIC_RING_BD_OFFSET;

	return 0;
}

static int
lsinic_uninit_bar_addr(struct rte_lsx_pciep_device *lsinic_dev)
{
	struct rte_eth_dev *eth_dev = lsinic_dev->eth_dev;
	struct lsinic_adapter *adapter = (struct lsinic_adapter *)
		eth_dev->process_private;

	adapter->hw_addr = NULL;
	adapter->bd_desc_base = NULL;
	adapter->ep_ring_virt_base = NULL;
	adapter->pf_idx = 0;
	adapter->is_vf = 0;
	adapter->vf_idx = 0;
	adapter->pcie_idx = 0;

	return 0;
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

static int
lsinic_dev_config_init(struct lsinic_adapter *adapter)
{
	struct lsinic_dev_reg *cfg =
		LSINIC_REG_OFFSET(adapter->hw_addr, LSINIC_DEV_REG_OFFSET);
	int rbp;

	cfg->rev = INIC_VERSION;
	cfg->rx_ring_max_num = LSINIC_RING_MAX_COUNT;
	cfg->rx_entry_max_num = LSINIC_BD_ENTRY_COUNT;
	cfg->tx_ring_max_num = LSINIC_RING_MAX_COUNT;
	cfg->tx_entry_max_num = LSINIC_BD_ENTRY_COUNT;
	cfg->dev_reg_offset = LSINIC_ETH_REG_OFFSET;
	if (adapter->is_vf)
		cfg->vf_idx = adapter->vf_idx | LSXINIC_VF_AVAILABLE;
	else
		cfg->vf_idx = 0;
	cfg->pf_idx = adapter->pf_idx;
	cfg->vf_num = PCIE_MAX_VF_NUM;

	rbp = lsx_pciep_hw_rbp_get(adapter->pcie_idx);

	if (rbp) {
		cfg->obwin_size = ilog2(adapter->lsinic_dev->rbp_win_size);
		cfg->rbp_enable = 1;
	} else {
		cfg->obwin_size = ilog2(adapter->lsinic_dev->ob_win_size);
		cfg->rbp_enable = 0;
	}

	return 0;
}

int
lsinic_split_dev_flow_create(struct lsinic_adapter *adapter)
{
	struct rte_dpaa2_device *split_dev = adapter->split_dev;
	struct rte_dpaa2_device *split_dst_dev = adapter->split_dst_dev;
	uint16_t split_id, dst_id;
	struct rte_flow_attr flow_attr;
	struct rte_flow_item flow_item[2];
	struct rte_flow_action flow_action[2];
	struct rte_flow_item_eth spec, mask;
	struct rte_flow_action_phy_port dst_port;
	char dst_name[RTE_ETH_NAME_MAX_LEN];
	char split_name[RTE_ETH_NAME_MAX_LEN];

	if (split_dev && split_dst_dev) {
		split_id = split_dev->eth_dev->data->port_id;
		dst_id = split_dst_dev->eth_dev->data->port_id;
		memcpy(dst_name, split_dst_dev->eth_dev->data->name,
			RTE_ETH_NAME_MAX_LEN);
		memcpy(split_name, split_dev->eth_dev->data->name,
			RTE_ETH_NAME_MAX_LEN);
		memset(&flow_attr, 0, sizeof(struct rte_flow_attr));
		memset(flow_item, 0, 2 * sizeof(struct rte_flow_item));
		memset(flow_action, 0, 2 * sizeof(struct rte_flow_action));
		memset(&spec, 0, sizeof(struct rte_flow_item_eth));
		memset(&mask, 0, sizeof(struct rte_flow_item_eth));
		memset(&dst_port, 0, sizeof(struct rte_flow_action_phy_port));

		flow_attr.group = 0;
		flow_attr.priority = 0;
		flow_attr.egress = 1;

		flow_item[0].type = RTE_FLOW_ITEM_TYPE_ETH;
		spec.type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
		mask.type = 0xffff;
		flow_item[0].spec = &spec;
		flow_item[0].mask = &mask;
		flow_item[1].type = RTE_FLOW_ITEM_TYPE_END;

		flow_action[0].type = RTE_FLOW_ACTION_TYPE_PHY_PORT;
		dst_port.original = 0;
		dst_port.index = dst_id;
		flow_action[0].conf = &dst_port;
		flow_action[1].type = RTE_FLOW_ACTION_TYPE_END;

		if (rte_flow_create(split_id, &flow_attr, &flow_item[0],
			&flow_action[0], NULL))
			LSXINIC_PMD_INFO("Redirect ipv4 to %s by %s",
				dst_name, split_name);
		else
			LSXINIC_PMD_ERR("Unable redirect ipv4 to %s by %s",
				dst_name, split_name);

		return 0;
	}

	return -1;
}

static inline struct rte_dpaa2_device *
lsinic_dev_id_to_dpaa2_dev(int eth_id)
{
	struct rte_dpaa2_device *dpaa2_dev = NULL;
	struct rte_device *rdev;
	if (eth_id >= 0 && eth_id < RTE_MAX_ETHPORTS &&
		dpaa2_dev_is_dpaa2(&rte_eth_devices[eth_id])) {
		rdev = rte_eth_devices[eth_id].device;
		dpaa2_dev =
			container_of(rdev, struct rte_dpaa2_device, device);
	}

	return dpaa2_dev;
}

static void
lsinic_netdev_env_init(struct rte_eth_dev *eth_dev)
{
	char env_name[128];
	char *penv;
	struct lsinic_adapter *adapter = eth_dev->process_private;
	struct rte_lsx_pciep_device *lsinic_dev = adapter->lsinic_dev;
	const char *cnf_env = "LSINIC_EP_RXQ_CONFIRM";
	const char *notify_env = "LSINIC_EP_TXQ_NOTIFY";

	adapter->ep_cap = 0;

	/* NO TX DMA RSP and write BD to RC by DMA as well.*/
	penv = getenv("LSINIC_TXQ_QDMA_NO_RESPONSE");
	if (penv)
		adapter->ep_cap |= LSINIC_EP_CAP_TXQ_DMA_NO_RSP;

	penv = getenv("LSINIC_RXQ_ORDER_PRESERVE");
	if (penv)
		adapter->ep_cap |= LSINIC_EP_CAP_RXQ_ORP;

	/* Write BD of RXQ from EP to RC by DMA of its TXQ pair.*/
	penv = getenv("LSINIC_RXQ_WRITE_BD_BY_DMA");
	if (penv)
		adapter->ep_cap |= LSINIC_EP_CAP_RXQ_WBD_DMA;

	/* Above capability is handled only on EP side and no sensible to RC.*/

	adapter->cap = 0;

	penv = getenv("LSINIC_MERGE_PACKETS");
	if (penv)
		adapter->cap |= LSINIC_CAP_XFER_PKT_MERGE;

	penv = getenv("LSINIC_RXQ_QDMA_NO_RESPONSE");
	if (penv)
		adapter->cap |= LSINIC_CAP_XFER_COMPLETE;

	if (adapter->cap & (LSINIC_CAP_XFER_COMPLETE |
		LSINIC_EP_CAP_RXQ_ORP)) {
		/** Index confirm as default*/
		LSINIC_CAP_XFER_EGRESS_CNF_SET(adapter->cap,
			EGRESS_INDEX_CNF);
		penv = getenv(cnf_env);
		if (penv) {
			if (atoi(penv) == EGRESS_BD_CNF) {
				LSINIC_CAP_XFER_EGRESS_CNF_SET(adapter->cap,
					EGRESS_BD_CNF);
			} else if (atoi(penv) == EGRESS_RING_CNF) {
				LSINIC_CAP_XFER_EGRESS_CNF_SET(adapter->cap,
					EGRESS_RING_CNF);
			} else if (atoi(penv) == EGRESS_INDEX_CNF) {
				LSINIC_CAP_XFER_EGRESS_CNF_SET(adapter->cap,
					EGRESS_INDEX_CNF);
			} else {
				LSXINIC_PMD_INFO("%s:%d-%s,%d-%s,%d-%s",
					cnf_env,
					EGRESS_BD_CNF, "BD confirm",
					EGRESS_RING_CNF, "RING confirm",
					EGRESS_INDEX_CNF, "INDEX confirm");
			}
		}
	}

	LSINIC_CAP_XFER_INGRESS_NOTIFY_SET(adapter->cap,
		INGRESS_RING_NOTIFY);
	penv = getenv(notify_env);
	if (penv) {
		if (atoi(penv) == INGRESS_BD_NOTIFY) {
			LSINIC_CAP_XFER_INGRESS_NOTIFY_SET(adapter->cap,
				INGRESS_BD_NOTIFY);
		} else if (atoi(penv) == INGRESS_RING_NOTIFY) {
			LSINIC_CAP_XFER_INGRESS_NOTIFY_SET(adapter->cap,
				INGRESS_RING_NOTIFY);
		} else {
			LSXINIC_PMD_INFO("%s:%d-%s,%d-%s",
				notify_env,
				INGRESS_BD_NOTIFY, "BD notify",
				INGRESS_RING_NOTIFY, "RING notify");
		}
	}

	penv = getenv("LSINIC_RXQ_READ_BD_BY_DMA");
	if (penv)
		adapter->cap |= LSINIC_CAP_XFER_TX_BD_UPDATE;

	penv = getenv("LSINIC_TXQ_READ_BD_BY_DMA");
	if (penv)
		adapter->cap |= LSINIC_CAP_XFER_RX_BD_UPDATE;

	penv = getenv("LSINIC_XFER_HOST_ACCESS_EP_MEM");
	if (penv)
		adapter->cap |= LSINIC_CAP_XFER_HOST_ACCESS_EP_MEM;

	if (!(adapter->cap & LSINIC_CAP_XFER_PKT_MERGE))
		return;

	penv = getenv("LSXINIC_PMD_RCV_MERGE_RECYCLE_DEV");
	if (penv)
		adapter->ep_cap |= LSINIC_EP_CAP_RCV_MERGE_RECYCLE_RX;

	penv = getenv("LSXINIC_PMD_RCV_SPLIT_RECYCLE_DEV");
	if (penv)
		adapter->ep_cap |= LSINIC_EP_CAP_RCV_SPLIT_RECYCLE_RX;

	/** Direct MAC egress. */
	if (lsinic_dev->is_vf) {
		sprintf(env_name, "LSXINIC_PCIE%d_PF%d_VF%d_EGRESS",
			lsinic_dev->pcie_id, lsinic_dev->pf,
			lsinic_dev->vf);
	} else {
		sprintf(env_name, "LSXINIC_PCIE%d_PF%d_EGRESS",
			lsinic_dev->pcie_id, lsinic_dev->pf);
	}
	penv = getenv(env_name);
	if (penv) {
		adapter->split_dev =
			lsinic_dev_id_to_dpaa2_dev(atoi(penv));
		if (adapter->split_dev)
			adapter->ep_cap |= LSINIC_EP_CAP_HW_DIRECT_EGRESS;
	}

	/** Split traffic from PCIe host by recycle port. */
	if (!adapter->split_dev) {
		if (lsinic_dev->is_vf) {
			sprintf(env_name, "LSXINIC_PCIE%d_PF%d_VF%d_HW_SPLIT",
				lsinic_dev->pcie_id, lsinic_dev->pf,
				lsinic_dev->vf);
		} else {
			sprintf(env_name, "LSXINIC_PCIE%d_PF%d_HW_SPLIT",
				lsinic_dev->pcie_id, lsinic_dev->pf);
		}

		penv = getenv(env_name);
		if (penv)
			adapter->split_dev = lsinic_dev_id_to_dpaa2_dev(atoi(penv));

		/** Apply rule on recycle port to fwd traffic by HW. */
		if (adapter->is_vf) {
			sprintf(env_name, "LSXINIC_PCIE%d_PF%d_VF%d_SPLIT_DST",
				lsinic_dev->pcie_id, lsinic_dev->pf,
				lsinic_dev->vf);
		} else {
			sprintf(env_name, "LSXINIC_PCIE%d_PF%d_SPLIT_DST",
				lsinic_dev->pcie_id, lsinic_dev->pf);
		}
		penv = getenv(env_name);
		if (penv)
			adapter->split_dst_dev = lsinic_dev_id_to_dpaa2_dev(atoi(penv));
	}

	if (adapter->split_dev) {
		adapter->ep_cap |= LSINIC_EP_CAP_HW_SPLIT_PKTS;
		if (adapter->ep_cap & LSINIC_EP_CAP_HW_DIRECT_EGRESS) {
			LSXINIC_PMD_INFO("Traffic from %s is directed to %s",
				eth_dev->data->name,
				adapter->split_dev->eth_dev->data->name);
		} else {
			LSXINIC_PMD_INFO("Traffic from %s is splited by %s to redirect",
				eth_dev->data->name,
				adapter->split_dev->eth_dev->data->name);
		}
	}

	if (lsinic_dev->is_vf) {
		sprintf(env_name, "LSXINIC_PCIE%d_PF%d_VF%d_HW_MERGE",
			lsinic_dev->pcie_id, lsinic_dev->pf,
			lsinic_dev->vf);
	} else {
		sprintf(env_name, "LSXINIC_PCIE%d_PF%d_HW_MERGE",
			lsinic_dev->pcie_id, lsinic_dev->pf);
	}
	penv = getenv(env_name);
	if (penv) {
		adapter->merge_dev = lsinic_dev_id_to_dpaa2_dev(atoi(penv));
		if (adapter->merge_dev)
			adapter->ep_cap |= LSINIC_EP_CAP_HW_MERGE_PKTS;
	}

	if (lsinic_dev->is_vf) {
		sprintf(env_name, "LSXINIC_PCIE%d_PF%d_VF%d_MERGE_THRESHOLD",
			lsinic_dev->pcie_id, lsinic_dev->pf,
			lsinic_dev->vf);
	} else {
		sprintf(env_name, "LSXINIC_PCIE%d_PF%d_MERGE_THRESHOLD",
			lsinic_dev->pcie_id, lsinic_dev->pf);
	}
	penv = getenv(env_name);
	if (penv) {
		adapter->merge_threshold = atoi(penv);
		if (adapter->merge_threshold <
			(RTE_ETHER_MIN_LEN - RTE_ETHER_CRC_LEN)) {
			LSXINIC_PMD_WARN("Invalid merge threshold %d",
				adapter->merge_threshold);
			adapter->merge_threshold =
				LSINIC_MERGE_DEFAULT_THRESHOLD;
		}
	} else {
		adapter->merge_threshold =
			LSINIC_MERGE_DEFAULT_THRESHOLD;
	}

	if (!(adapter->ep_cap & LSINIC_EP_CAP_HW_SPLIT_PKTS)) {
		if (lsinic_dev->is_vf) {
			sprintf(env_name,
				"LSXINIC_PCIE%d_PF%d_VF%d_CLONE_SPLIT",
				lsinic_dev->pcie_id, lsinic_dev->pf,
				lsinic_dev->vf);
		} else {
			sprintf(env_name,
				"LSXINIC_PCIE%d_PF%d_CLONE_SPLIT",
				lsinic_dev->pcie_id, lsinic_dev->pf);
		}
		penv = getenv(env_name);
		if (penv && atoi(penv) > 0)
			adapter->ep_cap |= LSINIC_EP_CAP_MBUF_CLONE_SPLIT_PKTS;
	}

	if (!(adapter->ep_cap & LSINIC_EP_CAP_HW_MERGE_PKTS))
		adapter->ep_cap |= LSINIC_EP_CAP_SW_MERGE_PKTS;

	if (!((adapter->ep_cap & LSINIC_EP_CAP_HW_SPLIT_PKTS) ||
		(adapter->ep_cap & LSINIC_EP_CAP_MBUF_CLONE_SPLIT_PKTS)))
		adapter->ep_cap |= LSINIC_EP_CAP_SW_SPLIT_PKTS;

	if (adapter->ep_cap & LSINIC_EP_CAP_HW_DIRECT_EGRESS)
		adapter->ep_cap &= ~LSINIC_EP_CAP_RCV_SPLIT_RECYCLE_RX;
}

static void
lsinic_netdev_reg_init(struct lsinic_adapter *adapter)
{
	int i;
	uint32_t macaddrl = 0;
	uint32_t macaddrh = 0;
	struct lsinic_eth_reg *reg =
		LSINIC_REG_OFFSET(adapter->hw_addr, LSINIC_ETH_REG_OFFSET);
	struct rte_eth_dev *eth_dev = adapter->lsinic_dev->eth_dev;

	inic_memset(reg, 0, sizeof(*reg));

	LSINIC_WRITE_REG(&reg->rev, INIC_VERSION);
	if (adapter->is_vf) {
		LSINIC_WRITE_REG(&reg->fmidx,
			(adapter->pcie_idx << 24) |
			(adapter->pf_idx << 16) |
			LSXINIC_VF_AVAILABLE | adapter->vf_idx);
		LSINIC_WRITE_REG(&reg->macidx,
			(adapter->pcie_idx << 24) |
			(adapter->pf_idx << 16) |
			LSXINIC_VF_AVAILABLE | adapter->vf_idx);
	} else {
		LSINIC_WRITE_REG(&reg->fmidx,
			(adapter->pcie_idx << 24) |
			(adapter->pf_idx << 16));
		LSINIC_WRITE_REG(&reg->macidx,
			(adapter->pcie_idx << 24) |
			(adapter->pf_idx << 16));
	}

	LSINIC_WRITE_REG(&reg->tx_ring_num, 0);
	LSINIC_WRITE_REG(&reg->rx_ring_num, 0);
	LSINIC_WRITE_REG(&reg->tx_entry_num, LSINIC_BD_ENTRY_COUNT);
	LSINIC_WRITE_REG(&reg->rx_entry_num, LSINIC_BD_ENTRY_COUNT);

	LSINIC_WRITE_REG(&reg->cap, adapter->cap);

	LSINIC_WRITE_REG(&reg->merge_threshold, adapter->merge_threshold);

	memcpy(adapter->mac_addr,
		eth_dev->data->mac_addrs->addr_bytes,
		RTE_ETHER_ADDR_LEN);

	/* write mac */
	for (i = 0; i < 4; i++)
		macaddrl |= (uint32_t)adapter->mac_addr[5 - i]
				 << (i * 8);
	for (i = 0; i < 2; i++)
		macaddrh |= (uint32_t)adapter->mac_addr[1 - i]
				 << (i * 8);

	LSINIC_WRITE_REG(&reg->macaddrh, macaddrh);
	LSINIC_WRITE_REG(&reg->macaddrl, macaddrl);
}

static void
lsinic_mac_init(struct rte_ether_addr *mac_addrs,
	struct rte_lsx_pciep_device *lsinic_dev)
{
	int pf_idx = lsinic_dev->pf;
	int vf_idx = lsinic_dev->vf;
	int is_vf = lsinic_dev->is_vf;

	/* 00:e0:0c:fm_idx-mac_idx:mac_type-PF index: VF index */
	mac_addrs->addr_bytes[0] = 0x00;
	mac_addrs->addr_bytes[1] = 0xe0;
	mac_addrs->addr_bytes[2] = 0x0c;
	mac_addrs->addr_bytes[3] = pf_idx + 1;
	mac_addrs->addr_bytes[4] = is_vf;
	mac_addrs->addr_bytes[5] = vf_idx;
}

/* rte_lsinic_probe:
 *
 * Interrupt is used only for link status notification on dpdk.
 * we don't think about the interrupt handlle situation right now.
 * we can port our MSIX interrupt in iNIC host driver to dpdk,
 * need to test the performance.
 */

static int
rte_lsinic_probe(struct rte_lsx_pciep_driver *lsinic_drv,
	struct rte_lsx_pciep_device *lsinic_dev)
{
	struct rte_eth_dev *eth_dev = NULL;
	struct lsinic_adapter *adapter = NULL;

	if (LSINIC_RING_BD_OFFSET <
		(LSINIC_RING_REG_OFFSET +
		(int)sizeof(struct lsinic_bdr_reg))) {
		rte_panic("LSINIC_RING_BD_OFFSET(%d)"
			" < LSINIC_RING_REG_OFFSET(%d) +"
			" sizeof(struct lsinic_bdr_reg)(%d)",
			LSINIC_RING_BD_OFFSET,
			LSINIC_RING_REG_OFFSET,
			(int)sizeof(struct lsinic_bdr_reg));
	}

	if (LSINIC_RCS_REG_OFFSET <
		(LSINIC_DEV_REG_OFFSET +
		(int)sizeof(struct lsinic_dev_reg))) {
		rte_panic("LSINIC_RCS_REG_OFFSET(%d)"
			" < LSINIC_DEV_REG_OFFSET(%d) +"
			" sizeof(struct lsinic_dev_reg)(%d)",
			LSINIC_RCS_REG_OFFSET,
			LSINIC_DEV_REG_OFFSET,
			(int)sizeof(struct lsinic_dev_reg));
	}

	if (LSINIC_ETH_REG_OFFSET <
		(LSINIC_RCS_REG_OFFSET +
		(int)sizeof(struct lsinic_rcs_reg))) {
		rte_panic("LSINIC_ETH_REG_OFFSET(%d)"
			" < LSINIC_RCS_REG_OFFSET(%d) +"
			" sizeof(struct lsinic_rcs_reg)(%d)",
			LSINIC_ETH_REG_OFFSET,
			LSINIC_RCS_REG_OFFSET,
			(int)sizeof(struct lsinic_rcs_reg));
	}

	if (lsinic_dev->init_flag) {
		LSXINIC_PMD_ERR("pf:%d vf:%d has been initialized!",
			lsinic_dev->pf, lsinic_dev->vf);
		return 0;
	}

	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
		eth_dev = rte_eth_dev_allocate(lsinic_dev->device.name);
		if (!eth_dev) {
			LSXINIC_PMD_ERR("Cannot allocate eth_dev");
			return -ENODEV;
		}
	} else {
		eth_dev = rte_eth_dev_attach_secondary(lsinic_dev->device.name);
		if (!eth_dev) {
			LSXINIC_PMD_ERR("Cannot attach eth_dev");
			return -ENODEV;
		}
	}

	adapter = rte_zmalloc("ethdev process private adapter",
				sizeof(struct lsinic_adapter),
				RTE_CACHE_LINE_SIZE);
	if (!adapter) {
		LSXINIC_PMD_ERR("Cannot allocate memzone for private data");
		rte_eth_dev_release_port(eth_dev);
		return -ENOMEM;
	}
	eth_dev->process_private = adapter;

	adapter->merge_dev = NULL;
	adapter->split_dev = NULL;
	rte_spinlock_init(&adapter->merge_dev_cfg_lock);
	rte_spinlock_init(&adapter->split_dev_cfg_lock);
	rte_spinlock_init(&adapter->cap_lock);
	adapter->merge_dev_cfg_done = 0;
	adapter->split_dev_cfg_done = 0;
	adapter->lsinic_dev = lsinic_dev;

	eth_dev->device = &lsinic_dev->device;
	eth_dev->device->driver = &lsinic_drv->driver;
	lsinic_dev->driver = lsinic_drv;
	lsinic_dev->eth_dev = eth_dev;
	lsinic_dev->chk_eth_status = lsinic_dev_chk_eth_status;
	eth_dev->data->rx_mbuf_alloc_failed = 0;

	eth_dev->dev_ops = &lsinic_eth_dev_ops;
	eth_dev->rx_pkt_burst = &lsinic_recv_pkts;
	eth_dev->tx_pkt_burst = &lsinic_xmit_pkts;

	/* Allocate memory for storing MAC addresses */
	if (!eth_dev->data->mac_addrs) {
		eth_dev->data->mac_addrs =
			rte_zmalloc("lsinic", RTE_ETHER_ADDR_LEN, 0);
		if (!eth_dev->data->mac_addrs) {
			LSXINIC_PMD_ERR("Failed to allocate MAC address");
			return -ENOMEM;
		}

		lsinic_mac_init(eth_dev->data->mac_addrs, lsinic_dev);
	}
	lsinic_dev->init_flag = 1;

	rte_eth_dev_probing_finish(eth_dev);
	return 0;
}

#ifdef LSXINIC_LATENCY_TEST
static uint64_t s_cycs_per_us;
static uint64_t
calculate_cycles_per_us(void)
{
	uint64_t start_cycles, end_cycles;

	if (s_cycs_per_us)
		return s_cycs_per_us;

	start_cycles = rte_get_timer_cycles();
	rte_delay_ms(1000);
	end_cycles = rte_get_timer_cycles();
	s_cycs_per_us = (end_cycles - start_cycles) / (1000 * 1000);
	LSXINIC_PMD_INFO("Cycles per us is: %ld",
		(unsigned long)s_cycs_per_us);

	return s_cycs_per_us;
}
#endif

static int
lsinic_dev_configure(struct rte_eth_dev *eth_dev)
{
	struct lsinic_adapter *adapter =
		eth_dev->process_private;
	struct rte_lsx_pciep_device *lsinic_dev =
		adapter->lsinic_dev;
	uint16_t vendor_id, device_id, class_id;
	enum PEX_TYPE pex_type =
		lsx_pciep_type_get(lsinic_dev->pcie_id);
	char env_name[128];
	char *penv;
	int err;

	vendor_id = NXP_PCI_VENDOR_ID;
	class_id = NXP_PCI_CLASS_ID;
	if (pex_type == PEX_LX2160_REV1 || pex_type == PEX_LX2160_REV2)
		device_id = NXP_PCI_DEV_ID_LX2160A;
	else if (pex_type == PEX_LS208X)
		device_id = NXP_PCI_DEV_ID_LS2088A;
	else
		device_id = NXP_PCI_DEV_ID_NULL;

	if (!lsinic_dev->is_vf) {
		sprintf(env_name, "LSINIC_PCIE%d_PF%d_VENDOR_ID",
			lsinic_dev->pcie_id, lsinic_dev->pf);
		penv = getenv(env_name);
		if (penv)
			vendor_id = strtol(penv, 0, 16);
		sprintf(env_name, "LSINIC_PCIE%d_PF%d_DEVICE_ID",
			lsinic_dev->pcie_id, lsinic_dev->pf);
		penv = getenv(env_name);
		if (penv)
			device_id = strtol(penv, 0, 16);
		sprintf(env_name, "LSINIC_PCIE%d_PF%d_CLASS_ID",
			lsinic_dev->pcie_id, lsinic_dev->pf);
		penv = getenv(env_name);
		if (penv)
			class_id = strtol(penv, 0, 16);
	}

	if (!lsinic_dev->is_vf) {
		err = lsx_pciep_ctl_dev_set(vendor_id,
				device_id, class_id,
				lsinic_dev->pcie_id, lsinic_dev->pf);
		if (err)
			return err;
	}

	lsinic_netdev_env_init(eth_dev);
	lsinic_init_bar_addr(lsinic_dev);

	lsinic_netdev_reg_init(adapter);
	lsinic_dev_config_init(adapter);

	err = lsinic_txrx_queues_create(adapter);
	if (err)
		return -ENODEV;

	/* Clear adapter stopped flag */
	adapter->adapter_stopped = false;

	/* setup the private structure */
	err = lsinic_sw_init(adapter);
	if (err) {
		LSXINIC_PMD_ERR("lsinic_sw_init failed");
		return -ENODEV;
	}
	lsinic_set_init_flag(adapter);
	lsinic_set_netdev(adapter, PCIDEV_COMMAND_INIT);
#ifdef LSXINIC_LATENCY_TEST
	adapter->cycs_per_us = calculate_cycles_per_us();
#endif

	return 0;
}

static int
lsinic_dev_recycle_start(struct rte_eth_dev *recycle_dev,
	int nb_tx_queues, int nb_rx_queues,
	uint16_t nb_tx_desc, uint16_t nb_rx_desc,
	const struct rte_eth_conf *port_conf,
	struct rte_mempool *mb_pool)
{
	const struct eth_dev_ops *dev_ops;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_rxconf rxconf;
	struct rte_eth_txconf txconf;
	int ret, qnb;

	if (recycle_dev->data->dev_started)
		return 0;

	dev_ops = recycle_dev->dev_ops;
	RTE_ASSERT(dev_ops);
	ret = -ENOTSUP;
	if (dev_ops->dev_infos_get)
		ret = dev_ops->dev_infos_get(recycle_dev, &dev_info);
	if (ret) {
		LSXINIC_PMD_ERR("Recycle device gets info failed!");
		return ret;
	}

	memcpy(&recycle_dev->data->dev_conf, port_conf,
			sizeof(struct rte_eth_conf));

	recycle_dev->data->rx_queues = rte_zmalloc(NULL,
				sizeof(void *) * nb_rx_queues,
				RTE_CACHE_LINE_SIZE);
	if (!recycle_dev->data->rx_queues) {
		LSXINIC_PMD_ERR("Recycle device alloc rxqs failed!");
		return -ENOMEM;
	}
	recycle_dev->data->nb_rx_queues = nb_rx_queues;

	recycle_dev->data->tx_queues = rte_zmalloc(NULL,
				sizeof(void *) * nb_tx_queues,
				RTE_CACHE_LINE_SIZE);
	if (!recycle_dev->data->tx_queues) {
		LSXINIC_PMD_ERR("Recycle device alloc txqs failed!");
		return -ENOMEM;
	}
	recycle_dev->data->nb_tx_queues = nb_tx_queues;

	ret = -ENOTSUP;
	if (dev_ops->dev_configure) {
		recycle_dev->data->dev_conf.lpbk_mode = 1;
		ret = dev_ops->dev_configure(recycle_dev);
	}
	if (ret) {
		LSXINIC_PMD_ERR("Recycle device conf failed!");
		return ret;
	}

	for (qnb = 0; qnb < recycle_dev->data->nb_tx_queues; qnb++) {
		memcpy(&txconf, &dev_info.default_txconf,
			sizeof(struct rte_eth_rxconf));
		txconf.offloads = port_conf->txmode.offloads;
		ret = dev_ops->tx_queue_setup(recycle_dev, qnb,
						nb_tx_desc,
						0, &txconf);
		if (ret < 0) {
			LSXINIC_PMD_ERR("Recycle device set txq%d failed!", qnb);
			return ret;
		}
	}

	for (qnb = 0; qnb < recycle_dev->data->nb_rx_queues; qnb++) {
		memcpy(&rxconf, &dev_info.default_rxconf,
			sizeof(struct rte_eth_rxconf));
		rxconf.offloads = port_conf->rxmode.offloads;
		ret = dev_ops->rx_queue_setup(recycle_dev, qnb,
						nb_rx_desc,
						0, &rxconf, mb_pool);
		if (ret < 0) {
			LSXINIC_PMD_ERR("Recycle device set rxq%d failed!", qnb);
			return ret;
		}
	}

	ret = dev_ops->dev_start(recycle_dev);
	if (ret) {
		LSXINIC_PMD_ERR("Recycle device start failed!");
		return ret;
	}
	recycle_dev->data->dev_started = 1;

	ret = dev_ops->promiscuous_enable(recycle_dev);
	if (ret) {
		LSXINIC_PMD_ERR("Recycle device promiscuous enable failed!");
		return ret;
	}

	return 0;
}

/* Configure device link speed and setup link.
 * It returns 0 on success.
 */
static int
lsinic_dev_start(struct rte_eth_dev *eth_dev)
{
	int err;
	pthread_t thread;
	static uint32_t thread_init_flag;
	struct lsinic_adapter *adapter = eth_dev->process_private;

	/* stop adapter */
	adapter->adapter_stopped = false;
	adapter->rc_ring_phy_base = 0;
	adapter->rc_ring_virt_base = 0;

	/* initialize transmission unit */
	lsinic_dev_tx_init(eth_dev);

	/* This can fail when allocating mbufs for descriptor rings */
	err = lsinic_dev_rx_init(eth_dev);
	if (err) {
		LSXINIC_PMD_ERR("Unable to initialize RX hardware");
		lsinic_dev_clear_queues(eth_dev);
		return -EIO;
	}

	lsinic_dev_rx_tx_bind(eth_dev);

	if (!thread_init_flag) {
		if (pthread_create(&thread, NULL, lsinic_poll_dev_cmd, NULL)) {
			LSXINIC_PMD_ERR("Could not create poll_dev_cmd pthread");
			return -1;
		}

		thread_init_flag = 1;
	}

	if (adapter->ep_cap & LSINIC_EP_CAP_RCV_MERGE_RECYCLE_RX ||
		adapter->ep_cap & LSINIC_EP_CAP_RCV_SPLIT_RECYCLE_RX) {
		struct rte_eth_dev *recycle_eth_dev;

		if (eth_dev->data->nb_tx_queues !=
			eth_dev->data->nb_rx_queues &&
			(adapter->merge_dev || adapter->split_dev)) {
			LSXINIC_PMD_ERR("Recycle dev(%s) nb_txq(%d)!=nb_rxq(%d)",
				eth_dev->data->name,
				eth_dev->data->nb_tx_queues,
				eth_dev->data->nb_rx_queues);
			return -ENOTSUP;
		}
		if (adapter->merge_dev &&
			(adapter->ep_cap & LSINIC_EP_CAP_RCV_MERGE_RECYCLE_RX)) {
			recycle_eth_dev = adapter->merge_dev->eth_dev;
			err = lsinic_dev_recycle_start(recycle_eth_dev,
					eth_dev->data->nb_tx_queues,
					eth_dev->data->nb_rx_queues,
					adapter->txqs[0].nb_desc,
					adapter->rxqs[0].nb_desc,
					&eth_dev->data->dev_conf,
					adapter->rxqs[0].mb_pool);
			if (err) {
				LSXINIC_PMD_ERR("Failed to start merge device %s!",
					recycle_eth_dev->data->name);
				return -EIO;
			}
		}
		if (adapter->split_dev &&
			(adapter->ep_cap & LSINIC_EP_CAP_RCV_SPLIT_RECYCLE_RX)) {
			recycle_eth_dev = adapter->split_dev->eth_dev;
			err = lsinic_dev_recycle_start(recycle_eth_dev,
					eth_dev->data->nb_tx_queues,
					eth_dev->data->nb_rx_queues,
					adapter->txqs[0].nb_desc,
					adapter->rxqs[0].nb_desc,
					&eth_dev->data->dev_conf,
					adapter->rxqs[0].mb_pool);
			if (err) {
				LSXINIC_PMD_ERR("Failed to start split device %s!",
					recycle_eth_dev->data->name);
				return -EIO;
			}
		}
	}

	lsinic_set_netdev(adapter, PCIDEV_COMMAND_START);

	return 0;
}

/* Stop device: disable rx and tx functions to allow for reconfiguring.
 */
static void
lsinic_dev_stop(struct rte_eth_dev *dev)
{
	struct lsinic_adapter *adapter = dev->process_private;

	/* disable the netdev receive */
	lsinic_set_netdev(adapter, PCIDEV_COMMAND_STOP);

	/* disable all enabled rx & tx queues */
	lsinic_dev_rx_stop(dev);
	lsinic_dev_tx_stop(dev);

	/* reset the NIC */
	adapter->adapter_stopped = true;

	lsinic_dev_clear_queues(dev);
	if (adapter->complete_src) {
		rte_free(adapter->complete_src);
		adapter->complete_src = NULL;
	}
}

/* Reest and stop device.
 */
static void
lsinic_dev_close(struct rte_eth_dev *dev)
{
	struct lsinic_adapter *adapter = dev->process_private;

	lsinic_dev_stop(dev);
	adapter->adapter_stopped = true;

	lsinic_set_netdev(adapter, PCIDEV_COMMAND_REMOVE);
}

static int
lsinic_dev_info_get(struct rte_eth_dev *dev __rte_unused,
	struct rte_eth_dev_info *dev_info)
{
	dev_info->max_rx_queues = (uint16_t)512;
	dev_info->max_tx_queues = (uint16_t)512;
	dev_info->min_rx_bufsize = 1024; /* cf BSIZEPACKET in SRRCTL register */
	dev_info->max_rx_pktlen = 15872; /* includes CRC, cf MAXFRS register */
	dev_info->max_vfs = PCIE_MAX_VF_NUM;

	dev_info->rx_desc_lim = rx_desc_lim;
	dev_info->tx_desc_lim = tx_desc_lim;
	dev_info->rx_offload_capa = DEV_RX_OFFLOAD_CHECKSUM |
		DEV_RX_OFFLOAD_JUMBO_FRAME;

	return 0;
}

static int
lsinic_dev_mtu_set(struct rte_eth_dev *dev, uint16_t mtu)
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
rte_lsinic_dev_atomic_write_link_status(struct rte_eth_dev *dev,
	struct rte_eth_link *link)
{
	struct rte_eth_link *dst = &dev->data->dev_link;
	struct rte_eth_link *src = link;

	if (rte_atomic64_cmpset((uint64_t *)dst, *(uint64_t *)dst,
			*(uint64_t *)src) == 0)
		return -1;

	return 0;
}

static void
lsinic_dev_map_rc_ring(struct lsinic_adapter *adapter,
	uint64_t rc_reg_addr)
{
	int sim;
	void *vir_addr;
	uint64_t vir_offset;
	struct rte_lsx_pciep_device *lsinic_dev = adapter->lsinic_dev;
	struct lsinic_dev_reg *cfg =
		LSINIC_REG_OFFSET(adapter->hw_addr, LSINIC_DEV_REG_OFFSET);
	int ring_total_size;

	ring_total_size = adapter->num_rx_queues *
					adapter->rx_ring_bd_count *
					sizeof(struct lsinic_bd_desc);
	ring_total_size += adapter->num_tx_queues *
					adapter->tx_ring_bd_count *
					sizeof(struct lsinic_bd_desc);

	/** RX complete ring to notify RC recv complete.*/
	ring_total_size += adapter->num_rx_queues *
					adapter->rx_ring_bd_count *
					sizeof(uint8_t);
	/** TX complete ring to notify RC xmit complete.*/
	ring_total_size += adapter->num_tx_queues *
					adapter->tx_ring_bd_count *
					sizeof(uint8_t);

	sim = lsx_pciep_hw_sim_get(adapter->pcie_idx);
	adapter->rc_ring_phy_base = rc_reg_addr;
	if (sim) {
		vir_addr = DPAA2_IOVA_TO_VADDR(rc_reg_addr);
		vir_offset = (uint64_t)vir_addr - rc_reg_addr;

		adapter->rc_ring_virt_base = vir_addr;
		lsx_pciep_set_sim_ob_win(lsinic_dev, vir_offset);
	} else {
		if (cfg->rbp_enable) {
			adapter->rc_ring_virt_base =
				lsx_pciep_set_ob_win(lsinic_dev,
							rc_reg_addr,
							ring_total_size);
		} else {
			adapter->rc_ring_virt_base =
				lsinic_dev->ob_virt_base +
					rc_reg_addr -
					lsinic_dev->ob_map_bus_base;
		}
	}
}

void
lsinic_reset_config_fromrc(struct lsinic_adapter *adapter)
{
	uint64_t rc_reg_addr = 0;
	struct rte_lsx_pciep_device *lsinic_dev = adapter->lsinic_dev;
	struct lsinic_eth_reg *eth_reg =
		LSINIC_REG_OFFSET(adapter->hw_addr, LSINIC_ETH_REG_OFFSET);
	struct lsinic_rcs_reg *rcs_reg =
		LSINIC_REG_OFFSET(adapter->hw_addr, LSINIC_RCS_REG_OFFSET);
	int sim;

	sim = lsx_pciep_hw_sim_get(adapter->pcie_idx);
	/* get ring setting */
	if (1) {
		adapter->rx_ring_bd_count = LSINIC_BD_ENTRY_COUNT;
		adapter->tx_ring_bd_count = LSINIC_BD_ENTRY_COUNT;
	} else {
		adapter->rx_ring_bd_count =
			LSINIC_READ_REG(&eth_reg->tx_entry_num);
		adapter->tx_ring_bd_count =
			LSINIC_READ_REG(&eth_reg->rx_entry_num);
	}

	/* Note: ep-tx == rc-rx and ep-rx == rc-tx */
	adapter->num_rx_queues = LSINIC_READ_REG(&eth_reg->tx_ring_num);
	adapter->num_tx_queues = LSINIC_READ_REG(&eth_reg->rx_ring_num);
	lsinic_dev->mmsi_flag = LSINIC_READ_REG(&rcs_reg->msi_flag);

	if (lsinic_dev->mmsi_flag == LSX_PCIEP_DONT_INT) {
		int i;

		for (i = 0; i < 32; i++)
			LSINIC_WRITE_REG(&rcs_reg->msix_mask[i], 0x01);
	}

	LSXINIC_PMD_INFO("rx-tx queues:%d-%d BDs:%d-%d mmsi_flag:%d",
		adapter->num_rx_queues, adapter->num_tx_queues,
		adapter->rx_ring_bd_count, adapter->tx_ring_bd_count,
		lsinic_dev->mmsi_flag);

	rc_reg_addr = LSINIC_READ_REG_64B((uint64_t *)(&rcs_reg->r_regl));
	if (adapter->rc_ring_phy_base == 0 ||
		adapter->rc_ring_phy_base != rc_reg_addr) {
		if (rc_reg_addr)
			lsinic_dev_map_rc_ring(adapter, rc_reg_addr);
		else
			LSXINIC_PMD_ERR("Reconfig from RC ERROR!");
		LSXINIC_PMD_DBG("Reconfig from RC rc_reg_addr:%lX",
			rc_reg_addr);
	}

	rc_reg_addr = LSINIC_READ_REG_64B((uint64_t *)(&rcs_reg->rxdma_regl));
	adapter->rx_pcidma_dbg = rc_reg_addr;
	rc_reg_addr = LSINIC_READ_REG_64B((uint64_t *)(&rcs_reg->txdma_regl));
	adapter->tx_pcidma_dbg = rc_reg_addr;
	if (LSINIC_CAP_XFER_EGRESS_CNF_GET(adapter->cap) ==
		EGRESS_RING_CNF) {
		adapter->complete_src =
			rte_malloc(NULL, LSINIC_EP2RC_COMPLETE_RING_SIZE,
				LSINIC_EP2RC_COMPLETE_RING_SIZE);
		if (adapter->complete_src) {
			memset(adapter->complete_src, RING_BD_HW_COMPLETE,
				LSINIC_EP2RC_COMPLETE_RING_SIZE);
		} else {
			LSXINIC_PMD_WARN("complete src malloc failed");
		}
	} else {
		adapter->complete_src = NULL;
	}

	if (!sim)
		lsx_pciep_msix_init(lsinic_dev);
}

/* return 0 means link status changed, -1 means not changed */
static int
lsinic_dev_link_update(struct rte_eth_dev *dev,
	int wait_to_complete __rte_unused)
{
	struct lsinic_adapter *adapter;
	struct rte_eth_link link;

	adapter = (struct lsinic_adapter *)dev->process_private;
	if (adapter->rc_state == LSINIC_DEV_UP) {
		link.link_status = ETH_LINK_UP;
		link.link_duplex = ETH_LINK_FULL_DUPLEX;
		link.link_speed = ETH_SPEED_NUM_25G;
	} else {
		link.link_status = ETH_LINK_DOWN;
		link.link_duplex = ETH_LINK_HALF_DUPLEX;
		link.link_speed = ETH_SPEED_NUM_NONE;
	}

	rte_lsinic_dev_atomic_write_link_status(dev, &link);

	return 0;
}

int
lsinic_dev_chk_eth_status(struct rte_eth_dev *dev)
{
	struct lsinic_adapter *adapter = dev->process_private;

	if (adapter->ep_state == LSINIC_DEV_INITING ||
		adapter->ep_state == LSINIC_DEV_INITED ||
		adapter->ep_state == LSINIC_DEV_REMOVED)
		return 0;
	else
		return 1;
}

static int
lsinic_dev_promiscuous_enable(struct rte_eth_dev *dev __rte_unused)
{
	return 0;
}

static int
lsinic_dev_promiscuous_disable(struct rte_eth_dev *dev __rte_unused)
{
	return 0;
}

static int
lsinic_dev_allmulticast_enable(struct rte_eth_dev *dev __rte_unused)
{
	return 0;
}

static int
lsinic_dev_allmulticast_disable(struct rte_eth_dev *dev __rte_unused)
{
	return 0;
}

/* Staticstic related function
 */
static int
lsinic_dev_stats_get(struct rte_eth_dev *dev,
	struct rte_eth_stats *stats)
{
	uint64_t total_ipackets, total_ibytes, total_ierrors;
	uint64_t total_opackets, total_obytes, total_oerrors;
	struct lsinic_tx_queue *txq, *txtmp;
	struct lsinic_rx_queue *rxq, *rxtmp;
	unsigned i, j;

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
lsinic_dev_stats_reset(struct rte_eth_dev *dev)
{
	struct lsinic_tx_queue *txq;
	struct lsinic_rx_queue *rxq;
	unsigned i, j;

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
lsinic_dev_uninit(struct rte_eth_dev *eth_dev)
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
rte_lsinic_remove(struct rte_lsx_pciep_device *lsinic_dev)
{
	struct rte_eth_dev *eth_dev;

	eth_dev = lsinic_dev->eth_dev;

	lsinic_dev_uninit(eth_dev);

	lsinic_uninit_bar_addr(lsinic_dev);

	rte_free(eth_dev->process_private);
	lsinic_dma_uninit();

	rte_eth_dev_release_port(eth_dev);
	lsinic_dev->init_flag = 0;

	return 0;
}

static struct rte_lsx_pciep_driver rte_lsinic_pmd = {
	.drv_type = 0,
	.name = LSX_PCIEP_NXP_NAME_PREFIX "_driver",
	.probe = rte_lsinic_probe,
	.remove = rte_lsinic_remove,
};

RTE_PMD_REGISTER_LSX_PCIEP(net_lsinic, rte_lsinic_pmd);
