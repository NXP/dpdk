/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2021 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_lsx_pciep_bus.h>

#include "lsxinic_common_pmd.h"
#include "lsxinic_common_reg.h"
#include "lsxinic_common_helper.h"
#include "lsxinic_ep_ethdev.h"
#include "lsxinic_ep_rxtx.h"
#include "lsxinic_ep_ethtool.h"

#define LSINIC_CMD_POLLING_INTERVAL 2

static int lsinic_if_init(struct rte_eth_dev *dev)
{
	struct lsinic_adapter *adapter = dev->process_private;

	adapter->rc_state = LSINIC_DEV_INITED;
	lsinic_reset_config_fromrc(adapter);

	return PCIDEV_RESULT_SUCCEED;
}

static int lsinic_if_link_up(struct rte_eth_dev *dev)
{
	struct lsinic_adapter *adapter = dev->process_private;

	if (adapter->rc_state != LSINIC_DEV_INITED) {
		LSXINIC_PMD_INFO("Please first send init command");
		return PCIDEV_RESULT_FAILED;
	}

	if (adapter->is_vf)
		LSXINIC_PMD_INFO("pcie%d:pf%d:vf%d link up",
			adapter->pcie_idx, adapter->pf_idx,
			adapter->vf_idx);
	else
		LSXINIC_PMD_INFO("pcie%d:pf%d link up",
			adapter->pcie_idx, adapter->pf_idx);
	adapter->rc_state = LSINIC_DEV_UP;
	lsinic_dev_rx_enable_start(dev);
	lsinic_dev_tx_enable_start(dev);

	return PCIDEV_RESULT_SUCCEED;
}

static int lsinic_if_link_down(struct rte_eth_dev *dev)
{
	struct lsinic_adapter *adapter = dev->process_private;

	if (adapter->is_vf) {
		LSXINIC_PMD_INFO("pice%d:pf%d:vf%d link down",
			adapter->pcie_idx, adapter->pf_idx, adapter->vf_idx);
	} else {
		LSXINIC_PMD_INFO("pice%d:pf%d link down",
			adapter->pcie_idx, adapter->pf_idx);
	}
	adapter->rc_state = LSINIC_DEV_DOWN;
	lsinic_dev_rx_stop(dev);
	lsinic_dev_tx_stop(dev);

	return PCIDEV_RESULT_SUCCEED;
}

static int lsinic_if_remove(struct rte_eth_dev *dev)
{
	struct lsinic_adapter *adapter = dev->process_private;

	if (adapter->rc_state == LSINIC_DEV_UP)
		lsinic_if_link_down(dev);

	adapter->rc_state = LSINIC_DEV_REMOVED;

	return PCIDEV_RESULT_SUCCEED;
}

static int lsinic_set_mac(struct rte_eth_dev *dev)
{
	struct lsinic_adapter *adapter = dev->process_private;
	struct lsinic_eth_reg *eth_reg =
		LSINIC_REG_OFFSET(adapter->hw_addr, LSINIC_ETH_REG_OFFSET);
	uint8_t mac_addr[RTE_ETHER_ADDR_LEN];
	uint32_t mac_high = 0;
	uint32_t mac_low = 0;
	int i;

	mac_high = LSINIC_READ_REG(&eth_reg->macaddrh);
	mac_low = LSINIC_READ_REG(&eth_reg->macaddrl);

	for (i = 0; i < 2; i++)
		mac_addr[i] = (uint8_t)(mac_high >> ((1 - i) * 8));

	for (i = 0; i < 4; i++)
		mac_addr[i + 2] = (uint8_t)(mac_low >> ((3 - i) * 8));

	if (!adapter->is_vf)
		LSXINIC_PMD_INFO("pcie%d:pf%d"
			" mac addr=%02x:%02x:%02x:%02x:%02x:%02x",
			adapter->pcie_idx, adapter->pf_idx,
			mac_addr[0], mac_addr[1], mac_addr[2],
			mac_addr[3], mac_addr[4], mac_addr[5]);
	else
		LSXINIC_PMD_INFO("pcie%d:pf%d:vf%d"
			" mac addr=%02x:%02x:%02x:%02x:%02x:%02x",
			adapter->pcie_idx, adapter->pf_idx,
			adapter->vf_idx,
			mac_addr[0], mac_addr[1], mac_addr[2],
			mac_addr[3], mac_addr[4], mac_addr[5]);

	return PCIDEV_RESULT_SUCCEED;
}

static int lsinic_set_mtu(struct rte_eth_dev *dev)
{
	int mtu;
	struct lsinic_adapter *adapter = dev->process_private;
	struct lsinic_eth_reg *eth_reg =
		LSINIC_REG_OFFSET(adapter->hw_addr, LSINIC_ETH_REG_OFFSET);

	mtu = LSINIC_READ_REG(&eth_reg->max_data_room);

	if (!adapter->is_vf)
		LSXINIC_PMD_INFO("pcie%d:pf%d align mtu(%d) with RC",
			adapter->pcie_idx, adapter->pf_idx, mtu);
	else
		LSXINIC_PMD_INFO("pcie%d:pf%d:vf%d align mtu(%d) with RC",
			adapter->pcie_idx, adapter->pf_idx, adapter->vf_idx, mtu);
	adapter->data_room_size = mtu;

	return PCIDEV_RESULT_SUCCEED;
}

#define DEBUG_PRINT_INTERVAL 4

static void lsinic_print_ep_status(void)
{
	static int debug_interval;
	struct rte_lsx_pciep_device *dev;
	struct rte_eth_dev *eth_dev;
	struct lsinic_adapter *adapter;
	uint64_t core_mask = 0;

	if (debug_interval < DEBUG_PRINT_INTERVAL) {
		debug_interval++;
		return;
	}

	debug_interval = 0;
	dev = lsx_pciep_first_dev();

	while (dev) {
		eth_dev = dev->eth_dev;
		adapter = eth_dev->process_private;

		if (adapter->ep_state != LSINIC_DEV_UP) {
			dev = (struct rte_lsx_pciep_device *)
				TAILQ_NEXT(dev, next);
			continue;
		}

		printf("\n\nPF%d", dev->pf);
		if (dev->is_vf)
			printf("-VF%d", dev->vf);
		printf("-Port%d -- statistics:\n", eth_dev->data->port_id);

		print_port_status(eth_dev, &core_mask,
			(DEBUG_PRINT_INTERVAL + 1) *
			LSINIC_CMD_POLLING_INTERVAL, 1, 0);

		printf("\r\n\r\n");
		dev = (struct rte_lsx_pciep_device *)TAILQ_NEXT(dev, next);
	}
}

void *lsinic_poll_dev_cmd(void *arg __rte_unused)
{
	struct rte_lsx_pciep_device *dev;
	struct rte_lsx_pciep_device *first_dev;
	struct lsinic_adapter *adapter;
	struct lsinic_dev_reg *reg;
	uint32_t command, status;
	char *penv = getenv("LSINIC_EP_PRINT_STATUS");
	int print_status = 0;
	struct lsinic_queue *queue = NULL;

	if (penv)
		print_status = atoi(penv);

#ifdef LSXINIC_LATENCY_TEST
		print_status = 1;
#endif

	while (1) {
		first_dev = lsx_pciep_first_dev();
		dev = first_dev;
		while (dev) {
			adapter = dev->eth_dev->process_private;
			if (!adapter->hw_addr) {
				dev = (struct rte_lsx_pciep_device *)
					TAILQ_NEXT(dev, next);
				if (dev == first_dev)
					dev = NULL;
				continue;
			}
			reg = LSINIC_REG_OFFSET(adapter->hw_addr,
					LSINIC_DEV_REG_OFFSET);
			if (dev->eth_dev->data->rx_queues) {
				queue = dev->eth_dev->data->rx_queues[0];
				if (queue && queue->dma_test.pci_addr)
					print_status = 1;
			}

			command = LSINIC_READ_REG(&reg->command);
			if (command == PCIDEV_COMMAND_IDLE) {
				dev = (struct rte_lsx_pciep_device *)TAILQ_NEXT(dev, next);
				if (dev == first_dev)
					dev = NULL;
				continue;
			}

			switch (command) {
			case PCIDEV_COMMAND_INIT:
				status = lsinic_if_init(dev->eth_dev);
				break;

			case PCIDEV_COMMAND_START:
				status = lsinic_if_link_up(dev->eth_dev);
				break;
			case PCIDEV_COMMAND_STOP:
				status = lsinic_if_link_down(dev->eth_dev);
				break;
			case PCIDEV_COMMAND_REMOVE:
				status = lsinic_if_remove(dev->eth_dev);
				break;
			case PCIDEV_COMMAND_SET_MAC:
				status = lsinic_set_mac(dev->eth_dev);
				break;
			case PCIDEV_COMMAND_SET_MTU:
				status = lsinic_set_mtu(dev->eth_dev);
				break;
			default:
				status = PCIDEV_RESULT_FAILED;
			}

			LSINIC_WRITE_REG(&reg->result, status);
			LSINIC_WRITE_REG(&reg->command, PCIDEV_COMMAND_IDLE);

			dev = (struct rte_lsx_pciep_device *)TAILQ_NEXT(dev, next);
			if (dev == first_dev)
				dev = NULL;
		}

		if (print_status)
			lsinic_print_ep_status();
		sleep(LSINIC_CMD_POLLING_INTERVAL);
	}
}
