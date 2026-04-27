/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2026 NXP
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

static int lsinic_if_dma_test(struct rte_eth_dev *dev)
{
	if (lsinic_dma_test_mem_config_fromrc(dev))
		return PCIDEV_RESULT_FAILED;

	return PCIDEV_RESULT_SUCCEED;
}

static int lsinic_if_init(struct rte_eth_dev *dev)
{
	struct lsinic_adapter *adapter = LSINIC_DEV_PRIVATE(dev);

	adapter->rc_state = LSINIC_DEV_INITED;

	if (lsinic_reset_config_fromrc(dev))
		return PCIDEV_RESULT_FAILED;

	return PCIDEV_RESULT_SUCCEED;
}

static int lsinic_if_link_up(struct rte_eth_dev *dev)
{
	struct lsinic_adapter *adapter = LSINIC_DEV_PRIVATE(dev);

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
	struct lsinic_adapter *adapter = LSINIC_DEV_PRIVATE(dev);

	if (adapter->is_vf) {
		LSXINIC_PMD_INFO("pice%d:pf%d:vf%d link down",
			adapter->pcie_idx, adapter->pf_idx, adapter->vf_idx);
	} else {
		LSXINIC_PMD_INFO("pice%d:pf%d link down",
			adapter->pcie_idx, adapter->pf_idx);
	}
	adapter->rc_state = LSINIC_DEV_DOWN;
	lsinic_dev_rx_stop(dev, 1);
	lsinic_dev_tx_stop(dev, 1);

	return PCIDEV_RESULT_SUCCEED;
}

static int lsinic_if_remove(struct rte_eth_dev *dev)
{
	struct lsinic_adapter *adapter = LSINIC_DEV_PRIVATE(dev);

	if (adapter->rc_state == LSINIC_DEV_UP)
		lsinic_if_link_down(dev);

	adapter->rc_state = LSINIC_DEV_REMOVED;

	return PCIDEV_RESULT_SUCCEED;
}

static int lsinic_set_mac(struct rte_eth_dev *dev)
{
	struct lsinic_adapter *adapter = LSINIC_DEV_PRIVATE(dev);
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

	if (!adapter->is_vf) {
		LSXINIC_PMD_INFO("pcie%d:pf%d",
			adapter->pcie_idx, adapter->pf_idx);
	} else {
		LSXINIC_PMD_INFO("pcie%d:pf%d:vf%d",
			adapter->pcie_idx, adapter->pf_idx,
			adapter->vf_idx);
	}
	LSXINIC_PMD_INFO("mac addr=%02x:%02x:%02x:%02x:%02x:%02x",
		mac_addr[0], mac_addr[1], mac_addr[2],
		mac_addr[3], mac_addr[4], mac_addr[5]);

	return PCIDEV_RESULT_SUCCEED;
}

static int lsinic_set_mtu(struct rte_eth_dev *dev)
{
	uint32_t mtu;
	struct lsinic_adapter *adapter = LSINIC_DEV_PRIVATE(dev);
	struct lsinic_eth_reg *eth_reg =
		LSINIC_REG_OFFSET(adapter->hw_addr, LSINIC_ETH_REG_OFFSET);

	mtu = LSINIC_READ_REG(&eth_reg->max_data_room);

	if (!adapter->is_vf) {
		LSXINIC_PMD_INFO("pcie%d:pf%d align mtu(%d) with RC",
			adapter->pcie_idx, adapter->pf_idx, mtu);
	} else {
		LSXINIC_PMD_INFO("pcie%d:pf%d:vf%d align mtu(%d) with RC",
			adapter->pcie_idx, adapter->pf_idx,
			adapter->vf_idx, mtu);
	}
	if (mtu > adapter->data_room_size) {
		LSXINIC_PMD_ERR("Invalid mtu(%d) > %d", mtu, adapter->data_room_size);
		return PCIDEV_RESULT_FAILED;
	}
	adapter->max_tx_size = mtu;

	return PCIDEV_RESULT_SUCCEED;
}

void *lsinic_poll_dev_cmd(void *arg)
{
	struct rte_eth_dev *eth_dev = arg;
	struct lsinic_adapter *adapter = LSINIC_DEV_PRIVATE(eth_dev);
	struct lsinic_dev_reg *reg;
	uint32_t command, status;
	char *penv = getenv("LSINIC_EP_PRINT_STATUS");
	int print_status = 0, ret;
	cpu_set_t cpuset;

	adapter->poll_stat = LSINIC_POLL_START;

	if (penv)
		print_status = atoi(penv);

	CPU_SET(0, &cpuset);
	ret = pthread_setaffinity_np(pthread_self(),
			sizeof(cpu_set_t), &cpuset);
	LSXINIC_PMD_INFO("Cmd/status thread affinity to control cpu 0 %s",
		ret ? "failed" : "success");

	adapter->cycs = rte_get_timer_cycles();

	while (1) {
		if (adapter->poll_stat != LSINIC_POLL_START) {
			adapter->poll_stat = LSINIC_POLL_INIT;
			LSXINIC_PMD_DBG("%s: Quit from polling command",
				eth_dev->data->name);
			return arg;
		}
		if (!adapter->hw_addr)
			goto next_loop;

		reg = LSINIC_REG_OFFSET(adapter->hw_addr, LSINIC_DEV_REG_OFFSET);
		command = LSINIC_READ_REG(&reg->command);
		if (command == PCIDEV_COMMAND_IDLE)
			goto next_loop;

		switch (command) {
		case PCIDEV_COMMAND_DMA_TEST:
			status = lsinic_if_dma_test(eth_dev);
			break;
		case PCIDEV_COMMAND_INIT:
			status = lsinic_if_init(eth_dev);
			break;
		case PCIDEV_COMMAND_START:
			status = lsinic_if_link_up(eth_dev);
			break;
		case PCIDEV_COMMAND_STOP:
			status = lsinic_if_link_down(eth_dev);
			break;
		case PCIDEV_COMMAND_REMOVE:
			status = lsinic_if_remove(eth_dev);
			break;
		case PCIDEV_COMMAND_SET_MAC:
			status = lsinic_set_mac(eth_dev);
			break;
		case PCIDEV_COMMAND_SET_MTU:
			status = lsinic_set_mtu(eth_dev);
			break;
		default:
			status = PCIDEV_RESULT_FAILED;
		}

		LSINIC_WRITE_REG(&reg->result, status);
		rte_wmb();
		status = LSINIC_READ_REG(&reg->result);
		rte_rmb();
		LSINIC_WRITE_REG(&reg->command, PCIDEV_COMMAND_IDLE);

		if (command == PCIDEV_COMMAND_REMOVE && status == PCIDEV_RESULT_SUCCEED)
			lsinic_remove_config_fromrc(eth_dev);

next_loop:
		if (print_status && adapter->ep_state == LSINIC_DEV_UP)
			print_port_status_cycle(eth_dev, &adapter->cycs, LSINIC_EP_PORT);
		sleep(LSINIC_CMD_POLLING_INTERVAL);
	}

	return arg;
}
