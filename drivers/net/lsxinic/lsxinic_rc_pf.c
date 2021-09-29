/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018-2021 NXP
 */

#include "lsxinic_rc_ethdev.h"

static inline uint16_t
dev_num_vf(struct rte_eth_dev *eth_dev)
{
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);

	return pci_dev->max_vfs;
}

static int
lxsnic_enable_sriov(struct lxsnic_adapter *adapter)
{
	uint8_t i = 0;
	/* enable spoof checking for all VFs */
	for (i = 0; i < adapter->num_vfs; i++)
		adapter->vfinfo[i].spoofchk_enabled = true;

	adapter->flags |= LXSNIC_FLAG_SRIOV_ENABLED;

	return -ENOMEM;
}

int
lxsnic_disable_sriov(struct lxsnic_adapter *adapter)
{
	/* set num VFs to 0 to prevent access to vfinfo */
	adapter->num_vfs = 0;

	/* if SR-IOV is already disabled then there is nothing to do */
	if (!(adapter->flags & LXSNIC_FLAG_SRIOV_ENABLED))
		return 0;

	/* take a breather then clean up driver data */
	adapter->flags &= ~LXSNIC_FLAG_SRIOV_ENABLED;
	return 0;
}

void
lxsnic_pf_host_init(struct rte_eth_dev *eth_dev)
{
	struct vf_data_storage **vfinfo =
		LXSNIC_DEV_PRIVATE_TO_P_VFDATA(eth_dev->data->dev_private);
	struct lxsnic_adapter *adapter =
		LXSNIC_DEV_PRIVATE(eth_dev->data->dev_private);
	uint16_t vf_num;

	RTE_ETH_DEV_SRIOV(eth_dev).active = 0;
	vf_num = dev_num_vf(eth_dev);
	adapter->num_vfs = vf_num;
	LSXINIC_PMD_DBG("lxsnic vf_num is %d", vf_num);
	if (vf_num == 0) {
		lxsnic_disable_sriov(adapter);
		return;
	}

	*vfinfo = rte_zmalloc("lxsnic_vf_info",
			sizeof(struct vf_data_storage) * vf_num, 0);
	if (!(*vfinfo)) {
		rte_panic("Cannot allocate memory for private VF data\n");
		return;
	}

	lxsnic_enable_sriov(adapter);
	/* TODO FIX ENABLE PF INIT */
	RTE_ETH_DEV_SRIOV(eth_dev).active = 0;
}
