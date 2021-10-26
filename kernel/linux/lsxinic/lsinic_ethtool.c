/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018-2021 NXP
 */

#include "lsinic_ethtool.h"
#include "lsinic_kmod.h"
#include <linux/ethtool.h>

static void lsinic_get_drvinfo(struct net_device *netdev,
			struct ethtool_drvinfo *drvinfo)
{
	struct lsinic_adapter *adapter = netdev_priv(netdev);

	strlcpy(drvinfo->driver, lsinic_driver_name,
		sizeof(drvinfo->driver));

	strlcpy(drvinfo->version, lsinic_driver_version,
		sizeof(drvinfo->version));

	strlcpy(drvinfo->bus_info, pci_name(adapter->pdev),
		sizeof(drvinfo->bus_info));
}

#ifndef ETHTOOL_GLINKSETTINGS
static int lsinic_get_settings(struct net_device *netdev,
				struct ethtool_cmd *ecmd)
{
	struct lsinic_adapter *adapter = netdev_priv(netdev);

	ecmd->supported = (SUPPORTED_100baseT_Full |
			SUPPORTED_1000baseT_Full|
			SUPPORTED_10000baseT_Full);

	ethtool_cmd_speed_set(ecmd, adapter->link_speed);
	ecmd->duplex = DUPLEX_FULL;

	return 0;
}
#endif

static const struct ethtool_ops lsinic_ethtool_ops = {
	.get_drvinfo		= lsinic_get_drvinfo,
#ifndef ETHTOOL_GLINKSETTINGS
	.get_settings		= lsinic_get_settings,
#endif
};

void lsinic_set_ethtool_ops(struct net_device *netdev)
{
	netdev->ethtool_ops = &lsinic_ethtool_ops;
}
