/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018-2021 NXP
 */

#ifndef _LSINIC_ETHTOOL_H_
#define _LSINIC_ETHTOOL_H_

#include <linux/pci.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>

void lsinic_set_ethtool_ops(struct net_device *netdev);

#endif
