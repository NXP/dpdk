#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2020 NXP

# script 'update_split_port_mac_addr.sh' extract the MAC address from the dpmac
# and assign to kernel(eth0) and DPDK interface(dpni)
#
# USAGE:   . ./update_split_port_mac_addr.sh <dpmac> <kernel_eth> <dpdk_ni>
# Example: . ./update_split_port_mac_addr.sh dpmac.1 eth0 dpni.2
#
# Note:
# This script required the input arguments (dpmac, kernel and dpdk interface)
# from the user and assign MAC address accordingly.

# Extract the MAC address from dpmac
mac="$(restool dpmac info $1 | awk '/MAC address/ {print $3}')"

# Update the MAC address to Linux kernel and DPDK interface
ifconfig $2 hw ether $mac
restool dpni update $3 --mac-addr=$mac

if [ $? -eq 0 ]; then
	echo "MAC address $mac is updated to both $2 and $3 "
else
	echo "Invalid!"
fi

# End of the script
