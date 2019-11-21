#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2019 NXP
#
# DPDK script to configure 1 switch (swp0) and 1 enetc port
# for forwarding
#
# Assume both ENETC and Felix drivers are already loaded
#

BRIDGE=br0
MAC_ROOT=bc:8d:bf:7c:5b
SW_NETNS=swns
EXEC_SWNS="ip netns exec $SW_NETNS"

# Create bridge namespace
ip netns add $SW_NETNS
# Create bridge device in net namespace
$EXEC_SWNS ip link add name $BRIDGE type bridge
$EXEC_SWNS ip link set $BRIDGE up

# Configure switch ports
#  * set MAC address
#  * bring up interface
#  * move net device into the bridge net namespace
#  * set bridge device as master
swps=($(ls /sys/bus/pci/devices/0000:00:00.5/net/))
nr=${#swps[@]}
for (( i=0; i<$nr; i++ ))
do
	echo "adding ${swps[$i]} to brigde .."
	ip link set ${swps[$i]} address $MAC_ROOT:$(echo "${swps[$i]}" | tr -dc '0-9')
	ip link set ${swps[$i]} netns $SW_NETNS
	$EXEC_SWNS ip link set ${swps[$i]} master $BRIDGE
	if [[ "${swps[$i]}" == "swp0" || "${swps[$i]}" == "swp4" ]]
	then
		$EXEC_SWNS ip link set ${swps[$i]} up
	else
		$EXEC_SWNS ifconfig ${swps[$i]} down
	fi
done

# move ENETC port connected to switch CPU port in bridge ns
enetc3=$(ls /sys/bus/pci/devices/0000:00:00.6/net/)
ip link set $enetc3 netns $SW_NETNS
$EXEC_SWNS ifconfig $enetc3 down

# Check configuration
$EXEC_SWNS bridge link show

# Mount hugetlbfs
mkdir -p /dev/hugepages
mount -t hugetlbfs hugetlbfs /dev/hugepages
echo 256 > /proc/sys/vm/nr_hugepages

# Bind enetc devices to vfio
echo vfio-pci > /sys/bus/pci/devices/0000\:00\:00.0/driver_override
echo 0000:00:00.0 > /sys/bus/pci/drivers/fsl_enetc/unbind
echo 0000:00:00.0 > /sys/bus/pci/drivers/vfio-pci/bind

echo vfio-pci > /sys/bus/pci/devices/0000\:00\:00.2/driver_override
echo 0000:00:00.2 > /sys/bus/pci/drivers/fsl_enetc/unbind
echo 0000:00:00.2 > /sys/bus/pci/drivers/vfio-pci/bind
