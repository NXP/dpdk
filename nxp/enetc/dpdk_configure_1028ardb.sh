#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2019-2020 NXP
#
# DPDK script to configure 1 switch (swp0) and 1 enetc port
# for forwarding
#
# Assume both ENETC and Felix drivers are already loaded
#

BRIDGE=br0

# Mount hugetlbfs
mkdir -p /dev/hugepages
mount -t hugetlbfs hugetlbfs /dev/hugepages
echo 256 > /proc/sys/vm/nr_hugepages

# Bind enetc0 device to vfio
echo vfio-pci > /sys/bus/pci/devices/0000\:00\:00.0/driver_override
echo 0000:00:00.0 > /sys/bus/pci/drivers/fsl_enetc/unbind
echo 0000:00:00.0 > /sys/bus/pci/drivers/vfio-pci/bind

swps=($(ls /sys/bus/pci/devices/0000:00:00.5/net/))
nr=${#swps[@]}

# Create bridge device
ip link add name $BRIDGE type bridge

# Up the kernel enetc2 port
enetc2=$(ls /sys/bus/pci/devices/0000:00:00.2/net/)
ifconfig $enetc2 up

for (( i=0; i<$nr; i++ ))
do
	echo "adding ${swps[$i]} to brigde .."
	ip link set ${swps[$i]} master $BRIDGE
	if [[ "${swps[$i]}" == "swp0" || "${swps[$i]}" == "swp5" ]]
	then
		ifconfig ${swps[$i]} up
	else
		ifconfig ${swps[$i]} down
	fi
done

echo vfio-pci > /sys/bus/pci/devices/0000\:00\:00.6/driver_override
echo 0000:00:00.6 > /sys/bus/pci/drivers/fsl_enetc/unbind
echo 0000:00:00.6 > /sys/bus/pci/drivers/vfio-pci/bind
ifconfig $BRIDGE up
