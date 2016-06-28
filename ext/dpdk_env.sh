#!/bin/bash

if [ ! -d /mnt/hugetlbfs ]; then
	mkdir /mnt/hugetlbfs
fi

echo 512 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
mount -t hugetlbfs nodev /mnt/hugetlbfs/

insmod ./rte_kni.ko

fmc -c usdpaa_config_ls1043.xml -p usdpaa_policy_hash_ipv4.xml -a
