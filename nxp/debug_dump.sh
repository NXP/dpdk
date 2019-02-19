#!/bin/bash -i
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2018-2020 NXP

# tunable parameters

logoutput="dpdk_debug_"
logoutput="${logoutput}_"`date +%d%m%Y_%H%M%S`".txt"
silent=0
# Some colors

RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

function print() {
	echo -e "$@" >> ${logoutput}
}

function mycmd() {
	print "CMD: $@"
	$@ >> ${logoutput}
	if [ $? -ne 0 ]; then
		echo -e "Error in ${RED}${OUTPUT}${NC}"
#		exit 1
	fi
}

function devicetree() {
	cmd="dtc -I fs /sys/firmware/devicetree/base"
	${cmd} >> ${logoutput}
	if [ $? -ne 0 ]; then
		echo -e "Error in dtc"
		cmd="cat /proc/device-tree/*/*"
		${cmd} >> ${logoutput}
	fi
}

function system() {
	print "*************** Boot message"
	dmesg | head -100 >> $(logoutput)
	print "*************** kernel version*******"
	mycmd "uname -a"
	print "*************** Bootargs*******"
	mycmd "cat /proc/cmdline"
	print "*************** CPU Architecture*******"
	mycmd "lscpu"
	print "*************** PCI details *******"
	mycmd "lspci -v"
	print "*************** Block Details *******"
	mycmd "lsblk"
	print "*************** Loaded modules *******"
	mycmd "lsmod"
	print "*************** CPU INFO *******"
	mycmd "cat /proc/cpuinfo"
	print "*************** MEMINFO *******"
	mycmd "cat /proc/meminfo"
	print "*************** network interfaces"
	mycmd "ifconfig -a"
	print "*************** Distro information"
	mycmd "cat /etc/*-release"
	mycmd "cat /proc/version"
	print "*************** Env"
	mycmd "env"
	print "*************** Kernel config"
	mycmd "zcat /proc/config.gz"

	print "*************** Performance Settings"
	local gov_set=`cat /sys/devices/system/cpu/cpufreq/policy0/scaling_governor`
	print "Performance governor set to: ${gov_set}"
	local max_freq=`cat /sys/devices/system/cpu/cpufreq/policy0/scaling_max_freq`
	local min_freq=`cat /sys/devices/system/cpu/cpufreq/policy0/scaling_min_freq`
	print "Current Max CPU freq is ${max_freq} and Min is ${min_freq}"
	local rt_us=`cat /proc/sys/kernel/sched_rt_runtime_us`
	print "Value for Userspace non-RT slice: ${rt_us}"
}

function system_adv() {

	print "*************** Device tree"
	devicetree

	print "*************** History"
	history 100 >> ${logoutput}

	print "*************** systemd *******"
	mycmd "systemctl status"

	print "*************** ZONEINFO *******"
	mycmd "cat /proc/zoneinfo"
	print "*************** Mounts *******"
	mycmd "cat /proc/mounts"

	print "*************** Display the currently netstat"
	mycmd "netstat -lnp --ip"

	print "*************** Find the Top 10 Memory Consuming Processes"
	ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%mem | head >> ${logoutput}
	print "*************** Find the Top 10 CPU Consuming Processes"
	ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%cpu | head >> ${logoutput}

	print "*************** Display Memory Utilization Slabinfo"
	mycmd "vmstat -m"
}

function ppfe_info() {
	echo "PPFE: $@" >> ${logoutput}
	mycmd "ls /sys/module/pfe/parameters/*"
	mycmd "cat /sys/module/pfe/parameters/*"
}

function dpaa_info() {
	echo "DPAA1: $@" >> ${logoutput}
	fmc --version >> ${logoutput}

	echo "Stats are: " >> ${logoutput}
	echo "port_dealloc_buf " >> ${logoutput}
	echo "port_deq_confirm " >> ${logoutput}
	echo "port_deq_from_default " >> ${logoutput}
	echo "port_deq_total " >> ${logoutput}
	echo "port_discard_frame " >> ${logoutput}
	echo "port_enq_total " >> ${logoutput}
	echo "port_frame " >> ${logoutput}
	echo "port_length_err " >> ${logoutput}
	echo "port_unsupprted_format " >> ${logoutput}

	mycmd "cat /sys/devices/platform/soc/*.fman/*.port/statistics/*"
	mycmd "cat /sys/devices/platform/soc/*.fman/*.port/uevent"
	mycmd "ls /sys/devices/platform/soc/*.qman/subsystem/devices"
	mycmd "cat /sys/kernel/debug/bman/query_bp_state"
	mycmd "cat /sys/devices/platform/soc/*.bman/pool_count/*"
}


function dpaa2_info() {
	echo "DPAA2: $@" >> ${logoutput}
	restool -v >> ${logoutput}
	restool -m >> ${logoutput}
	mycmd "ls-listmac"
	mycmd "ls-listni"
	for i in `restool dprc show $DPRC | tr -s "^I" | cut -f1`;
	do
		TYPE=$(echo $i | cut -f1 -d '.')
		echo "$i"
		if [ "$TYPE" == "dpni" -o "$TYPE" == "dpseci" ]
		then
			echo "============================"
			restool $TYPE info $i >> outfile
			echo "============================"
		fi
	done
}

function usage() {
	echo "Usage: $0 [-o <logfile>]"
	echo "           -o Output file. if not specified and randomly generated"
	echo "              file is used."
	echo
	echo "           -h This help"
}

#/* Function, to get platform info
#*/
function board_config() {
	if [ -e /sys/firmware/devicetree/base/compatible ]
	then
	board_type=`grep -ao '1012\|1046\|1043\|1088\|2088\|2160' /sys/firmware/devicetree/base/compatible | head -1`
	fi

	echo "Board type ${board_type} detected."

	print "Board Detected is ${board_type}"

	if [[ $board_type == "1088" || $board_type == "2088" || $board_type == "2160" ]]
	then
		platform="dpaa2"
		echo "platform detected is ${platform}"
		dpaa2_info
	fi
	if [[ $board_type == "1043" || $board_type == "1046" ]]
	then
		platform="dpaa"
		echo "platform detected is ${platform}"
		dpaa_info
	fi

	if [[ $board_type == "1012" ]]
	then
		platform="ppfe"
		echo "platform detected is ${platform}"
		ppfe_info
	fi
}

function dump_configuration() {
	echo "Output redirected to $logoutput"
	print "============================================"
	system
	system_adv
	print "============================================"
	board_config
	print "==========================================="
}

while getopts ":o:h" o; do
	case "${o}" in
		o)
			logoutput=${OPTARG}
			if [ ! -e ${logoutput} ]; then
				touch ${logoutput}
			fi
			silent=1
			touch ${logoutput}
			if [ $? -ne 0 ]; then
				print "Unable to create output file; Disabling Output to file"
				silent=0
				logoutput=
			fi
			;;
		h)
			usage
			exit 1
			;;
		*)
			if [ "$OPTERR" != 1 ] || [ "${o:0:1}" = ":" ]; then
				usage
				exit 1
			fi
			;;
		\?)
			echo "Unknown argument"
			usage
			exit 1
			;;
	esac
done

dump_configuration
echo "Output redirected to $logoutput"
