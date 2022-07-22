#!/bin/bash -i
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2018-2022 NXP

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
	mycmd "cat /proc/iomem"
	print "*************** interrupts *******"
	mycmd "cat /proc/interrupts"
	print "*************** misc *******"
	mycmd "cat /proc/devices"
	mycmd "cat /proc/execdomains"
	mycmd "cat /proc/buddyinfo"
	mycmd "cat /proc/misc"

	print "*************** network interfaces"
	mycmd "ifconfig -a"
	print "*************** Distro information"
	mycmd "cat /etc/*-release"
	mycmd "cat /proc/version"
	mycmd "lsb_release -a"

	print "*************** Env"
	mycmd "env"

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
	for i in `ls-listmac | sed -e "s/dprc.1\///" | cut -f1 -d '('`;
	do
		echo "============================" >> ${logoutput}
		mycmd "restool dpmac info $i"
	done
	mycmd "ls-listni"
	for i in `restool dprc show $DPRC | tr -s "^I" | cut -f1`;
	do
		TYPE=$(echo $i | cut -f1 -d '.')
		echo "$i" >> ${logoutput}
		if [[ "$TYPE" == "dpni" || "$TYPE" == "dpseci" ]]
		then
			echo "============================" >> ${logoutput}
			mycmd "restool $TYPE info $i"
		fi
		if [[ "$TYPE" == "dpmac" || "$TYPE" == "dpdmux" ]]
		then
			echo "============================" >> ${logoutput}
			mycmd "restool $TYPE info $i"
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
	board_type=`grep -ao 'imx8m\|imx9\|1028\|1012\|1046\|1043\|1088\|2088\|2160\|2162' /sys/firmware/devicetree/base/compatible | head -1`
	fi

	echo "Board type ${board_type} detected."

	print "Board Detected is ${board_type}"

	if [[ $board_type == "1088" || $board_type == "2088" || $board_type == "2160" || $board_type == "2162" ]]
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
	if [[ $board_type == "1028" ]]
	then
		platform="enetc"
		echo "platform detected is ${platform}"
	fi
	if [[ $board_type == "imx8m" || $board_type == "imx9" ]]
	then
		platform="fec-enet"
		echo "platform detected is ${platform}"
	fi
}

function dump_configuration() {
	echo "Output redirected to $logoutput"
	print "============================================"
	system
	system_adv
	print "============================================"
	board_config
	print "===============SYSCTL =================="
	mycmd "sysctl -a"
	print "===============Kernel Config =================="
	mycmd "zcat /proc/config.gz"
	print "===============Device Tree =================="
	devicetree
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
