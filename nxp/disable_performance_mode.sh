#!/bin/bash
# spdx-license-identifier: bsd-3-clause
# copyright 2018 nxp

# This script should be executed as root user.
function validate_root_user() {
	if [ "$EUID" -ne 0 ]
	then
		echo "Not a root user!."
		echo "This script should be run as 'root' (not sudo)."
		return 1
	fi
}

validate_root_user
if [ $? -ne 0 ]
then
	[ "$0" == "-bash" ] && return 1 || exit 1
fi

# Restore the non-RT timeslice so that Core 0 has enough CPU cycles to execute
# non RT tasks
if [ -e "/proc/sys/kernel/sched_rt_runtime_us" ]
then
	# Assuming it to be 95% - default for LSDK Ubuntu
	echo 950000 > /proc/sys/kernel/sched_rt_runtime_us
fi

# Restore the governor back to 'ondemand' - which is default for Ubuntu.
if [ -e "/sys/devices/system/cpu/cpufreq/policy0/scaling_governor" ]
then
	echo "ondemand" > /sys/devices/system/cpu/cpufreq/policy0/scaling_governor
fi

# Enable the DPDK Performance mode; This script should be 'source'd rather
# than directly executed for this to take effect.
if [ "$0" != "-bash" ]
then
	# this script was probably executed using "./enable_performance_mode"
	echo "This script should be sourced and not directly executed!"
	echo "Please run:"
	echo "unset NXP_CHRT_PERF_MODE"
else
	unset NXP_CHRT_PERF_MODE
fi
