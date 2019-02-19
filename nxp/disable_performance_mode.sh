#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2018-2019 NXP

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

# Enable the 'ondemand' mode for the CPU power governors
# This currently supports 16 cores and breaks out after first non-available
# core.
for i in `seq 0 15`
do
	if [ -e "/sys/devices/system/cpu/cpu${i}/cpufreq/scaling_governor" ]
	then
		echo 'ondemand' > /sys/devices/system/cpu/cpu${i}/cpufreq/scaling_governor
	else
		echo "Setting ondemand mode on ${i} cores only."
		break
	fi
done

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
