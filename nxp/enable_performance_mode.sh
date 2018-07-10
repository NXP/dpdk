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
	return 0
}

validate_root_user
if [ $? -ne 0 ]
then
	[ "$0" == "-bash" ] && return 1 || exit 1
fi

# Enable the 'performance' mode for the CPU power governors
# Following also assumes the default 'policy0' is being used by the system.
if [ -e "/sys/devices/system/cpu/cpufreq/policy0/scaling_governor" ]
then
	echo "performance" > /sys/devices/system/cpu/cpufreq/policy0/scaling_governor
else
	echo "ERROR: Failed to set governor; Not enabling performance mode"
fi

# Disable some watchdogs so as not to complain in case RT priority process
# of DPDK application hog the CPU. Ignore errors like non-existent file.
echo 0 > /proc/sys/kernel/hung_task_timeout_secs
echo 0 > /proc/sys/kernel/nmi_watchdog
echo 0 > /proc/sys/kernel/hung_task_check_count
echo 0 > /proc/sys/kernel/hung_task_warnings
echo 0 > /proc/sys/kernel/soft_watchdog

# Finally, reduce timeslice for non-RT processes. This directly impacts the
# Core 0 (non-isolated cores). Once this is set, a RT application which
# doesn't yield the CPU would stall it.

if [ -e "/proc/sys/kernel/sched_rt_runtime_us" ]
then
	echo -1 > /proc/sys/kernel/sched_rt_runtime_us
	echo "WARN: Hereafter, don't execute RT tasks on Core 0"
else
	echo "Unable to reduce non-RT timeslice; Performance will be reduced"
fi

# Enable the DPDK Performance mode; This script should be 'source'd rather
# than directly executed for this to take effect.
if [ "$0" != "-bash" ]
then
	# this script was probably executed using "./enable_performance_mode"
	echo "This script should be sourced and not directly executed!"
	echo "Please run:"
	echo "export NXP_CHRT_PERF_MODE=1"
else
	export NXP_CHRT_PERF_MODE=1
fi
