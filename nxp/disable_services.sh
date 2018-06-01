#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2018 NXP

ISSUEFILE="/etc/os-release"

# This script should be executed as root user. Sudo might not work for
# various services.
function validate_root_user() {
	if [ "$EUID" -ne 0 ]
	then
		echo "Not a root user!."
		echo "This script should be run as 'root' (not sudo)."
		exit -1
	fi
}

# Check if this platform is Ubuntu or not. This script need not be run on
# non-Ubuntu environment.
# Validation based on info from:
# https://www.freedesktop.org/software/systemd/man/os-release.html
function validate_ubuntu() {
	isUbuntu=0
	if [ -e $ISSUEFILE ]
	then
		# If '/etc/issue', "Ubuntu" should be present in it
		cat $ISSUEFILE | grep $"NAME=\"Ubuntu\"" > /dev/null
		returnval=$?
		if [ $returnval -eq 0 ]
		then
			isUbuntu=1
		fi
	fi

	if [ $isUbuntu -ne 1 ]
	then
		echo "Not an Ubuntu environment!."
		echo "This script is valid for Ubuntu environment only."
		exit -1
	fi
}

validate_root_user
validate_ubuntu

# This script will be used to disable the services on ls2088
# board in order to take performance numbers

systemctl stop systemd-timesyncd.service > /dev/null 2>&1
systemctl stop time-sync.target > /dev/null 2>&1
systemctl stop timers.target > /dev/null 2>&1
systemctl stop ureadahead-stop.timer > /dev/null 2>&1

service apparmor stop > /dev/null 2>&1
service console-setup stop > /dev/null 2>&1
service ebtables stop > /dev/null 2>&1
service keyboard-setup stop > /dev/null 2>&1
service kmod stop > /dev/null 2>&1
service networking stop > /dev/null 2>&1
service procps stop > /dev/null 2>&1
service qemu-kvm stop > /dev/null 2>&1
service resolvconf stop > /dev/null 2>&1
service udev stop > /dev/null 2>&1
service urandom stop > /dev/null 2>&1
service web-sysmon.sh stop > /dev/null 2>&1
service cgmanager stop > /dev/null 2>&1
service cpufrequtils stop > /dev/null 2>&1
service cron stop > /dev/null 2>&1
service docker stop > /dev/null 2>&1
service dbus stop > /dev/null 2>&1
service libvirt-bin stop > /dev/null 2>&1
service libvirt-guests stop > /dev/null 2>&1
service lm-sensors stop > /dev/null 2>&1
service loadcpufreq stop > /dev/null 2>&1
service lxcfs stop > /dev/null 2>&1
service mountdebugfs stop > /dev/null 2>&1
service netperf stop > /dev/null 2>&1
service nginx stop > /dev/null 2>&1
service ondemand stop > /dev/null 2>&1
service rc.local stop > /dev/null 2>&1
service rsyslog stop > /dev/null 2>&1
service setkey stop > /dev/null 2>&1
service ssh stop > /dev/null 2>&1
service sysfsutils stop > /dev/null 2>&1
service sysstat stop > /dev/null 2>&1
service ubuntu-fan stop > /dev/null 2>&1
service vsftpd stop > /dev/null 2>&1
service udev stop > /dev/null 2>&1
