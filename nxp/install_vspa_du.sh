#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2021 NXP

help() {
	echo
	echo "USAGE: . ./install_vspa_du.sh <options>
The Options are:
	-m		Mode			vdma, ipc or org
						vdma: install DU VSPA DMA binaries for VSPA loading
						ipc: install DU VSPA IPC binaries for VSPA loading
						org: to install original binaries (which will be kept
						      as backup when using 'vdma' or 'ipc' mode)

	-h		Display help		Display this help"
}

VDMA_INPUT_NAME=/lib/firmware/geul-vspa-vdma-du.eld
IPC_INPUT_NAME=/lib/firmware/geul-vspa-ipc-du.eld

load_img() {
	cp -n /lib/firmware/geul-vspa0.eld /lib/firmware/geul-vspa0-org.eld
	cp -n /lib/firmware/geul-vspa1.eld /lib/firmware/geul-vspa1-org.eld
	cp -n /lib/firmware/geul-vspa2.eld /lib/firmware/geul-vspa2-org.eld
	cp -n /lib/firmware/geul-vspa3.eld /lib/firmware/geul-vspa3-org.eld
	cp -n /lib/firmware/geul-vspa4.eld /lib/firmware/geul-vspa4-org.eld
	cp -n /lib/firmware/geul-vspa5.eld /lib/firmware/geul-vspa5-org.eld
	cp -n /lib/firmware/geul-vspa6.eld /lib/firmware/geul-vspa6-org.eld
	cp -n /lib/firmware/geul-vspa7.eld /lib/firmware/geul-vspa7-org.eld

	if [ ! -f "${FILE_INPUT_NAME}" ]
	then
		echo "${FILE_INPUT_NAME} does not exist.. exitting"
		[[ "${BASH_SOURCE[0]}" != $0 ]] && return || exit
	fi

	echo "Installing file ${FILE_INPUT_NAME}"
	ln -fs ${FILE_INPUT_NAME} /lib/firmware/geul-vspa0.eld
	ln -fs ${FILE_INPUT_NAME} /lib/firmware/geul-vspa1.eld
	ln -fs ${FILE_INPUT_NAME} /lib/firmware/geul-vspa2.eld
	ln -fs ${FILE_INPUT_NAME} /lib/firmware/geul-vspa3.eld
	ln -fs ${FILE_INPUT_NAME} /lib/firmware/geul-vspa4.eld
	ln -fs ${FILE_INPUT_NAME} /lib/firmware/geul-vspa5.eld
	ln -fs ${FILE_INPUT_NAME} /lib/firmware/geul-vspa6.eld
	ln -fs ${FILE_INPUT_NAME} /lib/firmware/geul-vspa7.eld
	sync
}

load_org() {
	if [ ! -f "/lib/firmware/geul-vspa0-org.eld" ]; then
		echo "Original files not present"
	fi

	echo "Installing original files"
	ln -fs /lib/firmware/geul-vspa0-org.eld /lib/firmware/geul-vspa0.eld
	ln -fs /lib/firmware/geul-vspa1-org.eld /lib/firmware/geul-vspa1.eld
	ln -fs /lib/firmware/geul-vspa2-org.eld /lib/firmware/geul-vspa2.eld
	ln -fs /lib/firmware/geul-vspa3-org.eld /lib/firmware/geul-vspa3.eld
	ln -fs /lib/firmware/geul-vspa4-org.eld /lib/firmware/geul-vspa4.eld
	ln -fs /lib/firmware/geul-vspa5-org.eld /lib/firmware/geul-vspa5.eld
	ln -fs /lib/firmware/geul-vspa6-org.eld /lib/firmware/geul-vspa6.eld
	ln -fs /lib/firmware/geul-vspa7-org.eld /lib/firmware/geul-vspa7.eld
	sync
}

#/*
# * Parsing the arguments.
# */
if [[ $1 ]]
then
	for i in "$@"
	do
		case $i in
			-h)
				help
				[[ "${BASH_SOURCE[0]}" != $0 ]] && return || exit
				;;
			-m=*)
				mode="${i#*=}"
				;;
			*)
				echo "Invalid option $i"
				help
				[[ "${BASH_SOURCE[0]}" != $0 ]] && return || exit
				;;
		esac
	done
fi

if [[ -z "$mode" ]]
then
	echo "mode not specified, installing default VDMA binary"
	mode=vdma
fi

if [[ $mode = "vdma" ]]
then
	FILE_INPUT_NAME=${VDMA_INPUT_NAME}
	load_img
elif [[ $mode = "ipc" ]]
then
	FILE_INPUT_NAME=${IPC_INPUT_NAME}
	load_img
elif [[ $mode = "org" ]]
then
	load_org
else
	echo "Invalid mode $mode"
fi
