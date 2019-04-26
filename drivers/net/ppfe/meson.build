# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2019 NXP

if host_machine.system() != 'linux'
	build = false
endif
deps += ['bus_dpaa']

sources = files('rte_eth_pfe.c',
		'pfe_hal.c',
		'pfe_hif_lib.c',
		'pfe_hif.c')

allow_experimental_apis = true

includes += include_directories('base', '../../bus/dpaa/include/')
