# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2022 NXP

if not is_linux
    build = false
    reason = 'only supported on Linux'
endif

deps += ['bus_lsx_pciep', 'dmadev', 'dma_dpaa2', 'net_dpaa2']
sources = files(
	'lsxinic_common_helper.c',
	'lsxinic_ep_ethdev.c',
	'lsxinic_ep_rxtx.c',
	'lsxinic_ep_dma.c',
	'lsxinic_ep_ethtool.c',
	'lsxinic_ep_tool.c',
	'lsxinic_rc_ethdev.c',
	'lsxinic_rc_rxtx.c',
	'lsxinic_rc_pf.c'
)

includes += include_directories(
	'../../bus/fslmc',
	'../../bus/fslmc/mc',
	'../../bus/fslmc/portal',
	'../../bus/fslmc/qbman/include',
	'../../mempool/dpaa2',
	'../dpaa2/mc',
)
