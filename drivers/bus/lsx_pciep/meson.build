# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2022 NXP

if not is_linux
    build = false
    reason = 'only supported on Linux'
endif

deps += ['kvargs', 'common_dpaax']

sources = files(
	'lsx_pciep_bus.c',
	'lsx_pciep_pcie.c',
	'lsx_pciep_dw.c',
	'lsx_pciep_mv.c'
)

includes += include_directories('../../../lib/pci')
