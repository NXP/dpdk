# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2022-2023 NXP

if not is_linux
    build = false
    reason = 'only supported on Linux'
endif

deps += ['kvargs', 'common_dpaax', 'bus_fslmc']

sources = files(
	'lsx_pciep_bus.c',
	'lsx_pciep_pcie.c',
	'lsx_pciep_dw.c',
	'lsx_pciep_mv.c'
)

includes += include_directories('../../../lib/pci')
includes += include_directories('../../../lib/mbuf')
includes += include_directories('../../../lib/mempool')
includes += include_directories('../../../lib/ring')
includes += include_directories('../../../lib/eventdev')
includes += include_directories('../fslmc')
