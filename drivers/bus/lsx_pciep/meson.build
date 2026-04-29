# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2022-2026 NXP

if not is_linux
    build = false
    reason = 'only supported on Linux'
endif

deps += ['kvargs', 'common_dpaax', 'bus_fslmc']

sources = files(
	'lsx_pciep_bus.c',
	'lsx_pciep_pcie.c',
	'lsx_pciep_dw.c',
	'lsx_pciep_mv.c',
	'lsx_pciep_base_symbols.c'
)

includes += include_directories('../../../lib/pci')
includes += include_directories('../../../lib/mbuf')
includes += include_directories('../../../lib/mempool')
includes += include_directories('../../../lib/ring')
includes += include_directories('../../../lib/eventdev')
includes += include_directories('../../../kernel/linux/kpage_ncache')
includes += include_directories('../fslmc')

cflags += no_wvla_cflag
