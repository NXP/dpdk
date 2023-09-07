# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2021-2026 NXP

if not is_linux
    build = false
    reason = 'only supported on Linux'
endif

deps += ['common_dpaax']
sources = files(
	'enetqos_ethdev.c',
	'enetqos_rxtx.c',
)

includes += include_directories('../../../kernel/linux/kpage_ncache')
