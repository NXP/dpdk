# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2018,2020-2021 NXP

if not is_linux
	build = false
	reason = 'only supported on linux'
endif

deps += ['security', 'mempool_dpaa2']
sources = files('dpaa2_sec_dpseci.c',
		'dpaa2_sec_raw_dp.c',
		'mc/dpseci.c')

allow_experimental_apis = true

includes += include_directories('mc', '../../common/dpaax', '../../common/dpaax/caamflib')
