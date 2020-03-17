# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2020 NXP

if not is_linux
	build = false
	reason = 'only supported on linux'
endif

deps += ['rawdev', 'bus_dpaa']
sources = files('dpaa_qdma.c')
includes += include_directories('../dpaa2_qdma')

allow_experimental_apis = true

if cc.has_argument('-Wno-pointer-arith')
	cflags += '-Wno-pointer-arith'
endif
