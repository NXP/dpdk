# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2022-2023 NXP

# meson file, for building this example as part of a main DPDK build.
#
# To build this example as a standalone application with an already-installed
# DPDK instance, use 'make'

allow_experimental_apis = true
sources = files(
	'main.c'
)

includes += include_directories('../../drivers/net/dpaa/')
includes += include_directories('../../drivers/net/dpaa2/')
