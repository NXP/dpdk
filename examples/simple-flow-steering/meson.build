# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2026 NXP
#
# meson file, for building this example as part of a main DPDK build.
#
# To build this example as a standalone application with an already-installed
# DPDK instance, use 'make'

allow_experimental_apis = true
if dpdk_conf.has('RTE_NET_DPAA2')
        deps += ['net_dpaa2', 'event_dpaa2']
endif
sources = files(
        'main.c',
)

includes += include_directories('../../drivers/net/dpaa2/')
