# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017 Intel Corporation
# Copyright 2022-2023 NXP
#
# meson file, for building this example as part of a main DPDK build.
#
# To build this example as a standalone application with an already-installed
# DPDK instance, use 'make'

allow_experimental_apis = true
deps += ['security', 'lpm', 'acl', 'hash', 'ip_frag', 'ipsec', 'eventdev', 'telemetry']
sources = files(
	'ipsec_ike.c',
	'pfkey_utils.c',
	'xfrm_km.c',
)
