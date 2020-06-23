# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017 Intel Corporation

# meson file, for building this example as part of a main DPDK build.
#
# To build this example as a standalone application with an already-installed
# DPDK instance, use 'make'

deps += ['hash', 'lpm','eventdev']
sources = files(
	'l3fwd_em.c', 'l3fwd_lpm.c', 'main.c'
)
if dpdk_conf.has('RTE_LIBRTE_DPAA2_PMD')
	deps += ['bus_fslmc', 'mempool_dpaa2', 'pmd_dpaa2']
endif
# depends on dpaa2 bus which uses experimental API
allow_experimental_apis = true
