# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2018-2023 NXP

build = dpdk_conf.has('RTE_LIBRTE_DPAA2_MEMPOOL')
reason = 'missing dependency, DPDK DPAA2 mempool driver'
deps += ['rawdev', 'mempool_dpaa2', 'ring', 'kvargs']
sources = files('dpaa2_qdma.c', 'dpaa2_qdma_dmadev.c', 'rte_dmadev.c')

allow_experimental_apis = true

install_headers('rte_pmd_dpaa2_qdma.h')
