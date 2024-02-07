# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2023-2024 NXP

if is_windows
    build = false
    reason = 'not supported on Windows'
    subdir_done()
endif

sources = files(
        'main.c',
)
deps += ['bbdev', 'bus_vdev']
if dpdk_conf.has('RTE_LIBRTE_PMD_BBDEV_LA12XX')
	deps += ['pmd_bbdev_la12xx']
endif
cmd = run_command('sh', '-c', 'echo $COMMON_HEADERS_DIR')
COMMON_HEADERS_DIR = cmd.stdout().strip()
message('COMMON_HEADERS_DIR=' + COMMON_HEADERS_DIR)
allow_experimental_apis = true
includes += [include_directories(COMMON_HEADERS_DIR)]
includes += include_directories('../../drivers/baseband/la12xx/')
