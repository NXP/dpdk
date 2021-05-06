# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2018 Luca Boccassi <bluca@debian.org>

drivers = ['null', 'turbo_sw', 'fpga_lte_fec']

cmd = run_command('sh', '-c', 'echo $COMMON_HEADERS_DIR')
COMMON_HEADERS_DIR = cmd.stdout().strip()
if COMMON_HEADERS_DIR != ''
drivers += ['la12xx']
endif

cmd = run_command('sh', '-c', 'echo $LA9310_COMMON_HEADERS')
LA9310_COMMON_HEADERS = cmd.stdout().strip()
if LA9310_COMMON_HEADERS != ''
drivers += ['la93xx']
endif

config_flag_fmt = 'RTE_LIBRTE_PMD_BBDEV_@0@'
driver_name_fmt = 'rte_pmd_bbdev_@0@'
