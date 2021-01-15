# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2018 Luca Boccassi <bluca@debian.org>
# Copyright 2020-2021 NXP

if is_windows
	subdir_done()
endif

drivers = ['null', 'turbo_sw', 'fpga_lte_fec', 'fpga_5gnr_fec', 'acc100']

cmd = run_command('sh', '-c', 'echo $COMMON_HEADERS_DIR')
COMMON_HEADERS_DIR = cmd.stdout().strip()
if COMMON_HEADERS_DIR != ''
drivers += ['la12xx']
endif

config_flag_fmt = 'RTE_LIBRTE_PMD_BBDEV_@0@'
