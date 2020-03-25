# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2020 NXP
#

deps += ['bbdev', 'bus_vdev', 'ring']
allow_experimental_apis = true
sources = files('bbdev_la12xx.c')
cflags += ['-DHOST=1',
           '-DMODEM=0']
cmd = run_command('sh', '-c', 'echo $LA12XX_COMMON_HDR_DIR')
LA12XX_COMMON_HDR_DIR = cmd.stdout().strip()
message('LA12XX_COMMON_HDR_DIR=' + LA12XX_COMMON_HDR_DIR)
includes += [include_directories(LA12XX_COMMON_HDR_DIR)]
