# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2021 NXP
#

deps += ['bbdev', 'bus_vdev', 'ring']
allow_experimental_apis = true

sources = files('bbdev_la93xx.c')

cmd = run_command('sh', '-c', 'echo $LA9310_COMMON_HEADERS')
LA9310_COMMON_HEADERS = cmd.stdout().strip()
message('LA9310_COMMON_HEADERS=' + LA9310_COMMON_HEADERS)
includes += [include_directories(LA9310_COMMON_HEADERS)]

