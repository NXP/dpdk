# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2025 NXP

if not is_linux
    build = false
    reason = 'only supported on Linux'
endif

deps += ['bus_vdev', 'security']
sources = files(
        'v2x_fce_capabilities.c',
        'v2x_fce_ops.c',
        'v2x_fce_uio.c',
        'v2x_fce_mu.c',
        'v2x_fce_crypt.c',
        'v2x_fce_api.c',
        'v2x_fce.c',
)

includes += include_directories('../../common/dpaax/')
