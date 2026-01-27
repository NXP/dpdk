# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2021-2026 NXP

if not is_linux
    build = false
    reason = 'only supported on linux'
endif

deps += ['common_dpaax']
sources = files(
        'enet_ethdev.c',
        'enet_uio.c',
        'enet_rxtx.c',
)
