# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017 Intel Corporation
# Copyright 2024 NXP

subdir('base')

if dpdk_conf.get('RTE_USE_NON_CACHE_MEM') == 1
         deps += ['common_dpaax']
endif

sources += files(
        'e1000_logs.c',
        'em_ethdev.c',
        'em_rxtx.c',
        'igb_ethdev.c',
        'igb_flow.c',
        'igb_pf.c',
        'igb_rxtx.c',
)

# do not build IGC on Windows
if not is_windows
        sources += files(
                'igc_ethdev.c',
                'igc_logs.c',
                'igc_filter.c',
                'igc_flow.c',
                'igc_txrx.c',
        )
endif
includes += include_directories('../../../../kernel/linux/kpage_ncache')
