# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2018 NXP

allow_experimental_apis = true

if host_machine.system() != 'linux'
        build = false
endif

sources = files('dpaax_iova_table.c', 'dpaa_of.c')

cflags += ['-D_GNU_SOURCE']
if cc.has_argument('-Wno-cast-qual')
        cflags += '-Wno-cast-qual'
endif
