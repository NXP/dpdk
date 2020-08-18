# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2020 NXP

# meson file, for building this example as part of a main DPDK build.
#
# To build this example as a standalone application with an already-installed
# DPDK instance, use 'make'

build = is_linux
sources = files('lib/client/cmdif_client_flib.c',
	'lib/client/cmdif_client_gpp.c',
	'lib/server/cmdif_srv_flib.c',
	'lib/server/cmdif_srv_gpp.c',
	'lib/shbp/shbp.c',
	'cmdif_demo/main.c')

#CFLAGS += -I$(RTE_SDK)/examples/cmdif/lib
#CFLAGS += -I$(RTE_SDK)/examples/cmdif/lib/client
#CFLAGS += -I$(RTE_SDK)/examples/cmdif/lib/server
#CFLAGS += -I$(RTE_SDK)/examples/cmdif/lib/shbp

includes = include_directories('lib',
			'lib/client',
			'lib/server',
			'lib/shbp',
			'cmdif_demo')

deps += ['rawdev', 'rawdev_dpaa2_cmdif']

allow_experimental_apis = true
