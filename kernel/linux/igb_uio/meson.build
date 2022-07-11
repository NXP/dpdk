# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017 Intel Corporation

kmod_cflags = ''
mkfile = custom_target('igb_uio_makefile',
	output: 'Makefile',
	command: ['touch', '@OUTPUT@'])

igb_sources = files(
        'igb_uio.c',
        'Kbuild',
)
custom_target('igb_uio',
	input: igb_sources,
	output: 'igb_uio.ko',
	command: ['make', '-C', kernel_build_dir,
		'M=' + meson.current_build_dir(),
		'src=' + meson.current_source_dir(),
        ' '.join(['MODULE_CFLAGS=', kmod_cflags,'-include '])
        + meson.source_root() + '/config/rte_config.h' +
        ' -I' + meson.source_root() + '/lib/eal/include' +
        ' -I' + meson.build_root() +
        ' -I' + meson.current_source_dir(),
        'modules'] + cross_args,
	depends: mkfile,
	install: true,
    install_dir: kernel_install_dir,
	build_by_default: get_option('enable_kmods'))
