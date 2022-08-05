# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2022 NXP


kmod_cflags = ''
mkfile = custom_target('kpage_ncache_makefile',
	output: 'Makefile',
	command: ['touch', '@OUTPUT@'])

kpage_ncache_sources = files(
        'kpage_ncache.c',
		'Kbuild',
)
custom_target('kpage_ncache',
	input: kpage_ncache_sources,
	output: 'kpage_ncache.ko',
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
