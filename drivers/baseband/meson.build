# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2018 Luca Boccassi <bluca@debian.org>

if is_windows
    subdir_done()
endif

drivers = [
        'acc',
        'fpga_5gnr_fec',
        'fpga_lte_fec',
        'null',
        'turbo_sw',
]

cmd = run_command('sh', '-c', 'echo $COMMON_HEADERS_DIR')
COMMON_HEADERS_DIR = cmd.stdout().strip()
if COMMON_HEADERS_DIR != ''
  drivers += 'la12xx'
endif
message('####### Dumping list of compiled baseband drivers ########')
foreach elem : drivers
  message (elem)
endforeach

log_prefix = 'pmd.bb'
