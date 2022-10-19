# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017 Intel Corporation

# meson file, for building this example as part of a main DPDK build.
#
# To build this example as a standalone application with an already-installed
# DPDK instance, use 'make'

allow_experimental_apis = true

deps += ['hash', 'lpm', 'fib', 'eventdev', 'cmdline', 'acl']
sources = files(
        'main.c',
        'config.c',
        'module.c',
        'worker.c',
        'cli.c',
        'json.c',

        # interface
        'interface/interface.c',

        # decode
        'decode/decode.c',

        # acl
        'acl/acl.c',
)
