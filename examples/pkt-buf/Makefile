# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2020 NXP

ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

# Default target, can be overridden by command line or environment
RTE_TARGET ?= arm64-dpaa-linuxapp-gcc

include $(RTE_SDK)/mk/rte.vars.mk

# binary name
APP = dpdk-pkt-buf

# all source are stored in SRCS-y
SRCS-y := main.c

CFLAGS += -O3
CFLAGS += $(WERROR_FLAGS)
CFLAGS += -DALLOW_EXPERIMENTAL_API

include $(RTE_SDK)/mk/rte.extapp.mk
