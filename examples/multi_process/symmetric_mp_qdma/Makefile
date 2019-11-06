# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2019 NXP

ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

# Default target, can be overridden by command line or environment
RTE_TARGET ?= x86_64-native-linuxapp-gcc

include $(RTE_SDK)/mk/rte.vars.mk

# binary name
APP = symmetric_mp_qdma

# all source are stored in SRCS-y
SRCS-y := main.c

CFLAGS += -O3
CFLAGS += $(WERROR_FLAGS)

include $(RTE_SDK)/mk/rte.extapp.mk
