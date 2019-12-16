# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2018,2019 NXP

ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

# Default target, can be overridden by command line or environment
RTE_TARGET ?= arm64-dpaa-native-linuxapp-gcc

include $(RTE_SDK)/mk/rte.vars.mk

# binary name
APP = qdma_demo

# all source are stored in SRCS-y
SRCS-y := main.c

CFLAGS += -O3 -g
CFLAGS += -I$(RTE_SDK)/drivers/raw/dpaa2_qdma
CFLAGS += -I$(RTE_SDK)/lib/librte_hash
CFLAGS += -I$(RTE_SDK)/lib/librte_eal/common/include
CFLAGS += $(WERROR_FLAGS)

LDLIBS += -L$(subst qdma_demo,lib,$(RTE_OUTPUT))/lib

include $(RTE_SDK)/mk/rte.extapp.mk
