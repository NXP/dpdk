# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2018-2019 NXP

ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

# Default target, can be overridden by command line or environment
RTE_TARGET ?= arm64-dpaa2-native-linuxapp-gcc

include $(RTE_SDK)/mk/rte.vars.mk

# binary name
APP = cmdif_demo

# all source are stored in SRCS-y
SRCS-y := main.c

CFLAGS += -O3
CFLAGS += -I$(SRCDIR)/../lib
CFLAGS += -I$(SRCDIR)/../lib/client
CFLAGS += -I$(SRCDIR)/../lib/server
CFLAGS += -I$(SRCDIR)/../lib/shbp
CFLAGS += $(WERROR_FLAGS)

LDLIBS += -L$(subst cmdif_demo,lib,$(RTE_OUTPUT))/lib
LDLIBS += -lrte_cmdif
LDLIBS += -lrte_mempool_dpaa2

include $(RTE_SDK)/mk/rte.extapp.mk
