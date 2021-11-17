# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2018-2019 NXP

ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

# Default target, can be overwritten by command line or environment
RTE_TARGET ?= x86_64-native-linuxapp-gcc

include $(RTE_SDK)/mk/rte.vars.mk

ifneq ($(CONFIG_RTE_EXEC_ENV),"linuxapp")
$(error This application can only operate in a linuxapp environment, \
please change the definition of the RTE_TARGET environment variable)
endif

# library name
LIB = librte_cmdif.a

LIBABIVER := 1

# all source are stored in SRC-Y
SRCS-y += client/cmdif_client_flib.c
SRCS-y += client/cmdif_client_gpp.c
SRCS-y += server/cmdif_srv_flib.c
SRCS-y += server/cmdif_srv_gpp.c
SRCS-y += shbp/shbp.c

CFLAGS += -O3
CFLAGS += $(WERROR_FLAGS)
CFLAGS += -I$(RTE_SDK)/examples/cmdif/lib
CFLAGS += -I$(RTE_SDK)/examples/cmdif/lib/client
CFLAGS += -I$(RTE_SDK)/examples/cmdif/lib/server
CFLAGS += -I$(RTE_SDK)/examples/cmdif/lib/shbp

LDLIBS += -lrte_eal
LDLIBS += -lrte_rawdev

include $(RTE_SDK)/mk/rte.extlib.mk
