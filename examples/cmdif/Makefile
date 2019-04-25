# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2018-2019 NXP

ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

# Default target, can be overwritten by command line or environment
RTE_TARGET ?= arm64-dpaa2-linuxapp-gcc

include $(RTE_SDK)/mk/rte.vars.mk

ifneq ($(CONFIG_RTE_EXEC_ENV),"linuxapp")
$(info This application can only operate in a linuxapp environment, \
please change the definition of the RTE_TARGET environment variable)
else

DIRS-y += lib cmdif_demo
endif

DEPDIRS-cmdif_demo := lib

include $(RTE_SDK)/mk/rte.extsubdir.mk
