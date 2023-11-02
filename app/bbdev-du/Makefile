# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2023 NXP

include $(RTE_SDK)/mk/rte.vars.mk

#
# library name
#
APP = bbdev-du

CFLAGS += -DALLOW_EXPERIMENTAL_API
CFLAGS += -O3
CFLAGS += $(WERROR_FLAGS)

#
# all sources are stored in SRCS-y
#
SRCS-$(CONFIG_RTE_TEST_BBDEV) += main.c

LDLIBS += -lm
ifeq ($(CONFIG_RTE_LIBRTE_PMD_BBDEV_FPGA_LTE_FEC),y)
LDLIBS += -lrte_pmd_bbdev_fpga_lte_fec
endif

ifeq ($(CONFIG_RTE_LIBRTE_PMD_BBDEV_LA12XX),y)
LDLIBS += -lrte_pmd_bbdev_la12xx
endif
include $(RTE_SDK)/mk/rte.app.mk
