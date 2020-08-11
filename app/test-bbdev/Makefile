# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017 Intel Corporation

include $(RTE_SDK)/mk/rte.vars.mk

#
# library name
#
APP = testbbdev

CFLAGS += -DALLOW_EXPERIMENTAL_API
CFLAGS += -O3
CFLAGS += $(WERROR_FLAGS)

#
# all sources are stored in SRCS-y
#
SRCS-$(CONFIG_RTE_TEST_BBDEV) += main.c
# Disabling test_bbdev.c as it does only basic tests using RTE_BBDEV_OP_NONE,
# and then this queues are reconfigured for EMC/DEC ops. Reconfiguration
# of queues is not currently supported by the LA12xx driver
#SRCS-$(CONFIG_RTE_TEST_BBDEV) += test_bbdev.c
SRCS-$(CONFIG_RTE_TEST_BBDEV) += test_bbdev_perf.c
SRCS-$(CONFIG_RTE_TEST_BBDEV) += test_bbdev_vector.c

LDLIBS += -lm
ifeq ($(CONFIG_RTE_LIBRTE_PMD_BBDEV_FPGA_LTE_FEC),y)
LDLIBS += -lrte_pmd_bbdev_fpga_lte_fec
endif

ifeq ($(CONFIG_RTE_LIBRTE_PMD_BBDEV_LA12XX),y)
LDLIBS += -lrte_pmd_bbdev_la12xx
endif
include $(RTE_SDK)/mk/rte.app.mk
