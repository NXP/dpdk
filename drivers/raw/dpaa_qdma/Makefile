# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2020 NXP

include $(RTE_SDK)/mk/rte.vars.mk

#
# library name
#
LIB = librte_rawdev_dpaa_qdma.a

CFLAGS += -O3
CFLAGS += $(WERROR_FLAGS)
CFLAGS += -Wno-pointer-arith

CFLAGS += -I$(RTE_SDK)/lib/librte_eal/linuxapp/eal
CFLAGS += -I$(RTE_SDK)/drivers/common/dpaax
CFLAGS += -I$(RTE_SDK)/drivers/bus/dpaa
CFLAGS += -I$(RTE_SDK)/drivers/bus/dpaa/include/

LDLIBS += -lrte_eal
LDLIBS += -lpthread
LDLIBS += -lrte_rawdev
LDLIBS += -lrte_bus_dpaa

EXPORT_MAP := rte_rawdev_dpaa_qdma_version.map

LIBABIVER := 1

CFLAGS += -DALLOW_EXPERIMENTAL_API
#
# all source are stored in SRCS-y
#
SRCS-$(CONFIG_RTE_LIBRTE_PMD_DPAA_QDMA_RAWDEV) += dpaa_qdma.c

include $(RTE_SDK)/mk/rte.lib.mk
