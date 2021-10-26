# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2020-2021 NXP
#

include $(RTE_SDK)/mk/rte.vars.mk

#
# library name
#
LIB = librte_bus_lsx_pciep.a

CFLAGS += -DALLOW_EXPERIMENTAL_API
CFLAGS += -O3
CFLAGS += $(WERROR_FLAGS)

CFLAGS += -I$(RTE_SDK)/drivers/bus/lsx_pciep
CFLAGS += -I$(RTE_SDK)/lib/librte_eal/common
CFLAGS += -I$(RTE_SDK)/drivers/bus/fslmc
CFLAGS += -I$(RTE_SDK)/drivers/bus/fslmc/qbman/include
CFLAGS += -I$(RTE_SDK)/drivers/common/dpaax

LDLIBS += -lpthread
LDLIBS += -lrte_eal -lrte_mbuf -lrte_mempool -lrte_ring
LDLIBS += -lrte_common_dpaax

# versioning export map
EXPORT_MAP := rte_bus_lsx_pciep_version.map

SRCS-$(CONFIG_RTE_LIBRTE_LSX_PCIEP_BUS) += lsx_pciep_bus.c
SRCS-$(CONFIG_RTE_LIBRTE_LSX_PCIEP_BUS) += lsx_pciep_dw.c
SRCS-$(CONFIG_RTE_LIBRTE_LSX_PCIEP_BUS) += lsx_pciep_mv.c
SRCS-$(CONFIG_RTE_LIBRTE_LSX_PCIEP_BUS) += lsx_pciep_pcie.c

include $(RTE_SDK)/mk/rte.lib.mk
