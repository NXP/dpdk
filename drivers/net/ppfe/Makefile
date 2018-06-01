# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2018 NXP
#

include $(RTE_SDK)/mk/rte.vars.mk
RTE_SDK_DPAA=$(RTE_SDK)/drivers/net/ppfe

#
# library name
#
LIB = librte_pmd_ppfe.a

CFLAGS := -I$(SRCDIR) $(CFLAGS)
CFLAGS += -O3 $(WERROR_FLAGS)
CFLAGS += -Wno-pointer-arith
CFLAGS += -I$(RTE_SDK)/drivers/bus/vdev
CFLAGS += -I$(RTE_SDK)/drivers/bus/dpaa/
CFLAGS += -I$(RTE_SDK)/drivers/bus/dpaa/include/
CFLAGS += -I$(RTE_SDK)/drivers/net/ppfe/base/
CFLAGS += -I$(RTE_SDK)/lib/librte_eal/common/include
CFLAGS += -I$(RTE_SDK)/lib/librte_eal/linuxapp/eal/include

EXPORT_MAP := rte_pmd_ppfe_version.map

LIBABIVER := 1

# Interfaces with DPDK
SRCS-$(CONFIG_RTE_LIBRTE_PPFE_PMD) += rte_eth_pfe.c
SRCS-$(CONFIG_RTE_LIBRTE_PPFE_PMD) += pfe_hal.c
SRCS-$(CONFIG_RTE_LIBRTE_PPFE_PMD) += pfe_hif_lib.c
SRCS-$(CONFIG_RTE_LIBRTE_PPFE_PMD) += pfe_hif.c

LDLIBS += -lrte_bus_vdev
LDLIBS += -lrte_bus_dpaa
LDLIBS += -lrte_eal -lrte_mbuf -lrte_mempool -lrte_ring
LDLIBS += -lrte_ethdev -lrte_net -lrte_kvargs

include $(RTE_SDK)/mk/rte.lib.mk
