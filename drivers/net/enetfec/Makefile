# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2020 NXP
#

include $(RTE_SDK)/mk/rte.vars.mk

#
# library name
#
LIB = librte_pmd_enetfec.a

CFLAGS += -O3 $(WERROR_FLAGS)
CFLAGS += -Wno-pointer-arith
CFLAGS += -I$(RTE_SDK)/drivers/common/dpaax

EXPORT_MAP := rte_pmd_enetfec_version.map
CFLAGS += -DALLOW_EXPERIMENTAL_API

# Interfaces with DPDK
SRCS-$(CONFIG_RTE_LIBRTE_ENETFEC_PMD) += enet_ethdev.c
SRCS-$(CONFIG_RTE_LIBRTE_ENETFEC_PMD) += enet_rxtx.c
SRCS-$(CONFIG_RTE_LIBRTE_ENETFEC_PMD) += enet_uio.c

LDLIBS += -lrte_bus_vdev
LDLIBS += -lrte_common_dpaax
LDLIBS += -lrte_eal -lrte_mbuf -lrte_mempool
LDLIBS += -lrte_ethdev -lrte_kvargs -lrte_net

include $(RTE_SDK)/mk/rte.lib.mk
