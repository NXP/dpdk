# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2018 NXP

include $(RTE_SDK)/mk/rte.vars.mk

#
# library name
#
LIB = librte_rawdev_dpaa2_qdma.a

CFLAGS += -DALLOW_EXPERIMENTAL_API
CFLAGS += -O3
CFLAGS += $(WERROR_FLAGS)

CFLAGS += -I$(RTE_SDK)/drivers/bus/fslmc
CFLAGS += -I$(RTE_SDK)/drivers/bus/fslmc/qbman/include
CFLAGS += -I$(RTE_SDK)/drivers/common/dpaax
CFLAGS += -I$(RTE_SDK)/drivers/raw/dpaa2_qdma

LDLIBS += -lrte_bus_fslmc
LDLIBS += -lrte_eal
LDLIBS += -lrte_mempool
LDLIBS += -lrte_mempool_dpaa2
LDLIBS += -lrte_rawdev
LDLIBS += -lrte_kvargs
LDLIBS += -lrte_ring
LDLIBS += -lrte_common_dpaax

EXPORT_MAP := rte_rawdev_dpaa2_qdma_version.map

#
# all source are stored in SRCS-y
#
SRCS-$(CONFIG_RTE_LIBRTE_PMD_DPAA2_QDMA_RAWDEV) += dpaa2_qdma.c
SRCS-$(CONFIG_RTE_LIBRTE_PMD_DPAA2_QDMA_RAWDEV) += dpaa2_qdma_dmadev.c
SRCS-$(CONFIG_RTE_LIBRTE_PMD_DPAA2_QDMA_RAWDEV) += rte_dmadev.c

SYMLINK-$(CONFIG_RTE_LIBRTE_PMD_DPAA2_QDMA_RAWDEV)-include += rte_pmd_dpaa2_qdma.h
SYMLINK-$(CONFIG_RTE_LIBRTE_PMD_DPAA2_QDMA_RAWDEV)-include += rte_dmadev.h
SYMLINK-$(CONFIG_RTE_LIBRTE_PMD_DPAA2_QDMA_RAWDEV)-include += rte_dmadev_core.h

include $(RTE_SDK)/mk/rte.lib.mk
