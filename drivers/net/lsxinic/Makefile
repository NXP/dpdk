# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2018-2021 NXP

include $(RTE_SDK)/mk/rte.vars.mk

#
# library name
#
LIB = librte_pmd_lsxinic.a

ifeq ($(CONFIG_RTE_LIBRTE_VIRTINIC_DEBUG_INIT),y)
CFLAGS += -O0 -g
CFLAGS += "-Wno-error"
else
CFLAGS += -O3
CFLAGS += $(WERROR_FLAGS)
endif

CFLAGS += -I$(RTE_SDK)/drivers/net/lsxinic
CFLAGS += -I$(RTE_SDK)/lib/librte_eal/linuxapp/eal
CFLAGS += -I$(RTE_SDK)/drivers/bus/lsx_pciep

CFLAGS += -I$(RTE_SDK)/drivers/bus/dpaa/include/
CFLAGS += -I$(RTE_SDK)/drivers/bus/fslmc
CFLAGS += -I$(RTE_SDK)/drivers/bus/fslmc/portal
CFLAGS += -I$(RTE_SDK)/drivers/bus/fslmc/qbman/include
CFLAGS += -I$(RTE_SDK)/drivers/mempool/dpaa2
CFLAGS += -I$(RTE_SDK)/drivers/raw/dpaa2_qdma
CFLAGS += -I$(RTE_SDK)/drivers/common/dpaax
CFLAGS += -I$(RTE_SDK)/drivers/net/dpaa2
CFLAGS += -I$(RTE_SDK)/drivers/net/dpaa2/mc
CFLAGS += -I$(RTE_SDK)/drivers/bus/fslmc/mc

# depends on fslmc bus which uses experimental API
CFLAGS += -DALLOW_EXPERIMENTAL_API

# versioning export map
EXPORT_MAP := rte_pmd_lsxinic_version.map

# library version
LIBABIVER := 1

#
# all source are stored in SRCS-y
#
ifeq ($(CONFIG_RTE_LIBRTE_LSX_PCIEP_BUS),y)
SRCS-$(CONFIG_RTE_LIBRTE_LSXINIC_PMD) += lsxinic_common_helper.c

SRCS-$(CONFIG_RTE_LIBRTE_LSXINIC_PMD) += lsxinic_ep_tool.c
SRCS-$(CONFIG_RTE_LIBRTE_LSXINIC_PMD) += lsxinic_ep_dma.c

SRCS-$(CONFIG_RTE_LIBRTE_LSXINIC_PMD) += lsxinic_ep_ethdev.c
SRCS-$(CONFIG_RTE_LIBRTE_LSXINIC_PMD) += lsxinic_ep_rxtx.c
SRCS-$(CONFIG_RTE_LIBRTE_LSXINIC_PMD) += lsxinic_ep_ethtool.c

SRCS-$(CONFIG_RTE_LIBRTE_LSXINIC_PMD) += lsxinic_rc_ethdev.c
SRCS-$(CONFIG_RTE_LIBRTE_LSXINIC_PMD) += lsxinic_rc_pf.c
SRCS-$(CONFIG_RTE_LIBRTE_LSXINIC_PMD) += lsxinic_rc_rxtx.c

SRCS-$(CONFIG_RTE_LIBRTE_LSXINIC_PMD) += lsxinic_vio.c
SRCS-$(CONFIG_RTE_LIBRTE_LSXINIC_PMD) += lsxinic_vio_net.c
SRCS-$(CONFIG_RTE_LIBRTE_LSXINIC_PMD) += lsxinic_vio_rxtx.c

LDLIBS += -lrte_bus_fslmc
LDLIBS += -lrte_mempool_dpaa2
LDLIBS += -lrte_pmd_dpaa2
LDLIBS += -lrte_rawdev
LDLIBS += -lrte_bus_lsx_pciep
LDLIBS += -lrte_common_dpaax
else
SRCS-$(CONFIG_RTE_LIBRTE_LSXINIC_PMD) += lsxinic_common_helper.c

SRCS-$(CONFIG_RTE_LIBRTE_LSXINIC_PMD) += lsxinic_rc_ethdev.c
SRCS-$(CONFIG_RTE_LIBRTE_LSXINIC_PMD) += lsxinic_rc_pf.c
SRCS-$(CONFIG_RTE_LIBRTE_LSXINIC_PMD) += lsxinic_rc_rxtx.c

LDLIBS += -lrte_bus_fslmc
LDLIBS += -lrte_mempool_dpaa2
LDLIBS += -lrte_pmd_dpaa2
LDLIBS += -lrte_rawdev
LDLIBS += -lrte_common_dpaax
endif

LDLIBS += -lrte_bus_pci

LDLIBS += -lrte_eal -lrte_mbuf -lrte_mempool -lrte_ring
LDLIBS += -lrte_ethdev -lrte_net -lrte_kvargs -lrte_hash
LDLIBS += -lpthread

include $(RTE_SDK)/mk/rte.lib.mk
