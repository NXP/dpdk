# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2021 NXP
#

include $(RTE_SDK)/mk/rte.vars.mk
#
# library name
LIB = librte_pmd_bbdev_la93xx.a

# build flags
CFLAGS += -DALLOW_EXPERIMENTAL_API
CFLAGS += -O3
CFLAGS += $(WERROR_FLAGS)
LDLIBS += -lrte_eal -lrte_mbuf -lrte_mempool -lrte_ring -lrte_kvargs
LDLIBS += -lrte_bbdev
LDLIBS += -lrte_bus_vdev

# versioning export map
EXPORT_MAP := rte_pmd_bbdev_la93xx_version.map

# library version
LIBABIVER := 1

# library source files
SRCS-$(CONFIG_RTE_LIBRTE_PMD_BBDEV_LA93XX) += bbdev_la93xx.c

# create symbolic links for LA93xx common headers required by application
COMMON_HDRS := $(shell find $(LA9310_COMMON_HEADERS) -name '*.h')
SYMLINK-$(CONFIG_RTE_LIBRTE_PMD_BBDEV_LA93XX)-include += $(COMMON_HDRS)

include $(RTE_SDK)/mk/rte.lib.mk
