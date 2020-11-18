# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2020 NXP
#

include $(RTE_SDK)/mk/rte.vars.mk
ifeq ($(COMMON_HEADERS_DIR),)
$(error "Please define COMMON_HEADERS_DIR environment variable \
	to include LA12xx common header files")
endif
#
# library name
LIB = librte_pmd_bbdev_la12xx.a

# build flags
CFLAGS += -DALLOW_EXPERIMENTAL_API
CFLAGS += -O3
CFLAGS += $(WERROR_FLAGS)
CFLAGS += -I$(COMMON_HEADERS_DIR)/
CFLAGS += -DDEBUG
CFLAGS += -DHOST=1 -DMODEM=0
LDLIBS += -lrte_eal -lrte_mbuf -lrte_mempool -lrte_ring -lrte_kvargs
LDLIBS += -lrte_bbdev
LDLIBS += -lrte_bus_vdev

# versioning export map
EXPORT_MAP := rte_pmd_bbdev_la12xx_version.map

# library version
LIBABIVER := 1

# library source files
SRCS-$(CONFIG_RTE_LIBRTE_PMD_BBDEV_LA12XX) += bbdev_la12xx.c
SRCS-$(CONFIG_RTE_LIBRTE_PMD_BBDEV_LA12XX) += bbdev_la12xx_wdog.c
SRCS-$(CONFIG_RTE_LIBRTE_PMD_BBDEV_LA12XX) += bbdev_la12xx_feca_param.c

# create symbolic links for geul common headers required by application
COMMON_HDRS := $(shell find $(COMMON_HEADERS_DIR) -name '*.h')
SYMLINK-$(CONFIG_RTE_LIBRTE_PMD_BBDEV_LA12XX)-include += $(COMMON_HDRS)
SYMLINK-$(CONFIG_RTE_LIBRTE_PMD_BBDEV_LA12XX)-include += rte_pmd_bbdev_la12xx.h

include $(RTE_SDK)/mk/rte.lib.mk
