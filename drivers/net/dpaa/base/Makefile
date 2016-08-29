#/*
#* Copyright (c) 2013 Freescale Semiconductor, Inc. All rights reserved.
#*/

include $(RTE_SDK)/mk/rte.vars.mk

#
# library name
#
LIB = libnxp_usdpaa.a

CFLAGS += -O3 -DCONFIG_ARM64
CFLAGS += -I$(RTE_SDK)/drivers/net/dpaa/base/include
CFLAGS += -I$(RTE_SDK)/drivers/net/dpaa/base/include/libxml2/include/

# all source are stored in SRCS-y
SRCS-$(CONFIG_RTE_LIBRTE_DPAA_PMD) += \
	drivers/fman/fman.c \
	drivers/of/of.c \
	drivers/process/process.c \
	drivers/qbman/bman_high.c \
	drivers/qbman/bman_driver.c \
	drivers/qbman/qman_high.c \
	drivers/qbman/qman_driver.c \
	drivers/qbman/dpa_alloc.c \
	drivers/qbman/dpa_sys.c \
	drivers/syscfg/fmc_netcfg_parser.c \
	drivers/syscfg/usdpaa_netcfg_layer.c

include $(RTE_SDK)/mk/rte.lib.mk	
