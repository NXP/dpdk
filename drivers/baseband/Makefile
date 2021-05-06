# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017 Intel Corporation

include $(RTE_SDK)/mk/rte.vars.mk

core-libs := librte_eal librte_mbuf librte_mempool librte_ring
core-libs += librte_bbdev librte_kvargs librte_cfgfile

DIRS-$(CONFIG_RTE_LIBRTE_PMD_BBDEV_NULL) += null
DEPDIRS-null = $(core-libs)
DIRS-$(CONFIG_RTE_LIBRTE_PMD_BBDEV_TURBO_SW) += turbo_sw
DEPDIRS-turbo_sw = $(core-libs)
DIRS-$(CONFIG_RTE_LIBRTE_PMD_BBDEV_FPGA_LTE_FEC) += fpga_lte_fec
DEPDIRS-fpga_lte_fec = $(core-libs)
ifneq ($(COMMON_HEADERS_DIR),)
DIRS-$(CONFIG_RTE_LIBRTE_PMD_BBDEV_LA12XX) += la12xx
DEPDIRS-bbdev_la12xx = $(core-libs)
endif
ifneq ($(LA9310_COMMON_HEADERS),)
DIRS-$(CONFIG_RTE_LIBRTE_PMD_BBDEV_LA93XX) += la93xx
DEPDIRS-bbdev_la93xx = $(core-libs)
endif

include $(RTE_SDK)/mk/rte.subdir.mk
