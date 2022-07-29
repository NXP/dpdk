# SPDX-License-Identifier: GPL-2.0
# Copyright 2018-2022 NXP

include $(RTE_SDK)/mk/rte.vars.mk

#
# module name and path
#
MODULE = lsinic

MODULE_PATH = drivers/net/lsinic

#
# CFLAGS
#
MODULE_CFLAGS += -I$(SRCDIR)
MODULE_CFLAGS += -I$(RTE_OUTPUT)/include
MODULE_CFLAGS += -I$(RTE_SDK)/drivers/bus/lsx_pciep
MODULE_CFLAGS += -I$(RTE_SDK)/drivers/net/lsxinic
MODULE_CFLAGS += -Wall -Werror
MODULE_CFLAGS += -include $(RTE_OUTPUT)/include/rte_config.h

#
# all source are stored in SRCS-y
#
SRCS-$(CONFIG_RTE_LSXINIC_RC_KMOD) = lsinic_kmod.c
SRCS-$(CONFIG_RTE_LSXINIC_RC_KMOD) += lsinic_ethtool.c
SRCS-$(CONFIG_RTE_LSXINIC_RC_KMOD) += lsinic_kcompat.c
SRCS-$(CONFIG_RTE_LSXINIC_RC_KMOD) += print_buffer.c

include $(RTE_SDK)/mk/rte.module.mk
