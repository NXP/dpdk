# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2018-2021 NXP

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
MODULE_CFLAGS += -Winline -Wall -Werror
MODULE_CFLAGS += -include $(RTE_OUTPUT)/include/rte_config.h

#
# all source are stored in SRCS-y
#
SRCS-$(CONFIG_RTE_LSXINIC_RC_KMOD) = lsinic_kmod.c
SRCS-$(CONFIG_RTE_LSXINIC_RC_KMOD) += lsinic_ethtool.c
SRCS-$(CONFIG_RTE_LSXINIC_RC_KMOD) += lsinic_kcompat.c
SRCS-$(CONFIG_RTE_LSXINIC_RC_KMOD) += print_buffer.c

include $(RTE_SDK)/mk/rte.module.mk
