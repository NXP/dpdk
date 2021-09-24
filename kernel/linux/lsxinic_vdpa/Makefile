# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2020-2021 NXP

include $(RTE_SDK)/mk/rte.vars.mk

#
# module name and path
#

MODULE = lsinic_vdpa

MODULE_PATH = drivers/net/lsinic_vdpa

#
# CFLAGS
#
MODULE_CFLAGS += -I$(SRCDIR)
MODULE_CFLAGS += -I$(RTE_OUTPUT)/include
MODULE_CFLAGS += -I$(RTE_SDK)/drivers/net/lsxinic/
MODULE_CFLAGS += -Wall -Werror
MODULE_CFLAGS += -include $(RTE_OUTPUT)/include/rte_config.h

#
# all source are stored in SRCS-y
#
SRCS-$(CONFIG_RTE_LSXINIC_RC_VDPA_KMOD) = lsxinic_main.c
SRCS-$(CONFIG_RTE_LSXINIC_RC_VDPA_KMOD) += lsxinic_base.c

include $(RTE_SDK)/mk/rte.module.mk
