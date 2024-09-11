# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2024 NXP

include $(RTE_SDK)/mk/rte.vars.mk

APP = dpdk-shm_app

CFLAGS += -DALLOW_EXPERIMENTAL_API
CFLAGS += $(WERROR_FLAGS)

# all source are stored in SRCS-y

SRCS-y := main.c

include $(RTE_SDK)/mk/rte.app.mk
