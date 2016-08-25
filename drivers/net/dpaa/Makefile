#   BSD LICENSE
#
#   Copyright (c) 2014 Freescale Semiconductor, Inc. All rights reserved.
#
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions
#   are met:
#
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in
#       the documentation and/or other materials provided with the
#       distribution.
#     * Neither the name of Freescale Semiconductor nor the names of its
#       contributors may be used to endorse or promote products derived
#       from this software without specific prior written permission.
#
#   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

include $(RTE_SDK)/mk/rte.vars.mk

#
# library name
#
LIB = librte_pmd_dpaa.a

CFLAGS += -D _GNU_SOURCE -DDEF_CFG_PATH=$(DEF_CFG_PATH) -DDEF_PCD_PATH=$(DEF_PCD_PATH ) -DDPAA_DEF_RX=$(DPAA_DEF_RX)
ifeq ($(CONFIG_RTE_LIBRTE_DPAA_DEBUG_INIT),y)
CFLAGS += -O0 -g
CFLAGS += "-Wno-error"
else
CFLAGS += -O3
#CFLAGS += $(WERROR_FLAGS)
endif
CFLAGS +=-Wno-strict-aliasing
CFLAGS +=-Wno-missing-prototypes
CFLAGS +=-Wno-missing-declarations
CFLAGS +=-Wno-unused-function
CFLAGS += -I$(RTE_SDK)/drivers/net/dpaa/base/include
CFLAGS += -I$(RTE_SDK)/lib/librte_eal/common/include
CFLAGS += -I$(RTE_SDK)/lib/librte_eal/linuxapp/eal/include
CFLAGS += -I$(RTE_SDK)/lib/librte_net
EXPORT_MAP := rte_pmd_dpaa_version.map

SRCS-$(CONFIG_RTE_LIBRTE_DPAA_PMD) += \
	dpaa_ethdev.c
DIRS-y += base
SYMLINK-y-include +=

# this lib depends upon:
DEPDIRS-y += lib/librte_eal
include $(RTE_SDK)/mk/rte.lib.mk
