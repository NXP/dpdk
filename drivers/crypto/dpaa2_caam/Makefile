#   BSD LICENSE
#
#   Copyright (c) 2016 Freescale Semiconductor, Inc. All rights reserved.
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
#     * Neither the name of Freescale Semiconductor, Inc nor the names of its
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

#ifeq ($(AESNI_MULTI_BUFFER_LIB_PATH),)
#$(error "Please define AESNI_MULTI_BUFFER_LIB_PATH environment variable")
#endif

# library name
LIB = librte_pmd_dpaa2_caam.a

# build flags
CFLAGS += -g -O3
#CFLAGS += $(WERROR_FLAGS)
CFLAGS += "-Wno-error"
CFLAGS += -I$(RTE_SDK)/drivers/net/dpaa2
CFLAGS += -I$(RTE_SDK)/drivers/net/dpaa2/mc
CFLAGS += -I$(RTE_SDK)/drivers/net/dpaa2/qbman/include
CFLAGS += -I$(RTE_SDK)/drivers/net/dpaa2/qbman/include/drivers
CFLAGS += -I$(RTE_SDK)/drivers/net/dpaa2/driver/
CFLAGS += -I$(RTE_SDK)/drivers/crypto/dpaa2_caam/
CFLAGS += -I$(RTE_SDK)/lib/librte_eal/common/include
CFLAGS += -I$(RTE_SDK)/lib/librte_eal/linuxapp/eal

# library version
LIBABIVER := 1

# versioning export map
EXPORT_MAP := rte_pmd_dpaa2_caam_version.map

# external library include paths
#CFLAGS += -I$(AESNI_MULTI_BUFFER_LIB_PATH)
#CFLAGS += -I$(AESNI_MULTI_BUFFER_LIB_PATH)/include
CFLAGS += -Iinclude
LDLIBS += -lcrypto

# library source files
SRCS-$(CONFIG_RTE_LIBRTE_PMD_DPAA2_CAAM) += dpaa2_caam_dpseci.c

# export include files
SYMLINK-y-include +=

# library dependencies
DEPDIRS-$(CONFIG_RTE_LIBRTE_PMD_DPAA2_CAAM) += lib/librte_eal
DEPDIRS-$(CONFIG_RTE_LIBRTE_PMD_DPAA2_CAAM) += lib/librte_mbuf
DEPDIRS-$(CONFIG_RTE_LIBRTE_PMD_DPAA2_CAAM) += lib/librte_cryptodev

include $(RTE_SDK)/mk/rte.lib.mk
