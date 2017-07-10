include $(RTE_SDK)/mk/rte.vars.mk

ifeq ($(CONFIG_RTE_DEBUG),y)
APP = plat_debug

CFLAGS += $(WERROR_FLAGS)

# all source are stored in SRCS-y

SRCS-y := plat_debug_tool.c

# this application needs libraries first
DEPDIRS-y += lib drivers

include $(RTE_SDK)/mk/rte.app.mk

endif
