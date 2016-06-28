#/*
#* Copyright (c) 2013 Freescale Semiconductor, Inc. All rights reserved.
#*/

SUBDIRS =  process of qbman fman syscfg

.PHONY: subdirs  $(SUBDIRS) clean

subdirs: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@ all

all: subdirs

clean:
	@for sdir in $(SUBDIRS); do \
		$(MAKE) -C $$sdir clean; \
	done

