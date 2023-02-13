#
# Copyright 2023 NXP
#

include ../../common.mk

all: hse-kek-provision

hse-kek-provision: hse-kek-provision.c
	$(CROSS_COMPILE)gcc $(LDFLAGS) -L$(LIBHSE_DIR) $(INCLUDE_LIBHSE) $(INCDIR) $(CFLAGS) $^ -o $@ -lhse

clean:
	rm -f hse-kek-provision

install:
	install hse-kek-provision $(EXAMPLES_INSTALLDIR)