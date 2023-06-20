#
# Copyright 2023 NXP
#

include ../../common.mk

all: hse-encrypt

hse-encrypt: hse-encrypt.c
	$(CROSS_COMPILE)gcc $(LDFLAGS) $(INCLUDE_LIBHSE) $(CFLAGS) $^ -o $@ $(LD_LIBHSE)

clean:
	rm -f hse-encrypt

install:
	install hse-encrypt $(EXAMPLES_INSTALLDIR)