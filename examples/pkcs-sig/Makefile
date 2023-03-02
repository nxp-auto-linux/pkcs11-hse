#
# Copyright 2023 NXP
#

include ../common.mk

all: pkcs-sig

pkcs-sig: pkcs-sig.c
	$(CROSS_COMPILE)gcc $(LDFLAGS) $(INCLUDE_LIBPKCS) $(CFLAGS) $^ -o $@ $(LD_OPENSSL) -ldl

clean:
	rm -f pkcs-sig

install:
	install pkcs-sig $(EXAMPLES_INSTALLDIR)