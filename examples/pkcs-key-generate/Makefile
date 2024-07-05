#
# Copyright 2024 NXP
#

include ../../common.mk

all: pkcs-key-generate

pkcs-key-generate: pkcs-key-generate.c
	$(CROSS_COMPILE)gcc $(LDFLAGS) $(INCLUDE_LIBPKCS) $(INCLUDE_LIBHSE) $(CFLAGS) $^ -o $@ $(LD_LIBHSE) $(LD_OPENSSL) -ldl
clean:
	rm -rf pkcs-key-generate

install:
	 install pkcs-key-generate $(EXAMPLES_INSTALLDIR)

