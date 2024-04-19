#
# Copyright 2023-2024 NXP
#

include ../../common.mk

all: pkcs-key-provision

pkcs-key-provision: pkcs-key-provision.c
	$(CROSS_COMPILE)gcc $(LDFLAGS) $(INCLUDE_LIBPKCS) $(INCLUDE_LIBHSE) $(CFLAGS) $^ -o $@ $(LD_LIBHSE) $(LD_OPENSSL) -ldl

clean:
	rm -f pkcs-key-provision

install:
	install pkcs-key-provision $(EXAMPLES_INSTALLDIR)
