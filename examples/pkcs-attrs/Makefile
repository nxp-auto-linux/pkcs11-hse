#
# Copyright 2023-2024 NXP
#

include ../../common.mk

all: pkcs-attrs

pkcs-attrs: pkcs-attrs.c
	$(CROSS_COMPILE)gcc $(LDFLAGS) $(INCLUDE_LIBPKCS) $(INCLUDE_LIBHSE) $(CFLAGS) $^ -o $@ $(LD_LIBHSE) $(LD_OPENSSL) -ldl
clean:
	rm -rf pkcs-attrs

install:
	 install pkcs-attrs $(EXAMPLES_INSTALLDIR)

