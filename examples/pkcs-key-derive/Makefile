#
# Copyright 2026 NXP
#

include ../../common.mk

all: pkcs-key-derive

pkcs-key-derive: pkcs-key-derive.c
	$(CROSS_COMPILE)gcc $(LDFLAGS) $(INCLUDE_LIBPKCS) $(INCLUDE_LIBHSE) $(CFLAGS) $^ -o $@ $(LD_LIBHSE) $(LD_OPENSSL) -ldl

clean:
	rm -f pkcs-key-derive

install:
	install pkcs-key-derive $(EXAMPLES_INSTALLDIR)
