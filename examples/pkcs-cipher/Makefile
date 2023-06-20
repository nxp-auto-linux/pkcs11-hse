#
# Copyright 2023 NXP
#

include ../../common.mk

all: pkcs-cipher

pkcs-cipher: pkcs-cipher.c
	$(CROSS_COMPILE)gcc $(LDFLAGS) $(INCLUDE_LIBPKCS) $(CFLAGS) $^ -o $@ -ldl

clean:
	rm -f pkcs-cipher

install:
	install pkcs-cipher $(EXAMPLES_INSTALLDIR)