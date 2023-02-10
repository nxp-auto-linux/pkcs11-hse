#
# Copyright 2023 NXP
#

include ../common.mk

all: pkcs-msg-digest

pkcs-msg-digest: pkcs-msg-digest.c
	$(CROSS_COMPILE)gcc $(LDFLAGS) $(INCLUDE_LIBPKCS) $(CFLAGS) $^ -o $@ $(LD_OPENSSL) -ldl

clean:
	rm -f pkcs-msg-digest

install:
	install pkcs-msg-digest $(EXAMPLES_INSTALLDIR)