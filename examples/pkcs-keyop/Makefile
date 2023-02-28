#
# Copyright 2023 NXP
#

include ../common.mk

INCLUDE_KEYOP ?= -I$(OPENSSL_DIR)/include \
		 -I$(LIBP11_DIR)/include

all: pkcs-keyop

pkcs-keyop: pkcs-keyop.c
	$(CROSS_COMPILE)gcc $(LDFLAGS) $(INCLUDE_KEYOP) $(CFLAGS)  $^ -o $@ $(LD_OPENSSL) $(LD_LIBP11)

clean:
	rm -f pkcs-keyop

install:
	install pkcs-keyop $(EXAMPLES_INSTALLDIR)