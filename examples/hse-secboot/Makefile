#
# Copyright 2023 NXP
#

include ../common.mk

all: hse-secboot

hse-secboot: hse-secboot.c
	$(CROSS_COMPILE)gcc $(LDFLAGS) -I$(OPENSSL_DIR)/include $(INCLUDE_LIBHSE) $(CFLAGS) $^ -o $@ \
	$(LD_OPENSSL) $(LD_LIBHSE)

clean:
	rm -f hse-secboot

install:
	install hse-secboot $(EXAMPLES_INSTALLDIR)
