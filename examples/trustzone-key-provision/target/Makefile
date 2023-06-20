#
# Copyright 2023 NXP
#

include ../../../common.mk

ifeq (,$(TEEC_EXPORT))
$(warning Path to TEE Client API not defined, using default location)
endif
TEEC_EXPORT ?= $(HOME)/optee_client/out/export/usr

TEEC_LIB := -L$(TEEC_EXPORT)/lib -lteec
TEEC_INCLUDE := -I$(TEEC_EXPORT)/include

all: hse-kek-provision hse-symkey-provision

hse-kek-provision: hse-kek-provision.c
	$(CROSS_COMPILE)gcc $(LDFLAGS) -L$(LIBHSE_DIR) $(INCLUDE_LIBHSE) $(INCDIR) $(CFLAGS) $^ -o $@ -lhse

hse-symkey-provision: hse-symkey-provision.c
	$(CROSS_COMPILE)gcc $(LDFLAGS) $(INCLUDE_LIBHSE) $(INCDIR) $(TEEC_INCLUDE) \
	$(CFLAGS) $^ -o $@ $(TEEC_LIB)

clean:
	rm -f hse-kek-provision hse-symkey-provision

install:
	install hse-kek-provision $(EXAMPLES_INSTALLDIR)
	install hse-symkey-provision $(EXAMPLES_INSTALLDIR)
