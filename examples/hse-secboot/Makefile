#
# Copyright 2023, 2026 NXP
#

include ../../common.mk

KS_CONFIG_OPTEE_EN ?= false
ifeq ($(KS_CONFIG_OPTEE_EN),true)
CFLAGS += -DKS_CONFIG_OPTEE_EN
endif

all: hse-secboot

hse-secboot: hse-secboot.c
	$(CROSS_COMPILE)gcc $(LDFLAGS) -I$(OPENSSL_DIR)/include $(INCLUDE_LIBHSE) $(CFLAGS) $^ -o $@ \
	$(LD_OPENSSL) $(LD_LIBHSE)

clean:
	rm -f hse-secboot

install:
	install hse-secboot $(EXAMPLES_INSTALLDIR)
