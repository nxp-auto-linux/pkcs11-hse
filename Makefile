#
# Copyright 2021 NXP
#

ifeq (,$(CROSS_COMPILE))
$(warning CROSS_COMPILE is not set, using default host compiler)
endif
CROSS_COMPILE ?=

CFLAGS ?= -shared -fPIC -Wall -fno-builtin
LDFLAGS ?=
SRCS := $(wildcard src/*.c)

ifeq (,$(HSE_FWDIR))
$(warning Path to HSE firmware not defined, using default location)
endif
HSE_FWDIR ?= $(HOME)/HSE_FW_S32G274_0_0_8_5

INCLUDE ?= -I$(HSE_FWDIR)/interface \
		  -I$(HSE_FWDIR)/interface/inc_common \
		  -I$(HSE_FWDIR)/interface/inc_custom \
		  -I$(HSE_FWDIR)/interface/inc_services \
		  -I$(HSE_FWDIR)/interface/config

all: pkcs11-hse.so

pkcs11-hse.so: $(SRCS)
	$(CROSS_COMPILE)gcc $(CFLAGS) $(INCLUDE) $(LDFLAGS) $^ -o $@

clean:
	rm -f pkcs11-hse.so
