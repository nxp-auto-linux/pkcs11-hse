#
# Copyright 2021 NXP
#

CFLAGS ?= -Wall -g
LDFLAGS ?= -lcrypto -lp11

ifeq (,$(CROSS_COMPILE))
    $(error CROSS_COMPILE is not set)
endif

ifeq (,$(OPENSSL_DIR))
$(warning Path to cross-compiled OpenSSL not defined, using default location)
endif
OPENSSL_DIR ?= $(HOME)/openssl-aarch64

ifeq (,$(LIBP11_DIR))
$(warning Path to cross-compiled libp11 not defined, using default location)
endif
LIBP11_DIR ?= $(HOME)/libp11-aarch64

ifeq (,$(HSE_FWDIR))
$(warning Path to HSE firmware package not defined, using default location)
endif
HSE_FWDIR ?= $(HOME)/HSE_FW_S32G2_0_1_0_0
LIBHSE_SRCDIR ?= ../libhse
LIBHSE_DIR ?= ..

INCLUDE1 ?= -I$(OPENSSL_DIR)/include \
	    -I$(LIBP11_DIR)/include

INCLUDE2 := -I$(LIBHSE_SRCDIR) \
	    -I$(HSE_FWDIR)/interface \
	    -I$(HSE_FWDIR)/interface/config \
	    -I$(HSE_FWDIR)/interface/inc_common \
	    -I$(HSE_FWDIR)/interface/inc_services

LIBS ?= -L$(OPENSSL_DIR)/lib \
	-L$(LIBP11_DIR)/lib

all: pkcs-keyop hse-encrypt

pkcs-keyop: pkcs-keyop.c
	$(CROSS_COMPILE)gcc $(LIBS) $(INCLUDE1) $(CFLAGS) $^ -o $@ $(LDFLAGS)

hse-encrypt: hse-encrypt.c
	$(CROSS_COMPILE)gcc -L$(LIBHSE_DIR) $(INCLUDE2) $(CFLAGS) $^ -o $@ -lhse

clean:
	rm -f pkcs-keyop hse-encrypt
