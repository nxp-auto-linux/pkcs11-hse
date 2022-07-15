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

LIBPKCS_SRCDIR ?= ../libpkcs

INCLUDE_KEYOP ?= -I$(OPENSSL_DIR)/include \
		 -I$(LIBP11_DIR)/include

INCLUDE_LIBHSE := -I$(LIBHSE_SRCDIR) \
		  -I$(HSE_FWDIR)/interface \
		  -I$(HSE_FWDIR)/interface/config \
		  -I$(HSE_FWDIR)/interface/inc_common \
		  -I$(HSE_FWDIR)/interface/inc_services

INCLUDE_LIBPKCS := -I$(OPENSSL_DIR)/include \
		   -I$(LIBPKCS_SRCDIR)

LIBS ?= -L$(OPENSSL_DIR)/lib \
	-L$(LIBP11_DIR)/lib

all: pkcs-keyop pkcs-key-provision hse-encrypt hse-sysimg

pkcs-keyop: pkcs-keyop.c
	$(CROSS_COMPILE)gcc $(LIBS) $(INCLUDE_KEYOP) $(CFLAGS) $^ -o $@ $(LDFLAGS)

pkcs-key-provision: pkcs-key-provision.c
	$(CROSS_COMPILE)gcc -L$(OPENSSL_DIR)/lib $(INCLUDE_LIBPKCS) $(CFLAGS) $^ -o $@ -lcrypto -ldl

hse-encrypt: hse-encrypt.c
	$(CROSS_COMPILE)gcc -L$(LIBHSE_DIR) $(INCLUDE_LIBHSE) $(CFLAGS) $^ -o $@ -lhse

hse-sysimg: hse-sysimg.c
	$(CROSS_COMPILE)gcc -L$(LIBHSE_DIR) $(INCLUDE_LIBHSE) $(CFLAGS) $^ -o $@ -lhse

clean:
	rm -f pkcs-keyop pkcs-key-provision hse-encrypt hse-sysimg
