#
# Copyright 2021 NXP
#

CROSS_COMPILE?=
CFLAGS ?= -Wall -g
LDFLAGS ?= -lcrypto -lp11

ifeq (,$(OPENSSL_DIR))
$(warning Path to cross-compiled OpenSSL not defined, using default location)
endif
OPENSSL_DIR ?= $(HOME)/openssl-aarch64

ifeq (,$(LIBP11_DIR))
$(warning Path to cross-compiled libp11 not defined, using default location)
endif
LIBP11_DIR ?= $(HOME)/libp11-aarch64

INCLUDE ?= -I$(OPENSSL_DIR)/include \
		-I$(LIBP11_DIR)/include

LIBS ?= -L$(OPENSSL_DIR)/lib \
	-L$(LIBP11_DIR)/lib

all: pkcs-keyop

pkcs-keyop: pkcs-keyop.c
	$(CROSS_COMPILE)gcc $(LIBS) $(INCLUDE) $(CFLAGS) $^ -o $@ $(LDFLAGS)

clean:
	rm -f pkcs-keyop
