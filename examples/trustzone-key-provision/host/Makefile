#
# Copyright 2023 NXP
#

include ../../common.mk

HOST_CC ?= gcc
HOST_CFLAGS ?= -Wall -g
HOST_LDFLAGS ?=

HOST_OPENSSL_LIB ?= /lib
HOST_OPENSSL_INC ?= /usr/include/openssl

all: aes-gcm-key-encryption

aes-gcm-key-encryption: aes-gcm-key-encryption.c
	$(HOST_CC) $(HOST_LDFLAGS) $(INCLUDE_LIBHSE) $(INCDIR) -L$(HOST_OPENSSL_LIB) \
	$(HOST_CFLAGS) $^ -o $@ -lcrypto

clean:
	rm -f aes-gcm-key-encryption