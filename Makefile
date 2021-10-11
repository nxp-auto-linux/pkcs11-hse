#
# Copyright 2021 NXP
#

ifeq (,$(CROSS_COMPILE))
$(error CROSS_COMPILE is not set)
endif

CC := $(CROSS_COMPILE)gcc
LD := $(CROSS_COMPILE)ld
CFLAGS ?= -Wall -g
LDFLAGS ?=

PKCS_LIB ?= libpkcs-hse.so
PKCS_SDIR = libpkcs
PKCS_ODIR = $(PKCS_SDIR)/obj
PKCS_SRCS = $(wildcard $(PKCS_SDIR)/*.c)
PKCS_OBJS = $(patsubst $(PKCS_SDIR)/%.c,$(PKCS_ODIR)/%.o,$(PKCS_SRCS))

HSE_LIB ?= libhse.so
HSE_MAJOR ?= 0
HSE_MINOR ?= 9
HSE_REV ?= 0
HSE_PREMIUM ?= 0
HSE_LIBVER = $(HSE_MAJOR).$(HSE_MINOR).$(HSE_REV)
ifeq (,$(HSE_FWDIR))
$(warning Path to HSE firmware not defined, using location based on fw version; default 0.0.9.0)
endif
HSE_FWDIR ?= $(HOME)/HSE_FW_S32G274_$(HSE_PREMIUM)_$(HSE_MAJOR)_$(HSE_MINOR)_$(HSE_REV)
HSE_SDIR = libhse
HSE_ODIR = $(HSE_SDIR)/obj
HSE_SRCS = $(wildcard $(HSE_SDIR)/*.c)
HSE_OBJS = $(patsubst $(HSE_SDIR)/%.c,$(HSE_ODIR)/%.o,$(HSE_SRCS))

INCLUDE = -I$(HSE_FWDIR)/interface \
		  -I$(HSE_FWDIR)/interface/inc_common \
		  -I$(HSE_FWDIR)/interface/inc_custom \
		  -I$(HSE_FWDIR)/interface/inc_services \
		  -I$(HSE_FWDIR)/interface/config \
		  -I$(HSE_SDIR)

all: $(PKCS_LIB)

$(PKCS_LIB): $(HSE_LIB).$(HSE_LIBVER) $(PKCS_OBJS)
	$(CC) $(CFLAGS) -shared -fPIC -L$(shell pwd) $(LDFLAGS) $(PKCS_OBJS) -o $@ -lhse

$(PKCS_ODIR)/%.o: $(PKCS_SDIR)/%.c $(PKCS_ODIR)
	$(CC) -c $(CFLAGS) $(INCLUDE) $(LDFLAGS) $< -o $@

$(PKCS_ODIR):
	mkdir -p $@

$(HSE_LIB).$(HSE_LIBVER): $(HSE_OBJS)
	$(CC) $(CFLAGS) -shared -fPIC -Wl,-soname,$(HSE_LIB).$(HSE_MAJOR) $(LDFLAGS) $(HSE_OBJS) -o $@
	ln -s $@ $(HSE_LIB)

$(HSE_ODIR)/%.o: $(HSE_SDIR)/%.c $(HSE_ODIR)
	$(CC) -c $(CFLAGS) $(INCLUDE) $(LDFLAGS) $< -o $@

$(HSE_ODIR):
	mkdir -p $@

.PHONY: clean all

clean:
	rm -f *.so*
	rm -rf $(PKCS_ODIR) $(HSE_ODIR)
