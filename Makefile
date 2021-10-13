#
# Copyright 2021 NXP
#

PLATFORM ?= S32G274
FWTYPE ?= 0
FWMAJOR ?= 0
FWMINOR ?= 9
FWPATCH ?= 2

# Skip prerequisites check when invoking make clean
ifeq ($(filter clean,$(MAKECMDGOALS)),$(strip $(MAKECMDGOALS)))
    ifneq ($(filter clean,$(MAKECMDGOALS)),)
        CROSS_COMPILE ?= not_set
        HSE_FWDIR ?= not_set
        UIO_DEV ?= not_set
    endif
endif

# Prerequisites check
ifeq (,$(CROSS_COMPILE))
    $(error CROSS_COMPILE is not set)
endif

ifeq (,$(HSE_FWDIR))
    HSE_FWDIR ?= $(HOME)/HSE_$(PLATFORM)_$(FWTYPE)_$(FWMAJOR)_$(FWMINOR)_$(FWPATCH)
    $(warning Path to HSE firmware package not defined, using default $HSE_FWDIR)
endif

# Build libraries
CC := $(CROSS_COMPILE)gcc
LD := $(CROSS_COMPILE)ld
CFLAGS ?= -fPIC -Wall -g
LDFLAGS ?=

PKCS_LIB ?= libpkcs-hse.so
PKCS_SDIR = libpkcs
PKCS_ODIR = $(PKCS_SDIR)/obj
PKCS_SRCS = $(wildcard $(PKCS_SDIR)/*.c)
PKCS_OBJS = $(patsubst $(PKCS_SDIR)/%.c,$(PKCS_ODIR)/%.o,$(PKCS_SRCS))

HSE_LIB ?= libhse.so
HSE_LIBVER_MAJOR = 1
HSE_LIBVER_MINOR = 0
HSE_LIBVER = $(HSE_LIBVER_MAJOR).$(HSE_LIBVER_MINOR)
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
	$(CC) -shared $(CFLAGS) -L$(shell pwd) $(LDFLAGS) $(PKCS_OBJS) -o $@ -lhse

$(PKCS_ODIR)/%.o: $(PKCS_SDIR)/%.c $(PKCS_ODIR)
	$(CC) -c $(CFLAGS) $(INCLUDE) $(LDFLAGS) $< -o $@

$(PKCS_ODIR):
	mkdir -p $@

$(HSE_LIB).$(HSE_LIBVER): $(HSE_OBJS)
	$(CC) -shared $(CFLAGS) -Wl,-soname,$(HSE_LIB).$(HSE_MAJOR) $(LDFLAGS) $(HSE_OBJS) -o $@
	ln -s $@ $(HSE_LIB)

$(HSE_ODIR)/%.o: $(HSE_SDIR)/%.c $(HSE_ODIR)
	$(CC) -c $(CFLAGS) $(INCLUDE) $(LDFLAGS) $< -o $@

$(HSE_ODIR):
	mkdir -p $@

clean:
	rm -f *.so*
	rm -rf $(PKCS_ODIR) $(HSE_ODIR)

.PHONY: clean all
