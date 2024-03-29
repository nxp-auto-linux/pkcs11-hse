#
# Copyright 2021 NXP
#

PLATFORM ?= S32G2
FWTYPE ?= 0
FWMAJOR ?= 1
FWMINOR ?= 0
FWPATCH ?= 9

include common.mk

CFLAGS += -fPIC
LDFLAGS ?=

PKCS_LIB ?= libpkcs-hse.so
PKCS_LIBVER_MAJOR = 1
PKCS_LIBVER_MINOR = 0
PKCS_LIBVER = $(PKCS_LIBVER_MAJOR).$(PKCS_LIBVER_MINOR)
PKCS_SDIR = libpkcs
PKCS_ODIR = $(PKCS_SDIR)/obj
PKCS_SRCS = $(wildcard $(PKCS_SDIR)/*.c)
PKCS_OBJS = $(patsubst $(PKCS_SDIR)/%.c,$(PKCS_ODIR)/%.o,$(PKCS_SRCS))

HSE_LIB ?= libhse.so
HSE_LIBVER_MAJOR = 2
HSE_LIBVER_MINOR = 1
HSE_LIBVER = $(HSE_LIBVER_MAJOR).$(HSE_LIBVER_MINOR)
HSE_SDIR = libhse
HSE_HEADER = libhse.h
HSE_ODIR = $(HSE_SDIR)/obj
HSE_SRCS = $(wildcard $(HSE_SDIR)/*.c)
HSE_OBJS = $(patsubst $(HSE_SDIR)/%.c,$(HSE_ODIR)/%.o,$(HSE_SRCS))

INCL = -I$(HSE_FWDIR)/interface                                                \
       -I$(HSE_FWDIR)/interface/inc_common                                     \
       -I$(HSE_FWDIR)/interface/inc_custom                                     \
       -I$(HSE_FWDIR)/interface/inc_services                                   \
       -I$(HSE_FWDIR)/interface/config                                         \
       -I$(HSE_SDIR)

DEFS := -DUIO_DEV=$(UIO_DEV) -DHSE_LIBVER_MAJOR=$(HSE_LIBVER_MAJOR)

all: $(PKCS_LIB).$(PKCS_LIBVER) examples

$(PKCS_LIB).$(PKCS_LIBVER): $(HSE_LIB).$(HSE_LIBVER) $(PKCS_OBJS)
	$(CC) -shared $(CFLAGS) -L$(shell pwd) -Wl,-soname,$(PKCS_LIB).$(PKCS_LIBVER_MAJOR) \
	$(LDFLAGS) $(PKCS_OBJS) -o $@ -lhse

$(PKCS_ODIR)/%.o: $(PKCS_SDIR)/%.c $(PKCS_ODIR)
	$(CC) -c $(CFLAGS) $(INCL) $(LDFLAGS) $< -o $@

$(PKCS_ODIR):
	mkdir -p $@

$(HSE_LIB).$(HSE_LIBVER): $(HSE_OBJS)
	$(CC) -shared $(CFLAGS) -Wl,-soname,$(HSE_LIB).$(HSE_LIBVER_MAJOR) $(LDFLAGS) $(HSE_OBJS) -o $@ -lpthread
	ln -sf $@ $(HSE_LIB)

$(HSE_ODIR)/%.o: $(HSE_SDIR)/%.c $(HSE_ODIR)
	$(CC) -c $(CFLAGS) $(INCL) $(DEFS) $(LDFLAGS) $< -o $@

$(HSE_ODIR):
	mkdir -p $@

.PHONY: examples
examples: $(HSE_LIB).$(HSE_LIBVER)
	make -C examples PKCS11HSE_DIR=$(CURDIR)

clean:
	rm -f *.so*
	rm -rf $(PKCS_ODIR) $(HSE_ODIR)
	make -C examples clean

install: $(PKCS_LIB).$(PKCS_LIBVER) examples
	@mkdir -p $(INSTALL_INCLUDEDIR)
	@mkdir -p $(INSTALL_LIBDIR)
	@mkdir -p $(INSTALL_BINDIR)

	@echo "Installing pkcs11 libraries in $(INSTALL_LIBDIR)"
	@install $(PKCS_LIB).$(PKCS_LIBVER) $(INSTALL_LIBDIR)
	@ln -sf $(PKCS_LIB).$(PKCS_LIBVER) $(INSTALL_LIBDIR)/$(PKCS_LIB).$(PKCS_LIBVER_MAJOR)

	@install $(HSE_LIB).$(HSE_LIBVER) $(INSTALL_LIBDIR)
	@ln -sf $(HSE_LIB).$(HSE_LIBVER) $(INSTALL_LIBDIR)/$(HSE_LIB).$(HSE_LIBVER_MAJOR)
	@ln -sf $(HSE_LIB).$(HSE_LIBVER) $(INSTALL_LIBDIR)/$(HSE_LIB)

	@install $(HSE_SDIR)/$(HSE_HEADER) $(INSTALL_INCLUDEDIR)

	@echo "Installing example binaries in $(INSTALL_BINDIR)"
	make -C examples install EXAMPLES_INSTALLDIR=$(INSTALL_BINDIR)

.PHONY: clean all install
