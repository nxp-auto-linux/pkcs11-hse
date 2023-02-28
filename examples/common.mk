CFLAGS ?= -Wall -g
LDFLAGS ?=

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

PKCS11HSE_DIR ?= $(HOME)/pkcs11-hse

LIBHSE_SRCDIR ?= $(PKCS11HSE_DIR)/libhse
LIBHSE_DIR ?= $(PKCS11HSE_DIR)
LIBPKCS_SRCDIR ?= $(PKCS11HSE_DIR)/libpkcs

INCLUDE_KEYOP ?= -I$(OPENSSL_DIR)/include \
		 -I$(LIBP11_DIR)/include

INCLUDE_LIBHSE := -I$(LIBHSE_SRCDIR) \
		  -I$(HSE_FWDIR)/interface \
		  -I$(HSE_FWDIR)/interface/config \
		  -I$(HSE_FWDIR)/interface/inc_common \
		  -I$(HSE_FWDIR)/interface/inc_services

INCLUDE_LIBPKCS := -I$(OPENSSL_DIR)/include \
		   -I$(LIBPKCS_SRCDIR)

LD_OPENSSL := -L$(OPENSSL_DIR)/lib -lcrypto
LD_LIBP11 := -L$(LIBP11_DIR)/lib -lp11
LD_LIBHSE := -L$(LIBHSE_DIR) -lhse
