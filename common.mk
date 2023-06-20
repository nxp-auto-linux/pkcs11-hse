ifeq ($(MAKECMDGOALS),clean)
    CROSS_COMPILE ?= not_set
    OPENSSL_DIR ?= not_set
    LIBP11_DIR ?= not_set
    HSE_FWDIR ?= not_set
    UIO_DEV ?= not_set
endif

ifeq (,$(CROSS_COMPILE))
    $(error CROSS_COMPILE is not set)
endif

ifeq (,$(OPENSSL_DIR))
$(warning Path to cross-compiled OpenSSL not defined ( OPENSSL_DIR ), using default location)
endif
OPENSSL_DIR ?= $(HOME)/openssl-aarch64

ifeq (,$(LIBP11_DIR))
$(warning Path to cross-compiled libp11 not defined ( LIBP11_DIR ), using default location)
endif
LIBP11_DIR ?= $(HOME)/libp11-aarch64

ifeq (,$(HSE_FWDIR))
$(warning Path to HSE firmware package not defined ( HSE_FWDIR ), using default location)
endif
HSE_FWDIR ?= $(HOME)/HSE_FW_S32G2_0_1_0_0

ifeq (,$(UIO_DEV))
    UIO_DEV ?= uio0
    $(warning UIO device not defined ( UIO_DEV ) , using default device $(UIO_DEV) )
endif

ifndef DEBUG
    DEBUG_FLAGS =  -O2
else
    ifeq ($(DEBUG),1)
        DEBUG_FLAGS = -O0
    else ifeq ($(DEBUG),0)
        DEBUG_FLAGS = -O2
    else
        $(error unexpected value for DEBUG - can be either DEBUG=1 or DEBUG=0 )
    endif
endif

CFLAGS ?= -Wall -g $(DEBUG_FLAGS)
LDFLAGS ?=

INSTALL_DIR := $(CURDIR)/out
INSTALL_INCLUDEDIR := $(INSTALL_DIR)/include
INSTALL_LIBDIR := $(INSTALL_DIR)/lib
INSTALL_BINDIR := $(INSTALL_DIR)/bin

CC = $(CROSS_COMPILE)gcc
LD = $(CROSS_COMPILE)ld

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
