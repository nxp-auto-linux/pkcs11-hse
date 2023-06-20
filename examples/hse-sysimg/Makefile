#
# Copyright 2023 NXP
#

include ../../common.mk

all: hse-sysimg

hse-sysimg: hse-sysimg.c
	$(CROSS_COMPILE)gcc $(LDFLAGS) $(INCLUDE_LIBHSE) $(CFLAGS) $^ -o $@ $(LD_LIBHSE)

clean:
	rm -f hse-sysimg

install:
	install hse-sysimg $(EXAMPLES_INSTALLDIR)