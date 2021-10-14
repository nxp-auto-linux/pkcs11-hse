/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * NXP HSE User Space Driver - Core
 *
 * Copyright 2019-2021 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include "libhse.h"
#include "hse-internal.h"

#include "hse_interface.h"

#define __stringify_1(x)    #x
#define __stringify(x)      __stringify_1(x)

#ifndef UIO_DEV
#error HSE UIO device not defined
#endif /* UIO_DEV */
#define HSE_UIO_DEVICE    __stringify(UIO_DEV)

/* UIO mappings index */
#define HSE_UIO_MAP_REGS    0 /* MU hardware register space */
#define HSE_UIO_MAP_DESC    1 /* service descriptor space */
#define HSE_UIO_MAP_INTL    2 /* driver internal shared memory */
#define HSE_UIO_MAP_RMEM    3 /* reserved DMA-able memory range */

/* sysfs files containing base address and size of UIO mappings */
#define HSE_UIO_REGS_SIZE    "/sys/class/uio/" HSE_UIO_DEVICE "/maps/map" \
			     __stringify(HSE_UIO_MAP_REGS) "/size"
#define HSE_UIO_DESC_ADDR    "/sys/class/uio/" HSE_UIO_DEVICE "/maps/map" \
			     __stringify(HSE_UIO_MAP_DESC) "/addr"
#define HSE_UIO_DESC_SIZE    "/sys/class/uio/" HSE_UIO_DEVICE "/maps/map" \
			     __stringify(HSE_UIO_MAP_DESC) "/size"
#define HSE_UIO_INTL_SIZE    "/sys/class/uio/" HSE_UIO_DEVICE "/maps/map" \
			     __stringify(HSE_UIO_MAP_INTL) "/size"
#define HSE_UIO_RMEM_ADDR    "/sys/class/uio/" HSE_UIO_DEVICE "/maps/map" \
			     __stringify(HSE_UIO_MAP_RMEM) "/addr"
#define HSE_UIO_RMEM_SIZE    "/sys/class/uio/" HSE_UIO_DEVICE "/maps/map" \
			     __stringify(HSE_UIO_MAP_RMEM) "/size"

#define HSE_UIO_MAX_FILE_SIZE    20u

/**
 * struct hse_mu_regs - HSE Messaging Unit Registers
 * @ver: Version ID Register, offset 0x0
 * @par: Parameter Register, offset 0x4
 * @cr: Control Register, offset 0x8
 * @sr: Status Register, offset 0xC
 * @fcr: Flag Control Register, offset 0x100
 * @fsr: Flag Status Register, offset 0x104
 * @gier: General Interrupt Enable Register, offset 0x110
 * @gcr: General Control Register, offset 0x114
 * @gsr: General Status Register, offset 0x118
 * @tcr: Transmit Control Register, offset 0x120
 * @tsr: Transmit Status Register, offset 0x124
 * @rcr: Receive Control Register, offset 0x128
 * @rsr: Receive Status Register, offset 0x12C
 * @tr[n]: Transmit Register n, offset 0x200 + 4*n
 * @rr[n]: Receive Register n, offset 0x280 + 4*n
 */
struct hse_mu_regs {
	const volatile uint32_t ver;
	const volatile uint32_t par;
	volatile uint32_t cr;
	volatile uint32_t sr;
	volatile uint8_t reserved0[240]; /* 0xF0 */
	volatile uint32_t fcr;
	const volatile uint32_t fsr;
	volatile uint8_t reserved1[8]; /* 0x8 */
	volatile uint32_t gier;
	volatile uint32_t gcr;
	volatile uint32_t gsr;
	volatile uint8_t reserved2[4]; /* 0x4 */
	volatile uint32_t tcr;
	const volatile uint32_t tsr;
	volatile uint32_t rcr;
	const volatile uint32_t rsr;
	volatile uint8_t reserved3[208]; /* 0xD0 */
	volatile uint32_t tr[16];
	volatile uint8_t reserved4[64]; /* 0x40 */
	const volatile uint32_t rr[16];
};

/**
 * struct hse_uio_intl - driver internal shared memory layout
 * @ready[n]: reply ready on channel n
 * @reply[n]: service response on channel n
 * @event: HSE system event mask
 * @reserved_end: placeholder for the end of reserved area
 */
struct hse_uio_intl {
	volatile uint8_t ready[HSE_NUM_CHANNELS];
	volatile uint32_t reply[HSE_NUM_CHANNELS];
	volatile uint32_t event;
	uint8_t reserved_end __attribute__((aligned(16)));
} __attribute__((packed));

/**
 * struct hse_usr_priv - driver private data
 * @regs: HSE MU register space address
 * @regs_size: HSE MU register space size
 * @desc: service descriptor space virtual address
 * @desc_dma: service descriptor space DMA address
 * @desc_size: service descriptor space size
 * @intl: driver internal shared memory address
 * @intl_size: driver internal shared memory size
 * @shared: driver internal shared memory address
 * @rmem: HSE reserved memory virtual address
 * @rmem_dma: HSE reserved memory DMA address
 * @rmem_size: HSE reserved memory size
 * @fd: UIO file descriptor
 * @channel busy: cached channel status
 * @init: UIO component initialized flag
 */
static struct hse_usr_priv {
	struct hse_mu_regs *regs;
	uint64_t regs_size;
	void *desc;
	uint64_t desc_dma;
	uint64_t desc_size;
	struct hse_uio_intl *intl;
	uint64_t intl_size;
	struct hse_uio_intl *shared;
	void *rmem;
	uint64_t rmem_dma;
	uint64_t rmem_size;
	int fd;
	bool channel_busy[HSE_NUM_CHANNELS];
	bool init;
} priv;

/**
 * hse_err_decode - HSE Error Code Translation
 * @srv_rsp: HSE service response
 *
 * Return: 0 on service request success, error code otherwise
 */
static inline int hse_err_decode(uint32_t srv_rsp)
{
	switch (srv_rsp) {
	case HSE_SRV_RSP_OK:
		return 0;
	case HSE_SRV_RSP_VERIFY_FAILED:
		return EBADMSG;
	case HSE_SRV_RSP_INVALID_ADDR:
	case HSE_SRV_RSP_INVALID_PARAM:
		return EBADR;
	case HSE_SRV_RSP_NOT_SUPPORTED:
		return EOPNOTSUPP;
	case HSE_SRV_RSP_NOT_ALLOWED:
		return EPERM;
	case HSE_SRV_RSP_NOT_ENOUGH_SPACE:
		return ENOMEM;
	case HSE_SRV_RSP_KEY_NOT_AVAILABLE:
	case HSE_SRV_RSP_KEY_EMPTY:
		return ENOKEY;
	case HSE_SRV_RSP_KEY_INVALID:
	case HSE_SRV_RSP_KEY_WRITE_PROTECTED:
	case HSE_SRV_RSP_KEY_UPDATE_ERROR:
		return EKEYREJECTED;
	case HSE_SRV_RSP_CANCELED:
		return ECANCELED;
	default:
		return EFAULT;
	}
}

/**
 * hse_check_status - check the HSE global status
 *
 * Return: 16 MSB of MU instance FSR
 */
uint16_t hse_check_status(void)
{
	return (uint16_t)(priv.regs->fsr >> 16u);
}

/**
 * hse_mu_channel_available - check service channel status
 * @channel: channel index
 *
 * The 16 LSB of MU instance FSR are used by HSE for signaling channel status
 * as busy after a service request has been sent, until the HSE reply is ready.
 *
 * Return: true for channel available, false for invalid index or channel busy
 */
static inline bool hse_mu_channel_available(uint8_t channel)
{
	uint32_t fsrval, tsrval, rsrval;

	if (channel >= HSE_NUM_CHANNELS)
		return false;

	fsrval = priv.regs->fsr & (1 << channel);
	tsrval = priv.regs->tsr & (1 << channel);
	rsrval = priv.regs->rsr & (1 << channel);

	if (fsrval || !tsrval || rsrval)
		return false;

	return true;
}

/**
 * hse_mu_msg_send - send a message over MU (non-blocking)
 * @channel: channel index
 * @msg: input message
 *
 * Return: 0 on success, ECHRNG for channel index out of range, EBUSY for
 *         selected service channel busy
 */
static inline int hse_mu_msg_send(uint8_t channel, uint32_t msg)
{
	if (channel >= HSE_NUM_CHANNELS)
		return ECHRNG;

	if (!hse_mu_channel_available(channel)) {
		printf("hse: service channel %d busy\n", channel);
		return EBUSY;
	}

	priv.regs->tr[channel] = msg;

	return 0;
}

/**
 * hse_srv_req_sync - issue a synchronous service request (blocking)
 * @channel: service channel index
 * @srv_desc: service descriptor
 *
 * Send a HSE service descriptor on the selected channel and block until the
 * HSE response becomes available, then read the reply.
 *
 * Return: 0 on success, EINVAL for invalid parameter, ECHRNG for channel
 *         index out of range, EBUSY for channel busy or none available,
 *         ENOMSG for failure to read the HSE service response
 */
int hse_srv_req_sync(uint8_t channel, const void *srv_desc)
{
	uint32_t status;
	size_t offset;
	int i, err;

	if (!srv_desc)
		return EINVAL;

	if (channel != HSE_CHANNEL_ANY && channel >= HSE_NUM_CHANNELS)
		return ECHRNG;

	if (channel == HSE_CHANNEL_ANY) {
		for (i = 1u; i < HSE_NUM_CHANNELS; i++)
			if (!priv.channel_busy[i]) {
				channel = i;
				break;
			}
		if (channel > HSE_NUM_CHANNELS) {
			printf("hse: no service channel currently available\n");
			return EBUSY;
		}
	}

	priv.channel_busy[channel] = true;

	offset = channel * HSE_SRV_DESC_MAX_SIZE;
	memcpy(priv.desc + offset, srv_desc, HSE_SRV_DESC_MAX_SIZE);

	err = hse_mu_msg_send(channel, priv.desc_dma + offset);
	if (err) {
		printf("hse: send request failed on channel %d\n", channel);
		return err;
	}
	ssize_t rc = read(priv.fd, &status, sizeof(status));
	if (rc != sizeof(status) || priv.shared->ready[channel] == 0) {
		printf("hse: read response failed on channel %d\n", channel);
		err = ENOMSG;
		goto exit;
	}

	err = hse_err_decode(priv.shared->reply[channel]);
	if (err) {
		printf("hse: service response 0x%08X on channel %d\n",
		       priv.shared->reply[channel], channel);
		goto exit;
	}

	priv.shared->ready[channel] = 0;
	priv.shared->reply[channel] = 0;

exit:
	priv.channel_busy[channel] = false;
	return err;
}

/**
 * hse_virt_to_dma - get DMA address from virtual address
 * @addr: virtual address in the reserved memory range
 */
uint64_t hse_virt_to_dma(const void *addr)
{
	uint offset;

	if (!addr)
		return 0ul;

	offset = (uint)((uint8_t *)addr - (uint8_t *)priv.rmem);
	if (offset > priv.rmem_size) {
		printf("hse: address not located in HSE reserved memory\n");
		return 0ul;
	}

	return priv.rmem_dma + offset;
}

/**
 * hse_dev_open - open HSE UIO device and initialize user space driver
 */
int hse_dev_open(void)
{
	struct stat statbuf;
	uint16_t status;
	FILE *f;
	char s[HSE_UIO_MAX_FILE_SIZE];
	int i, err;

	if (priv.init) {
		printf("hse: driver already initialized\n");
		return 0;
	}

	/* open UIO device */
	priv.fd = open("/dev/" HSE_UIO_DEVICE, O_RDWR);
	if (priv.fd < 0) {
		printf("hse: failed to open %s\n", HSE_UIO_DEVICE);
		return ENOENT;
	}

	err = fstat(priv.fd, &statbuf);
	if(err < 0) {
		printf("hse: failed to open %s\n", HSE_UIO_DEVICE);
		err = ENOENT;
		goto err_close_fd;
	}

	/* map MU hardware register space */
	if ((f = fopen(HSE_UIO_REGS_SIZE, "r")) == NULL) {
		printf("hse: failed to open %s\n", HSE_UIO_REGS_SIZE);
		err = ENOENT;
		goto err_close_fd;
	}
	fgets(s, HSE_UIO_MAX_FILE_SIZE, f);
	priv.regs_size = (uint64_t)strtol(s, NULL, 0);
	fclose(f);

	priv.regs = mmap(NULL, priv.regs_size, PROT_READ | PROT_WRITE,
			 MAP_SHARED, priv.fd, HSE_UIO_MAP_REGS * getpagesize());
	if (priv.regs == MAP_FAILED) {
		printf("hse: failed to map MU register space\n");
		err = ENXIO;
		goto err_close_fd;
	}

	/* map service descriptor space */
	if ((f = fopen(HSE_UIO_DESC_ADDR, "r")) == NULL) {
		printf("hse: failed to open %s\n", HSE_UIO_DESC_ADDR);
		err = ENOENT;
		goto err_unmap_regs;
	}
	fgets(s, HSE_UIO_MAX_FILE_SIZE, f);
	priv.desc_dma = (uint64_t)strtol(s, NULL, 0);
	fclose(f);

	if ((f = fopen(HSE_UIO_DESC_SIZE, "r")) == NULL) {
		printf("hse: failed to open %s\n", HSE_UIO_DESC_SIZE);
		err = ENXIO;
		goto err_unmap_regs;
	}
	fgets(s, HSE_UIO_MAX_FILE_SIZE, f);
	priv.desc_size = (uint64_t)strtol(s, NULL, 0);
	fclose(f);

	priv.desc = mmap(NULL, priv.desc_size, PROT_READ | PROT_WRITE,
			 MAP_SHARED, priv.fd, HSE_UIO_MAP_DESC * getpagesize());
	if (priv.desc == MAP_FAILED) {
		printf("hse: failed to map descriptor space\n");
		err = ENXIO;
		goto err_unmap_regs;
	}

	/* map driver internal shared RAM */
	if ((f = fopen(HSE_UIO_INTL_SIZE, "r")) == NULL) {
		printf("hse: failed to open %s\n", HSE_UIO_INTL_SIZE);
		err = ENOENT;
		goto err_unmap_desc;
	}
	fgets(s, HSE_UIO_MAX_FILE_SIZE, f);
	priv.intl_size = (uint64_t)strtol(s, NULL, 0);
	fclose(f);

	priv.intl = mmap(NULL, priv.intl_size, PROT_READ | PROT_WRITE,
			 MAP_SHARED, priv.fd, HSE_UIO_MAP_INTL * getpagesize());
	if (priv.intl == MAP_FAILED) {
		printf("hse: failed to map driver internal RAM\n");
		err = ENXIO;
		goto err_unmap_desc;
	}

	/* map HSE reserved memory */
	if ((f = fopen(HSE_UIO_RMEM_ADDR, "r")) == NULL) {
		printf("hse: failed to open %s\n", HSE_UIO_RMEM_ADDR);
		err = ENOENT;
		goto err_unmap_intl;
	}
	fgets(s, HSE_UIO_MAX_FILE_SIZE, f);
	priv.rmem_dma = (uint64_t)strtol(s, NULL, 0);
	fclose(f);

	if ((f = fopen(HSE_UIO_RMEM_SIZE, "r")) == NULL) {
		printf("hse: failed to open %s\n", HSE_UIO_RMEM_SIZE);
		err = ENOENT;
		goto err_unmap_intl;
	}
	fgets(s, HSE_UIO_MAX_FILE_SIZE, f);
	priv.rmem_size = (uint64_t)strtol(s, NULL, 0);
	fclose(f);

	priv.rmem = mmap(NULL, priv.rmem_size, PROT_READ | PROT_WRITE,
			 MAP_SHARED, priv.fd, HSE_UIO_MAP_RMEM * getpagesize());
	if (priv.rmem == MAP_FAILED) {
		printf("hse: failed to map HSE reserved memory\n");
		err = ENXIO;
		goto err_unmap_intl;
	}
	priv.shared = priv.rmem;

	/* manage channels */
	for (i = 0; i < HSE_NUM_CHANNELS; i++) {
		priv.shared->ready[i] = 0;
		priv.shared->reply[i] = 0;
		priv.channel_busy[i] = false;
	}

	/* init mem pool */
	if (hse_mem_init(&priv.shared->reserved_end, priv.rmem_size - sizeof(struct hse_uio_intl))) {
		printf("hse: failed to init mem pool\n");
		err = ENOMEM;
		goto err_unmap_intl;
	}

	priv.init = true;

	status = hse_check_status();
	if (!(status & HSE_STATUS_INIT_OK)) {
		printf("hse: firmware not found");
		err = ENODEV;
		goto err_unmap_intl;
	}
	printf("hse: device initialized, status 0x%04x\n", status);

	return 0;
err_unmap_intl:
	munmap(priv.intl, priv.intl_size);
err_unmap_desc:
	munmap(priv.desc, priv.desc_size);
err_unmap_regs:
	munmap(priv.regs, priv.regs_size);
err_close_fd:
	close(priv.fd);
	printf("hse: init failed\n");
	return err;
}

/**
 * hse_dev_close - close HSE UIO device
 */
void hse_dev_close(void)
{
	if (!priv.init) {
		printf("hse: driver not initialized\n");
		return;
	}

	/* unmap UIO mappings */
	munmap(priv.rmem, priv.rmem_size);
	munmap(priv.intl, priv.intl_size);
	munmap(priv.desc, priv.desc_size);
	munmap(priv.regs, priv.regs_size);

	priv.init = false;

	/* close device */
	close(priv.fd);
}
