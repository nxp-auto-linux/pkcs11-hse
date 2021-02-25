/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * NXP HSE Driver - User-space driver support
 *
 * Copyright 2019-2021 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include "hse-usr.h"

#include "hse_interface.h"

#define HSE_UIO_DEVICE    "/dev/uio0"

#define HSE_UIO_REG_ADDR    "/sys/class/uio/uio0/maps/map0/addr"
#define HSE_UIO_REG_SIZE    "/sys/class/uio/uio0/maps/map0/size"

#define HSE_UIO_SHM_ADDR    "/sys/class/uio/uio0/maps/map1/addr"
#define HSE_UIO_SHM_SIZE    "/sys/class/uio/uio0/maps/map1/size"

#define MAX_FILE_SIZE    20u

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
	const uint32_t ver;
	const uint32_t par;
	uint32_t cr;
	uint32_t sr;
	uint8_t reserved0[240]; /* 0xF0 */
	uint32_t fcr;
	const uint32_t fsr;
	uint8_t reserved1[8]; /* 0x8 */
	uint32_t gier;
	uint32_t gcr;
	uint32_t gsr;
	uint8_t reserved2[4]; /* 0x4 */
	uint32_t tcr;
	const uint32_t tsr;
	uint32_t rcr;
	const uint32_t rsr;
	uint8_t reserved3[208]; /* 0xD0 */
	uint32_t tr[16];
	uint8_t reserved4[64]; /* 0x40 */
	const uint32_t rr[16];
};

/**
 * struct hse_uio_shm - HSE shared RAM layout
 * @ready[n]: reply ready on channel n
 * @reply[n]: service response on channel n
 * @srv_desc[n]: service descriptor reserved for channel n
 * @reserved_end: placeholder for the end of reserved area
 */
struct hse_uio_shm {
	uint8_t ready[HSE_NUM_CHANNELS];
	uint32_t reply[HSE_NUM_CHANNELS];
	uint8_t reserved_end;
};

/**
 * struct hse_usr_priv - driver private data
 * @regs: HSE MU register space address
 * @regs_size: HSE MU register space size
 * @shm: HSE shared RAM address
 * @shm_base: HSE shared RAM physical address
 * @shm_size: HSE shared RAM size
 * @fd: UIO file descriptor
 * @channel busy: cached channel status
 */
static struct hse_usr_priv {
	struct hse_mu_regs *regs;
	uint64_t regs_size;
	struct hse_uio_shm *shm;
	uint64_t shm_base;
	uint64_t shm_size;
	int fd;
	bool channel_busy[HSE_NUM_CHANNELS];
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
 * @srv_desc: service descriptor DMA address
 *
 * Send a HSE service descriptor on the selected channel and block until the
 * HSE response becomes available, then read the reply. The channel index
 * may be set to HSE_CHANNEL_ANY if request ordering is not required.
 * Service descriptors and all other data must be located in the HSE shared RAM.
 *
 * Return: 0 on success, EINVAL for invalid parameter, ECHRNG for channel
 *         index out of range, EBUSY for channel busy or none available,
 *         ENOMSG for failure to read the HSE service response
 */
int hse_srv_req_sync(uint8_t channel, uint32_t srv_desc)
{
	int i, err;

	if (channel != HSE_CHANNEL_ANY && channel >= HSE_NUM_CHANNELS)
		return ECHRNG;

	uint64_t res_offset = (uint64_t)((uint8_t *)&priv.shm->reserved_end -
			      (uint8_t *)priv.shm);

	uint64_t shm_start = priv.shm_base + res_offset;
	if (srv_desc < shm_start || srv_desc > priv.shm_base + priv.shm_size) {
		printf("hse: service descriptor not inside HSE shared RAM\n");
		return EINVAL;
	}

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

	err = hse_mu_msg_send(channel, srv_desc);
	if (err) {
		printf("hse: send request failed on channel %d\n", channel);
		return err;
	}

	uint32_t status;
	ssize_t rc = read(priv.fd, &status, sizeof(status));
	if (rc != sizeof(status) || priv.shm->ready[channel] == 0) {
		printf("hse: read response failed on channel %d\n", channel);
		err = ENOMSG;
		goto exit;
	}

	err = hse_err_decode(priv.shm->reply[channel]);
	if (err) {
		printf("hse: service response 0x%08X on channel %d\n",
		       priv.shm->reply[channel], channel);
		goto exit;
	}

	priv.shm->ready[channel] = 0;
	priv.shm->reply[channel] = 0;

exit:
	priv.channel_busy[channel] = false;
	return err;
}

/**
 * hse_get_shared_mem_addr - get shared RAM virtual address from offset
 * @offset: shared RAM offset
 */
void *hse_get_shared_mem_addr(uint64_t offset)
{
	uint64_t res_offset = (uint64_t)((uint8_t *)&priv.shm->reserved_end -
			      (uint8_t *)priv.shm);

	if (offset < res_offset)
		return NULL;

	return (uint8_t *)priv.shm + offset;
}

/**
 * hse_virt_to_phys - get shared RAM physical address from virtual address
 * @virt_addr: virtual address located pointing to shared RAM
 */
uint64_t hse_virt_to_phys(const void *virt_addr)
{
	uint offset;

	if (!virt_addr)
		return 0ul;

	offset = (uint)((uint8_t *)virt_addr - (uint8_t *)priv.shm);
	if (offset > priv.shm_size) {
		printf("hse: address not located in HSE shared RAM \n");
		return EINVAL;
	}

	return priv.shm_base + offset;
}

/**
 * hse_usr_initialize - initialize UIO driver user-space component
 */
int hse_usr_initialize(void)
{
	struct stat statbuf;
	FILE *f;
	char s[MAX_FILE_SIZE];
	int i, err;

	/* open UIO device */
	priv.fd = open(HSE_UIO_DEVICE, O_RDWR);
	if (priv.fd < 0) {
		printf("hse: failed to open %s\n", HSE_UIO_DEVICE);
		return ENOENT;
	}

	err = fstat(priv.fd, &statbuf);
	if(err < 0) {
		printf("hse: failed to open %s\n", HSE_UIO_DEVICE);
		return ENOENT;
	}

	/* get hardware register space size */
	if ((f = fopen(HSE_UIO_REG_SIZE, "r")) == NULL) {
		printf("hse: failed to open %s\n", HSE_UIO_REG_SIZE);
		return ENOENT;
	}
	fgets(s, MAX_FILE_SIZE, f);
	priv.regs_size = (uint64_t)strtol(s, NULL, 0);
	fclose(f);

	/* map hardware register space */
	priv.regs = mmap(NULL, priv.regs_size, PROT_READ | PROT_WRITE,
			 MAP_SHARED, priv.fd, 0 * getpagesize());
	if (priv.regs == MAP_FAILED) {
		printf("hse: failed to map MU registers\n");
		return EFAULT;
	}

	/* get HSE shared memory base address */
	if ((f = fopen(HSE_UIO_SHM_ADDR, "r")) == NULL) {
		printf("hse: failed to open %s\n", HSE_UIO_SHM_ADDR);
		return ENOENT;
	}
	fgets(s, MAX_FILE_SIZE, f);
	priv.shm_base = (uint64_t)strtol(s, NULL, 0);
	fclose(f);

	/* get HSE shared memory size */
	if ((f = fopen(HSE_UIO_SHM_SIZE, "r")) == NULL) {
		printf("hse: failed to open %s\n", HSE_UIO_SHM_SIZE);
		return ENOENT;
	}
	fgets(s, MAX_FILE_SIZE, f);
	priv.shm_size = (uint64_t)strtol(s, NULL, 0);
	fclose(f);

	/* map HSE shared RAM */
	priv.shm = mmap(NULL, priv.shm_size, PROT_READ | PROT_WRITE,
			MAP_SHARED, priv.fd, 1 * getpagesize());
	if (priv.shm == MAP_FAILED) {
		printf("hse: failed to map HSE shared RAM\n");
		return EFAULT;
	}

	for (i = 0; i < HSE_NUM_CHANNELS; i++) {
		priv.shm->ready[i] = 0;
		priv.shm->reply[i] = 0;
		priv.channel_busy[i] = false;
	}

	printf("hse: UIO device open\n");

	return 0;
}

/**
 * hse_usr_finalize - UIO driver user-space component cleanup
 */
void hse_usr_finalize(void)
{
	munmap(priv.regs, priv.regs_size);
	munmap(priv.shm, priv.shm_size);

	close(priv.fd);

	printf("hse: UIO device closed\n");
}
