/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * NXP HSE User Space Driver - Core
 *
 * Copyright 2019-2026 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stddef.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <semaphore.h>
#include <unistd.h>
#include <poll.h>
#include <pthread.h>
#include <errno.h>

#include "libhse.h"
#include "hse-internal.h"

#include "hse_interface.h"

#define __stringify_1(x)    #x
#define __stringify(x)      __stringify_1(x)

#define hse_wmb() asm volatile("dmb oshst" : : : "memory")

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
#define HSE_UIO_VERSION      "/sys/class/uio/" HSE_UIO_DEVICE "/version"

#define HSE_UIO_FILE_SIZE    20u /* maximum size of sysfs file content */

#define HSE_UIO_REQ_TIMEOUT  2000u /* request timeout, in milliseconds */

#define HSE_DEV_SETUP_SEM    "/libhse_dev_setup" /* POSIX semaphore name used during device setup */
#define HSE_SEM_PERMS		 0660

/*
 * HSE_INTL_RESERVED_SIZE - Size of reserved region in internal memory
 *
 * This region cannot be used for internal node metadata or the dynamic
 * allocation pool.
 * When intl_size equals this value (4KB minimum config), no dynamic
 * internal memory allocations are possible.
 */
#define HSE_INTL_RESERVED_SIZE    4096u
#define HSE_MIN_POOL_SIZE 4096u

/*
 * HSE_INTL_MIN_SIZE - Minimum internal memory size to enable dynamic pool
 *
 * To have a functional internal memory pool, we need:
 * - HSE_INTL_RESERVED_SIZE: Reserved internal memory
 * - HSE_MEM_OFF: Node metadata region
 * - 4KB: Minimum dynamic pool size
 *
 * If intl_size < HSE_INTL_MIN_SIZE, no dynamic internal allocations
 * are possible and hse_intl_mem_alloc() will return -ENOSPC.
 */
#define HSE_INTL_MIN_SIZE  (HSE_INTL_RESERVED_SIZE + \
							HSE_MEM_OFF + HSE_MIN_POOL_SIZE)
/**
 * enum hse_fw_status - HSE firmware status
 * @HSE_FW_SHUTDOWN: firmware not initialized or shut down due to fatal error
 * @HSE_FW_RUNNING: firmware running and able to service any type of request
 * @HSE_FW_STANDBY: firmware considered in stand-by state, no service requests
 */
enum hse_fw_status {
	HSE_FW_SHUTDOWN = 0u,
	HSE_FW_RUNNING = 1u,
	HSE_FW_STANDBY = 2u,
};

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
 * @channel_ready[n]: reply ready on channel n
 * @channel_reply[n]: response on channel n
 * @event: HSE firmware system event mask
 * @setup_done: initialization sequence done flag
 * @firmware_status: cached status of HSE firmware
 * @channel_busy[n]: service channel busy flag
 * @channel_res[n]: channel currently reserved
 * @stream_busy[n]: streaming context busy flag
 * @channel_lock: used for channel acquisition
 * @stream_lock: used for streaming context acquisiton
 * @mem_lock: used for shared memory allocation
 */
struct hse_uio_intl {
	volatile uint8_t channel_ready[HSE_NUM_CHANNELS];
	volatile uint32_t channel_reply[HSE_NUM_CHANNELS];
	volatile uint32_t event;
	volatile bool setup_done;
	enum hse_fw_status firmware_status;
	uint8_t reserved[2];
	volatile bool channel_busy[HSE_NUM_CHANNELS];
	volatile bool channel_res[HSE_NUM_CHANNELS];
	volatile bool stream_busy[HSE_STREAM_COUNT];
	volatile pthread_spinlock_t channel_lock __attribute__((aligned(16)));
	volatile pthread_spinlock_t stream_lock __attribute__((aligned(16)));
	volatile pthread_spinlock_t mem_lock __attribute__((aligned(16)));
	uint32_t mem_ph __attribute__((aligned(16)));
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
 * @rmem: HSE reserved memory virtual address
 * @rmem_dma: HSE reserved memory DMA address
 * @rmem_size: HSE reserved memory size
 * @fd: UIO file descriptor
 * @channel busy: cached channel status
 * @channel_res: reserved for upper layer session
 * @init: UIO component initialized flag
 * @locked: single instance only permitted flag
 * @thread_refcnt: number of threads currently active
 */
static struct hse_usr_priv {
	struct hse_mu_regs *regs;
	uint64_t regs_size;
	void *desc;
	uint64_t desc_dma;
	uint64_t desc_size;
	struct hse_uio_intl *intl;
	uint64_t intl_size;
	void *rmem;
	uint64_t rmem_dma;
	uint64_t rmem_size;
	int fd;
	bool init;
	bool locked;
	atomic_int thread_refcnt;
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

pthread_spinlock_t *get_mem_lock(void)
{
	return &priv.intl->mem_lock;
}

/**
 * hse_check_status - check the HSE global status
 *
 * Return: 16 MSB of MU instance FSR
 */
uint16_t hse_check_status(void)
{
	if(!priv.init)
		return 0;

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
 * Return: 0 on success, ENODEV for device not initialized or disabled due to
 *         fatal error or tamper detection, ECHRNG for channel index out of
 *         range, EBUSY for selected service channel busy
 */
static int hse_mu_msg_send(uint8_t channel, uint32_t msg)
{
	if (!priv.init || priv.intl->event)
		return ENODEV;

	if (channel >= HSE_NUM_CHANNELS)
		return ECHRNG;

	if (!hse_mu_channel_available(channel)) {
		printf("libhse: service channel %d busy\n", channel);
		return EBUSY;
	}

	hse_wmb();
	priv.regs->tr[channel] = msg;

	return 0;
}

/**
 * hse_mu_msg_recv - receive a message over MU (blocking)
 * @channel: channel index
 * @msg: output message
 *
 * Return: 0 on success, EINVAL for invalid parameter, ENODEV for device not
 *         initialized or disabled due to fatal error or tamper detection,
 *         ECHRNG for channel index out of range, EFAULT for polling error,
 *         ETIMEDOUT for message waiting time exceeding HSE_UIO_REQ_TIMEOUT
 */
static int hse_mu_msg_recv(uint8_t channel, uint32_t *msg)
{
	struct pollfd pfd;
	int ret, err = 0;

	if (!msg)
		return EINVAL;

	if (!priv.init || priv.intl->event)
		return ENODEV;

	if (channel >= HSE_NUM_CHANNELS)
		return ECHRNG;

	/* wait for reply */
	pfd.fd = priv.fd;
	pfd.events = POLLIN;

	do {
		ret = poll(&pfd, 1, HSE_UIO_REQ_TIMEOUT);
		if (ret == -1) {
			printf("libhse: poll failed on channel %d\n", channel);
			return EFAULT;
		}

		if (!ret) {
			printf ("libhse: reply timeout on channel %d\n",
				channel);
			return ETIMEDOUT;
		}

		if (priv.intl->event) {
			printf("libhse: firmware communication terminated\n");
			return ENODEV;
		}
	} while (priv.intl->channel_ready[channel] == 0);

	/* return reply */
	*msg = priv.intl->channel_reply[channel];

	priv.intl->channel_ready[channel] = 0;
	priv.intl->channel_reply[channel] = 0;

	return err;
}

/**
 * hse_srv_req_sync - issue a synchronous service request (blocking)
 * @channel: service channel index
 * @srv_desc: service descriptor
 * @size: service descriptor size
 * @srv_rsp: service response (can be NULL)
 *
 * Send a HSE service descriptor on the selected channel and block until the
 * HSE response has become available on the selected channel (or a timeout has
 * occured since the last reply received from firmware), then read the reply.
 *
 * Service response parameter can be used to retrieve the original HSE reply
 * code for parsing it directly in the application (mainly for custom firmware
 * extensions). If not required, it can be left NULL and will just be ignored.
 * In case of MU message send / receive error, it will be left untouched.
 *
 * Return: 0 on success, EINVAL for invalid parameter, ENODEV for device not
 *         initialized or disabled due to fatal error or tamper detection,
 *         ECHRNG for channel index out of range, EBUSY for channel busy, none
 *         available or firmware on stand-by, ENOTRECOVERABLE for firmware in
 *         shutdown state, ENOMSG for failure to read service request response,
 *         EBADMSG for verification failed, EBADR for invalid descriptor,
 *         EOPNOTSUPP for operation not supported, EPERM for operation not
 *         allowed, ENOMEM for not enough space, ENOKEY for key empty or not
 *         available, EKEYREJECTED for invalid key or write / update error,
 *         ECANCELED for request canceled, EFAULT for other request errors
 */
int hse_srv_req_sync(uint8_t channel, const void *srv_desc, const size_t size,
		     uint32_t *srv_rsp)
{
	size_t offset;
	int i, err = 0;
	uint32_t reply;

	if (!srv_desc || !size)
		return EINVAL;

	if (!priv.init || priv.intl->event)
		return ENODEV;

	if (channel != HSE_CHANNEL_ANY && channel >= HSE_NUM_CHANNELS)
		return ECHRNG;

	switch (priv.intl->firmware_status) {
	case HSE_FW_STANDBY:
		return EBUSY;
	case HSE_FW_SHUTDOWN:
		return ENOTRECOVERABLE;
	default:
		break;
	}

	pthread_spin_lock(&priv.intl->channel_lock);

	if (channel == HSE_CHANNEL_ANY) {
		for (i = 1u; i < HSE_NUM_CHANNELS; i++)
			if (!priv.intl->channel_busy[i] &&
			    !priv.intl->channel_res[i]) {
				channel = i;
				break;
			}
		if (channel >= HSE_NUM_CHANNELS) {
			pthread_spin_unlock(&priv.intl->channel_lock);
			return EBUSY;
		}
	}

	priv.intl->channel_busy[channel] = true;

	pthread_spin_unlock(&priv.intl->channel_lock);

	/* copy service descriptor */
	offset = channel * HSE_SRV_DESC_MAX_SIZE;
	_raw_hse_memcpy(priv.desc + offset, srv_desc, size);
	_raw_hse_memset(priv.desc + offset + size, 0, HSE_SRV_DESC_MAX_SIZE - size);

	/* issue request */
	err = hse_mu_msg_send(channel, priv.desc_dma + offset);
	if (err) {
		printf("libhse: send request failed on channel %d\n", channel);
		goto exit;
	}

	/* wait for reply */
	err = hse_mu_msg_recv(channel, &reply);
	if (err) {
		printf("libhse: read reply failed on channel %d\n", channel);
		goto exit;
	}

	/* return original service response, if required */
	if (srv_rsp)
		*srv_rsp = reply;

	/* translate reply to error code */
	err = hse_err_decode(reply);
	if (err) {
		printf("libhse: service response 0x%08X on channel %d\n",
		       reply, channel);
	}

exit:
	priv.intl->channel_busy[channel] = false;
	return err;
}

/**
 * hse_channel_acquire - acquire a service channel
 * @channel: channel index
 *
 * Acquire a service channel for an upper layer session or streaming operation.
 * Skip channel zero, which is restricted to administrative requests and cannot
 * be used for crypto operations.
 *
 * Return: 0 on success, ENODEV for device not initialized or disabled due to
 *         fatal error or tamper detection, EINVAL for invalid parameter,
 *         EBUSY for no service channel available
 */
int hse_channel_acquire(uint8_t *channel)
{
	uint8_t crt;

	if (!priv.init || priv.intl->event)
		return ENODEV;

	if (!channel)
		return EINVAL;

	pthread_spin_lock(&priv.intl->channel_lock);

	for (crt = 1u; crt < HSE_NUM_CHANNELS; crt++)
		if (!priv.intl->channel_busy[crt] &&
		    !priv.intl->channel_res[crt])
			break;
	if (crt >= HSE_NUM_CHANNELS) {
		pthread_spin_unlock(&priv.intl->channel_lock);
		printf("libhse: no service channel currently available\n");
		return EBUSY;
	}

	priv.intl->channel_res[crt] = true;
	*channel = crt;

	pthread_spin_unlock(&priv.intl->channel_lock);

	return 0;
}

/**
 * hse_channel_free - free the selected service channel
 * @channel: channel index
 */
void hse_channel_free(uint8_t channel)
{
	if (!priv.init || priv.intl->event)
		return;

	if (channel >= HSE_NUM_CHANNELS)
		return;

	priv.intl->channel_res[channel] = false;
}

/**
 * hse_stream-aqcuire - acquire a streaming context
 * @channel: streaming context index
 *
 * Acquire a streaming context for a streaming operation.
 *
 * Return: 0 on success, ENODEV for device not initialized or disabled due to
 *         fatal error or tamper detection, EINVAL for invalid parameter,
 *         EBUSY for no streaming context available
 */
int hse_stream_acquire(uint8_t *stream)
{
	uint8_t srt;

	if (!priv.init || priv.intl->event)
		return ENODEV;

	if (!stream)
		return EINVAL;

	pthread_spin_lock(&priv.intl->stream_lock);

	for (srt = 0; srt < HSE_STREAM_COUNT; srt++)
		if (!priv.intl->stream_busy[srt])
			break;
	if (srt >= HSE_STREAM_COUNT) {
		pthread_spin_unlock(&priv.intl->stream_lock);
		printf("libhse: no streaming context currently available\n");
		return EBUSY;
	}

	priv.intl->stream_busy[srt] = true;
	*stream = srt;

	pthread_spin_unlock(&priv.intl->stream_lock);

	return 0;
}

/**
 * hse_stream_free - free the selected streaming context
 * @channel: streaming context index
 */
void hse_stream_free(uint8_t stream)
{
	if (!priv.init || priv.intl->event)
		return;

	if (stream >= HSE_STREAM_COUNT)
		return;

	priv.intl->stream_busy[stream] = false;
}

/**
 * hse_virt_to_dma - get DMA address from virtual address
 * @addr: virtual address in the reserved memory range
 */
uint64_t hse_virt_to_dma(int node_handle, uint32_t off)
{
	uint32_t offset;
	uint64_t addr;

	if (!priv.init || priv.intl->event || node_handle < 0)
		return 0ul;

	addr = hse_get_node_mem_addr(node_handle, false);
	if (addr == 0) {
		printf("libhse: node handle invalid\n");
		return 0ul;
	}

	offset = (uint32_t)(((uint8_t *)addr + off) - (uint8_t *)priv.rmem);
	if (offset > priv.rmem_size) {
		printf("libhse: address not located in HSE reserved memory\n");
		return 0ul;
	}

	return priv.rmem_dma + offset;
}

/**
 * hse_dev_setup - HSE device one-time setup
 */
static int hse_dev_setup(void)
{
	sem_t *setup_sem = NULL;
	bool intl_pool_available;
	int rc = 0;

	/* Check if there is space for internal memory pool */
	intl_pool_available = (priv.intl_size >= HSE_INTL_MIN_SIZE);

	setup_sem = sem_open(HSE_DEV_SETUP_SEM, O_CREAT, HSE_SEM_PERMS, 1);
	if (setup_sem == SEM_FAILED) {
		printf("libhse: couldn't open setup semaphore\n");
		return errno;
	}

	sem_wait(setup_sem);

	if (priv.intl->setup_done) {
		if (intl_pool_available)
			rc = hse_mem_init((uint8_t *)priv.intl + HSE_INTL_RESERVED_SIZE, priv.rmem);
		else
			rc = hse_mem_init(NULL, priv.rmem);  /* No internal pool */
		goto out;
	}

	/* initialize locks */
	pthread_spin_init(&priv.intl->channel_lock, PTHREAD_PROCESS_SHARED);
	pthread_spin_init(&priv.intl->stream_lock, PTHREAD_PROCESS_SHARED);
	pthread_spin_init(&priv.intl->mem_lock, PTHREAD_PROCESS_SHARED);

	/* initialize internal memory as buffer pool (only if space available) */
	if (intl_pool_available) {
		if (hse_mem_setup((uint8_t *)priv.intl + HSE_INTL_RESERVED_SIZE,
			priv.intl_size - HSE_INTL_RESERVED_SIZE, true)) {
			printf("libhse: failed to set up intl mem pool\n");
			rc = ENOMEM;
			goto out;
		}
		printf("libhse: internal memory pool initialized (%lu KB available)\n",
			   (unsigned long)(priv.intl_size - HSE_INTL_RESERVED_SIZE) / 1024);
	} else {
		printf("libhse: internal memory pool disabled (intl_size=%lu, min=%u)\n",
			   (unsigned long)priv.intl_size, HSE_INTL_RESERVED_SIZE);
	}

	/* initialize reserved memory as buffer pool */
	if (hse_mem_setup(priv.rmem, priv.rmem_size, false)) {
		printf("libhse: failed to set up shared mem pool\n");
		rc = ENOMEM;
		goto out;
	}

	priv.intl->setup_done = true;

	/* destroy semaphore once all processes close it */
	sem_unlink(HSE_DEV_SETUP_SEM);

out:
	sem_post(setup_sem);
	sem_close(setup_sem);

	return rc;
}

/**
 * hse_dev_open - open HSE UIO device and initialize user space driver
 *
 * Meant to be called just once per library instance, before any other call.
 */
int hse_dev_open(void)
{
	struct stat statbuf;
	uint16_t status;
	FILE *f;
	char s[HSE_UIO_FILE_SIZE];
	unsigned int ver;
	int err;

	if (priv.locked) {
		printf("libhse: only single instance allowed at this time\n");
		return EBUSY;
	}

	if (priv.init) {
		atomic_fetch_add(&priv.thread_refcnt, 1);
		return 0;
	}

	priv.locked = true;

	/* open UIO device */
	priv.fd = open("/dev/" HSE_UIO_DEVICE, O_RDWR);
	if (priv.fd < 0) {
		printf("libhse: failed to open %s\n", HSE_UIO_DEVICE);
		return ENOENT;
	}

	err = fstat(priv.fd, &statbuf);
	if(err < 0) {
		printf("libhse: failed to open %s\n", HSE_UIO_DEVICE);
		err = ENOENT;
		goto err_close_fd;
	}

	/* check kernel driver version */
	if ((f = fopen(HSE_UIO_VERSION, "r")) == NULL) {
		printf("libhse: failed to open %s\n", HSE_UIO_VERSION);
		err = ENOENT;
		goto err_close_fd;
	}
	fgets(s, HSE_UIO_FILE_SIZE, f);
	ver = (unsigned int)strtol(s, NULL, 0); /* skip minor */
	fclose(f);

	if (ver != HSE_LIBVER_MAJOR) {
		printf("libhse: kernel driver version mismatch\n");
		err = ENODEV;
		goto err_close_fd;
	}

	/* map MU hardware register space */
	if ((f = fopen(HSE_UIO_REGS_SIZE, "r")) == NULL) {
		printf("libhse: failed to open %s\n", HSE_UIO_REGS_SIZE);
		err = ENOENT;
		goto err_close_fd;
	}
	fgets(s, HSE_UIO_FILE_SIZE, f);
	priv.regs_size = (uint64_t)strtol(s, NULL, 0);
	fclose(f);

	priv.regs = mmap(NULL, priv.regs_size, PROT_READ | PROT_WRITE,
			 MAP_SHARED, priv.fd, HSE_UIO_MAP_REGS * getpagesize());
	if (priv.regs == MAP_FAILED) {
		printf("libhse: failed to map MU register space\n");
		err = ENXIO;
		goto err_close_fd;
	}

	/* map service descriptor space */
	if ((f = fopen(HSE_UIO_DESC_ADDR, "r")) == NULL) {
		printf("libhse: failed to open %s\n", HSE_UIO_DESC_ADDR);
		err = ENOENT;
		goto err_unmap_regs;
	}
	fgets(s, HSE_UIO_FILE_SIZE, f);
	priv.desc_dma = (uint64_t)strtol(s, NULL, 0);
	fclose(f);

	if ((f = fopen(HSE_UIO_DESC_SIZE, "r")) == NULL) {
		printf("libhse: failed to open %s\n", HSE_UIO_DESC_SIZE);
		err = ENXIO;
		goto err_unmap_regs;
	}
	fgets(s, HSE_UIO_FILE_SIZE, f);
	priv.desc_size = (uint64_t)strtol(s, NULL, 0);
	fclose(f);

	priv.desc = mmap(NULL, priv.desc_size, PROT_READ | PROT_WRITE,
			 MAP_SHARED, priv.fd, HSE_UIO_MAP_DESC * getpagesize());
	if (priv.desc == MAP_FAILED) {
		printf("libhse: failed to map descriptor space\n");
		err = ENXIO;
		goto err_unmap_regs;
	}

	/* map driver internal shared RAM */
	if ((f = fopen(HSE_UIO_INTL_SIZE, "r")) == NULL) {
		printf("libhse: failed to open %s\n", HSE_UIO_INTL_SIZE);
		err = ENOENT;
		goto err_unmap_desc;
	}
	fgets(s, HSE_UIO_FILE_SIZE, f);
	priv.intl_size = (uint64_t)strtol(s, NULL, 0);
	fclose(f);

	priv.intl = mmap(NULL, priv.intl_size, PROT_READ | PROT_WRITE,
			 MAP_SHARED, priv.fd, HSE_UIO_MAP_INTL * getpagesize());
	if (priv.intl == MAP_FAILED) {
		printf("libhse: failed to map driver internal RAM\n");
		err = ENXIO;
		goto err_unmap_desc;
	}

	/* map HSE reserved memory */
	if ((f = fopen(HSE_UIO_RMEM_ADDR, "r")) == NULL) {
		printf("libhse: failed to open %s\n", HSE_UIO_RMEM_ADDR);
		err = ENOENT;
		goto err_unmap_intl;
	}
	fgets(s, HSE_UIO_FILE_SIZE, f);
	priv.rmem_dma = (uint64_t)strtol(s, NULL, 0);
	fclose(f);

	if ((f = fopen(HSE_UIO_RMEM_SIZE, "r")) == NULL) {
		printf("libhse: failed to open %s\n", HSE_UIO_RMEM_SIZE);
		err = ENOENT;
		goto err_unmap_intl;
	}
	fgets(s, HSE_UIO_FILE_SIZE, f);
	priv.rmem_size = (uint64_t)strtol(s, NULL, 0);
	fclose(f);

	priv.rmem = mmap(NULL, priv.rmem_size, PROT_READ | PROT_WRITE,
			 MAP_SHARED, priv.fd, HSE_UIO_MAP_RMEM * getpagesize());
	if (priv.rmem == MAP_FAILED) {
		printf("libhse: failed to map HSE reserved memory\n");
		err = ENXIO;
		goto err_unmap_intl;
	}

	/* set up shared resources */
	err = hse_dev_setup();
	if (err)
		goto err_unmap_rmem;
	priv.init = true;

	/* check firmware status */
	status = hse_check_status();
	if (!(status & HSE_STATUS_INIT_OK)) {
		printf("libhse: firmware not found or MU interface inactive\n");
		err = ENODEV;
		priv.init = false;
		goto err_unmap_rmem;
	}
	printf("libhse: initialized, firmware status 0x%04x\n", status);

	atomic_init(&priv.thread_refcnt, 1);
	priv.locked = false;

	return 0;
err_unmap_rmem:
	munmap(priv.rmem, priv.rmem_size);
err_unmap_intl:
	munmap(priv.intl, priv.intl_size);
err_unmap_desc:
	munmap(priv.desc, priv.desc_size);
err_unmap_regs:
	munmap(priv.regs, priv.regs_size);
err_close_fd:
	close(priv.fd);
	priv.locked = false;
	printf("libhse: init failed (err = %d)\n", err);
	return err;
}

/**
 * Get pointer to the static memory region
 *
 * This static region occupies the space between the end of hse_uio_intl
 * and the 4KB page boundary. This provides approximately 3.8KB for other
 * use cases.
 */
void *hse_intl_get_static_mem(void)
{
	if (!priv.init || !priv.intl)
		return NULL;

	return (uint8_t *)priv.intl + offsetof(struct hse_uio_intl, mem_ph);
}

/*
 * Get size of the static memory region
 *
 * Return: available size in bytes
 */
size_t hse_intl_get_static_size(void)
{
	return HSE_INTL_RESERVED_SIZE - offsetof(struct hse_uio_intl, mem_ph);
}

/**
 * hse_dev_close - close HSE UIO device
 *
 * Meant to be called just once per library instance, with no subsequent calls
 * to any of the library routines allowed past this point in time.
 */
void hse_dev_close(void)
{
	if (!priv.init) {
		printf("libhse: not initialized\n");
		return;
	}

	if (priv.locked) {
		printf("libhse: only single instance allowed at this time\n");
		return;
	}

	/* check for other open instances */
	if (atomic_fetch_sub(&priv.thread_refcnt, 1) > 1)
		return;

	/* unmap UIO mappings */
	munmap(priv.rmem, priv.rmem_size);
	munmap(priv.intl, priv.intl_size);
	munmap(priv.desc, priv.desc_size);
	munmap(priv.regs, priv.regs_size);

	/* close device */
	close(priv.fd);

	priv.init = false;

	printf("libhse: closed\n");
}
