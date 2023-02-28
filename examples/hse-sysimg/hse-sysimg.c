/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * hse-sysimg - example application using libhse to publish SYS_IMG to SD Card
 *
 * Copyright 2019-2022 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "libhse.h"
#include "hse_interface.h"

#define IVT_OFFSET 0x1000

struct ivt {
	uint8_t reserved1[52];
	uint32_t sysimg;
	uint32_t sysimg_bckup;
	uint8_t reserved2[196];
} __attribute__((packed));

int hse_sysimg_get_size(uint32_t *size)
{
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	hseGetSysImageSizeSrv_t *get_sysimg_size_req;
	int err;

	get_sysimg_size_req = &srv_desc.hseSrv.getSysImageSizeReq;

	srv_desc.srvId = HSE_SRV_ID_GET_SYS_IMAGE_SIZE;
	get_sysimg_size_req->pSysImageSize = hse_virt_to_dma(size);

	err = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc, sizeof(srv_desc));

	return err;
}

int hse_sysimg_write(const char *device, void *sysimg, uint32_t sysimg_size)
{
	struct ivt *ivt;
	off_t seek_off;
	int fd, bytes;
	int err = 0;

	fd = open(device, O_SYNC | O_RDWR);
	if (fd < 0) {
		printf("ERROR: could not open %s\n", device);
		return errno;
	}

	seek_off = lseek(fd, IVT_OFFSET, SEEK_SET);
	if (seek_off < 0 || seek_off != IVT_OFFSET) {
		printf("ERROR: could not find IVT\n");
		err = errno;
		goto err_close_fd;
	}

	ivt = malloc(sizeof(*ivt));
	if (!ivt) {
		printf("ERROR: could not allocate space for IVT\n");
		err = ENOMEM;
		goto err_close_fd;
	}

	bytes = read(fd, (void *)ivt, sizeof(*ivt));
	if (bytes < 0 || bytes != sizeof(*ivt)) {
		printf("ERROR: could not read IVT\n");
		err = errno;
		goto err_free_ivt;
	}

	seek_off = lseek(fd, ivt->sysimg, SEEK_SET);
	if (seek_off < 0 || seek_off != ivt->sysimg) {
		printf("ERROR: could not find SYSIMG location\n");
		err = errno;
		goto err_free_ivt;
	}

	bytes = write(fd, sysimg, sysimg_size);
	if (bytes < 0 || bytes != sysimg_size) {
		printf("ERROR: could not write SYSIMG\n");
		err = errno;
	}

err_free_ivt:
	free(ivt);
err_close_fd:
	close(fd);
	return err;
}

int main(int argc, char *argv[])
{
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	hsePublishSysImageSrv_t *publish_sysimg_req;
	uint32_t *publish_off, *sysimg_size;
	uint16_t status;
	void *sysimg;
	int err;

	if (argc != 2) {
		printf("ERROR: Missing MMC device argument!\n\n");
		printf("Usage:\n");
		printf("\t./hse-sysimg /dev/<mmc>\n");
		return 1;
	}

	printf("DEVICE: %s\n\n", argv[1]);

	/* open HSE device */
	err = hse_dev_open();
	if (err) {
		printf("ERROR: failed to open HSE device: error %d\n", err);
		return err;
	}

	/* check firmware global status */
	status = hse_check_status();
	if (!(status & HSE_STATUS_INSTALL_OK)) {
		printf("ERROR: key catalogs not formatted\n");
		return ENODEV;
	}

	/* unused, but required by HSE */
	publish_off = hse_mem_alloc(sizeof(*publish_off));
	if (!publish_off) {
		printf("ERROR: 'publish_off' allocation failed\n");
		return ENOMEM;
	}

	sysimg_size = hse_mem_alloc(sizeof(*sysimg_size));
	if (!sysimg_size) {
		printf("ERROR: 'sysimg_size' allocation failed\n");
		err = ENOMEM;
		goto err_free_publish_off;
	}

	err = hse_sysimg_get_size(sysimg_size);
	if (err) {
		printf("ERROR: could not read SYSIMG size\n");
		goto err_free_sysimg_size;
	}

	sysimg = hse_mem_alloc(*sysimg_size);
	if (!sysimg) {
		printf("ERROR: could not allocate memory for SYSIMG\n");
		err = ENOMEM;
		goto err_free_sysimg_size;
	}

	publish_sysimg_req = &srv_desc.hseSrv.publishSysImageReq;

	srv_desc.srvId = HSE_SRV_ID_PUBLISH_SYS_IMAGE;
	publish_sysimg_req->publishOptions = HSE_PUBLISH_ALL_DATA_SETS;
	publish_sysimg_req->pPublishOffset = hse_virt_to_dma(publish_off);
	publish_sysimg_req->pBuffLength = hse_virt_to_dma(sysimg_size);
	publish_sysimg_req->pBuff = hse_virt_to_dma(sysimg);

	err = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc, sizeof(srv_desc));
	if (err) {
		printf("ERROR: could not publish SYSIMG\n");
		goto err_free_sysimg;
	}

	err = hse_sysimg_write(argv[1], sysimg, *sysimg_size);

err_free_sysimg:
	hse_mem_free(sysimg);
err_free_sysimg_size:
	hse_mem_free(sysimg_size);
err_free_publish_off:
	hse_mem_free(publish_off);
	return err;
}
