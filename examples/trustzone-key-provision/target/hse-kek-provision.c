// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2025 NXP
 */

#include <stdio.h>
#include <stdint.h>
#include <errno.h>

#include <libhse.h>
#include <hse_kp.h>

#define ERROR(fmt, ...) printf("[ERROR] " fmt, ##__VA_ARGS__)
#define INFO(fmt, ...) printf("[INFO] " fmt, ##__VA_ARGS__)

int main(int argc, char *argv[])
{
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	DECLARE_SET_ZERO(hseImportKeySrv_t, import_key_req);
	DECLARE_SET_ZERO(hseKeyInfo_t, key_info);

	FILE *file;
	uint16_t status;
	int err, kek_buff_handle, key_info_handle;
	char kek[HSE_KEK_SIZE];
	size_t bytes_read;

	switch (argc) {
	case 2:
		file = fopen(argv[1], "r");
		if (!file) {
			ERROR("Cannot open file %s\n", argv[1]);
			return -EINVAL;
		}
		break;
	default:
		INFO("Usage: %s <path/to/file>\n", argv[0]);
		INFO("- path to a file containing the KEK (Key Encryption Key)\n");
		return -EINVAL;
	}

	bytes_read = fread(kek, sizeof(uint8_t), HSE_KEK_SIZE, file);
	if (bytes_read != HSE_KEK_SIZE) {
		err = -EIO;
		goto out_file_close;
	}

	/* Open HSE device */
	err = hse_dev_open();
	if (err) {
		ERROR("Failed to open HSE device: error %d\n", err);
		goto out_file_close;
	}

	/* Check firmware global status */
	status = hse_check_status();
	if (!(status & HSE_STATUS_INSTALL_OK)) {
		ERROR("Key catalogs not formatted\n");
		err = -ENODEV;
		goto out_dev_close;
	}

	kek_buff_handle = hse_mem_alloc(HSE_KEK_SIZE);
	if (kek_buff_handle < 0) {
		err = -ENOMEM;
		goto out_dev_close;
	}
	hse_memcpy_to_dev(kek_buff_handle, kek, HSE_KEK_SIZE, 0);
	
	key_info.keyFlags = HSE_KF_ACCESS_WRITE_PROT | HSE_KF_USAGE_DECRYPT |
				 HSE_KF_USAGE_ENCRYPT | HSE_KF_USAGE_KEY_PROVISION;
	key_info.keyBitLen = HSE_KEK_SIZE * 8;
	key_info.keyType = HSE_KEY_TYPE_AES;
	key_info.smrFlags = 0;

	key_info_handle = hse_mem_alloc(sizeof(hseKeyInfo_t));
	if (key_info_handle < 0) {
		err = -ENOMEM;
		goto out_free_kek;
	}
	hse_memcpy_to_dev(key_info_handle, &key_info, sizeof(key_info), 0);

	srv_desc.srvId = HSE_SRV_ID_IMPORT_KEY;
	import_key_req.targetKeyHandle = HSE_NVM_KEK_HANDLE;
	import_key_req.pKeyInfo = hse_virt_to_dma(key_info_handle, 0);
	import_key_req.pKey[2] = hse_virt_to_dma(kek_buff_handle, 0);
	import_key_req.keyLen[2] = HSE_KEK_SIZE;
	import_key_req.cipher.cipherKeyHandle = HSE_INVALID_KEY_HANDLE;
	import_key_req.keyContainer.authKeyHandle = HSE_INVALID_KEY_HANDLE;

	srv_desc.hseSrv.importKeyReq = import_key_req;

	INFO("Importing KEK into NVM Catalog\n");

	/* Issue key import service request */
	err = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc, sizeof(srv_desc));
	if (err) {
		ERROR("Key Import service request failed: error %d\n", err);
		goto out_free_key;
	}

	INFO("KEK was successfully imported\n");

out_free_key:
	hse_mem_free(key_info_handle);
out_free_kek:
	hse_mem_free(kek_buff_handle);
out_dev_close:
	hse_dev_close();
out_file_close:
	fclose(file);
	return err;
}
