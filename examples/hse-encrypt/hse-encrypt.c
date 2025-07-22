// SPDX-License-Identifier: BSD-3-Clause
/*
 * Demo using libhse interface
 *
 * This is a simple application that generates an AES-256 key, encrypts some
 * data using AES-CBC, then decrypts it in-place and compares the result.
 *
 * Copyright 2022-2025 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include "libhse.h"
#include "hse_interface.h"

#define AES_BLOCK_SIZE    16u

#define INPUT_SIZE    256u

int hse_erase_key(uint32_t key_handle)
{
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);

	srv_desc.srvId = HSE_SRV_ID_ERASE_KEY;
	srv_desc.hseSrv.eraseKeyReq.keyHandle = key_handle;
	srv_desc.hseSrv.eraseKeyReq.eraseKeyOptions = HSE_ERASE_NOT_USED;

	return hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc, sizeof(srv_desc), NULL);
}

int main(int argc, char *argv[])
{
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	int iv_handle, plaintext_handle, ciphertext_handle;
	void *plaintext, *ciphertext;
	unsigned int group_id, slot_id;
	uint32_t key_handle;
	uint16_t status;
	int err;

	switch (argc) {
	case 1:
		/* when no arguments are given, use handle 010105 by default */
		group_id = 0x01u;
		slot_id = 0x05u;
		break;
	case 3:
		/* parse input key group and slot index */
		 sscanf(argv[1], "%d", &group_id);
		 sscanf(argv[2], "%d", &slot_id);
		 break;
	default:
		printf("usage: %s <group_id> <slot_index>\n", argv[1]);
		printf("- must point to a valid AES-256 slot in NVM catalog\n");
		return EINVAL;
	}
	key_handle = GET_KEY_HANDLE(HSE_KEY_CATALOG_ID_NVM, group_id, slot_id);

	/* open HSE device */
	err = hse_dev_open();
	if (err) {
		printf("DEMO: failed to open HSE device: error %d\n", err);
		return err;
	}

	/* check firmware global status */
	status = hse_check_status();
	if (!(status & HSE_STATUS_INSTALL_OK)) {
		printf("DEMO: key catalogs not formatted\n");
		err = ENODEV;
		goto out_dev_close;
	}
	printf("DEMO: using NVM key group %d, slot %d\n", group_id, slot_id);

	/* fill in key generation service descriptor */
	srv_desc.srvId = HSE_SRV_ID_KEY_GENERATE;
	srv_desc.hseSrv.keyGenReq.targetKeyHandle = key_handle;
	srv_desc.hseSrv.keyGenReq.keyInfo.keyBitLen = 256u;
	srv_desc.hseSrv.keyGenReq.keyInfo.keyFlags = HSE_KF_USAGE_ENCRYPT |
						     HSE_KF_USAGE_DECRYPT;
	srv_desc.hseSrv.keyGenReq.keyInfo.smrFlags = 0u;
	srv_desc.hseSrv.keyGenReq.keyInfo.keyType = HSE_KEY_TYPE_AES;
	srv_desc.hseSrv.keyGenReq.keyGenScheme = HSE_KEY_GEN_SYM_RANDOM_KEY;

	/* issue key generation service request */
	err = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc, sizeof(srv_desc), NULL);
	if (err) {
		printf("DEMO: generate key request failed: error %d\n", err);
		goto out_dev_close;
	}
	printf("DEMO: key generation successful\n");

	/* allocate IV, input and output buffers */
	iv_handle = hse_mem_alloc(AES_BLOCK_SIZE);
	if (iv_handle < 0) {
		err = ENOMEM;
		goto out_erase_key;
	}
	hse_memset(iv_handle, 0, AES_BLOCK_SIZE, 0);

	plaintext_handle = hse_mem_alloc(INPUT_SIZE);
	if (plaintext_handle < 0) {
		err = ENOMEM;
		goto out_free_iv;
	}
	hse_memcpy_to_dev(plaintext_handle, "Simple symmetric cipher encryption test", 40u, 0);

	ciphertext_handle = hse_mem_alloc(INPUT_SIZE);
	if (ciphertext_handle < 0) {
		err = ENOMEM;
		goto out_free_input;
	}

	/* fill in symmetric cipher encrypt service descriptor */
	srv_desc.srvId = HSE_SRV_ID_SYM_CIPHER;
	srv_desc.hseSrv.symCipherReq.accessMode = HSE_ACCESS_MODE_ONE_PASS;
	srv_desc.hseSrv.symCipherReq.cipherAlgo = HSE_CIPHER_ALGO_AES;
	srv_desc.hseSrv.symCipherReq.cipherBlockMode = HSE_CIPHER_BLOCK_MODE_CBC;
	srv_desc.hseSrv.symCipherReq.cipherDir = HSE_CIPHER_DIR_ENCRYPT;
	srv_desc.hseSrv.symCipherReq.sgtOption = HSE_SGT_OPTION_NONE;
	srv_desc.hseSrv.symCipherReq.keyHandle = key_handle;
	srv_desc.hseSrv.symCipherReq.pIV = hse_virt_to_dma(iv_handle, 0);
	srv_desc.hseSrv.symCipherReq.inputLength = INPUT_SIZE;
	srv_desc.hseSrv.symCipherReq.pInput = hse_virt_to_dma(plaintext_handle, 0);
	srv_desc.hseSrv.symCipherReq.pOutput = hse_virt_to_dma(ciphertext_handle, 0);

	/* issue encrypt service request */
	err = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc, sizeof(srv_desc), NULL);
	if (err) {
		printf("DEMO: encrypt request failed: error %d\n", err);
		goto out_free_output;
	}
	printf("DEMO: encrypt operation successful\n");

	/* fill in symmetric cipher decrypt service descriptor */
	srv_desc.srvId = HSE_SRV_ID_SYM_CIPHER;
	srv_desc.hseSrv.symCipherReq.accessMode = HSE_ACCESS_MODE_ONE_PASS;
	srv_desc.hseSrv.symCipherReq.cipherAlgo = HSE_CIPHER_ALGO_AES;
	srv_desc.hseSrv.symCipherReq.cipherBlockMode = HSE_CIPHER_BLOCK_MODE_CBC;
	srv_desc.hseSrv.symCipherReq.cipherDir = HSE_CIPHER_DIR_DECRYPT;
	srv_desc.hseSrv.symCipherReq.sgtOption = HSE_SGT_OPTION_NONE;
	srv_desc.hseSrv.symCipherReq.keyHandle = key_handle;
	srv_desc.hseSrv.symCipherReq.pIV = hse_virt_to_dma(iv_handle, 0);
	srv_desc.hseSrv.symCipherReq.inputLength = INPUT_SIZE;
	srv_desc.hseSrv.symCipherReq.pInput = hse_virt_to_dma(ciphertext_handle, 0);
	srv_desc.hseSrv.symCipherReq.pOutput = hse_virt_to_dma(ciphertext_handle, 0);

	/* issue decrypt service request */
	err = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc, sizeof(srv_desc), NULL);
	if (err) {
		printf("DEMO: decrypt request failed: error %d\n", err);
		goto out_free_output;
	}
	printf("DEMO: decrypt operation successful\n");

	/* check result against initial input */
	plaintext = malloc(INPUT_SIZE);
	ciphertext = malloc(INPUT_SIZE);

	if (!plaintext || !ciphertext) {
		printf("DEMO: plaintext and ciphertext alloc failed\n");
		goto out_free_output;
	}

	hse_memcpy_from_dev(plaintext, plaintext_handle, INPUT_SIZE, 0);
	hse_memcpy_from_dev(ciphertext, ciphertext_handle, INPUT_SIZE, 0);

	err = memcmp(plaintext, ciphertext, INPUT_SIZE);
	if (err != 0) {
		printf("DEMO: error - result does not match plaintext\n");
		err = EBADMSG;
		goto out_free_output;
	}
	printf("DEMO: result check successful\n");

out_free_output:
	hse_mem_free(plaintext_handle);
out_free_input:
	hse_mem_free(ciphertext_handle);
out_free_iv:
	hse_mem_free(iv_handle);
out_erase_key:
	if (hse_erase_key(key_handle))
		printf("DEMO: key erase failed\n");
out_dev_close:
	hse_dev_close();
	return err;
}
