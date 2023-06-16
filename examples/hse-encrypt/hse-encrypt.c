// SPDX-License-Identifier: BSD-3-Clause
/*
 * Demo using libhse interface
 *
 * This is a simple application that generates an AES-256 key, encrypts some
 * data using AES-CBC, then decrypts it in-place and compares the result.
 *
 * Copyright 2022 NXP
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include "libhse.h"
#include "hse_interface.h"

#define AES_BLOCK_SIZE    16u

#define INPUT_SIZE    256u

int main(int argc, char *argv[])
{
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	void *iv, *plaintext, *ciphertext;
	unsigned int group_id, slot_id;
	uint32_t key_handle;
	uint16_t status;
	int err;

	switch (argc) {
	case 1:
		/* when no arguments are given, use handle 020205 by default */
		group_id = 0x02u;
		slot_id = 0x05u;
		break;
	case 3:
		/* parse input key group and slot index */
		 sscanf(argv[1], "%d", &group_id);
		 sscanf(argv[2], "%d", &slot_id);
		 break;
	default:
		printf("usage: %s <group_id> <slot_index>\n", argv[1]);
		printf("- must point to a valid AES-256 slot in RAM catalog\n");
		return EINVAL;
	}
	key_handle = GET_KEY_HANDLE(HSE_KEY_CATALOG_ID_RAM, group_id, slot_id);

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
	printf("DEMO: using RAM key group %d, slot %d\n", group_id, slot_id);

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
	err = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc, sizeof(srv_desc));
	if (err) {
		printf("DEMO: generate key request failed: error %d\n", err);
		goto out_dev_close;
	}
	printf("DEMO: key generation successful\n");

	/* allocate IV, input and output buffers */
	iv = hse_mem_alloc(AES_BLOCK_SIZE);
	if (!iv) {
		err = ENOMEM;
		goto out_dev_close;
	}
	hse_memset(iv, 0, AES_BLOCK_SIZE);

	plaintext = hse_mem_alloc(INPUT_SIZE);
	if (!plaintext) {
		err = ENOMEM;
		goto out_free_iv;
	}
	hse_memcpy(plaintext, "Simple symmetric cipher encryption test", 40u);

	ciphertext = hse_mem_alloc(INPUT_SIZE);
	if (!ciphertext) {
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
	srv_desc.hseSrv.symCipherReq.pIV = hse_virt_to_dma(iv);
	srv_desc.hseSrv.symCipherReq.inputLength = INPUT_SIZE;
	srv_desc.hseSrv.symCipherReq.pInput = hse_virt_to_dma(plaintext);
	srv_desc.hseSrv.symCipherReq.pOutput = hse_virt_to_dma(ciphertext);

	/* issue encrypt service request */
	err = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc, sizeof(srv_desc));
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
	srv_desc.hseSrv.symCipherReq.pIV = hse_virt_to_dma(iv);
	srv_desc.hseSrv.symCipherReq.inputLength = INPUT_SIZE;
	srv_desc.hseSrv.symCipherReq.pInput = hse_virt_to_dma(ciphertext);
	srv_desc.hseSrv.symCipherReq.pOutput = hse_virt_to_dma(ciphertext);

	/* issue decrypt service request */
	err = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc, sizeof(srv_desc));
	if (err) {
		printf("DEMO: decrypt request failed: error %d\n", err);
		goto out_free_output;
	}
	printf("DEMO: decrypt operation successful\n");

	/* check result against initial input */
	err = memcmp(plaintext, ciphertext, INPUT_SIZE);
	if (err != 0) {
		printf("DEMO: error - result does not match plaintext\n");
		err = EBADMSG;
		goto out_free_output;
	}
	printf("DEMO: result check successful\n");

out_free_output:
	hse_mem_free(ciphertext);
out_free_input:
	hse_mem_free(plaintext);
out_free_iv:
	hse_mem_free(iv);
out_dev_close:
	hse_dev_close();
	return err;
}
