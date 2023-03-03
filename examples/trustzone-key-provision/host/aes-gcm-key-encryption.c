// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright OpenSSL 2023
 * Contents licensed under the terms of the OpenSSL license
 * See https://www.openssl.org/source/license.html for details
 * 
 * Copyright 2023 NXP
 */

#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>

#include <hse_kp.h>

#define ERROR(fmt, ...) printf("[ERROR] " fmt, ##__VA_ARGS__)
#define INFO(fmt, ...) printf("[INFO] " fmt, ##__VA_ARGS__)

#define PKEY_SIZE   32

/* Example KEK, Plaintext key, IV and Key Info */
uint8_t kek[HSE_KEK_SIZE] = "Hello there, cryptography world!";

uint8_t pkey[PKEY_SIZE] = "Cryptography keeps my data safe.";

uint8_t iv[HSE_GCM_IV_SIZE] = "012345678901";

hseKeyInfo_t key_info = {
    .keyFlags = HSE_KF_USAGE_ENCRYPT | HSE_KF_USAGE_DECRYPT,
    .keyBitLen = PKEY_SIZE * 8,
    .keyCounter = 0,
    .smrFlags = 0,
    .keyType = HSE_KEY_TYPE_AES,
};

int gcm_encrypt(unsigned char *plaintext, int plaintext_len,
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *ciphertext,
		int *ciphertext_len,
                unsigned char *tag)
{
	EVP_CIPHER_CTX *ctx;
	int ret, len;

	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new()))
		return 0;

	/* Initialise the encryption operation. */
	ret = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
	if (ret != 1)
		goto out;


	/* Set IV length if default 12 bytes (96 bits) is not appropriate */
	ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL);
	if (ret != 1)
		goto out;

	/* Initialise key and IV */
	ret = EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
	if (ret != 1)
		goto out;

	/*
	* Provide any AAD data. This can be called zero or more times as
	* required
	*/
	ret = EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len);
	if (ret != 1)
		goto out;

	/*
	* Provide the message to be encrypted, and obtain the encrypted output.
	* EVP_EncryptUpdate can be called multiple times if necessary
	*/
	ret = EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
	if (ret != 1)
		goto out;

	*ciphertext_len = len;

	/*
	* Finalise the encryption. Normally ciphertext bytes may be written at
	* this stage, but this does not occur in GCM mode
	*/
	ret = EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
	if (ret != 1)
		goto out;

	*ciphertext_len += len;

	/* Get the tag */
	ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
	if (ret != 1)
		goto out;

out:
	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);
	return ret;
}

int main(int argc, char *argv[])
{
	int err = 0;
	uint8_t enckey[PKEY_SIZE], tag[HSE_GCM_TAG_SIZE];
	int enckey_len;
	FILE *kek_file, *enckey_file;
	size_t write_len;
	struct hse_kp_payload payload;

	switch (argc) {
	case 3:
		kek_file = fopen(argv[1], "wb");
		if (!kek_file) {
			ERROR("Cannot open file %s\n", argv[1]);
			return -EINVAL;
		}

		enckey_file = fopen(argv[2], "wb");
		if (!enckey_file) {
			ERROR("Cannot open file %s\n", argv[2]);
			fclose(kek_file);
			return -EINVAL;
		}
		break;
	default:
		INFO("Usage: %s <path/to/kek-file> <path/to/encryped-key-file>\n", argv[0]);
		INFO("- path to output kek & encrypted key files\n");
		return -EINVAL;
	}

	err = gcm_encrypt(pkey, PKEY_SIZE, (unsigned char *)&key_info, sizeof(key_info),
			  kek, iv, HSE_GCM_IV_SIZE, enckey, &enckey_len,
			  tag);

	if (err != 1)
		goto out;

	payload.key_info = key_info;
	memcpy(payload.tag, tag, HSE_GCM_TAG_SIZE);
	memcpy(payload.iv, iv, HSE_GCM_IV_SIZE);
	memcpy(payload.enckey, enckey, PKEY_SIZE);
	payload.enckey_size = PKEY_SIZE;

	write_len = fwrite(&kek, sizeof(uint8_t), HSE_KEK_SIZE, kek_file);
	if (write_len != HSE_KEK_SIZE) {
		ERROR("Cannot write KEK to output file\n");
		err = EIO;
		goto out;
	}

	INFO("Key Encryption Key (KEK) has been written to %s\n", argv[1]);

	write_len = fwrite(&payload, sizeof(payload), 1, enckey_file);
	if (write_len != 1) {
		ERROR("Cannot write payload to output file\n");
		err = EIO;
		goto out;
	}

	INFO("Encrypted key & authentication data has been written to %s\n",
	     argv[2]);

	err = 0;

out:
	fclose(enckey_file);
	fclose(kek_file);
	return err;
}
