// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "pkcs11_context.h"
#include "hse-internal.h"

#define CEIL_MOD_8(x)		(((x) + 7) >> 3)

static int hse_get_key_info(hseKeyHandle_t key_handle, hseKeyInfo_t *info)
{
	int err;
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	hseGetKeyInfoSrv_t *get_key_info_srv;

	if (NULL == info)
		return -1;
	
	get_key_info_srv = &srv_desc.hseSrv.getKeyInfoReq;

	srv_desc.srvId = HSE_SRV_ID_GET_KEY_INFO;
	get_key_info_srv->keyHandle = key_handle;
	get_key_info_srv->pKeyInfo = hse_virt_to_dma(info);

	err = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc, sizeof(srv_desc));
	if (err) 
		return -1;

	return 0;
}

uint16_t hse_get_key_bit_length(struct hse_keyObject *key)
{
	hseKeyInfo_t *info;
	uint16_t bit_length;
	int err;

	info = hse_mem_alloc(sizeof(hseKeyInfo_t));
	if (info == NULL) 
		return 0;

	err = hse_get_key_info(key->key_handle, info);
	if (err) {
		hse_mem_free(info);
		return 0;
	}

	bit_length = info->keyBitLen;

	hse_mem_free(info);

	return bit_length;
}

uint32_t rsa_ciphering_get_max_input_length(uint16_t rsa_key_length_bit, CK_MECHANISM_PTR mechanism)
{
	uint32_t max_input_bytes = 0;
	uint16_t digest_size = 0;
	CK_RSA_PKCS_OAEP_PARAMS *oaep_params;

	if (mechanism->mechanism == CKM_RSA_PKCS) {
		/* HSE FW RM: Maximum input message size (RSA encryption with PKCS1 V1.5 encoding) */
		max_input_bytes = (uint32_t)CEIL_MOD_8(rsa_key_length_bit) - 11;
	} else if (mechanism->mechanism == CKM_RSA_PKCS_OAEP) {
		oaep_params = (CK_RSA_PKCS_OAEP_PARAMS *)mechanism->pParameter;
		if (NULL != oaep_params) {
			switch (oaep_params->hashAlg) {
				case CKM_SHA_1:
					digest_size = 160;
					break;
				case CKM_SHA256:
				case CKM_SHA3_256:
					digest_size = 256;
					break;
				case CKM_SHA224:
				case CKM_SHA3_224:
					digest_size = 224;
					break;
				case CKM_SHA384:
				case CKM_SHA3_384:
					digest_size = 384;
					break;
				case CKM_SHA512:
				case CKM_SHA3_512:
					digest_size = 512;
					break;
				default:
					return 0;
			}
		}
		/* HSE FW RM: Maximum of input message (RSA encryption with OAEP encoding) */
		max_input_bytes = (uint32_t)(CEIL_MOD_8(rsa_key_length_bit) - 2 * CEIL_MOD_8(digest_size) - 2);
	} else {
		return 0;
	}

	return max_input_bytes;
}

uint32_t rsa_ciphering_get_out_length(uint16_t rsa_key_length_bit)
{
	/* cipher text size is equal to the key length */
	return rsa_key_length_bit >> 3;
}

hseHashAlgo_t hse_pkcs_hash_alg_translate(CK_MECHANISM_TYPE mechanism)
{
	hseHashAlgo_t hash = HSE_HASH_ALGO_NULL;

	switch (mechanism) {
		case CKM_SHA_1:
			hash = HSE_HASH_ALGO_SHA_1;
			break;
		case CKM_SHA256:
			hash = HSE_HASH_ALGO_SHA2_256;
			break;
		case CKM_SHA3_256:
			hash = HSE_HASH_ALGO_SHA3_256;
			break;
		case CKM_SHA224:
			hash = HSE_HASH_ALGO_SHA2_224;
			break;
		case CKM_SHA3_224:
			hash = HSE_HASH_ALGO_SHA3_224;
			break;
		case CKM_SHA384:
			hash = HSE_HASH_ALGO_SHA2_384;
			break;
		case CKM_SHA3_384:
			hash = HSE_HASH_ALGO_SHA3_384;
			break;
		case CKM_SHA512:
			hash = HSE_HASH_ALGO_SHA2_512;
			break;
		case CKM_SHA3_512:
			hash = HSE_HASH_ALGO_SHA3_512;
			break;
		default:
			return HSE_HASH_ALGO_NULL;
	}

	return hash;
}

hseHashAlgo_t hse_get_hash_alg(CK_MECHANISM_TYPE mechanism)
{
	hseHashAlgo_t hash = HSE_HASH_ALGO_NULL;

	switch (mechanism) {
		case CKM_SHA1_RSA_PKCS:
		case CKM_ECDSA_SHA1:
			hash = HSE_HASH_ALGO_SHA_1;
			break;
		case CKM_ECDSA_SHA224:
			hash = HSE_HASH_ALGO_SHA2_224;
			break;
		case CKM_SHA256_RSA_PKCS:
		case CKM_SHA256_RSA_PKCS_PSS:
		case CKM_ECDSA_SHA256:
			hash = HSE_HASH_ALGO_SHA2_256;
			break;
		case CKM_SHA384_RSA_PKCS:
		case CKM_SHA384_RSA_PKCS_PSS:
		case CKM_ECDSA_SHA384:
			hash = HSE_HASH_ALGO_SHA2_384;
			break;
		case CKM_SHA512_RSA_PKCS:
		case CKM_SHA512_RSA_PKCS_PSS:
		case CKM_ECDSA_SHA512:
			hash = HSE_HASH_ALGO_SHA2_512;
			break;
		default:
			break;
	}

	return hash;
}

uint32_t sig_get_out_length(struct hse_keyObject *key, CK_MECHANISM_PTR mechanism)
{
	CK_MECHANISM_TYPE mechanism_type = mechanism->mechanism;
	uint32_t sig_len = 0;

	switch (mechanism_type) {
		case CKM_RSA_PKCS_OAEP:
		case CKM_SHA256_RSA_PKCS:
		case CKM_SHA384_RSA_PKCS:
		case CKM_SHA512_RSA_PKCS:
		case CKM_RSA_PKCS_PSS:
		case CKM_SHA256_RSA_PKCS_PSS:
		case CKM_SHA384_RSA_PKCS_PSS:
		case CKM_SHA512_RSA_PKCS_PSS:
			sig_len = hse_get_key_bit_length(key) >> 3;
			break;
		case CKM_ECDSA:
		case CKM_ECDSA_SHA1:
		case CKM_ECDSA_SHA224:
		case CKM_ECDSA_SHA384:
		case CKM_ECDSA_SHA512:
			sig_len = (hse_get_key_bit_length(key) >> 3) * 2;
			break;
		default:
			return 0;
	}

	return sig_len;
}
