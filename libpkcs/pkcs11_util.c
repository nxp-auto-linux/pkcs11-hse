// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "hse_interface.h"
#include "pkcs11_context.h"
#include "pkcs11_util.h"
#include "hse-internal.h"

#define CEIL_MOD_8(x)		(((x) + 7) >> 3)

void *getattr_pval(CK_ATTRIBUTE_PTR template,
		CK_ATTRIBUTE_TYPE attribute,
		CK_ULONG attrCount)
{
	int i;

	for (i = 0; i < attrCount; i++) {
		if (template[i].type == attribute) {
			return template[i].pValue;
		}
	}

	return NULL;
}

CK_ULONG getattr_len(CK_ATTRIBUTE_PTR template,
		CK_ATTRIBUTE_TYPE attribute,
		CK_ULONG attrCount)
{
	int i;

	for (i = 0; i < attrCount; i++) {
		if (template[i].type == attribute) {
			return template[i].ulValueLen;
		}
	}

	return 0;
}

static int hse_get_key_info(uint8_t channel, hseKeyHandle_t key_handle, hseKeyInfo_t *info)
{
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	hseGetKeyInfoSrv_t *get_key_info_srv;

	if (NULL == info)
		return EINVAL;
	
	get_key_info_srv = &srv_desc.hseSrv.getKeyInfoReq;

	srv_desc.srvId = HSE_SRV_ID_GET_KEY_INFO;
	get_key_info_srv->keyHandle = key_handle;
	get_key_info_srv->pKeyInfo = hse_virt_to_dma(info);

	return hse_srv_req_sync(channel, &srv_desc, sizeof(srv_desc));
}

uint16_t hse_get_key_bit_length(uint8_t channel, struct hse_keyObject *key)
{
	hseKeyInfo_t *info;
	uint16_t bit_length;
	int err;

	info = hse_mem_alloc(sizeof(*info));
	if (info == NULL) 
		return 0;

	err = hse_get_key_info(channel, key->key_handle, info);
	if (err) {
		hse_mem_free(info);
		return 0;
	}

	bit_length = info->keyBitLen;

	hse_mem_free(info);

	return bit_length;
}

int hse_get_ec_curve_id(uint8_t channel, struct hse_keyObject *key, hseEccCurveId_t *ec_curve_id)
{
	hseKeyInfo_t *info;
	hseEccCurveId_t curve_id = HSE_EC_CURVE_NONE;
	int err;

	info = hse_mem_alloc(sizeof(*info));
	if (info == NULL) 
		return ENOMEM;

	err = hse_get_key_info(channel, key->key_handle, info);
	if (err) {
		hse_mem_free(info);
		return err;
	}

	curve_id = info->specific.eccCurveId;
	if (ec_curve_id)
		*ec_curve_id = curve_id;

	hse_mem_free(info);

	return 0;
}

uint16_t hse_get_ec_key_bitlen(hseEccCurveId_t eccCurveId)
{
	switch(eccCurveId) {
		case HSE_EC_SEC_SECP256R1:
			return 256u;
		case HSE_EC_SEC_SECP384R1:
			return 384u;
		case HSE_EC_SEC_SECP521R1:
			return 521u;
		case HSE_EC_BRAINPOOL_BRAINPOOLP256R1:
			return 256u;
		case HSE_EC_BRAINPOOL_BRAINPOOLP320R1:
			return 320u;
		case HSE_EC_BRAINPOOL_BRAINPOOLP384R1:
			return 384u;
		case HSE_EC_BRAINPOOL_BRAINPOOLP512R1:
			return 512u;
		case HSE_EC_25519_ED25519:
			return 256u;
		case HSE_EC_25519_CURVE25519:
			return 256u;
		default:
			return 0u;
	}
}

#define MAX_OID_LEN  (16)
struct ec_param_oid {
	hseEccCurveId_t id;
	uint8_t oid_len;
	uint8_t oid_param[MAX_OID_LEN];
};

static const struct ec_param_oid ec_oid_param[] = {
	{
		.id = HSE_EC_SEC_SECP256R1,
		.oid_len = 10,
		.oid_param = {"\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x07"}
	},
	{
		.id = HSE_EC_SEC_SECP384R1,
		.oid_len = 7,
		.oid_param = {"\x06\x05\x2B\x81\x04\x00\x22"}
	},
	{
		.id = HSE_EC_SEC_SECP521R1,
		.oid_len = 7,
		.oid_param = {"\x06\x05\x2B\x81\x04\x00\x23"}
	},
	{
		.id = HSE_EC_BRAINPOOL_BRAINPOOLP256R1,
		.oid_len = 11,
		.oid_param = {"\x06\x09\x2B\x24\x03\x03\x02\x08\x01\x01\x07"}
	},
	{
		.id = HSE_EC_BRAINPOOL_BRAINPOOLP320R1,
		.oid_len = 11,
		.oid_param = {"\x06\x09\x2B\x24\x03\x03\x02\x08\x01\x01\x09"}
	},
	{
		.id = HSE_EC_BRAINPOOL_BRAINPOOLP384R1,
		.oid_len = 11,
		.oid_param = {"\x06\x09\x2B\x24\x03\x03\x02\x08\x01\x01\x0B"}
	},
	{
		.id = HSE_EC_BRAINPOOL_BRAINPOOLP512R1,
		.oid_len = 11,
		.oid_param = {"\x06\x09\x2B\x24\x03\x03\x02\x08\x01\x01\x0D"}
	},
	{
		.id = HSE_EC_25519_ED25519,
		.oid_len = 11,
		.oid_param = {"\x06\x09\x2B\x06\x01\x04\x01\xDA\x47\x0F\x01"}
	},
	{
		.id = HSE_EC_25519_CURVE25519,
		.oid_len = 5,
		.oid_param = {"\x06\x03\x2B\x65\x6E"}
	},
};

uint8_t ecparam2curveid(char *oid, uint8_t len)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(ec_oid_param); i++) {
		if ((len == ec_oid_param[i].oid_len)
				&& (memcmp(oid, ec_oid_param[i].oid_param, len) == 0))
			break; 
	}

	if (i == ARRAY_SIZE(ec_oid_param))
		return HSE_EC_CURVE_NONE;

	return ec_oid_param[i].id;
}

/* get EC param from HSE curve id */
const uint8_t* curveid2ecparam(hseEccCurveId_t curve_id, uint8_t *len)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(ec_oid_param); i++) {
		if (curve_id == ec_oid_param[i].id)
			break;
	}

	if (i == ARRAY_SIZE(ec_oid_param)) {
		if (len != NULL) 
			*len = 0;
		return NULL;
	}

	if (len != NULL) 
		*len = ec_oid_param[i].oid_len;

	return ec_oid_param[i].oid_param;
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
		case CKM_SHA_1_HMAC:
			hash = HSE_HASH_ALGO_SHA_1;
			break;
		case CKM_ECDSA_SHA224:
		case CKM_SHA224_HMAC:
			hash = HSE_HASH_ALGO_SHA2_224;
			break;
		case CKM_SHA256_RSA_PKCS:
		case CKM_SHA256_RSA_PKCS_PSS:
		case CKM_ECDSA_SHA256:
		case CKM_SHA256_HMAC:
			hash = HSE_HASH_ALGO_SHA2_256;
			break;
		case CKM_SHA384_RSA_PKCS:
		case CKM_SHA384_RSA_PKCS_PSS:
		case CKM_ECDSA_SHA384:
		case CKM_SHA384_HMAC:
			hash = HSE_HASH_ALGO_SHA2_384;
			break;
		case CKM_SHA512_RSA_PKCS:
		case CKM_SHA512_RSA_PKCS_PSS:
		case CKM_ECDSA_SHA512:
		case CKM_SHA512_HMAC:
			hash = HSE_HASH_ALGO_SHA2_512;
			break;
		default:
			break;
	}

	return hash;
}

uint32_t sig_get_out_length(uint8_t channel, struct hse_keyObject *key, CK_MECHANISM_PTR mechanism)
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
			sig_len = hse_get_key_bit_length(channel, key) >> 3;
			break;
		case CKM_ECDSA:
		case CKM_ECDSA_SHA1:
		case CKM_ECDSA_SHA224:
		case CKM_ECDSA_SHA384:
		case CKM_ECDSA_SHA512:
			sig_len = (hse_get_key_bit_length(channel, key) >> 3) * 2;
			break;
		case CKM_AES_CMAC:
			sig_len = 16;
			break;
		case CKM_SHA224_HMAC:
			sig_len = 28;
			break;
		case CKM_SHA256_HMAC:
			sig_len = 32;
			break;
		case CKM_SHA384_HMAC:
			sig_len = 48;
			break;
		case CKM_SHA512_HMAC:
			sig_len = 64;
			break;
		default:
			return 0;
	}

	return sig_len;
}

/* Public key value export 
 * Note on ECC key:
 *  For Weierstrass curves, export public key in uncompressed format: 0x04 || X || Y;
 * 	For Montgomery and Twisted Edward curves, export public key in raw format: X
*/
int32_t pkey_value_export(uint8_t channel, struct hse_keyObject *key, uint8_t *pkey0, uint8_t *pkey1, CK_ULONG *pkey0_len, CK_ULONG *pkey1_len)
{
	int err;
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	hseExportKeySrv_t *export_key_srv;
	uint16_t key_bit_length;
	uint16_t pkey_length[2] = {0, 0};
	uint8_t *key_value0, *key_value1;
	uint16_t *hse_pkey_length;
	hseKeyInfo_t *key_info;
	hseEccCurveId_t ecc_curve_id;
	bool Weierstrass_curve = FALSE;

	key_info = hse_mem_alloc(sizeof(*key_info));
	if (key_info == NULL) 
		return CKR_HOST_MEMORY;
	
	err = hse_get_key_info(channel, key->key_handle, key_info);
	if (err) {
		goto free_key_info;
	}

	/* get the key size */
	key_bit_length = key_info->keyBitLen;

	if (key->key_type == CKK_RSA) {
		/* RSA public modulus n */
		pkey_length[0] = key_bit_length >> 3;
		/* RSA public exponent e */
		pkey_length[1] = key_info->specific.pubExponentSize;
	} else if (key->key_type == CKK_EC) {
		/* Length of Q: todo */
		/* depends on the key format
     	 *  - Weierstrass curve keys:
     	 *    - raw format: X || Y, in big endian; the HSE will output 2 * #HSE_BITS_TO_BYTES(keyBitLength) bytes
     	 *    - uncompressed format: 0x04 || X || Y, in big endian; the HSE will output 1 + 2 * #HSE_BITS_TO_BYTES(keyBitLength) bytes
     	 *    - compressed format: 0x02 / x03 || X,  in big endian; the HSE will output 1 + #HSE_BITS_TO_BYTES(keyBitLength) bytes
     	 *  - Twisted Edwards curve keys:
     	 *    - raw format: point Y with the sign bit of X, in big endian; the HSE will output #HSE_BITS_TO_BYTES(keyBitLength) bytes
     	 *  - Montgomery curve keys:
     	 *    - raw format: the X coordinate, in big endian; the HSE will output #HSE_BITS_TO_BYTES(keyBitLength) bytes
	 	 **/
		ecc_curve_id = key_info->specific.eccCurveId;
		switch (ecc_curve_id) {
			case HSE_EC_SEC_SECP256R1:
			case HSE_EC_SEC_SECP384R1:
			case HSE_EC_SEC_SECP521R1:
			case HSE_EC_BRAINPOOL_BRAINPOOLP256R1:
			case HSE_EC_BRAINPOOL_BRAINPOOLP320R1:
			case HSE_EC_BRAINPOOL_BRAINPOOLP384R1:
			case HSE_EC_BRAINPOOL_BRAINPOOLP512R1:
				/* Weierstrass curves */
				Weierstrass_curve = TRUE;
				pkey_length[0] = (key_bit_length >> 3) * 2 + 1;	/* plus 1 to add the format byte for uncompressed format */
				break;
			case HSE_EC_25519_ED25519:
			case HSE_EC_448_ED448:
				/* Twisted Edward form */
				pkey_length[0] = key_bit_length >> 3;
				break;
			case HSE_EC_25519_CURVE25519:
			case HSE_EC_448_CURVE448:
				/* Montgomery form */
				pkey_length[0] = key_bit_length >> 3;
				break;
			default:
				break;
		}

		pkey_length[1] = 0;	/* pkey[1] is unused for ECC keys */
	} else {
		err = CKR_ARGUMENTS_BAD;
		goto free_key_info;
	}

	key_value0 = hse_mem_alloc(pkey_length[0]);
	if (NULL == key_value0) {
		err = CKR_HOST_MEMORY;
		goto free_key_info;
	}

	key_value1 = hse_mem_alloc(pkey_length[1]);
	if ((NULL == key_value1) && (key->key_type == CKK_RSA)) {
		err = CKR_HOST_MEMORY;
		goto free_pkey0;
	}

	hse_pkey_length = (uint16_t *)hse_mem_alloc(sizeof(uint16_t) * 2);
	if (NULL == hse_pkey_length) {
		err = CKR_HOST_MEMORY;
		goto free_pkey1;
	}

	hse_memcpy(&hse_pkey_length[0], &pkey_length[0], sizeof(uint16_t));
	hse_memcpy(&hse_pkey_length[1], &pkey_length[1], sizeof(uint16_t));

	srv_desc.srvId = HSE_SRV_ID_EXPORT_KEY;
	
	export_key_srv = &srv_desc.hseSrv.exportKeyReq;
	export_key_srv->targetKeyHandle = key->key_handle;
	export_key_srv->pKey[0] = hse_virt_to_dma(key_value0);
	export_key_srv->pKey[1] = hse_virt_to_dma(key_value1);
	export_key_srv->pKeyLen[0] = hse_virt_to_dma(hse_pkey_length);
	export_key_srv->pKeyLen[1] = hse_virt_to_dma(&hse_pkey_length[1]);
	export_key_srv->cipher.cipherKeyHandle = HSE_INVALID_KEY_HANDLE;
	export_key_srv->keyContainer.authKeyHandle = HSE_INVALID_KEY_HANDLE;
	/* TODO: better to use HSE FW interface version */
#if (HSE_PLATFORM == HSE_S32G3XX)
	/* The Montgomery and Twisted Edward public keys can be exported only in raw format */
	if (Weierstrass_curve)
		export_key_srv->keyFormat.eccKeyFormat = HSE_KEY_FORMAT_ECC_PUB_UNCOMPRESSED;
	else 
		export_key_srv->keyFormat.eccKeyFormat = HSE_KEY_FORMAT_ECC_PUB_RAW;
#elif ((HSE_PLATFORM == HSE_S32G2XX) || (HSE_PLATFORM == HSE_S32R45X))
	/* HSE FW for S32G2 (FW 1.x.x) doesn't support `keyFormat` parameter */
	/* Only raw format is supported */
#endif
	err = hse_srv_req_sync(channel, &srv_desc, sizeof(srv_desc));
	if (err)
		goto free_pkey_len;

#if (HSE_PLATFORM == HSE_S32G3XX)
	if (NULL != pkey0)
		hse_memcpy(pkey0, key_value0, hse_pkey_length[0]);
	if (NULL != pkey0_len)
		*(pkey0_len) = hse_pkey_length[0];
#elif ((HSE_PLATFORM == HSE_S32G2XX) || (HSE_PLATFORM == HSE_S32R45X))
	/* In case Weierstrass curve, convert raw format to uncompressed format: 0x04 || X || Y, in big endian; */
	if (NULL != pkey0) {
		if (Weierstrass_curve) {
			*pkey0 = 0x4;
			hse_memcpy(pkey0 + 1, key_value0, hse_pkey_length[0]);
		} else {
			hse_memcpy(pkey0, key_value0, hse_pkey_length[0]);
		}
	}
	if (NULL != pkey0_len) {
		if (Weierstrass_curve) 
			*(pkey0_len) = hse_pkey_length[0] + 1;
		else 
			*(pkey0_len) = hse_pkey_length[0];
	}
#endif

	if ((NULL != pkey1) && (key->key_type == CKK_RSA))
		hse_memcpy(pkey1, key_value1, hse_pkey_length[1]);
	if ((NULL != pkey1_len) && (key->key_type == CKK_RSA))
		*(pkey1_len) = hse_pkey_length[1];

free_pkey_len:
	hse_mem_free(hse_pkey_length);
free_pkey1:
	hse_mem_free(key_value1);
free_pkey0:
	hse_mem_free(key_value0);
free_key_info:
	hse_mem_free(key_info);
	return err;
}
