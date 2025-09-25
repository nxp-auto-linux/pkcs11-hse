// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024-2025 NXP
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>

#include "hse_interface.h"
#include "pkcs11_context.h"
#include "pkcs11_util.h"
#include "hse-internal.h"

#define PKCS_OBJ_DIR "/etc/pkcs-objs"
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

static int hse_get_key_info(uint8_t channel, hseKeyHandle_t key_handle, int info_handle)
{
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	hseGetKeyInfoSrv_t *get_key_info_srv;

	if (info_handle < 0)
		return EINVAL;
	
	get_key_info_srv = &srv_desc.hseSrv.getKeyInfoReq;

	srv_desc.srvId = HSE_SRV_ID_GET_KEY_INFO;
	get_key_info_srv->keyHandle = key_handle;
	get_key_info_srv->pKeyInfo = hse_virt_to_dma(info_handle, 0);

	return hse_srv_req_sync(channel, &srv_desc, sizeof(srv_desc), NULL);
}

uint16_t hse_get_key_bit_length(uint8_t channel, CK_OBJECT_HANDLE key_handle)
{
	hseKeyInfo_t info;
	uint16_t bit_length;
	int err, info_handle;

	info_handle = hse_mem_alloc(sizeof(info));
	if (info_handle < 0) 
		return 0;

	err = hse_get_key_info(channel, key_handle, info_handle);
	if (err) {
		hse_mem_free(info_handle);
		return 0;
	}
	hse_memcpy_from_dev((void *)&info, info_handle, sizeof(info), 0);
	bit_length = info.keyBitLen;

	hse_mem_free(info_handle);

	return bit_length;
}

int hse_get_ec_curve_id(uint8_t channel, struct hse_keyObject *key, hseEccCurveId_t *ec_curve_id)
{
	hseKeyInfo_t info;
	hseEccCurveId_t curve_id = HSE_EC_CURVE_NONE;
	int err, info_handle;

	info_handle = hse_mem_alloc(sizeof(info));
	if (info_handle < 0) 
		return ENOMEM;

	err = hse_get_key_info(channel, key->attrs.key_handle, info_handle);
	if (err) {
		hse_mem_free(info_handle);
		return err;
	}
	hse_memcpy_from_dev((void *)&info, info_handle, sizeof(info), 0);
	curve_id = info.specific.eccCurveId;
	if (ec_curve_id)
		*ec_curve_id = curve_id;

	hse_mem_free(info_handle);

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

int hse_get_hash_block_size(CK_MECHANISM_TYPE mechanism, uint32_t *block_size)
{
	int ret = 0;
	uint32_t block_s = 0;

	if (!block_size) {
		ret = EINVAL;
		goto err_exit;
	}

	switch (hse_get_hash_alg(mechanism)) {
		case HSE_HASH_ALGO_SHA_1:
		case HSE_HASH_ALGO_SHA2_224:
		case HSE_HASH_ALGO_SHA2_256:
			block_s = 64;
			break;
		case HSE_HASH_ALGO_NULL:
		case HSE_HASH_ALGO_SHA2_384:
		case HSE_HASH_ALGO_SHA2_512:
		case HSE_HASH_ALGO_SHA2_512_224:
		case HSE_HASH_ALGO_SHA2_512_256:
			block_s = 128;
			break;
		case HSE_HASH_ALGO_SHA3_224:
			block_s = 144;
			break;
		case HSE_HASH_ALGO_SHA3_256:
			block_s = 136;
			break;
		case HSE_HASH_ALGO_SHA3_384:
			block_s = 104;
			break;
		case HSE_HASH_ALGO_SHA3_512:
			block_s = 72;
			break;
		default:
			ret = EINVAL;
			goto err_exit;
	}

	*block_size = block_s;

err_exit:
	return ret;
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

hseCipherBlockMode_t hse_pkcs_cb_alg_translate(CK_MECHANISM_TYPE mechanism)
{
	hseCipherBlockMode_t cb_mode;

	switch (mechanism) {
		case CKM_AES_ECB:
			cb_mode = HSE_CIPHER_BLOCK_MODE_ECB;
			break;
		case CKM_AES_CBC:
		case CKM_AES_CBC_PAD:
			cb_mode = HSE_CIPHER_BLOCK_MODE_CBC;
			break;
		case CKM_AES_CTR:
			cb_mode = HSE_CIPHER_BLOCK_MODE_CTR;
			break;
		case CKM_AES_OFB:
			cb_mode = HSE_CIPHER_BLOCK_MODE_OFB;
			break;
		case CKM_AES_CFB128:
			cb_mode = HSE_CIPHER_BLOCK_MODE_CFB;
			break;
		default:
			cb_mode = HSE_CIPHER_BLOCK_MODE_NULL;
			break;
	}
	return cb_mode;
}

hseAuthCipherMode_t hse_pkcs_ac_alg_translate(CK_MECHANISM_TYPE mechanism)
{
	hseAuthCipherMode_t ac_mode;

	switch (mechanism) {
		case CKM_AES_GCM:
			ac_mode = HSE_AUTH_CIPHER_MODE_GCM;
			break;
		case CKM_AES_CCM:
			ac_mode = HSE_AUTH_CIPHER_MODE_CCM;
			break;
		default:
			ac_mode = 0;
			break;
	}
	return ac_mode;
}

hseRsaAlgo_t hse_pkcs_rsa_alg_translate(CK_MECHANISM_TYPE mechanism)
{
	hseRsaAlgo_t rsa_alg;

	switch (mechanism) {
		case CKM_RSA_PKCS:
			rsa_alg = HSE_RSA_ALGO_RSAES_PKCS1_V15;
			break;
		case CKM_RSA_PKCS_OAEP:
			rsa_alg = HSE_RSA_ALGO_RSAES_OAEP;
			break;
		default:
			rsa_alg = 0;
			break;
	}
	return rsa_alg;
}

hseHashAlgo_t hse_get_hash_alg(CK_MECHANISM_TYPE mechanism)
{
	hseHashAlgo_t hash = HSE_HASH_ALGO_NULL;

	switch (mechanism) {
		case CKM_SHA1_RSA_PKCS:
		case CKM_SHA1_RSA_PKCS_PSS:
		case CKM_ECDSA_SHA1:
		case CKM_SHA_1_HMAC:
			hash = HSE_HASH_ALGO_SHA_1;
			break;
		case CKM_SHA224_RSA_PKCS:
		case CKM_SHA224_RSA_PKCS_PSS:
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
		case CKM_ECDSA_SHA3_224:
			hash = HSE_HASH_ALGO_SHA3_224;
			break;
		case CKM_ECDSA_SHA3_256:
			hash = HSE_HASH_ALGO_SHA3_256;
			break;
		case CKM_ECDSA_SHA3_384:
			hash = HSE_HASH_ALGO_SHA3_384;
			break;
		case CKM_ECDSA_SHA3_512:
			hash = HSE_HASH_ALGO_SHA3_512;
			break;
		default:
			break;
	}

	return hash;
}

uint32_t sig_get_out_length(uint8_t channel, CK_OBJECT_HANDLE key_handle, CK_MECHANISM_PTR mechanism)
{
	CK_MECHANISM_TYPE mechanism_type = mechanism->mechanism;
	uint32_t sig_len = 0;

	switch (mechanism_type) {
		case CKM_RSA_PKCS_OAEP:
		case CKM_SHA1_RSA_PKCS:
		case CKM_SHA224_RSA_PKCS:
		case CKM_SHA256_RSA_PKCS:
		case CKM_SHA384_RSA_PKCS:
		case CKM_SHA512_RSA_PKCS:
		case CKM_RSA_PKCS_PSS:
		case CKM_SHA1_RSA_PKCS_PSS:
		case CKM_SHA224_RSA_PKCS_PSS:
		case CKM_SHA256_RSA_PKCS_PSS:
		case CKM_SHA384_RSA_PKCS_PSS:
		case CKM_SHA512_RSA_PKCS_PSS:
			sig_len = hse_get_key_bit_length(channel, key_handle) >> 3;
			break;
		case CKM_ECDSA:
		case CKM_ECDSA_SHA1:
		case CKM_ECDSA_SHA224:
		case CKM_ECDSA_SHA256:
		case CKM_ECDSA_SHA384:
		case CKM_ECDSA_SHA512:
		case CKM_ECDSA_SHA3_224:
		case CKM_ECDSA_SHA3_256:
		case CKM_ECDSA_SHA3_384:
		case CKM_ECDSA_SHA3_512:
			sig_len = (hse_get_key_bit_length(channel, key_handle) >> 3) * 2;
			break;
		case CKM_AES_CMAC:
			sig_len = 16;
			break;
		case CKM_SHA_1_HMAC:
			sig_len = 20;
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

uint16_t hse_get_tag_length(unsigned long tagBits)
{
	uint16_t tagLen;

	if (tagBits < 32 || tagBits > 128)
		return 0;

	if (tagBits < 104)
		tagLen = ((tagBits / 8) / 4) * 4;
	else
		tagLen = tagBits / 8;

	return tagLen;
}

/* Public key value export 
 * Note on ECC key:
 *  For Weierstrass curves, export public key in uncompressed format: 0x04 || X || Y;
 * 	For Montgomery and Twisted Edward curves, export public key in raw format: X
*/
int32_t pkey_value_export(uint8_t channel, struct hse_keyObject *key, uint8_t *pkey0, uint8_t *pkey1, CK_ULONG *pkey0_len, CK_ULONG *pkey1_len)
{
	int err, key_info_handle, key_value0_handle, key_value1_handle, hse_pkey_length_handle;
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	hseExportKeySrv_t *export_key_srv;
	uint16_t key_bit_length;
	uint16_t pkey_length[2] = {0, 0};
	hseKeyInfo_t key_info;
	hseEccCurveId_t ecc_curve_id;
	bool Weierstrass_curve = FALSE;

	key_info_handle = hse_mem_alloc(sizeof(key_info));
	if (key_info_handle < 0) 
		return CKR_HOST_MEMORY;
	
	err = hse_get_key_info(channel, key->attrs.key_handle, key_info_handle);
	if (err) {
		goto out_free_key_info;
	}
	hse_memcpy_from_dev((void *)&key_info, key_info_handle, sizeof(key_info), 0);

	/* get the key size */
	key_bit_length = key_info.keyBitLen;

	if (key->attrs.key_type == CKK_RSA) {
		/* RSA public modulus n */
		pkey_length[0] = key_bit_length >> 3;
		/* RSA public exponent e */
		pkey_length[1] = key_info.specific.pubExponentSize;
	} else if (key->attrs.key_type == CKK_EC) {
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
		ecc_curve_id = key_info.specific.eccCurveId;
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
		goto out_free_key_info;
	}

	key_value0_handle = hse_mem_alloc(pkey_length[0]);
	if (key_value0_handle < 0) {
		err = CKR_HOST_MEMORY;
		goto out_free_key_info;
	}

	key_value1_handle = hse_mem_alloc(pkey_length[1]);
	if ((key_value1_handle < 0) && (key->attrs.key_type == CKK_RSA)) {
		err = CKR_HOST_MEMORY;
		goto out_free_pkey0;
	}

	hse_pkey_length_handle = hse_mem_alloc(sizeof(uint16_t) * 2);
	if (hse_pkey_length_handle < 0) {
		err = CKR_HOST_MEMORY;
		goto out_free_pkey1;
	}

	hse_memcpy_to_dev(hse_pkey_length_handle, pkey_length, sizeof(uint16_t) * 2, 0);

	srv_desc.srvId = HSE_SRV_ID_EXPORT_KEY;
	
	export_key_srv = &srv_desc.hseSrv.exportKeyReq;
	export_key_srv->targetKeyHandle = key->attrs.key_handle;
	export_key_srv->pKey[0] = hse_virt_to_dma(key_value0_handle, 0);
	export_key_srv->pKey[1] = hse_virt_to_dma(key_value1_handle, 0);
	export_key_srv->pKeyLen[0] = hse_virt_to_dma(hse_pkey_length_handle, 0);
	export_key_srv->pKeyLen[1] = hse_virt_to_dma(hse_pkey_length_handle, sizeof(uint16_t));
	export_key_srv->cipher.cipherKeyHandle = HSE_INVALID_KEY_HANDLE;
	export_key_srv->keyContainer.authKeyHandle = HSE_INVALID_KEY_HANDLE;

#if HSE_FW_VERSION_MAJOR >= 2
	/* The Montgomery and Twisted Edward public keys can be exported only in raw format */
	if (Weierstrass_curve)
		export_key_srv->keyFormat.eccKeyFormat = HSE_KEY_FORMAT_ECC_PUB_UNCOMPRESSED;
	else 
		export_key_srv->keyFormat.eccKeyFormat = HSE_KEY_FORMAT_ECC_PUB_RAW;
#endif /* HSE_FW_VERSION_MAJOR >= 2 */
	err = hse_srv_req_sync(channel, &srv_desc, sizeof(srv_desc), NULL);
	if (err)
		goto out_free_pkey_len;
	hse_memcpy_from_dev(pkey_length, hse_pkey_length_handle, sizeof(uint16_t) * 2, 0);

#if HSE_FW_VERSION_MAJOR >= 2
	if (NULL != pkey0) 
		hse_memcpy_from_dev(pkey0, key_value0_handle, pkey_length[0], 0);
	if (NULL != pkey0_len)
		*(pkey0_len) = pkey_length[0];
#else
	/* In case Weierstrass curve, convert raw format to uncompressed format: 0x04 || X || Y, in big endian; */
	if (NULL != pkey0) {
		if (Weierstrass_curve) {
			*pkey0 = 0x4;
			hse_memcpy_from_dev(pkey0 + 1, key_value0_handle, pkey_length[0], 0);
		} else {
			hse_memcpy_from_dev(pkey0, key_value0_handle, pkey_length[0], 0);
		}
	}
	if (NULL != pkey0_len) {
		if (Weierstrass_curve) 
			*(pkey0_len) = pkey_length[0] + 1;
		else 
			*(pkey0_len) = pkey_length[0];
	}
#endif /* HSE_FW_VERSION_MAJOR >= 2 */

	if ((NULL != pkey1) && (key->attrs.key_type == CKK_RSA))
		hse_memcpy_from_dev(pkey1, key_value1_handle, pkey_length[1], 0);
	if ((NULL != pkey1_len) && (key->attrs.key_type == CKK_RSA))
		*(pkey1_len) = pkey_length[1];

out_free_pkey_len:
	hse_mem_free(hse_pkey_length_handle);
out_free_pkey1:
	hse_mem_free(key_value1_handle);
out_free_pkey0:
	hse_mem_free(key_value0_handle);
out_free_key_info:
	hse_mem_free(key_info_handle);
	return err;
}

/*
 * PKCS11 standard: char buffers MUST be padded with the blank character (' ').
 * MUST NOT be null-terminated.
 */
void strcpy_pkcs11_padding(unsigned char *dest, const char *source, size_t dest_len)
{
	/* todo: not safe in case the source is not null-terminated */
	size_t src_len = strlen(source);
	strncpy((char *)dest, source, dest_len);

	if (src_len < dest_len)
		memset(dest + src_len, ' ', dest_len - src_len);
}

/* Copy the ' ' padded string and restore it to NUL-terminated */
static void strcpy_pkcs11_nul_padding(unsigned char *dest, const char *source, size_t dest_len)
{
	int tail = 0;
	int index = (int)dest_len - 1;

	for (; index >= 0; index--) {
		if (((source[index] == ' ') || (source[index] == '\0')) && (tail == 0)) {
			dest[index] = '\0';
			continue;
		} else {
			tail = 1;
			dest[index] = source[index];
		}
	}
}

static bool check_static_attr_type(CK_ATTRIBUTE_TYPE attr_type)
{
	if (attr_type == CKA_LABEL || attr_type == CKA_ID || attr_type == CKA_KEY_TYPE ||
	    attr_type == CKA_CLASS || attr_type == CKA_MODULUS || attr_type == CKA_MODULUS_BITS ||
	    attr_type == CKA_VALUE || attr_type == CKA_PUBLIC_EXPONENT || attr_type == CKA_VALUE_LEN ||
	    attr_type == CKA_PRIVATE_EXPONENT || attr_type == CKA_EC_POINT ||
		attr_type == CKA_EC_PARAMS)
		return true;
	return false;
}

static CK_RV check_attr_value(CK_OBJECT_CLASS class, CK_ATTRIBUTE_TYPE type,
						CK_VOID_PTR pValue, CK_ULONG ulValueLen)
{
	if (pValue == NULL || ulValueLen == 0)
		return CKR_ATTRIBUTE_VALUE_INVALID;

	switch (class) {
		case CKO_PUBLIC_KEY:
			switch (type) {
				case CKA_DECRYPT:
				case CKA_SIGN:
				case CKA_UNWRAP:
					return CKR_ATTRIBUTE_TYPE_INVALID;
				case CKA_ENCRYPT:
				case CKA_VERIFY:
				case CKA_WRAP:
					if (ulValueLen != 1 || (*(CK_BBOOL *)pValue > CK_TRUE))
						return CKR_ATTRIBUTE_VALUE_INVALID;
					return CKR_OK;
				default:
					return CKR_OK;
			}
		case CKO_PRIVATE_KEY:
			switch (type) {
				case CKA_ENCRYPT:
				case CKA_VERIFY:
				case CKA_WRAP:
					return CKR_ATTRIBUTE_TYPE_INVALID;
				case CKA_DECRYPT:
				case CKA_SIGN:
				case CKA_UNWRAP:
					if (ulValueLen != 1 || (*(CK_BBOOL *)pValue > CK_TRUE))
						return CKR_ATTRIBUTE_VALUE_INVALID;
					return CKR_OK;
				default:
					return CKR_OK;
			}
		case CKO_SECRET_KEY:
			switch (type) {
				case CKA_ENCRYPT:
				case CKA_VERIFY:
				case CKA_WRAP:
				case CKA_DECRYPT:
				case CKA_SIGN:
				case CKA_UNWRAP:
					if (ulValueLen != 1 || (*(CK_BBOOL *)pValue > CK_TRUE))
						return CKR_ATTRIBUTE_VALUE_INVALID;
					return CKR_OK;
				default:
					return CKR_OK;
			}
		default:
			return CKR_OK;
	}
}

CK_RV hse_add_dyn_attr(struct hse_keyObject *key, CK_ATTRIBUTE attr)
{
	int attr_lhead_handle = key->dyn_attrs_handle;
	struct dyn_attrHdrObject *attr_header;
	void *attr_buf;
	CK_RV rc;

	rc = check_attr_value(key->attrs.key_class, attr.type, attr.pValue, attr.ulValueLen);
	if (rc)
		return rc;

	key->dyn_attrs_handle = hse_intl_mem_alloc(sizeof(*attr_header), HSE_ATTR_HDR_OBJ);
	if (key->dyn_attrs_handle < 0) {
		hse_free_dyn_attr_list(attr_lhead_handle);
		return CKR_HOST_MEMORY;
	}
	attr_header = (struct dyn_attrHdrObject *)hse_get_node_mem_addr(key->dyn_attrs_handle, true);

	attr_header->type = attr.type;
	attr_header->ulLen = attr.ulValueLen;
	attr_header->next_attr_hdr_handle = attr_lhead_handle;

	attr_header->attr_handle = hse_intl_mem_alloc(attr_header->ulLen, HSE_ATTR_BUF_OBJ);
	if (attr_header->attr_handle < 0) {
		hse_free_dyn_attr_list(attr_lhead_handle);
		hse_intl_mem_free(key->dyn_attrs_handle);
		return CKR_HOST_MEMORY;
	}
	attr_buf = (void *)hse_get_node_mem_addr(attr_header->attr_handle, true);

	memcpy(attr_buf, attr.pValue, attr_header->ulLen);
	return CKR_OK;
}

CK_RV hse_add_dyn_attr_list(struct hse_keyObject *key, CK_ATTRIBUTE_PTR pTemplate,
				CK_ULONG ulCount)
{
	int i, ret;

	for (i = 0; i < ulCount; i++) {
		if (check_static_attr_type(pTemplate[i].type))
			continue;

		ret = hse_add_dyn_attr(key, pTemplate[i]);
		if (ret)
			return ret;
	}
	return CKR_OK;
}

void hse_free_dyn_attr(struct hse_keyObject *key, CK_ATTRIBUTE_TYPE type)
{
	struct dyn_attrHdrObject *curr_attr_header = NULL, *prev_attr_header = NULL;
	int curr_attr_handle = key->dyn_attrs_handle;

	if (curr_attr_handle == -1)
		return;

	curr_attr_header = (struct dyn_attrHdrObject *)hse_get_node_mem_addr(curr_attr_handle, true);
	if (curr_attr_header->type == type) {
		hse_intl_mem_free(curr_attr_header->attr_handle);
		key->dyn_attrs_handle = curr_attr_header->next_attr_hdr_handle;
		hse_intl_mem_free(curr_attr_handle);
		return;
	}

	while (curr_attr_handle != -1 && curr_attr_header->type != type) {
		prev_attr_header = curr_attr_header;
		curr_attr_handle = curr_attr_header->next_attr_hdr_handle;
		curr_attr_header = (struct dyn_attrHdrObject *)hse_get_node_mem_addr(curr_attr_handle, true);
	}

	if (curr_attr_handle == -1)
		return;

	prev_attr_header->next_attr_hdr_handle = curr_attr_header->next_attr_hdr_handle;
	hse_intl_mem_free(curr_attr_header->attr_handle);
	hse_intl_mem_free(curr_attr_handle);
}

void hse_free_dyn_attr_list(int dyn_attr_head_handle)
{
	struct dyn_attrHdrObject *attr_header;
	int free_attr_handle, curr_attr_handle = dyn_attr_head_handle;

	while (curr_attr_handle != -1) {
		free_attr_handle = curr_attr_handle;

		attr_header = (struct dyn_attrHdrObject *)hse_get_node_mem_addr(curr_attr_handle, true);
		hse_intl_mem_free(attr_header->attr_handle);

		curr_attr_handle = attr_header->next_attr_hdr_handle;
		hse_intl_mem_free(free_attr_handle);
	}
}

int32_t hse_key_object_write(struct hse_keyObject *key)
{
	FILE *key_file;
	void *attr_buf;
	int ret, attr_handle;
	char key_file_path[64] = {0};
	struct hse_keyObject serialized;
	struct dyn_attrHdrObject *attr_header;

	if (!key)
		return EINVAL;

	sprintf(key_file_path, "%s/0x%06lx.bin", PKCS_OBJ_DIR, key->attrs.key_handle);
	key_file = fopen(key_file_path, "wb");
	if (!key_file)
		return EBADF;

	strcpy_pkcs11_padding((unsigned char *)serialized.attrs.key_label,
					key->attrs.key_label, MAX_LABEL_LEN);
	serialized.attrs.key_uid = key->attrs.key_uid;
	serialized.attrs.key_handle = key->attrs.key_handle;
	serialized.attrs.key_type = key->attrs.key_type;
	serialized.attrs.key_class = key->attrs.key_class;

	ret = fwrite(&serialized.attrs, sizeof(serialized.attrs), 1, key_file);
	if (ret != 1) {
		ret = EIO;
		goto err_close_file;
	}

	attr_handle = key->dyn_attrs_handle;
	while (attr_handle != -1) {
		attr_header = (struct dyn_attrHdrObject *)hse_get_node_mem_addr(attr_handle, true);

		ret = fwrite(&attr_header->type, sizeof(attr_header->type), 1, key_file);
		if (ret != 1) {
			ret = EIO;
			goto err_close_file;
		}

		ret = fwrite(&attr_header->ulLen, sizeof(attr_header->ulLen), 1, key_file);
		if (ret != 1) {
			ret = EIO;
			goto err_close_file;
		}

		attr_buf = (void *)hse_get_node_mem_addr(attr_header->attr_handle, true);
		ret = fwrite(attr_buf, attr_header->ulLen, 1, key_file);
		if (ret != 1) {
			ret = EIO;
			goto err_close_file;
		}
		attr_handle = attr_header->next_attr_hdr_handle;
	}
	ret = 0;

err_close_file:
	fclose(key_file);
	return ret;
}

int32_t hse_key_object_remove(struct hse_keyObject *key)
{
	char key_file_path[64] = {0};

	if (!key)
		return EINVAL;
	sprintf(key_file_path, "%s/0x%06lx.bin", PKCS_OBJ_DIR, key->attrs.key_handle);
	hse_free_dyn_attr_list(key->dyn_attrs_handle);
	
	return remove(key_file_path);
}

int32_t hse_key_obj_read(char *key_name)
{
	FILE *key_file;
	char key_file_path[64] = {0};
	struct dyn_attrHdrObject *attr_header;
	int ret, key_obj_handle, attr_lhead_handle;
	struct hse_keyObject *key_obj, tmp_key_obj;
	void *attr_buf;
	long size = 0;

	if (!key_name)
		return EINVAL;

	sprintf(key_file_path, "%s/%s", PKCS_OBJ_DIR, key_name);
	key_file = fopen(key_file_path, "rb");
	if (!key_file)
		return EBADF;

	fseek(key_file, 0, SEEK_END);
	size = ftell(key_file);
	fseek(key_file, 0, SEEK_SET);

	ret = fread(&tmp_key_obj.attrs, sizeof(tmp_key_obj.attrs), 1, key_file);
	if (ret != 1) {
		ret = EIO;
		goto err_close_file;
	}

	key_obj_handle = hse_intl_mem_alloc(sizeof(*key_obj), HSE_KEY_OBJ);
	if (key_obj_handle < 0) {
		ret = ENOMEM;
		goto err_close_file;
	}
	key_obj = (struct hse_keyObject *)hse_get_node_mem_addr(key_obj_handle, true);

	strcpy_pkcs11_nul_padding((unsigned char *)key_obj->attrs.key_label,
				tmp_key_obj.attrs.key_label, MAX_LABEL_LEN);
	key_obj->attrs.key_uid = tmp_key_obj.attrs.key_uid;
	key_obj->attrs.key_handle = tmp_key_obj.attrs.key_handle;
	key_obj->attrs.key_type = tmp_key_obj.attrs.key_type;
	key_obj->attrs.key_class = tmp_key_obj.attrs.key_class;
	key_obj->dyn_attrs_handle = -1;

	while (size - ftell(key_file)) {
		attr_lhead_handle = key_obj->dyn_attrs_handle;
		
		key_obj->dyn_attrs_handle = hse_intl_mem_alloc(sizeof(*attr_header), HSE_ATTR_HDR_OBJ);
		if (key_obj->dyn_attrs_handle < 0) {
			hse_free_dyn_attr_list(attr_lhead_handle);
			return -ENOMEM;
		}
		attr_header = (struct dyn_attrHdrObject *)hse_get_node_mem_addr(key_obj->dyn_attrs_handle, true);

		ret = fread(&attr_header->type, sizeof(attr_header->type), 1, key_file);
		if (ret != 1) {
			ret = EIO;
			goto err_close_file;
		}

		ret = fread(&attr_header->ulLen, sizeof(attr_header->ulLen), 1, key_file);
		if (ret != 1) {
			ret = EIO;
			goto err_close_file;
		}

		attr_header->next_attr_hdr_handle = attr_lhead_handle;
		
		attr_header->attr_handle = hse_intl_mem_alloc(attr_header->ulLen, HSE_ATTR_BUF_OBJ);
		if (attr_header->attr_handle < 0) {
			hse_intl_mem_free(key_obj->dyn_attrs_handle);
			hse_free_dyn_attr_list(attr_lhead_handle);
			return -ENOMEM;
		}
		attr_buf = (void *)hse_get_node_mem_addr(attr_header->attr_handle, true);
		
		ret = fread(attr_buf, attr_header->ulLen, 1, key_file);
		if (ret != 1) {
			ret = EIO;
			goto err_close_file;
		}
	}

	ret = 0;

err_close_file:
	fclose(key_file);
	return ret;
}

int32_t hse_pkcs_read_objs_dir(void)
{
	int ret = 0;
	DIR *pkcs_dir;
    struct dirent *in_file;

	pkcs_dir = opendir(PKCS_OBJ_DIR);
	if (!pkcs_dir)
		return EBADF;

	while ((in_file = readdir(pkcs_dir))) {
		if (!strcmp (in_file->d_name, ".") || !strcmp (in_file->d_name, ".."))
			continue;

		ret = hse_key_obj_read(in_file->d_name);
		if (ret)
			break;
    }
	return ret;
}

int get_key_object_handle(CK_OBJECT_HANDLE handle)
{
    int curr_handle = -1;
    struct hse_keyObject *key;

    hse_intl_iterstart();
    if (!hse_intl_hasnext())
        return -1;

    do {
        curr_handle = hse_intl_next();
        if (hse_intl_get_node_type(curr_handle) != HSE_KEY_OBJ)
            continue;

        key = (struct hse_keyObject *)hse_get_node_mem_addr(curr_handle, true);
        if (key->attrs.key_handle == handle) {
            hse_intl_iterstop();
            return curr_handle;
        }
    } while (hse_intl_hasnext());

    hse_intl_iterstop();
    return -1;
}

struct dyn_attrHdrObject *get_key_dyn_attr_hdr_handle(int attr_head_handle, CK_ATTRIBUTE_TYPE type)
{
	int curr_attr_hdr_handle = attr_head_handle;
	struct dyn_attrHdrObject *attr_header;

	while (curr_attr_hdr_handle != -1) {
		attr_header = (struct dyn_attrHdrObject *)hse_get_node_mem_addr(curr_attr_hdr_handle, true);

		if (attr_header->type != type) {
			curr_attr_hdr_handle = attr_header->next_attr_hdr_handle;
			continue;
		}
		return attr_header;
	}
	return NULL;
}
