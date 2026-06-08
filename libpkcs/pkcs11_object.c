// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2026 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pkcs11_context.h"
#include "hse-internal.h"
#include "pkcs11_util.h"
#include "pkcs11_key_mgmt.h"

CK_DECLARE_FUNCTION(CK_RV, C_CreateObject)(
		CK_SESSION_HANDLE hSession,
		CK_ATTRIBUTE_PTR pTemplate,
		CK_ULONG ulCount,
		CK_OBJECT_HANDLE_PTR phObject
)
{
	struct globalCtx *gCtx = getCtx();
	struct tokenCtx *tCtx = getTokenCtx();
	struct sessionCtx *sCtx = getSessionCtx(hSession);
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	hseImportKeySrv_t *import_key_req;
	hseKeyInfo_t key_info;
	uint32_t pkey0_len, pkey1_len, pkey2_len, fullkey_len, tweakkey_len;
	void *ecc_oid, *ec_point;
	struct hse_keyObject *key;
	char *label = NULL;
	CK_RV rc = CKR_OK;
	int err, key_info_handle = -1, key_handle = -1;
	int pkey0_handle = -1, pkey1_handle = -1, pkey2_handle = -1;
	uint32_t key_bit_len;
	int tweakmem_handle = -1;
	CK_BYTE *fullKey, *tweakKey;
	uint8_t *pubkey, *privkey;
	CK_BBOOL *keyFlag_val = NULL;
	uint32_t blocksize, digestsize;
	hseHashAlgo_t hash_algo;
	hseHashSrv_t *hash_req;
	int hash_len_handle = -1;
	hseKeyType_t hse_key_type = 0;
	CK_BBOOL *token_attr;
	enum object_domain is_token;
	uint32_t acquired_handle = 0;
	uint32_t tweak_handle = 0;
	CK_KEY_TYPE ck_key_type;
	CK_OBJECT_CLASS ck_class;
	CK_BYTE tweak_handle_bytes[3];
	CK_BYTE *key_id = NULL;
	CK_ULONG key_id_len = 0;

	if (gCtx->cryptokiInit == CK_FALSE)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pTemplate == NULL || ulCount == 0)
		return CKR_ARGUMENTS_BAD;

	if (!sCtx || sCtx->sessionInit == CK_FALSE)
		return CKR_SESSION_HANDLE_INVALID;

	if (getattr_pval(pTemplate, CKA_UNIQUE_ID, ulCount))
		return CKR_ATTRIBUTE_READ_ONLY;

	if (getattr_len(pTemplate, CKA_LABEL, ulCount) <= 0 ||
	    getattr_len(pTemplate, CKA_LABEL, ulCount) > MAX_LABEL_LEN)
		return CKR_ARGUMENTS_BAD;

	/* Extract key type */
	if ((CK_KEY_TYPE *)getattr_pval(pTemplate, CKA_KEY_TYPE, ulCount) == NULL)
		return CKR_TEMPLATE_INCOMPLETE;
	ck_key_type = *(CK_KEY_TYPE *)getattr_pval(pTemplate, CKA_KEY_TYPE, ulCount);

	/* Extract object class */
	if (((CK_OBJECT_CLASS *)getattr_pval(pTemplate, CKA_CLASS, ulCount) == NULL) &&
	    (ck_key_type == CKK_RSA || ck_key_type == CKK_EC || ck_key_type == CKK_EC_EDWARDS))
		return CKR_TEMPLATE_INCOMPLETE;

	if (getattr_pval(pTemplate, CKA_CLASS, ulCount))
		ck_class = *(CK_OBJECT_CLASS *)getattr_pval(pTemplate, CKA_CLASS, ulCount);
	else
		ck_class = CKO_SECRET_KEY;

	/* Determine HSE key type and storage class */
	switch (ck_key_type) {
		case CKK_AES:
		case CKK_AES_XTS:
			hse_key_type = HSE_KEY_TYPE_AES;
			break;

		case CKK_SHA_1_HMAC:
		case CKK_SHA224_HMAC:
		case CKK_SHA256_HMAC:
		case CKK_SHA384_HMAC:
		case CKK_SHA512_HMAC:
			hse_key_type = HSE_KEY_TYPE_HMAC;
			break;

		case CKK_RSA:
			if (ck_class == CKO_PUBLIC_KEY)
				hse_key_type = HSE_KEY_TYPE_RSA_PUB;
			else
				hse_key_type = HSE_KEY_TYPE_RSA_PAIR;
			break;

		case CKK_EC:
		case CKK_EC_EDWARDS:
			if (ck_class == CKO_PUBLIC_KEY)
				hse_key_type = HSE_KEY_TYPE_ECC_PUB;
			else
				hse_key_type = HSE_KEY_TYPE_ECC_PAIR;
			break;

		default:
			return CKR_KEY_TYPE_INCONSISTENT;
	}

	/* Determine obj type (token or session) */
	token_attr = (CK_BBOOL *)getattr_pval(pTemplate, CKA_TOKEN, ulCount);
	is_token = (token_attr && *token_attr == CK_TRUE) ? TOKEN_OBJ : SESSION_OBJ;

	/* Acquire slot from key ring */
	rc = key_slot_acquire(hse_key_type, is_token, &acquired_handle);
	if (rc != CKR_OK)
		return rc;

	key_info_handle = hse_mem_alloc(sizeof(key_info));
	if (key_info_handle < 0) {
		rc = CKR_HOST_MEMORY;
		goto err_release_slot;
	}
	hse_memset(key_info_handle, 0, sizeof(key_info), 0);

	key_handle = hse_intl_mem_alloc(sizeof(*key), HSE_KEY_OBJ);
	if (key_handle < 0) {
		rc = CKR_HOST_MEMORY;
		goto err_free_key_info;
	}

	key = (struct hse_keyObject *)hse_get_node_mem_addr(key_handle, true);
	memset(key, 0, sizeof(*key));

	/* key handles are unique in HSE; use them for UID */
	key->attrs.key_handle = acquired_handle;
	key->attrs.key_type = ck_key_type;
	key->attrs.key_class = ck_class;
	key->dyn_attrs_handle = -1;

	rc = generate_unique_id(sCtx->sID, key->attrs.key_class,
							key->attrs.key_handle, key->attrs.obj_uid);
	if (rc != CKR_OK) {
		goto err_free_key_intl;
	}

	key_id = (CK_BYTE *)getattr_pval(pTemplate, CKA_ID, ulCount);
	if (key_id) {
		key_id_len = getattr_len(pTemplate, CKA_ID, ulCount);
		if (key_id_len > MAX_KEY_ID_LEN) {
			rc = CKR_ARGUMENTS_BAD;
			goto err_free_key_intl;
		}
		memcpy(key->attrs.obj_id, key_id, key_id_len);
		key->attrs.obj_id_len = key_id_len;
	} else {
		key->attrs.obj_id_len = 0;
	}

	memset(key->attrs.key_label, 0, MAX_LABEL_LEN);
	label = (char *)getattr_pval(pTemplate, CKA_LABEL, ulCount);
	if (label != NULL)
		memcpy(key->attrs.key_label, label, getattr_len(pTemplate, CKA_LABEL, ulCount));

	rc = hse_add_dyn_attr_list(key, pTemplate, ulCount);
	if (rc)
		goto err_free_key_intl;

	memset(&key_info, 0, sizeof(key_info));

	import_key_req = &srv_desc.hseSrv.importKeyReq;

	srv_desc.srvId = HSE_SRV_ID_IMPORT_KEY;
	import_key_req->pKeyInfo = hse_virt_to_dma(key_info_handle, 0);
	import_key_req->targetKeyHandle = key->attrs.key_handle;
	import_key_req->cipher.cipherKeyHandle = HSE_INVALID_KEY_HANDLE;
	import_key_req->keyContainer.authKeyHandle = HSE_INVALID_KEY_HANDLE;

	switch (key->attrs.key_type) {
		case CKK_RSA:

			pkey0_len = getattr_len(pTemplate, CKA_MODULUS, ulCount);
			key_bit_len = HSE_BYTES_TO_BITS(pkey0_len);
			if (!is_valid_key_length(key->attrs.key_type, key_bit_len)) {
				rc = CKR_ARGUMENTS_BAD;
				goto err_free_key_intl;
			}
			pkey0_handle = hse_mem_alloc(pkey0_len);
			if (pkey0_handle < 0) {
				rc = CKR_HOST_MEMORY;
				goto err_free_key_intl;
			}
			hse_memcpy_to_dev(pkey0_handle, getattr_pval(pTemplate, CKA_MODULUS, ulCount), pkey0_len, 0);

			pkey1_len = getattr_len(pTemplate, CKA_PUBLIC_EXPONENT, ulCount);
			if (!pkey1_len) {
				rc = CKR_ARGUMENTS_BAD;
				goto err_free_pkey0;
			}
			pkey1_handle = hse_mem_alloc(pkey1_len);
			if (pkey1_handle < 0) {
				rc = CKR_HOST_MEMORY;
				goto err_free_pkey0;
			}
			hse_memcpy_to_dev(pkey1_handle, getattr_pval(pTemplate, CKA_PUBLIC_EXPONENT, ulCount), pkey1_len, 0);

			if ((keyFlag_val = (CK_BBOOL *)getattr_pval(pTemplate, CKA_ENCRYPT, ulCount)) && (*keyFlag_val))
				key_info.keyFlags |= HSE_KF_USAGE_ENCRYPT;
			if ((keyFlag_val = (CK_BBOOL *)getattr_pval(pTemplate, CKA_VERIFY, ulCount)) && (*keyFlag_val))
				key_info.keyFlags |= HSE_KF_USAGE_VERIFY;

			key_info.keyBitLen = pkey0_len * 8;
			key_info.specific.pubExponentSize = pkey1_len;
			key_info.keyType = HSE_KEY_TYPE_RSA_PUB;

			import_key_req->pKey[0] = hse_virt_to_dma(pkey0_handle, 0); /* public modulus */
			import_key_req->pKey[1] = hse_virt_to_dma(pkey1_handle, 0); /* public exponent */
			import_key_req->pKey[2] = 0u;
			import_key_req->keyLen[0] = pkey0_len;
			import_key_req->keyLen[1] = pkey1_len;
			import_key_req->keyLen[2] = 0u;

			if (key->attrs.key_class == CKO_PRIVATE_KEY) {

				pkey2_len = getattr_len(pTemplate, CKA_PRIVATE_EXPONENT, ulCount);
				if (!pkey2_len) {
					rc = CKR_ARGUMENTS_BAD;
					goto err_free_pkey1;
				}
				pkey2_handle = hse_mem_alloc(pkey2_len);
				if (pkey2_handle < 0) {
					rc = CKR_HOST_MEMORY;
					goto err_free_pkey1;
				}
				hse_memcpy_to_dev(pkey2_handle, getattr_pval(pTemplate, CKA_PRIVATE_EXPONENT, ulCount), pkey2_len, 0);

				if ((keyFlag_val = (CK_BBOOL *)getattr_pval(pTemplate, CKA_DECRYPT, ulCount)) && (*keyFlag_val))
					key_info.keyFlags |= HSE_KF_USAGE_DECRYPT;
				if ((keyFlag_val = (CK_BBOOL *)getattr_pval(pTemplate, CKA_SIGN, ulCount)) && (*keyFlag_val))
					key_info.keyFlags |= HSE_KF_USAGE_SIGN;

				/* default flags for RSA key pair if none specified */
				if (key_info.keyFlags == 0)
					key_info.keyFlags = HSE_KF_USAGE_DECRYPT | HSE_KF_USAGE_SIGN | HSE_KF_USAGE_ENCRYPT | HSE_KF_USAGE_VERIFY;

				key_info.keyType = HSE_KEY_TYPE_RSA_PAIR;

				import_key_req->pKey[2] = hse_virt_to_dma(pkey2_handle, 0); /* private exponent */
				import_key_req->keyLen[2] = pkey2_len;
			} else {
				/* default flags for RSA public key if none specified */
				if (key_info.keyFlags == 0)
					key_info.keyFlags = HSE_KF_USAGE_ENCRYPT | HSE_KF_USAGE_VERIFY;
			}

			/* always allow exporting public key */
			key_info.keyFlags |= HSE_KF_ACCESS_EXPORTABLE;

			break;
		case CKK_EC:

			pkey0_len = getattr_len(pTemplate, CKA_EC_POINT, ulCount);
			if (pkey0_len < 3) {
				rc = CKR_ARGUMENTS_BAD;
				goto err_free_key_intl;
			}

			/* bypass DER encoding header, we don't support it */
			pkey0_len = pkey0_len - 3;
			pkey0_handle = hse_mem_alloc(pkey0_len);
			if (pkey0_handle < 0) {
				rc = CKR_HOST_MEMORY;
				goto err_free_key_intl;
			}
			ec_point = getattr_pval(pTemplate, CKA_EC_POINT, ulCount);
			ec_point = (uint8_t *)ec_point + 3;
			hse_memcpy_to_dev(pkey0_handle, ec_point, pkey0_len, 0);

			ecc_oid = getattr_pval(pTemplate, CKA_EC_PARAMS, ulCount);
			if (ecc_oid == NULL) {
				rc = CKR_ARGUMENTS_BAD;
				goto err_free_pkey0;
			}

			if ((keyFlag_val = (CK_BBOOL *)getattr_pval(pTemplate, CKA_VERIFY, ulCount)) && (*keyFlag_val))
				key_info.keyFlags |= HSE_KF_USAGE_VERIFY;

			key_info.specific.eccCurveId = ecparam2curveid((char *)ecc_oid, 
							(uint8_t)getattr_len(pTemplate, CKA_EC_PARAMS, ulCount));
			key_info.keyBitLen = hse_get_ec_key_bitlen(key_info.specific.eccCurveId);
			key_info.keyType = HSE_KEY_TYPE_ECC_PUB;

			import_key_req->pKey[0] = hse_virt_to_dma(pkey0_handle, 0); /* public x & y coords of ec */
			import_key_req->pKey[1] = 0u;
			import_key_req->pKey[2] = 0u;
			import_key_req->keyLen[0] = pkey0_len;
			import_key_req->keyLen[1] = 0u;
			import_key_req->keyLen[2] = 0u;
#if HSE_FW_VERSION_MAJOR >= 2
			import_key_req->keyFormat.eccKeyFormat = HSE_KEY_FORMAT_ECC_PUB_RAW;
#endif /* HSE_FW_VERSION_MAJOR >= 2 */

			if (key->attrs.key_class == CKO_PRIVATE_KEY) {

				pkey2_len = getattr_len(pTemplate, CKA_VALUE, ulCount);
				key_bit_len = HSE_BYTES_TO_BITS(pkey2_len);
				if (!is_valid_key_length(key->attrs.key_type, key_bit_len)) {
					rc = CKR_ARGUMENTS_BAD;
					goto err_free_pkey0;
				}
				pkey2_handle = hse_mem_alloc(pkey2_len);
				if (pkey2_handle < 0) {
					rc = CKR_HOST_MEMORY;
					goto err_free_pkey0;
				}
				hse_memcpy_to_dev(pkey2_handle, getattr_pval(pTemplate, CKA_VALUE, ulCount), pkey2_len, 0);

				if ((keyFlag_val = (CK_BBOOL *)getattr_pval(pTemplate, CKA_SIGN, ulCount)) && (*keyFlag_val))
					key_info.keyFlags |= HSE_KF_USAGE_SIGN;
				if ((keyFlag_val = (CK_BBOOL *)getattr_pval(pTemplate, CKA_DERIVE, ulCount)) && (*keyFlag_val))
					key_info.keyFlags |= HSE_KF_USAGE_EXCHANGE;

				/* default flags for ECC key pair if none specified */
				if (key_info.keyFlags == 0)
					key_info.keyFlags = HSE_KF_USAGE_SIGN | HSE_KF_USAGE_VERIFY;

				key_info.keyType = HSE_KEY_TYPE_ECC_PAIR;

				import_key_req->pKey[2] = hse_virt_to_dma(pkey2_handle, 0); /* ec private scalar/order */
				import_key_req->keyLen[2] = pkey2_len;
			} else {
				/* default flags for ECC public key if none specified */
				if (key_info.keyFlags == 0)
					key_info.keyFlags |= HSE_KF_USAGE_VERIFY;
			}

			/* always allow exporting public key */
			key_info.keyFlags |= HSE_KF_ACCESS_EXPORTABLE;

			break;
		case CKK_EC_EDWARDS:
			pkey0_len = getattr_len(pTemplate, CKA_EC_POINT, ulCount);
			if (pkey0_len < 2) {
				rc = CKR_ARGUMENTS_BAD;
				goto err_free_key_intl;
			}

			/* Bypass DER encoding header */
			pkey0_len -= 2;
			pubkey = (uint8_t *)getattr_pval(pTemplate, CKA_EC_POINT, ulCount);
			pubkey = (uint8_t *)pubkey + 2;

			/*
			 * Convert to big-endian (required by HSE) from little-endian (imposed RFC 8032).
			 * Byte width used for swapping (endianness conversion) is equal to the curve-specific
			 * width, e.g. for Ed25519 byte width is 32 bytes.
			 */
			reverse_bytes(pubkey, pkey0_len);

			pkey0_handle = hse_mem_alloc(pkey0_len);
			if (pkey0_handle < 0) {
				rc = CKR_HOST_MEMORY;
				goto err_free_key_intl;
			}

			hse_memcpy_to_dev(pkey0_handle, pubkey, pkey0_len, 0);

			ecc_oid = getattr_pval(pTemplate, CKA_EC_PARAMS, ulCount);
			if (ecc_oid == NULL) {
				rc = CKR_ARGUMENTS_BAD;
				goto err_free_pkey0;
			}

			key_info.specific.eccCurveId = ecparam2curveid((char *)ecc_oid,
											(uint8_t)getattr_len(pTemplate, CKA_EC_PARAMS, ulCount));
			key_info.keyBitLen = hse_get_ec_key_bitlen(key_info.specific.eccCurveId);
			if (key_info.keyBitLen != 256) {
				rc = CKR_ARGUMENTS_BAD;
				goto err_free_pkey0;
			}

			if ((keyFlag_val = (CK_BBOOL *)getattr_pval(pTemplate, CKA_VERIFY, ulCount)) && (*keyFlag_val))
				key_info.keyFlags |= HSE_KF_USAGE_VERIFY;

			key_info.keyType = HSE_KEY_TYPE_ECC_PUB;

			import_key_req->pKey[0] = hse_virt_to_dma(pkey0_handle, 0);
			import_key_req->pKey[1] = 0u;
			import_key_req->pKey[2] = 0u;
			import_key_req->keyLen[0] = pkey0_len;
			import_key_req->keyLen[1] = 0u;
			import_key_req->keyLen[2] = 0u;

#if HSE_FW_VERSION_MAJOR >= 2
			import_key_req->keyFormat.eccKeyFormat = HSE_KEY_FORMAT_ECC_PUB_RAW;
#endif /* HSE_FW_VERSION_MAJOR >= 2 */

			/* Private key import */
			if (key->attrs.key_class == CKO_PRIVATE_KEY) {
				pkey2_len = getattr_len(pTemplate, CKA_VALUE, ulCount);
				if (pkey2_len != 32) {
					rc = CKR_ARGUMENTS_BAD;
					goto err_free_pkey0;
				}

				key_bit_len = HSE_BYTES_TO_BITS(pkey2_len);
				if (!is_valid_key_length(key->attrs.key_type, key_bit_len)) {
					rc = CKR_ARGUMENTS_BAD;
					goto err_free_pkey0;
				}

				privkey = (uint8_t *)getattr_pval(pTemplate, CKA_VALUE, ulCount);

				/* Convert to big-endian (required by HSE) from little-endian (imposed RFC 8032) */
				/* byte width used for swapping (endianness conversion) is equal to the curve-specific
				* width, e.g. for Ed25519 byte width is 32 bytes.*/
				reverse_bytes(privkey, pkey2_len);

				pkey2_handle = hse_mem_alloc(pkey2_len);
				if (pkey2_handle < 0) {
					rc = CKR_HOST_MEMORY;
					goto err_free_pkey0;
				}

				hse_memcpy_to_dev(pkey2_handle, privkey, pkey2_len, 0);

				if ((keyFlag_val = (CK_BBOOL *)getattr_pval(pTemplate, CKA_SIGN, ulCount)) && (*keyFlag_val))
					key_info.keyFlags |= HSE_KF_USAGE_SIGN;

				/* default flags for EdDSA key pair if none specified */
				if (key_info.keyFlags == 0)
					key_info.keyFlags = HSE_KF_USAGE_SIGN | HSE_KF_USAGE_VERIFY;

				key_info.keyType = HSE_KEY_TYPE_ECC_PAIR;

				import_key_req->pKey[2] = hse_virt_to_dma(pkey2_handle, 0);
				import_key_req->keyLen[2] = pkey2_len;
			} else {
				/* default flags for EdDSA public key if none specified */
				if (key_info.keyFlags == 0)
					key_info.keyFlags |= HSE_KF_USAGE_VERIFY;
			}

			/* always allow exporting public key */
			key_info.keyFlags |= HSE_KF_ACCESS_EXPORTABLE;

			break;
		/*
		 * CKK_AES_XTS case:
		 * - AES-XTS requires two keys: one for encryption/decryption and one for tweak.
		 * - CKA_VALUE is expected to contain both keys concatenated: [cipher_key || tweak_key].
		 * - The tweak key is extracted and imported separately using either
		 *   HSE_KF_USAGE_XTS_TWEAK or HSE_KF_USAGE_ENCRYPT depending on the hse firmware version.
		 * - After importing the tweak key, we fall through to CKK_AES to import the cipher key.
		 */
		case CKK_AES_XTS:

			/* Get full key */
			fullKey = (CK_BYTE *)getattr_pval(pTemplate, CKA_VALUE, ulCount);
			fullkey_len = getattr_len(pTemplate, CKA_VALUE, ulCount);
			if (!fullKey || !fullkey_len) {
				rc = CKR_ARGUMENTS_BAD;
				goto err_free_key_intl;
			}

			/* Extract tweak key */
			tweakKey = fullKey + (fullkey_len / 2);
			tweakkey_len = fullkey_len / 2;

			tweakmem_handle = hse_mem_alloc(tweakkey_len);
			if (tweakmem_handle < 0) {
				rc = CKR_HOST_MEMORY;
				goto err_free_key_intl;
			}

			hse_memcpy_to_dev(tweakmem_handle, tweakKey, tweakkey_len, 0);

			/* Acquire slot for tweak key */
			rc = key_slot_acquire(HSE_KEY_TYPE_AES, is_token, &tweak_handle);
			if (rc != CKR_OK)
				goto err_free_tweakmem;

/*
 * HSE_KF_USAGE_XTS_TWEAK flag is only supported starting with
 * HSE firmware version 2.x.x.
 * For older versions, encryption flag is used.
 */
#if HSE_FW_VERSION_MAJOR >= 2
			key_info.keyFlags = HSE_KF_USAGE_XTS_TWEAK;
#else
			key_info.keyFlags |= HSE_KF_USAGE_ENCRYPT;
#endif /* HSE_FW_VERSION_MAJOR >= 2 */

			key_info.keyType = HSE_KEY_TYPE_AES;
			key_info.keyBitLen = tweakkey_len * 8;

			import_key_req->pKeyInfo = hse_virt_to_dma(key_info_handle, 0);
			import_key_req->targetKeyHandle = tweak_handle;
			import_key_req->cipher.cipherKeyHandle = HSE_INVALID_KEY_HANDLE;
			import_key_req->keyContainer.authKeyHandle = HSE_INVALID_KEY_HANDLE;

			import_key_req->pKey[0] = 0u;
			import_key_req->pKey[1] = 0u;
			import_key_req->pKey[2] = hse_virt_to_dma(tweakmem_handle, 0);
			import_key_req->keyLen[0] = 0u;
			import_key_req->keyLen[1] = 0u;
			import_key_req->keyLen[2] = tweakkey_len;


			hse_memcpy_to_dev(key_info_handle, (void *)&key_info, sizeof(key_info), 0);

			err = hse_srv_req_sync(sCtx->sID, &srv_desc, sizeof(srv_desc), NULL);
			if (err) {
				key_slot_release(tweak_handle);
				rc = CKR_FUNCTION_FAILED;
				goto err_free_tweakmem;
			}

			/* Store tweak handle as dynamic attribute */
			tweak_handle_bytes[0] = GET_SLOT_IDX(tweak_handle);
			tweak_handle_bytes[1] = GET_GROUP_IDX(tweak_handle);
			tweak_handle_bytes[2] = GET_CATALOG_ID(tweak_handle);

			CK_ATTRIBUTE tweak_attr = {
				.type = CKA_XTS_TWEAK_HANDLE,
				.pValue = tweak_handle_bytes,
				.ulValueLen = 3
			};

			rc = hse_add_dyn_attr(key, tweak_attr);
			if (rc != CKR_OK) {
				key_slot_release(tweak_handle);
				goto err_free_tweakmem;
			}

			hse_mem_free(tweakmem_handle);
			tweakmem_handle = -1;

			/* Reset the service descriptor for the cipher key */
			memset(&srv_desc, 0, sizeof(srv_desc));
			memset(&key_info, 0, sizeof(key_info));

			srv_desc.srvId = HSE_SRV_ID_IMPORT_KEY;
			import_key_req = &srv_desc.hseSrv.importKeyReq;
			import_key_req->pKeyInfo = hse_virt_to_dma(key_info_handle, 0);
			import_key_req->targetKeyHandle = key->attrs.key_handle;
			import_key_req->cipher.cipherKeyHandle = HSE_INVALID_KEY_HANDLE;
			import_key_req->keyContainer.authKeyHandle = HSE_INVALID_KEY_HANDLE;

		/* Fallthrough to CKK_AES to import cipher key */
		case CKK_AES:
		case CKK_SHA_1_HMAC:
		case CKK_SHA224_HMAC:
		case CKK_SHA256_HMAC:
		case CKK_SHA384_HMAC:
		case CKK_SHA512_HMAC:

			pkey2_len = getattr_len(pTemplate, CKA_VALUE, ulCount);
			key_bit_len = HSE_BYTES_TO_BITS(pkey2_len);
			if (!is_valid_key_length(key->attrs.key_type, key_bit_len)) {
				rc = CKR_ARGUMENTS_BAD;
				goto err_free_key_intl;
			}

			if (key->attrs.key_type == CKK_AES_XTS)
				pkey2_len /= 2;

			pkey2_handle = hse_mem_alloc(pkey2_len);
			if (pkey2_handle < 0) {
				rc = CKR_HOST_MEMORY;
				goto err_free_key_intl;
			}
			hse_memcpy_to_dev(pkey2_handle, getattr_pval(pTemplate, CKA_VALUE, ulCount), pkey2_len, 0);

			if ((keyFlag_val = (CK_BBOOL *)getattr_pval(pTemplate, CKA_SIGN, ulCount)) && (*keyFlag_val))
				key_info.keyFlags |= HSE_KF_USAGE_SIGN;
			if ((keyFlag_val = (CK_BBOOL *)getattr_pval(pTemplate, CKA_VERIFY, ulCount)) && (*keyFlag_val))
				key_info.keyFlags |= HSE_KF_USAGE_VERIFY;
			if ((keyFlag_val = (CK_BBOOL *)getattr_pval(pTemplate, CKA_DERIVE, ulCount)) && (*keyFlag_val))
				key_info.keyFlags |= HSE_KF_USAGE_DERIVE;

			if (key->attrs.key_type == CKK_AES || key->attrs.key_type == CKK_AES_XTS) {
				if ((keyFlag_val = (CK_BBOOL *)getattr_pval(pTemplate, CKA_ENCRYPT, ulCount)) && (*keyFlag_val))
					key_info.keyFlags |= HSE_KF_USAGE_ENCRYPT;
				if ((keyFlag_val = (CK_BBOOL *)getattr_pval(pTemplate, CKA_DECRYPT, ulCount)) && (*keyFlag_val))
					key_info.keyFlags |= HSE_KF_USAGE_DECRYPT;

				/* default flags for AES key if none specified */
				if (key_info.keyFlags == 0)
					key_info.keyFlags = HSE_KF_USAGE_ENCRYPT | HSE_KF_USAGE_DECRYPT | HSE_KF_USAGE_SIGN | HSE_KF_USAGE_VERIFY;

				key_info.keyType = HSE_KEY_TYPE_AES;
			} else {
				/* HMAC key */
				if (hse_get_hmac_key_params(key->attrs.key_type, &hash_algo, &blocksize, &digestsize)) {
					rc = CKR_ARGUMENTS_BAD;
					goto err_free_pkey2;
				}

				/* keys longer than block size must be shortened by hashing */
				if (pkey2_len > blocksize) {
					hash_len_handle = hse_mem_alloc(sizeof(uint32_t));
					if (hash_len_handle < 0) {
						rc = CKR_HOST_MEMORY;
						goto err_free_pkey2;
					}
					hse_memcpy_to_dev(hash_len_handle, &digestsize, sizeof(uint32_t), 0);

					memset(&srv_desc, 0, sizeof(srv_desc));
					srv_desc.srvId = HSE_SRV_ID_HASH;
					hash_req = &srv_desc.hseSrv.hashReq;
					hash_req->accessMode = HSE_ACCESS_MODE_ONE_PASS;
					hash_req->hashAlgo = hash_algo;
					hash_req->sgtOption = HSE_SGT_OPTION_NONE;
					hash_req->inputLength = pkey2_len;
					hash_req->pInput = hse_virt_to_dma(pkey2_handle, 0);
					hash_req->pHashLength = hse_virt_to_dma(hash_len_handle, 0);
					hash_req->pHash = hse_virt_to_dma(pkey2_handle, 0);

					err = hse_srv_req_sync(sCtx->sID, &srv_desc, sizeof(srv_desc), NULL);
					hse_mem_free(hash_len_handle);
					if (err) {
						rc = CKR_FUNCTION_FAILED;
						goto err_free_pkey2;
					}

					pkey2_len = digestsize;

					/* reset srv_desc */
					memset(&srv_desc, 0, sizeof(srv_desc));
					srv_desc.srvId = HSE_SRV_ID_IMPORT_KEY;
					import_key_req = &srv_desc.hseSrv.importKeyReq;
					import_key_req->pKeyInfo = hse_virt_to_dma(key_info_handle, 0);
					import_key_req->targetKeyHandle = key->attrs.key_handle;
					import_key_req->cipher.cipherKeyHandle = HSE_INVALID_KEY_HANDLE;
					import_key_req->keyContainer.authKeyHandle = HSE_INVALID_KEY_HANDLE;
				}

				/* default flags for HMAC key if none specified */
				if (key_info.keyFlags == 0)
					key_info.keyFlags = HSE_KF_USAGE_SIGN | HSE_KF_USAGE_VERIFY;

				key_info.keyType = HSE_KEY_TYPE_HMAC;
			}

			key_info.keyBitLen = pkey2_len * 8;

			import_key_req->pKey[0] = 0u;
			import_key_req->pKey[1] = 0u;
			import_key_req->pKey[2] = hse_virt_to_dma(pkey2_handle, 0); /* sym key */
			import_key_req->keyLen[0] = 0u;
			import_key_req->keyLen[1] = 0u;
			import_key_req->keyLen[2] = pkey2_len;

			break;
		default:
			rc = CKR_ARGUMENTS_BAD;
			goto err_free_key_intl;
	}

	hse_memcpy_to_dev(key_info_handle, (void *)&key_info, sizeof(key_info), 0);

	err = hse_srv_req_sync(sCtx->sID, &srv_desc, sizeof(srv_desc), NULL);
	if (err) {
		rc = CKR_FUNCTION_FAILED;
		goto err_free_pkey2;
	}

	gCtx->mtxFns.lock(tCtx->keyMtx);
	hse_key_object_write(key);
	*phObject = key->attrs.key_handle;
	gCtx->mtxFns.unlock(tCtx->keyMtx);

	hse_mem_free(pkey2_handle);
	hse_mem_free(pkey1_handle);
	hse_mem_free(pkey0_handle);
	hse_mem_free(key_info_handle);

	return CKR_OK;

err_free_tweakmem:
	hse_mem_free(tweakmem_handle);
err_free_pkey2:
	hse_mem_free(pkey2_handle);
err_free_pkey1:
	hse_mem_free(pkey1_handle);
err_free_pkey0:
	hse_mem_free(pkey0_handle);
err_free_key_intl:
	hse_free_dyn_attr_list(key->dyn_attrs_handle);
	hse_intl_mem_free(key_handle);
err_free_key_info:
	hse_mem_free(key_info_handle);
err_release_slot:
	key_slot_release(acquired_handle);
	return rc;
}

CK_DECLARE_FUNCTION(CK_RV, C_DestroyObject)(
		CK_SESSION_HANDLE hSession,
		CK_OBJECT_HANDLE hObject
)
{
	struct globalCtx *gCtx = getCtx();
	struct tokenCtx *tCtx = getTokenCtx();
	struct sessionCtx *sCtx = getSessionCtx(hSession);
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	struct hse_keyObject *pkey;
	uint32_t tweak_handle;
	uint8_t *attr;
	int err, key_handle;

	if (gCtx->cryptokiInit == CK_FALSE)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!sCtx || sCtx->sessionInit == CK_FALSE)
		return CKR_SESSION_HANDLE_INVALID;

	gCtx->mtxFns.lock(tCtx->keyMtx);
	key_handle = get_key_object_handle(hObject);
	gCtx->mtxFns.unlock(tCtx->keyMtx);
	if (key_handle < 0)
		return CKR_OBJECT_HANDLE_INVALID;
	pkey = (struct hse_keyObject *)hse_get_node_mem_addr(key_handle, true);

	/* Handle AES-XTS: erase and release tweak key first */
	if (pkey->attrs.key_type == CKK_AES_XTS) {
		attr = get_attr_handle_from_key(hObject, CKA_XTS_TWEAK_HANDLE);
		if (attr != NULL) {
			tweak_handle = GET_KEY_HANDLE(attr[2], attr[1], attr[0]);

			/* Erase tweak key from HSE */
			srv_desc.srvId = HSE_SRV_ID_ERASE_KEY;
			srv_desc.hseSrv.eraseKeyReq.keyHandle = tweak_handle;
			srv_desc.hseSrv.eraseKeyReq.eraseKeyOptions = 0u;

			err = hse_srv_req_sync(sCtx->sID, &srv_desc, sizeof(srv_desc), NULL);
			if (err)
				printf("[C_DestroyObject] WARNING: Failed to erase XTS tweak key 0x%06X\n",
						tweak_handle);

			/* Release tweak key slot */
			key_slot_release(tweak_handle);

			/* Reset srv_desc for main key */
			memset(&srv_desc, 0, sizeof(srv_desc));
		}
	}

	srv_desc.srvId = HSE_SRV_ID_ERASE_KEY;
	srv_desc.hseSrv.eraseKeyReq.keyHandle = pkey->attrs.key_handle;
	srv_desc.hseSrv.eraseKeyReq.eraseKeyOptions = 0u;

	err = hse_srv_req_sync(sCtx->sID, &srv_desc, sizeof(srv_desc), NULL);
	if (err)
		return CKR_FUNCTION_FAILED;

	key_slot_release(pkey->attrs.key_handle);

	gCtx->mtxFns.lock(tCtx->keyMtx);
	hse_key_object_remove(pkey);
	hse_intl_mem_free(key_handle);
	gCtx->mtxFns.unlock(tCtx->keyMtx);

	return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_FindObjectsInit)(
	CK_SESSION_HANDLE hSession,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount
)
{
	struct globalCtx *gCtx = getCtx();
	struct sessionCtx *sCtx = getSessionCtx(hSession);

	if (gCtx->cryptokiInit == CK_FALSE)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!sCtx || sCtx->sessionInit == CK_FALSE)
		return CKR_SESSION_HANDLE_INVALID;

	if (sCtx->findCtx.init == CK_TRUE)
		return CKR_OPERATION_ACTIVE;

	if (ulCount > 0 && !pTemplate)
		return CKR_ARGUMENTS_BAD;

	if (ulCount > 0 && pTemplate) {
		sCtx->findCtx.obj_class = (CK_OBJECT_CLASS *)getattr_pval(pTemplate, CKA_CLASS, ulCount);
		sCtx->findCtx.obj_uid = (uint8_t *)getattr_pval(pTemplate, CKA_UNIQUE_ID, ulCount);
		sCtx->findCtx.obj_uid_len = getattr_len(pTemplate, CKA_UNIQUE_ID, ulCount);
		sCtx->findCtx.label = (CK_UTF8CHAR *)getattr_pval(pTemplate, CKA_LABEL, ulCount);
		sCtx->findCtx.obj_id = (uint8_t *)getattr_pval(pTemplate, CKA_ID, ulCount);
		sCtx->findCtx.obj_id_len = getattr_len(pTemplate, CKA_ID, ulCount);
		sCtx->findCtx.search_template = pTemplate;
	} else {
		sCtx->findCtx.obj_class = NULL;
		sCtx->findCtx.obj_uid = NULL;
		sCtx->findCtx.obj_uid_len = 0;
		sCtx->findCtx.label = NULL;
		sCtx->findCtx.obj_id = NULL;
		sCtx->findCtx.obj_id_len = 0;
	}

	sCtx->findCtx.ulCount = ulCount;
	sCtx->findCtx.init = CK_TRUE;
	hse_intl_iterstart();

	return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_FindObjects)(
	CK_SESSION_HANDLE hSession,
	CK_OBJECT_HANDLE_PTR phObject,
	CK_ULONG ulMaxObjectCount,
	CK_ULONG_PTR pulObjectCount
)
{
	struct globalCtx *gCtx = getCtx();
	struct sessionCtx *sCtx = getSessionCtx(hSession);
	struct hse_keyObject *key;
	struct hse_findCtx *finder;
	struct dyn_attrHdrObject *dyn_attr_hdr;
	int i, j, found, key_handle;

	if (gCtx->cryptokiInit == CK_FALSE)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!sCtx || sCtx->sessionInit == CK_FALSE)
		return CKR_SESSION_HANDLE_INVALID;

	if (sCtx->findCtx.init == CK_FALSE)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (phObject == NULL || ulMaxObjectCount == 0 || pulObjectCount == NULL)
		return CKR_ARGUMENTS_BAD;

	if (!hse_intl_hasnext()) {
		*pulObjectCount = 0;
		return CKR_OK;
	}

	finder = &sCtx->findCtx;
	i = 0;
	do {
		found = 0;

		key_handle = hse_intl_next();
		if (hse_intl_get_node_type(key_handle) != HSE_KEY_OBJ)
            continue;

		key = (struct hse_keyObject *)hse_get_node_mem_addr(key_handle, true);

		/* either ALL attributes match, or no attributes match (empty template -> return all) */
		if (finder->obj_class && key->attrs.key_class != *finder->obj_class)
			continue;
		else if (finder->obj_class)
			found++;

		if (finder->obj_uid && finder->obj_uid_len > 0) {
			if (finder->obj_uid_len != UNIQUE_ID_LEN)
				continue;
			if (memcmp(key->attrs.obj_uid, finder->obj_uid, UNIQUE_ID_LEN) != 0)
				continue;
			found++;
		}

		if (finder->label && (strcmp(key->attrs.key_label, (const char *)finder->label)))
			continue;
		else if (finder->label)
			found++;

		if (finder->obj_id && finder->obj_id_len > 0) {
			if (key->attrs.obj_id_len != finder->obj_id_len)
				continue;
			if (memcmp(key->attrs.obj_id, finder->obj_id, finder->obj_id_len) != 0)
				continue;
			found++;
		}

		for (j = 0; j < finder->ulCount; j++) {
			if (finder->search_template[j].type == CKA_CLASS ||
			    finder->search_template[j].type == CKA_ID ||
			    finder->search_template[j].type == CKA_UNIQUE_ID ||
			    finder->search_template[j].type == CKA_LABEL)
			    continue;

			dyn_attr_hdr = get_key_dyn_attr_hdr_handle(key->dyn_attrs_handle,
								finder->search_template[j].type);

			if (dyn_attr_hdr == NULL ||
				dyn_attr_hdr->ulLen != finder->search_template[j].ulValueLen)
				continue;

			if (memcmp(finder->search_template[j].pValue,
			    (void *)hse_get_node_mem_addr(dyn_attr_hdr->attr_handle, true),
				dyn_attr_hdr->ulLen))
				continue;
			found++;
		}

		if (found != finder->ulCount)
			continue;

		/* found a match */
		phObject[i++] = key->attrs.key_handle;
	} while (hse_intl_hasnext() && i < ulMaxObjectCount);

	*pulObjectCount = i;

	return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_FindObjectsFinal)(
	CK_SESSION_HANDLE hSession
)
{
	struct globalCtx *gCtx = getCtx();
	struct sessionCtx *sCtx = getSessionCtx(hSession);

	if (gCtx->cryptokiInit == CK_FALSE)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!sCtx || sCtx->sessionInit == CK_FALSE)
		return CKR_SESSION_HANDLE_INVALID;

	if (sCtx->findCtx.init == CK_FALSE)
		return CKR_OPERATION_NOT_INITIALIZED;

	sCtx->findCtx.init = CK_FALSE;
	hse_intl_iterstop();

	return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_CopyObject)(
	CK_SESSION_HANDLE hSession,
	CK_OBJECT_HANDLE hObject,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount,
	CK_OBJECT_HANDLE_PTR phNewObject
)
{
	(void)hSession;
	(void)hObject;
	(void)pTemplate;
	(void)ulCount;
	(void)phNewObject;

	return CKR_ACTION_PROHIBITED;
}
