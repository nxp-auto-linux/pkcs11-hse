// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2026 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <libhse.h>

#include "pkcs11_context.h"
#include "hse_interface.h"
#include "pkcs11_util.h"
#include "pkcs11_key_mgmt.h"
#include "hse-internal.h"

CK_DECLARE_FUNCTION(CK_RV, C_GenerateKeyPair)(
		CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,
		CK_ATTRIBUTE_PTR pPublicKeyTemplate,
		CK_ULONG ulPublicKeyAttributeCount,
		CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
		CK_ULONG ulPrivateKeyAttributeCount,
		CK_OBJECT_HANDLE_PTR phPublicKey,
		CK_OBJECT_HANDLE_PTR phPrivateKey
)
{
	struct globalCtx *gCtx = getCtx();
	struct tokenCtx *tCtx = getTokenCtx();
	struct sessionCtx *sCtx = getSessionCtx(hSession);
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	hseKeyGenerateSrv_t *keyGenReq = &srv_desc.hseSrv.keyGenReq;
	struct hse_keyObject *key = NULL;
	uint16_t *keyBitsLen;
	void *ecc_oid, *pubExp;
	CK_BYTE default_pubExp[] = { 0x01, 0x00, 0x01};
	CK_ULONG pubExpLen;
	CK_BBOOL *keyFlag_val;
	char *label = NULL;
	CK_RV rc = CKR_OK;
	int err, key_handle = -1, pubExp_handle = -1;
	hseKeyType_t hse_key_type;
	enum object_domain is_token;
	CK_BBOOL *token_attr;
	uint32_t acquired_handle = 0;

	if (gCtx->cryptokiInit == CK_FALSE)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pPublicKeyTemplate == NULL || ulPublicKeyAttributeCount == 0 ||
	    pPrivateKeyTemplate == NULL || ulPrivateKeyAttributeCount == 0)
		return CKR_ARGUMENTS_BAD;

	if (phPublicKey == NULL || phPrivateKey == NULL)
		return CKR_ARGUMENTS_BAD;

	if (!sCtx || sCtx->sessionInit == CK_FALSE)
		return CKR_SESSION_HANDLE_INVALID;

	if (getattr_pval(pPrivateKeyTemplate, CKA_UNIQUE_ID, ulPrivateKeyAttributeCount))
		return CKR_ATTRIBUTE_READ_ONLY;

	/* Determine HSE key type from mechanism */
	switch (pMechanism->mechanism) {
		case CKM_RSA_PKCS_KEY_PAIR_GEN:
			hse_key_type = HSE_KEY_TYPE_RSA_PAIR;
			break;
		case CKM_EC_KEY_PAIR_GEN:
		case CKM_EC_EDWARDS_KEY_PAIR_GEN:
			hse_key_type = HSE_KEY_TYPE_ECC_PAIR;
			break;
		default:
			return CKR_MECHANISM_INVALID;
	}

	/* Determine obj type (token or session) */
	token_attr = (CK_BBOOL *)getattr_pval(pPrivateKeyTemplate, CKA_TOKEN, ulPrivateKeyAttributeCount);
	is_token = (token_attr && *token_attr == CK_TRUE) ? TOKEN_OBJ : SESSION_OBJ;

	/* Acquire slot from key ring */
	rc = key_slot_acquire(hse_key_type, is_token, &acquired_handle);
	if (rc != CKR_OK)
		return rc;

	key_handle = hse_intl_mem_alloc(sizeof(*key), HSE_KEY_OBJ);
	if (key_handle < 0) {
		rc = CKR_HOST_MEMORY;
		goto err_release_slot;
	}
	key = (struct hse_keyObject *)hse_get_node_mem_addr(key_handle, true);
	memset(key, 0, sizeof(*key));

	/* key handles are unique in HSE; use them for UID */
	key->attrs.key_handle = acquired_handle;
	key->attrs.key_uid = acquired_handle;
	key->dyn_attrs_handle = -1;

	label = (char *)getattr_pval(pPrivateKeyTemplate, CKA_LABEL, ulPrivateKeyAttributeCount);
	if (label != NULL) {
        if (getattr_len(pPrivateKeyTemplate, CKA_LABEL, ulPrivateKeyAttributeCount) <= 0 ||
	        getattr_len(pPrivateKeyTemplate, CKA_LABEL, ulPrivateKeyAttributeCount) > MAX_LABEL_LEN) {
		    rc = CKR_ARGUMENTS_BAD;
            goto err_free_key_intl;
        }

		memcpy(key->attrs.key_label, label, getattr_len(pPrivateKeyTemplate, CKA_LABEL, ulPrivateKeyAttributeCount));
	}

	/* key class and key type */
	if (getattr_pval(pPrivateKeyTemplate, CKA_CLASS, ulPrivateKeyAttributeCount))
		key->attrs.key_class = *(CK_OBJECT_CLASS *)getattr_pval(pPrivateKeyTemplate, CKA_CLASS, ulPrivateKeyAttributeCount);
	if (getattr_pval(pPrivateKeyTemplate, CKA_KEY_TYPE, ulPrivateKeyAttributeCount))
		key->attrs.key_type = *(CK_KEY_TYPE *)getattr_pval(pPrivateKeyTemplate, CKA_KEY_TYPE, ulPrivateKeyAttributeCount);

	rc = hse_add_dyn_attr_list(key, pPrivateKeyTemplate, ulPrivateKeyAttributeCount);
	if (rc)
		goto err_free_key_intl;

	rc = hse_add_dyn_attr_list(key, pPublicKeyTemplate, ulPublicKeyAttributeCount);
	if (rc)
		goto err_free_key_intl;

	srv_desc.srvId = HSE_SRV_ID_KEY_GENERATE;
	keyGenReq->targetKeyHandle = key->attrs.key_handle;
	keyGenReq->keyInfo.keyCounter = 0u;
	keyGenReq->keyInfo.smrFlags = 0u;

	switch (pMechanism->mechanism) {
		case CKM_RSA_PKCS_KEY_PAIR_GEN:

			if ((getattr_pval(pPrivateKeyTemplate, CKA_KEY_TYPE, ulPrivateKeyAttributeCount)) &&
				(key->attrs.key_type != CKK_RSA)) {
				rc = CKR_TEMPLATE_INCONSISTENT;
				goto err_free_key_intl;
			}

			if (!(keyBitsLen = (uint16_t *)getattr_pval(pPublicKeyTemplate, CKA_MODULUS_BITS, ulPublicKeyAttributeCount))) {
				rc = CKR_ARGUMENTS_BAD;
				goto err_free_key_intl;
			}

			pubExp = getattr_pval(pPublicKeyTemplate, CKA_PUBLIC_EXPONENT, ulPublicKeyAttributeCount);
			if (!pubExp) {
				/* if a public exponent is not provided, use default 0x10001 (65537) */
				pubExpLen = sizeof(default_pubExp);
				pubExp = (void *)default_pubExp;
			} else {
				pubExpLen = getattr_len(pPublicKeyTemplate, CKA_PUBLIC_EXPONENT, ulPublicKeyAttributeCount);
				if (pubExpLen > 16) {
					rc = CKR_TEMPLATE_INCONSISTENT;
					goto err_free_key_intl;
				}
			}

			pubExp_handle = hse_mem_alloc(pubExpLen);
			if (pubExp_handle < 0) {
				rc = CKR_HOST_MEMORY;
				goto err_free_key_intl;
			}
			hse_memcpy_to_dev(pubExp_handle, pubExp, pubExpLen, 0);

			if ((keyFlag_val = (CK_BBOOL *)getattr_pval(pPublicKeyTemplate, CKA_ENCRYPT, ulPublicKeyAttributeCount)) && (*keyFlag_val))
				keyGenReq->keyInfo.keyFlags |= HSE_KF_USAGE_ENCRYPT;
			if ((keyFlag_val = (CK_BBOOL *)getattr_pval(pPublicKeyTemplate, CKA_VERIFY, ulPublicKeyAttributeCount)) && (*keyFlag_val))
				keyGenReq->keyInfo.keyFlags |= HSE_KF_USAGE_VERIFY;
			if ((keyFlag_val = (CK_BBOOL *)getattr_pval(pPrivateKeyTemplate, CKA_DECRYPT, ulPrivateKeyAttributeCount)) && (*keyFlag_val))
				keyGenReq->keyInfo.keyFlags |= HSE_KF_USAGE_DECRYPT;
			if ((keyFlag_val = (CK_BBOOL *)getattr_pval(pPrivateKeyTemplate, CKA_SIGN, ulPrivateKeyAttributeCount)) && (*keyFlag_val))
				keyGenReq->keyInfo.keyFlags |= HSE_KF_USAGE_SIGN;

			/* default flags for RSA key pair if none specified */
			if (keyGenReq->keyInfo.keyFlags == 0)
				keyGenReq->keyInfo.keyFlags = HSE_KF_USAGE_DECRYPT | HSE_KF_USAGE_SIGN | HSE_KF_USAGE_ENCRYPT | HSE_KF_USAGE_VERIFY;

			keyGenReq->keyInfo.keyType = HSE_KEY_TYPE_RSA_PAIR;
			keyGenReq->keyInfo.keyBitLen = *keyBitsLen;
			keyGenReq->keyInfo.specific.pubExponentSize = pubExpLen;
			keyGenReq->keyGenScheme = HSE_KEY_GEN_RSA_KEY_PAIR;
			keyGenReq->sch.rsaKey.pubExpLength = pubExpLen;
			keyGenReq->sch.rsaKey.pPubExp = hse_virt_to_dma(pubExp_handle, 0);
			keyGenReq->sch.rsaKey.pModulus = 0u;
			break;
		case CKM_EC_KEY_PAIR_GEN:

			ecc_oid = getattr_pval(pPublicKeyTemplate, CKA_EC_PARAMS, ulPublicKeyAttributeCount);
			if (!ecc_oid) {
				rc = CKR_ARGUMENTS_BAD;
				goto err_free_key_intl;
			}

			if ((getattr_pval(pPrivateKeyTemplate, CKA_KEY_TYPE, ulPrivateKeyAttributeCount)) &&
				(key->attrs.key_type != CKK_EC)) {
				rc = CKR_TEMPLATE_INCONSISTENT;
				goto err_free_key_intl;
			}

			if ((keyFlag_val = (CK_BBOOL *)getattr_pval(pPublicKeyTemplate, CKA_VERIFY, ulPublicKeyAttributeCount)) && (*keyFlag_val))
				keyGenReq->keyInfo.keyFlags |= HSE_KF_USAGE_VERIFY;
			if ((keyFlag_val = (CK_BBOOL *)getattr_pval(pPrivateKeyTemplate, CKA_SIGN, ulPrivateKeyAttributeCount)) && (*keyFlag_val))
				keyGenReq->keyInfo.keyFlags |= HSE_KF_USAGE_SIGN;
			if ((keyFlag_val = (CK_BBOOL *)getattr_pval(pPrivateKeyTemplate, CKA_DERIVE, ulPrivateKeyAttributeCount)) && (*keyFlag_val))
				keyGenReq->keyInfo.keyFlags |= HSE_KF_USAGE_EXCHANGE;

			/* default flags for ECC key pair if none specified */
			if (keyGenReq->keyInfo.keyFlags == 0)
				keyGenReq->keyInfo.keyFlags = HSE_KF_USAGE_SIGN | HSE_KF_USAGE_VERIFY;

			keyGenReq->keyInfo.keyType = HSE_KEY_TYPE_ECC_PAIR;
			keyGenReq->keyInfo.specific.eccCurveId = ecparam2curveid((char *)ecc_oid,
				(uint8_t)getattr_len(pPublicKeyTemplate, CKA_EC_PARAMS, ulPublicKeyAttributeCount));
			keyGenReq->keyInfo.keyBitLen = hse_get_ec_key_bitlen(keyGenReq->keyInfo.specific.eccCurveId);
			keyGenReq->keyGenScheme = HSE_KEY_GEN_ECC_KEY_PAIR;
			keyGenReq->sch.eccKey.pPubKey = 0u;
			break;
		case CKM_EC_EDWARDS_KEY_PAIR_GEN:
			ecc_oid = getattr_pval(pPublicKeyTemplate, CKA_EC_PARAMS, ulPublicKeyAttributeCount);
			if (!ecc_oid) {
				rc = CKR_ARGUMENTS_BAD;
				goto err_free_key_intl;
			}

			if ((getattr_pval(pPrivateKeyTemplate, CKA_KEY_TYPE, ulPrivateKeyAttributeCount)) &&
				(key->attrs.key_type != CKK_EC_EDWARDS)) {
				rc = CKR_TEMPLATE_INCONSISTENT;
				goto err_free_key_intl;
			}

			/* Set key flags based on template */
			if ((keyFlag_val = (CK_BBOOL *)getattr_pval(pPublicKeyTemplate, CKA_VERIFY, ulPublicKeyAttributeCount)) && (*keyFlag_val))
				keyGenReq->keyInfo.keyFlags |= HSE_KF_USAGE_VERIFY;
			if ((keyFlag_val = (CK_BBOOL *)getattr_pval(pPrivateKeyTemplate, CKA_SIGN, ulPrivateKeyAttributeCount)) && (*keyFlag_val))
				keyGenReq->keyInfo.keyFlags |= HSE_KF_USAGE_SIGN;

			/* default flags for EdDSA key pair if none specified */
			if (keyGenReq->keyInfo.keyFlags == 0)
				keyGenReq->keyInfo.keyFlags = HSE_KF_USAGE_SIGN | HSE_KF_USAGE_VERIFY;

			/* EdDSA uses HSE_KEY_TYPE_ECC_PAIR key type */
			keyGenReq->keyInfo.keyType = HSE_KEY_TYPE_ECC_PAIR;

			keyGenReq->keyInfo.specific.eccCurveId = ecparam2curveid((char *)ecc_oid,
				(uint8_t)getattr_len(pPublicKeyTemplate, CKA_EC_PARAMS, ulPublicKeyAttributeCount));

			keyGenReq->keyInfo.keyBitLen = hse_get_ec_key_bitlen(keyGenReq->keyInfo.specific.eccCurveId);

			/* Use ECC key pair generation scheme */
			keyGenReq->keyGenScheme = HSE_KEY_GEN_ECC_KEY_PAIR;
			keyGenReq->sch.eccKey.pPubKey = 0u;

			break;
		default:

			rc = CKR_ARGUMENTS_BAD;
			goto err_free_key_intl;
	}

	if ((keyFlag_val = (CK_BBOOL *)getattr_pval(pPrivateKeyTemplate, CKA_EXTRACTABLE, ulPrivateKeyAttributeCount)) && (*keyFlag_val))
		keyGenReq->keyInfo.keyFlags |= HSE_KF_ACCESS_EXPORTABLE;

	err = hse_srv_req_sync(sCtx->sID, &srv_desc, sizeof(srv_desc), NULL);
	if (err) {
		rc = CKR_FUNCTION_FAILED;
		goto err_free_key_data;
	}

	/* private and public key are stored in the same slot in HSE */
	*phPrivateKey = key->attrs.key_handle;
	*phPublicKey = key->attrs.key_handle;

	gCtx->mtxFns.lock(tCtx->keyMtx);
	hse_key_object_write(key);
	gCtx->mtxFns.unlock(tCtx->keyMtx);

	hse_mem_free(pubExp_handle);

	return CKR_OK;

err_free_key_data:
	hse_mem_free(pubExp_handle);
err_free_key_intl:
	hse_free_dyn_attr_list(key->dyn_attrs_handle);
	hse_intl_mem_free(key_handle);
err_release_slot:
	key_slot_release(acquired_handle);
	return rc;
}

CK_DECLARE_FUNCTION(CK_RV, C_GenerateKey)(
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount,
	CK_OBJECT_HANDLE_PTR phKey
)
{
	struct globalCtx *gCtx = getCtx();
	struct tokenCtx *tCtx = getTokenCtx();
	struct sessionCtx *sCtx = getSessionCtx(hSession);
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	hseKeyGenerateSrv_t *keyGenReq = &srv_desc.hseSrv.keyGenReq;
	struct hse_keyObject *key = NULL;
	uint8_t keyType;
	CK_BBOOL *keyFlag_val = NULL;
	CK_ULONG *keyBytesLen;
	char *label = NULL;
	CK_RV rc = CKR_OK;
	int err, key_handle = -1;
	enum object_domain is_token;
	CK_BBOOL *token_attr;
	uint32_t acquired_handle = 0;
	uint32_t tweak_handle = 0;
	CK_BYTE tweak_handle_bytes[3];

	if (gCtx->cryptokiInit == CK_FALSE)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pTemplate == NULL || ulCount == 0)
		return CKR_ARGUMENTS_BAD;

	if (!sCtx || sCtx->sessionInit == CK_FALSE)
		return CKR_SESSION_HANDLE_INVALID;

	switch (pMechanism->mechanism) {
		case CKM_AES_KEY_GEN:
		case CKM_AES_XTS_KEY_GEN:
			keyType = HSE_KEY_TYPE_AES;
			break;
		case CKM_SHA_1_KEY_GEN:
		case CKM_SHA224_KEY_GEN:
		case CKM_SHA256_KEY_GEN:
		case CKM_SHA384_KEY_GEN:
		case CKM_SHA512_KEY_GEN:
		case CKM_SHA512_224_KEY_GEN:
		case CKM_SHA512_256_KEY_GEN:
			keyType = HSE_KEY_TYPE_HMAC;
			break;
		default:
			return CKR_ARGUMENTS_BAD;
	}

	if (getattr_pval(pTemplate, CKA_UNIQUE_ID, ulCount))
		return CKR_ATTRIBUTE_READ_ONLY;

	if (getattr_len(pTemplate, CKA_LABEL, ulCount) <= 0 || getattr_len(pTemplate, CKA_LABEL, ulCount) > 32)
		return CKR_ARGUMENTS_BAD;

	/* Determine obj type (token or session) */
	token_attr = (CK_BBOOL *)getattr_pval(pTemplate, CKA_TOKEN, ulCount);
	is_token = (token_attr && *token_attr == CK_TRUE) ? TOKEN_OBJ : SESSION_OBJ;

	/* Acquire slot from key ring */
	rc = key_slot_acquire(keyType, is_token, &acquired_handle);
	if (rc != CKR_OK)
		return rc;

	/* For XTS, acquire additional slot for tweak key */
	if (pMechanism->mechanism == CKM_AES_XTS_KEY_GEN) {
		rc = key_slot_acquire(HSE_KEY_TYPE_AES, is_token, &tweak_handle);
		if (rc != CKR_OK) {
			key_slot_release(acquired_handle);
			return rc;
		}
	}

	key_handle = hse_intl_mem_alloc(sizeof(*key), HSE_KEY_OBJ);
	if (key_handle < 0) {
		rc = CKR_HOST_MEMORY;
		goto err_release_slots;
	}
	key = (struct hse_keyObject *)hse_get_node_mem_addr(key_handle, true);
	memset(key, 0, sizeof(*key));

	/* key handles are unique in HSE; use them for UID */
	key->attrs.key_handle = acquired_handle;
	key->attrs.key_uid = acquired_handle;
	key->dyn_attrs_handle = -1;

	/* key class and key type */
	if (getattr_pval(pTemplate, CKA_CLASS, ulCount)) {
		key->attrs.key_class = *(CK_OBJECT_CLASS *)getattr_pval(pTemplate, CKA_CLASS, ulCount);
		if (key->attrs.key_class != CKO_SECRET_KEY) {
			rc = CKR_TEMPLATE_INCONSISTENT;
			goto err_free_key_intl;
		}
	}
	if (getattr_pval(pTemplate, CKA_KEY_TYPE, ulCount)) {
		key->attrs.key_type = *(CK_KEY_TYPE *)getattr_pval(pTemplate, CKA_KEY_TYPE, ulCount);
		if (key->attrs.key_type != CKK_AES) {
			rc = CKR_TEMPLATE_INCONSISTENT;
			goto err_free_key_intl;
		}
	}

	label = (char *)getattr_pval(pTemplate, CKA_LABEL, ulCount);
	if (label != NULL)
		memcpy(key->attrs.key_label, label, getattr_len(pTemplate, CKA_LABEL, ulCount));

	if (!(keyBytesLen = (CK_ULONG *)getattr_pval(pTemplate, CKA_VALUE_LEN, ulCount))) {
		rc = CKR_ARGUMENTS_BAD;
		goto err_free_key_intl;
	}

	rc = hse_add_dyn_attr_list(key, pTemplate, ulCount);
	if (rc)
		goto err_free_key_intl;

	srv_desc.srvId = HSE_SRV_ID_KEY_GENERATE;

	if (pMechanism->mechanism == CKM_AES_XTS_KEY_GEN) {
		/* This block handles the generation of the tweak key required by AES-XTS */

		keyGenReq->targetKeyHandle = tweak_handle;

/*
 * HSE_KF_USAGE_XTS_TWEAK flag is only supported starting with
 * HSE firmware version 2.x.x.
 * For older versions, encryption flag is used.
 */
#if HSE_FW_VERSION_MAJOR >= 2
		keyGenReq->keyInfo.keyFlags = HSE_KF_USAGE_XTS_TWEAK;
		if (keyType == HSE_KEY_TYPE_AES)
			keyGenReq->keyInfo.specific.aesBlockModeMask = 0u;
#else
		keyGenReq->keyInfo.keyFlags |= HSE_KF_USAGE_ENCRYPT;
#endif /* HSE_FW_VERSION_MAJOR >= 2 */
		keyGenReq->keyInfo.keyType = keyType;
		keyGenReq->keyInfo.keyBitLen = (uint16_t)HSE_BYTES_TO_BITS(*keyBytesLen);
		keyGenReq->keyInfo.keyCounter = 0u;
		keyGenReq->keyInfo.smrFlags = 0u;
		keyGenReq->sch.symKey = 0u;
		keyGenReq->keyGenScheme = HSE_KEY_GEN_SYM_RANDOM_KEY;

		err = hse_srv_req_sync(sCtx->sID, &srv_desc, sizeof(srv_desc), NULL);
		if (err) {
			rc = CKR_FUNCTION_FAILED;
			goto err_free_key_intl;
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
		if (rc != CKR_OK)
			goto err_free_key_intl;

		/* Reset the service descriptor for the cipher key */
		memset(&srv_desc, 0, sizeof(srv_desc));
		srv_desc.srvId = HSE_SRV_ID_KEY_GENERATE;
		keyGenReq = &srv_desc.hseSrv.keyGenReq;
	}

	keyGenReq->targetKeyHandle = key->attrs.key_handle;

	/* only AES slot keys can be used for encrypt/decrypt ops */
	if ((keyFlag_val = (CK_BBOOL *)getattr_pval(pTemplate, CKA_ENCRYPT, ulCount)) && (*keyFlag_val)) {
		if (keyType == HSE_KEY_TYPE_AES)
			keyGenReq->keyInfo.keyFlags |= HSE_KF_USAGE_ENCRYPT;
		else
			printf("WARNING: HSE HMAC key type does not support encrypt operations.\n");
	}
	if ((keyFlag_val = (CK_BBOOL *)getattr_pval(pTemplate, CKA_DECRYPT, ulCount)) && (*keyFlag_val)) {
		if (keyType == HSE_KEY_TYPE_AES)
			keyGenReq->keyInfo.keyFlags |= HSE_KF_USAGE_DECRYPT;
		else
			printf("WARNING: HSE HMAC key type does not support decrypt operations.\n");
	}
	if ((keyFlag_val = (CK_BBOOL *)getattr_pval(pTemplate, CKA_SIGN, ulCount)) && (*keyFlag_val))
		keyGenReq->keyInfo.keyFlags |= HSE_KF_USAGE_SIGN;
	if ((keyFlag_val = (CK_BBOOL *)getattr_pval(pTemplate, CKA_VERIFY, ulCount)) && (*keyFlag_val))
		keyGenReq->keyInfo.keyFlags |= HSE_KF_USAGE_VERIFY;
	if ((keyFlag_val = (CK_BBOOL *)getattr_pval(pTemplate, CKA_DERIVE, ulCount)) && (*keyFlag_val))
		keyGenReq->keyInfo.keyFlags |= HSE_KF_USAGE_DERIVE;

	/* default flags if none specified */
	if (keyGenReq->keyInfo.keyFlags == 0) {
		if (keyType == HSE_KEY_TYPE_AES)
			keyGenReq->keyInfo.keyFlags = HSE_KF_USAGE_ENCRYPT | HSE_KF_USAGE_DECRYPT | HSE_KF_USAGE_SIGN | HSE_KF_USAGE_VERIFY;
		else
			keyGenReq->keyInfo.keyFlags = HSE_KF_USAGE_SIGN | HSE_KF_USAGE_VERIFY;
	}

	keyGenReq->keyInfo.keyType = keyType;
	keyGenReq->keyInfo.keyBitLen = (uint16_t)HSE_BYTES_TO_BITS(*keyBytesLen);
#if HSE_FW_VERSION_MAJOR >= 2
	if (keyType == HSE_KEY_TYPE_AES)
		keyGenReq->keyInfo.specific.aesBlockModeMask = 0u;
#endif /* HSE_FW_VERSION_MAJOR >= 2 */
	keyGenReq->sch.symKey = 0u;
	keyGenReq->keyGenScheme = HSE_KEY_GEN_SYM_RANDOM_KEY;

	err = hse_srv_req_sync(sCtx->sID, &srv_desc, sizeof(srv_desc), NULL);
	if (err) {
		rc = CKR_FUNCTION_FAILED;
		goto err_free_key_intl;
	}

	*phKey = key->attrs.key_handle;

	gCtx->mtxFns.lock(tCtx->keyMtx);
	hse_key_object_write(key);
	gCtx->mtxFns.unlock(tCtx->keyMtx);

	return CKR_OK;

err_free_key_intl:
	hse_free_dyn_attr_list(key->dyn_attrs_handle);
	hse_intl_mem_free(key_handle);
err_release_slots:
	key_slot_release(acquired_handle);
	if (tweak_handle != 0)
		key_slot_release(tweak_handle);
	return rc;
}
