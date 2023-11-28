// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <libhse.h>

#include "hse_interface.h"
#include "simclist.h"
#include "pkcs11.h"
#include "pkcs11_context.h"
#include "pkcs11_util.h"
#include "hse-internal.h"

CK_DEFINE_FUNCTION(CK_RV, C_GenerateKeyPair)(
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
	struct sessionCtx *sCtx = getSessionCtx(hSession);
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	hseKeyGenerateSrv_t *keyGenReq = &srv_desc.hseSrv.keyGenReq;
	struct hse_keyObject *key = NULL;
	CK_OBJECT_HANDLE obj;
	CK_BBOOL obj_found = CK_FALSE;
	uint8_t *hse_pubExp = NULL;
	uint16_t *keyBitsLen;
	void *ecc_oid, *pubExp;
	CK_BYTE *idtemp;
	CK_BYTE default_pubExp[] = { 0x01, 0x00, 0x01};
	CK_ULONG id_len, pubExpLen;
	CK_BBOOL *keyFlag_val;
	char *label = NULL;
	CK_RV rc = CKR_OK;
	int err;

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

	/* error if id_len doesn't conform to hse expectations */
	if (getattr_len(pPrivateKeyTemplate, CKA_ID, ulPrivateKeyAttributeCount) > 3)
		return CKR_ARGUMENTS_BAD;

	id_len = getattr_len(pPrivateKeyTemplate, CKA_ID, ulPrivateKeyAttributeCount);
	if (!id_len || id_len != 3)
		return CKR_TEMPLATE_INCONSISTENT;

	idtemp = (CK_BYTE *)getattr_pval(pPrivateKeyTemplate, CKA_ID, ulPrivateKeyAttributeCount);
	if (idtemp == NULL)
			return CKR_TEMPLATE_INCONSISTENT;

	obj = GET_KEY_HANDLE(idtemp[2], idtemp[1], idtemp[0]);

	gCtx->mtxFns.lock(gCtx->keyMtx);
	key = (struct hse_keyObject *)list_seek(&gCtx->object_list, &obj);
	gCtx->mtxFns.unlock(gCtx->keyMtx);
	if (!key) {
		key = (struct hse_keyObject *)hse_intl_mem_alloc(sizeof(struct hse_keyObject));
		if (!key)
			return CKR_HOST_MEMORY;
	} else if (idtemp[2] == HSE_KEY_CATALOG_ID_NVM) {
		printf("ERROR: NVM Slot is already occupied."
				" The slot should be cleared, before a new key can be added\n");
		return CKR_ARGUMENTS_BAD;
	} else {
		obj_found = CK_TRUE;
	}

	hse_memset(key, 0x0, sizeof(struct hse_keyObject));
	/* key handles are unique in HSE; use them for UID */
	key->key_handle = obj;
	key->key_uid = obj;

	label = (char *)getattr_pval(pPrivateKeyTemplate, CKA_LABEL, ulPrivateKeyAttributeCount);
	if (label != NULL) {
        if (getattr_len(pPrivateKeyTemplate, CKA_LABEL, ulPrivateKeyAttributeCount) <= 0 ||
	        getattr_len(pPrivateKeyTemplate, CKA_LABEL, ulPrivateKeyAttributeCount) > MAX_LABEL_LEN) {
		    rc = CKR_ARGUMENTS_BAD;
            goto err_free_key_intl;
        }

		hse_memcpy(key->key_label, label, getattr_len(pPrivateKeyTemplate, CKA_LABEL, ulPrivateKeyAttributeCount));
	}

	/* key class and key type */
	if (getattr_pval(pPrivateKeyTemplate, CKA_CLASS, ulPrivateKeyAttributeCount))
		key->key_class = *(CK_OBJECT_CLASS *)getattr_pval(pPrivateKeyTemplate, CKA_CLASS, ulPrivateKeyAttributeCount);
	if (getattr_pval(pPrivateKeyTemplate, CKA_KEY_TYPE, ulPrivateKeyAttributeCount))
		key->key_type = *(CK_KEY_TYPE *)getattr_pval(pPrivateKeyTemplate, CKA_KEY_TYPE, ulPrivateKeyAttributeCount);

	srv_desc.srvId = HSE_SRV_ID_KEY_GENERATE;
	keyGenReq->targetKeyHandle = key->key_handle;
	keyGenReq->keyInfo.keyCounter = 0u;
	keyGenReq->keyInfo.smrFlags = 0u;

	switch (pMechanism->mechanism) {
		case CKM_RSA_PKCS_KEY_PAIR_GEN:

			if ((getattr_pval(pPrivateKeyTemplate, CKA_KEY_TYPE, ulPrivateKeyAttributeCount)) &&
				(key->key_type != CKK_RSA)) {
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

			hse_pubExp = hse_mem_alloc(pubExpLen);
			if (!hse_pubExp) {
				rc = CKR_HOST_MEMORY;
				goto err_free_key_intl;
			}
			hse_memcpy(hse_pubExp, pubExp, pubExpLen);

			if ((keyFlag_val = (CK_BBOOL *)getattr_pval(pPublicKeyTemplate, CKA_ENCRYPT, ulPublicKeyAttributeCount)) && (*keyFlag_val))
				keyGenReq->keyInfo.keyFlags |= HSE_KF_USAGE_ENCRYPT;
			if ((keyFlag_val = (CK_BBOOL *)getattr_pval(pPublicKeyTemplate, CKA_VERIFY, ulPublicKeyAttributeCount)) && (*keyFlag_val))
				keyGenReq->keyInfo.keyFlags |= HSE_KF_USAGE_VERIFY;

			if ((keyFlag_val = (CK_BBOOL *)getattr_pval(pPrivateKeyTemplate, CKA_DECRYPT, ulPrivateKeyAttributeCount)) && (*keyFlag_val))
				keyGenReq->keyInfo.keyFlags |= HSE_KF_USAGE_DECRYPT;
			if ((keyFlag_val = (CK_BBOOL *)getattr_pval(pPrivateKeyTemplate, CKA_SIGN, ulPrivateKeyAttributeCount)) && (*keyFlag_val))
				keyGenReq->keyInfo.keyFlags |= HSE_KF_USAGE_SIGN;

			keyGenReq->keyInfo.keyFlags |= HSE_KF_ACCESS_EXPORTABLE;

			keyGenReq->keyInfo.keyType = HSE_KEY_TYPE_RSA_PAIR;
			keyGenReq->keyInfo.keyBitLen = *keyBitsLen;
			keyGenReq->keyInfo.specific.pubExponentSize = pubExpLen;
			keyGenReq->keyGenScheme = HSE_KEY_GEN_RSA_KEY_PAIR;
			keyGenReq->sch.rsaKey.pubExpLength = pubExpLen;
			keyGenReq->sch.rsaKey.pPubExp = hse_virt_to_dma((void *)hse_pubExp);
			keyGenReq->sch.rsaKey.pModulus = 0u;
			break;
		case CKM_EC_KEY_PAIR_GEN:

			ecc_oid = getattr_pval(pPublicKeyTemplate, CKA_EC_PARAMS, ulPublicKeyAttributeCount);
			if (!ecc_oid) {
				rc = CKR_ARGUMENTS_BAD;
				goto err_free_key_intl;
			}

			if ((keyFlag_val = (CK_BBOOL *)getattr_pval(pPublicKeyTemplate, CKA_VERIFY, ulPublicKeyAttributeCount)) && (*keyFlag_val))
				keyGenReq->keyInfo.keyFlags |= HSE_KF_USAGE_VERIFY;
			if ((keyFlag_val = (CK_BBOOL *)getattr_pval(pPrivateKeyTemplate, CKA_SIGN, ulPrivateKeyAttributeCount)) && (*keyFlag_val))
				keyGenReq->keyInfo.keyFlags |= HSE_KF_USAGE_SIGN;

			keyGenReq->keyInfo.keyFlags |= HSE_KF_ACCESS_EXPORTABLE;

			keyGenReq->keyInfo.keyType = HSE_KEY_TYPE_ECC_PAIR;
			keyGenReq->keyInfo.specific.eccCurveId = ecparam2curveid((char *)ecc_oid,
				(uint8_t)getattr_len(pPublicKeyTemplate, CKA_EC_PARAMS, ulPublicKeyAttributeCount));
			keyGenReq->keyInfo.keyBitLen = hse_get_ec_key_bitlen(keyGenReq->keyInfo.specific.eccCurveId);
			keyGenReq->keyGenScheme = HSE_KEY_GEN_ECC_KEY_PAIR;
			keyGenReq->sch.eccKey.pPubKey = 0u;
			break;
		default:

			rc = CKR_ARGUMENTS_BAD;
			goto err_free_key_intl;
	}

	gCtx->mtxFns.lock(gCtx->keyMtx);
	err = hse_srv_req_sync(sCtx->sID, &srv_desc, sizeof(srv_desc));
	gCtx->mtxFns.unlock(gCtx->keyMtx);
	if (err) {
		rc = CKR_FUNCTION_FAILED;
		goto err_free_key_data;
	}

	gCtx->mtxFns.lock(gCtx->keyMtx);
	/* private and public key are stored in the same slot in HSE */
	*phPrivateKey = key->key_handle;
	*phPublicKey = key->key_handle;
	/* append object to list if not already found */
	if (obj_found == CK_FALSE)
		list_append(&gCtx->object_list, key);
	gCtx->mtxFns.unlock(gCtx->keyMtx);

	hse_mem_free(hse_pubExp);

	return CKR_OK;

err_free_key_data:
	hse_mem_free(hse_pubExp);
err_free_key_intl:
	hse_intl_mem_free(key);
	return rc;
}

CK_DEFINE_FUNCTION(CK_RV, C_GenerateKey)(
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount,
	CK_OBJECT_HANDLE_PTR phKey
)
{
	struct globalCtx *gCtx = getCtx();
	struct sessionCtx *sCtx = getSessionCtx(hSession);
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	hseKeyGenerateSrv_t *keyGenReq = &srv_desc.hseSrv.keyGenReq;;
	struct hse_keyObject *key = NULL;
	CK_OBJECT_HANDLE obj;
	CK_BBOOL obj_found = CK_FALSE;
	CK_BBOOL *keyFlag_val = NULL;
	uint16_t *keyBitsLen;
	CK_BYTE *idtemp;
	CK_ULONG id_len;
	char *label = NULL;
	CK_RV rc = CKR_OK;
	int err;

	if (gCtx->cryptokiInit == CK_FALSE)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pTemplate == NULL || ulCount == 0)
		return CKR_ARGUMENTS_BAD;

	if (!sCtx || sCtx->sessionInit == CK_FALSE)
		return CKR_SESSION_HANDLE_INVALID;

	if (pMechanism->mechanism != CKM_AES_KEY_GEN)
		return CKR_ARGUMENTS_BAD;

	if (getattr_pval(pTemplate, CKA_UNIQUE_ID, ulCount))
		return CKR_ATTRIBUTE_READ_ONLY;

	/* error if id_len doesn't conform to hse expectations */
	if (getattr_len(pTemplate, CKA_ID, ulCount) > 3)
		return CKR_ARGUMENTS_BAD;

	if (getattr_len(pTemplate, CKA_LABEL, ulCount) <= 0 || getattr_len(pTemplate, CKA_LABEL, ulCount) > 32)
		return CKR_ARGUMENTS_BAD;

	id_len = getattr_len(pTemplate, CKA_ID, ulCount);
	if (!id_len || id_len != 3)
		return CKR_TEMPLATE_INCONSISTENT;

	idtemp = (CK_BYTE *)getattr_pval(pTemplate, CKA_ID, ulCount);
	if (idtemp == NULL)
		return CKR_TEMPLATE_INCONSISTENT;

	obj = GET_KEY_HANDLE(idtemp[2], idtemp[1], idtemp[0]);

	gCtx->mtxFns.lock(gCtx->keyMtx);
	key = (struct hse_keyObject *)list_seek(&gCtx->object_list, &obj);
	gCtx->mtxFns.unlock(gCtx->keyMtx);
	if (!key) {
		key = (struct hse_keyObject *)hse_intl_mem_alloc(sizeof(struct hse_keyObject));
		if (!key)
			return CKR_HOST_MEMORY;
	} else if (idtemp[2] == HSE_KEY_CATALOG_ID_NVM) {
		printf("ERROR: NVM Slot is already occupied."
				" The slot should be cleared, before a new key can be added\n");
		return CKR_ARGUMENTS_BAD;
	} else {
		obj_found = CK_TRUE;
	}

	hse_memset(key, 0x0, sizeof(struct hse_keyObject));

	/* key handles are unique in HSE; use them for UID */
	key->key_handle = obj;
	key->key_uid = obj;

	/* key class and key type */
	if (getattr_pval(pTemplate, CKA_CLASS, ulCount)) {
		key->key_class = *(CK_OBJECT_CLASS *)getattr_pval(pTemplate, CKA_CLASS, ulCount);
		if (key->key_class != CKO_SECRET_KEY) {
			rc = CKR_TEMPLATE_INCONSISTENT;
			goto err_free_key_intl;
		}
	}
	if (getattr_pval(pTemplate, CKA_KEY_TYPE, ulCount)) {
		key->key_type = *(CK_KEY_TYPE *)getattr_pval(pTemplate, CKA_KEY_TYPE, ulCount);
		if (key->key_type != CKK_AES) {
			rc = CKR_TEMPLATE_INCONSISTENT;
			goto err_free_key_intl;
		}
	}

	label = (char *)getattr_pval(pTemplate, CKA_LABEL, ulCount);
	if (label != NULL) {
		hse_memcpy(key->key_label, label, getattr_len(pTemplate, CKA_LABEL, ulCount));
	}

	if (!(keyBitsLen = (uint16_t *)getattr_pval(pTemplate, CKA_VALUE_BITS, ulCount))) {
		rc = CKR_ARGUMENTS_BAD;
		goto err_free_key_intl;
	}

	srv_desc.srvId = HSE_SRV_ID_KEY_GENERATE;
	keyGenReq->targetKeyHandle = key->key_handle;
	keyGenReq->keyInfo.keyCounter = 0u;
	keyGenReq->keyInfo.smrFlags = 0u;

	if ((keyFlag_val = (CK_BBOOL *)getattr_pval(pTemplate, CKA_ENCRYPT, ulCount)) && (*keyFlag_val))
		keyGenReq->keyInfo.keyFlags |= HSE_KF_USAGE_ENCRYPT;
	if ((keyFlag_val = (CK_BBOOL *)getattr_pval(pTemplate, CKA_DECRYPT, ulCount)) && (*keyFlag_val))
		keyGenReq->keyInfo.keyFlags |= HSE_KF_USAGE_DECRYPT;
	if ((keyFlag_val = (CK_BBOOL *)getattr_pval(pTemplate, CKA_SIGN, ulCount)) && (*keyFlag_val))
		keyGenReq->keyInfo.keyFlags |= HSE_KF_USAGE_SIGN;
	if ((keyFlag_val = (CK_BBOOL *)getattr_pval(pTemplate, CKA_VERIFY, ulCount)) && (*keyFlag_val))
		keyGenReq->keyInfo.keyFlags |= HSE_KF_USAGE_VERIFY;

	keyGenReq->keyInfo.keyType = HSE_KEY_TYPE_AES;
	keyGenReq->keyInfo.keyBitLen = *keyBitsLen;
#if (HSE_PLATFORM == HSE_S32G3XX)
	keyGenReq->keyInfo.specific.aesBlockModeMask = 0u;
#endif
	keyGenReq->sch.symKey = 0u;
	keyGenReq->keyGenScheme = HSE_KEY_GEN_SYM_RANDOM_KEY;

	gCtx->mtxFns.lock(gCtx->keyMtx);
	err = hse_srv_req_sync(sCtx->sID, &srv_desc, sizeof(srv_desc));
	gCtx->mtxFns.unlock(gCtx->keyMtx);
	if (err) {
		rc = CKR_FUNCTION_FAILED;
		goto err_free_key_intl;
	}

	gCtx->mtxFns.lock(gCtx->keyMtx);
	*phKey = key->key_handle;
	/* append object to list if not already found */
	if (obj_found == CK_FALSE)
		list_append(&gCtx->object_list, key);
	gCtx->mtxFns.unlock(gCtx->keyMtx);

	return CKR_OK;

err_free_key_intl:
	hse_intl_mem_free(key);
	return rc;
}