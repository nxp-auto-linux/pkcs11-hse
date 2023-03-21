// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2023 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pkcs11_context.h"
#include "simclist.h"
#include "hse-internal.h"

static uint16_t getkeybitlen(hseEccCurveId_t eccCurveId)
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

static uint8_t gethsecurveid(char *oid)
{
	if (strcmp(oid, "\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x07") == 0)
		return HSE_EC_SEC_SECP256R1;
	else if (strcmp(oid, "\x06\x05\x2B\x81\x04\x00\x22") == 0)
		return HSE_EC_SEC_SECP384R1;
	else if (strcmp(oid, "\x06\x05\x2B\x81\x04\x00\x23") == 0)
		return HSE_EC_SEC_SECP521R1;
	else if (strcmp(oid, "\x06\x09\x2B\x24\x03\x03\x02\x08\x01\x01\x07") == 0)
		return HSE_EC_BRAINPOOL_BRAINPOOLP256R1;
	else if (strcmp(oid, "\x06\x09\x2B\x24\x03\x03\x02\x08\x01\x01\x09") == 0)
		return HSE_EC_BRAINPOOL_BRAINPOOLP320R1;
	else if (strcmp(oid, "\x06\x09\x2B\x24\x03\x03\x02\x08\x01\x01\x0B") == 0)
		return HSE_EC_BRAINPOOL_BRAINPOOLP384R1;
	else if (strcmp(oid, "\x06\x09\x2B\x24\x03\x03\x02\x08\x01\x01\x0D") == 0)
		return HSE_EC_BRAINPOOL_BRAINPOOLP512R1;
	else if (strcmp(oid, "\x06\x09\x2B\x06\x01\x04\x01\xDA\x47\x0F\x01") == 0)
		return HSE_EC_25519_ED25519;
	else if (strcmp(oid, "\x06\x03\x2B\x65\x6E") == 0)
		return HSE_EC_25519_CURVE25519;
	else
		return HSE_EC_CURVE_NONE;
}

static void *getattr_pval(CK_ATTRIBUTE_PTR template,
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

static CK_ULONG getattr_len(CK_ATTRIBUTE_PTR template,
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

CK_DEFINE_FUNCTION(CK_RV, C_CreateObject)(
		CK_SESSION_HANDLE hSession,
		CK_ATTRIBUTE_PTR pTemplate,
		CK_ULONG ulCount,
		CK_OBJECT_HANDLE_PTR phObject
)
{
	struct globalCtx *gCtx = getCtx();
	struct sessionCtx *sCtx = getSessionCtx(hSession);
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	hseImportKeySrv_t *import_key_req;
	volatile hseKeyInfo_t *key_info;
	uint32_t pkey0_len, pkey1_len, pkey2_len;
	void *pkey0 = NULL, *pkey1 = NULL, *pkey2 = NULL, *ecc_oid, *ec_point;
	struct hse_keyObject *key;
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

	if (getattr_pval(pTemplate, CKA_UNIQUE_ID, ulCount))
		return CKR_ATTRIBUTE_READ_ONLY;

	/* error if id_len doesn't conform to hse expectations */
	if (getattr_len(pTemplate, CKA_ID, ulCount) > 3)
		return CKR_ARGUMENTS_BAD;

	if (getattr_len(pTemplate, CKA_LABEL, ulCount) <= 0 ||
	    getattr_len(pTemplate, CKA_LABEL, ulCount) > 32)
		return CKR_ARGUMENTS_BAD;

	key_info = (hseKeyInfo_t *)hse_mem_alloc(sizeof(hseKeyInfo_t));
	if (key_info == NULL)
		return CKR_HOST_MEMORY;
	hse_memset((void *)key_info, 0, sizeof(hseKeyInfo_t));

	key = (struct hse_keyObject *)hse_intl_mem_alloc(sizeof(struct hse_keyObject));
	if (key == NULL) {
		rc = CKR_HOST_MEMORY;
		goto err_free_key_info;
	}

	id_len = getattr_len(pTemplate, CKA_ID, ulCount);
	if (!id_len || id_len != 3)
		return CKR_ARGUMENTS_BAD;

	idtemp = (CK_BYTE *)getattr_pval(pTemplate, CKA_ID, ulCount);
	if (idtemp == NULL) {
		rc = CKR_ARGUMENTS_BAD;
		goto err_free_key_intl;
	}

	/* get key data and create key object struct */
	key->key_handle = GET_KEY_HANDLE(idtemp[2], idtemp[1], idtemp[0]);
	/* key handles are unique in HSE; use them for UID */
	key->key_uid = key->key_handle;

	if ((CK_KEY_TYPE *)getattr_pval(pTemplate, CKA_KEY_TYPE, ulCount) == NULL) {
		rc = CKR_ARGUMENTS_BAD;
		goto err_free_key_intl;
	} else {
		key->key_type = *(CK_KEY_TYPE *)getattr_pval(pTemplate, CKA_KEY_TYPE, ulCount);
	}

	if ((CK_OBJECT_CLASS *)getattr_pval(pTemplate, CKA_CLASS, ulCount) == NULL) {
		rc = CKR_ARGUMENTS_BAD;
		goto err_free_key_intl;
	} else {
		key->key_class = *(CK_OBJECT_CLASS *)getattr_pval(pTemplate, CKA_CLASS, ulCount);
	}

	/* check if key is already in nvm catalog */
	if (idtemp[2] == 1) {
		gCtx->mtxFns.lock(gCtx->keyMtx);
		if (list_seek(&gCtx->object_list, &key->key_handle) != NULL) {
			gCtx->mtxFns.unlock(gCtx->keyMtx);
			printf("ERROR: NVM Slot is already occupied.");
			printf(" The slot should be cleared, before a new key can be added\n");
			rc = CKR_ARGUMENTS_BAD;
			goto err_free_key_intl;
		}
		gCtx->mtxFns.unlock(gCtx->keyMtx);
	}

	label = (char *)getattr_pval(pTemplate, CKA_LABEL, ulCount);
	if (label != NULL) {
		memcpy(key->key_label, label, getattr_len(pTemplate, CKA_LABEL, ulCount));
	}

	key_info->keyCounter = 0;
	key_info->smrFlags = 0ul;

	import_key_req = &srv_desc.hseSrv.importKeyReq;

	srv_desc.srvId = HSE_SRV_ID_IMPORT_KEY;
	import_key_req->pKeyInfo = hse_virt_to_dma((void *)key_info);
	import_key_req->targetKeyHandle = key->key_handle;
	import_key_req->cipher.cipherKeyHandle = HSE_INVALID_KEY_HANDLE;
	import_key_req->keyContainer.authKeyHandle = HSE_INVALID_KEY_HANDLE;

	switch (key->key_type) {
		case CKK_RSA:

			pkey0_len = getattr_len(pTemplate, CKA_MODULUS, ulCount);
			if (!pkey0_len) {
				rc = CKR_ARGUMENTS_BAD;
				goto err_free_key_intl;
			}
			pkey0 = hse_mem_alloc(pkey0_len);
			if (pkey0 == NULL) {
				rc = CKR_HOST_MEMORY;
				goto err_free_key_intl;
			}
			hse_memcpy(pkey0, getattr_pval(pTemplate, CKA_MODULUS, ulCount), pkey0_len);

			pkey1_len = getattr_len(pTemplate, CKA_PUBLIC_EXPONENT, ulCount);
			if (!pkey1_len) {
				rc = CKR_ARGUMENTS_BAD;
				goto err_free_pkey0;
			}
			pkey1 = hse_mem_alloc(pkey1_len);
			if (pkey1 == NULL) {
				rc = CKR_HOST_MEMORY;
				goto err_free_pkey0;
			}
			hse_memcpy(pkey1, getattr_pval(pTemplate, CKA_PUBLIC_EXPONENT, ulCount), pkey1_len);

			/* rsa can be used for sign/verify */
			key_info->keyFlags = HSE_KF_USAGE_VERIFY | HSE_KF_USAGE_ENCRYPT;
			key_info->keyBitLen = pkey0_len * 8;
			key_info->specific.pubExponentSize = pkey1_len;
			key_info->keyType = HSE_KEY_TYPE_RSA_PUB;

			import_key_req->pKey[0] = hse_virt_to_dma(pkey0); /* public modulus */
			import_key_req->pKey[1] = hse_virt_to_dma(pkey1); /* public exponent */
			import_key_req->pKey[2] = 0u;
			import_key_req->keyLen[0] = pkey0_len;
			import_key_req->keyLen[1] = pkey1_len;
			import_key_req->keyLen[2] = 0u;

			if (key->key_class == CKO_PRIVATE_KEY) {

				pkey2_len = getattr_len(pTemplate, CKA_PRIVATE_EXPONENT, ulCount);
				if (!pkey2_len) {
					rc = CKR_ARGUMENTS_BAD;
					goto err_free_pkey1;
				}
				pkey2 = hse_mem_alloc(pkey2_len);
				if (pkey2 == NULL) {
					rc = CKR_HOST_MEMORY;
					goto err_free_pkey1;
				}
				hse_memcpy(pkey2, getattr_pval(pTemplate, CKA_PRIVATE_EXPONENT, ulCount), pkey2_len);

				key_info->keyFlags = HSE_KF_USAGE_SIGN | HSE_KF_USAGE_DECRYPT;
				key_info->keyType = HSE_KEY_TYPE_RSA_PAIR;

				import_key_req->pKey[2] = hse_virt_to_dma(pkey2); /* private exponent */
				import_key_req->keyLen[2] = pkey2_len;
			}

			break;
		case CKK_EC:

			pkey0_len = getattr_len(pTemplate, CKA_EC_POINT, ulCount);
			if (pkey0_len < 3) {
				rc = CKR_ARGUMENTS_BAD;
				goto err_free_key_intl;
			}

			/* bypass DER encoding header, we don't support it */
			pkey0_len = pkey0_len - 3;
			pkey0 = hse_mem_alloc(pkey0_len);
			if (pkey0 == NULL) {
				rc = CKR_HOST_MEMORY;
				goto err_free_key_intl;
			}
			ec_point = getattr_pval(pTemplate, CKA_EC_POINT, ulCount);
			ec_point = (uint8_t *)ec_point + 3;
			hse_memcpy(pkey0, ec_point, pkey0_len);

			ecc_oid = getattr_pval(pTemplate, CKA_EC_PARAMS, ulCount);
			if (ecc_oid == NULL) {
				rc = CKR_ARGUMENTS_BAD;
				goto err_free_pkey0;
			}

			/* ecc keys can only be used for sign/verify */
			key_info->keyFlags = HSE_KF_USAGE_VERIFY;
			key_info->specific.eccCurveId = gethsecurveid((char *)ecc_oid);
			key_info->keyBitLen = getkeybitlen(key_info->specific.eccCurveId);
			key_info->keyType = HSE_KEY_TYPE_ECC_PUB;

			import_key_req->pKey[0] = hse_virt_to_dma(pkey0); /* public x & y coords of ec */
			import_key_req->pKey[1] = 0u;
			import_key_req->pKey[2] = 0u;
			import_key_req->keyLen[0] = pkey0_len;
			import_key_req->keyLen[1] = 0u;
			import_key_req->keyLen[2] = 0u;
#if (HSE_PLATFORM == HSE_S32G3XX)
			import_key_req->keyFormat.eccKeyFormat = HSE_KEY_FORMAT_ECC_PUB_RAW;
#endif

			if (key->key_class == CKO_PRIVATE_KEY) {

				pkey2_len = getattr_len(pTemplate, CKA_VALUE, ulCount);
				if (!pkey2_len) {
					rc = CKR_ARGUMENTS_BAD;
					goto err_free_pkey0;
				}
				pkey2 = hse_mem_alloc(pkey2_len);
				if (pkey2 == NULL) {
					rc = CKR_HOST_MEMORY;
					goto err_free_pkey0;
				}
				hse_memcpy(pkey2, getattr_pval(pTemplate, CKA_VALUE, ulCount), pkey2_len);

				key_info->keyFlags |= HSE_KF_USAGE_SIGN;
				key_info->keyType = HSE_KEY_TYPE_ECC_PAIR;

				import_key_req->pKey[2] = hse_virt_to_dma(pkey2); /* ec private scalar/order */
				import_key_req->keyLen[2] = pkey2_len;
			}

			break;
		case CKK_AES:
		case CKK_SHA224_HMAC:
		case CKK_SHA256_HMAC:
		case CKK_SHA384_HMAC:
		case CKK_SHA512_HMAC:

			pkey2_len = getattr_len(pTemplate, CKA_VALUE, ulCount);
			if (!pkey2_len) {
				rc = CKR_ARGUMENTS_BAD;
				goto err_free_key_intl;
			}
			pkey2 = hse_mem_alloc(pkey2_len);
			if (pkey2 == NULL) {
				rc = CKR_HOST_MEMORY;
				goto err_free_key_intl;
			}
			hse_memcpy(pkey2, getattr_pval(pTemplate, CKA_VALUE, ulCount), pkey2_len);

			if (key->key_type == CKK_AES) {
				/* aes keys can only be used for encrypt/decrypt */
				key_info->keyFlags = (HSE_KF_USAGE_ENCRYPT | HSE_KF_USAGE_DECRYPT | HSE_KF_USAGE_SIGN | HSE_KF_USAGE_VERIFY);
				key_info->keyType = HSE_KEY_TYPE_AES;
			} else {
				/* HMAC key */
				key_info->keyFlags = (HSE_KF_USAGE_SIGN | HSE_KF_USAGE_VERIFY);
				key_info->keyType = HSE_KEY_TYPE_HMAC;
			}

			key_info->keyBitLen = pkey2_len * 8;

			import_key_req->pKey[0] = 0u;
			import_key_req->pKey[1] = 0u;
			import_key_req->pKey[2] = hse_virt_to_dma(pkey2); /* sym key */
			import_key_req->keyLen[0] = 0u;
			import_key_req->keyLen[1] = 0u;
			import_key_req->keyLen[2] = pkey2_len;

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
		goto err_free_pkey2;
	}

	gCtx->mtxFns.lock(gCtx->keyMtx);
	*phObject = key->key_handle;
	list_append(&gCtx->object_list, key);
	gCtx->mtxFns.unlock(gCtx->keyMtx);

	hse_mem_free(pkey2);
	hse_mem_free(pkey1);
	hse_mem_free(pkey0);
	hse_mem_free((void *)key_info);

	return CKR_OK;

err_free_pkey2:
	hse_mem_free(pkey2);
err_free_pkey1:
	hse_mem_free(pkey1);
err_free_pkey0:
	hse_mem_free(pkey0);
err_free_key_intl:
	hse_intl_mem_free(key);
err_free_key_info:
	hse_mem_free((void *)key_info);
	return rc;
}

CK_DEFINE_FUNCTION(CK_RV, C_DestroyObject)(
		CK_SESSION_HANDLE hSession,
		CK_OBJECT_HANDLE hObject
)
{
	struct globalCtx *gCtx = getCtx();
	struct sessionCtx *sCtx = getSessionCtx(hSession);
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	struct hse_keyObject *pkey;
	int err;

	if (gCtx->cryptokiInit == CK_FALSE)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!sCtx || sCtx->sessionInit == CK_FALSE)
		return CKR_SESSION_HANDLE_INVALID;

	gCtx->mtxFns.lock(gCtx->keyMtx);
	pkey = (struct hse_keyObject *)list_seek(&gCtx->object_list, &hObject);
	gCtx->mtxFns.unlock(gCtx->keyMtx);
	if (pkey == NULL)
		return CKR_OBJECT_HANDLE_INVALID;

	srv_desc.srvId = HSE_SRV_ID_ERASE_KEY;
	srv_desc.hseSrv.eraseKeyReq.keyHandle = pkey->key_handle;
	srv_desc.hseSrv.eraseKeyReq.eraseKeyOptions = 0u;

	gCtx->mtxFns.lock(gCtx->keyMtx);
	err = hse_srv_req_sync(sCtx->sID, &srv_desc, sizeof(srv_desc));
	gCtx->mtxFns.unlock(gCtx->keyMtx);
	if (err)
		return CKR_FUNCTION_FAILED;

	gCtx->mtxFns.lock(gCtx->keyMtx);
	if (list_delete(&gCtx->object_list, pkey) != 0) {
		gCtx->mtxFns.unlock(gCtx->keyMtx);
		return CKR_FUNCTION_FAILED;
	}
	gCtx->mtxFns.unlock(gCtx->keyMtx);

	hse_intl_mem_free(pkey);

	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsInit)(
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

	if (ulCount != 0) {
		if (pTemplate != NULL)
			sCtx->findCtx.obj_class = (CK_OBJECT_CLASS *)getattr_pval(pTemplate, CKA_CLASS, ulCount);
		else
			sCtx->findCtx.obj_class = NULL;
	}

	sCtx->findCtx.init = CK_TRUE;
	list_iterator_start(&gCtx->object_list);

	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_FindObjects)(
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
	int i;

	if (gCtx->cryptokiInit == CK_FALSE)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!sCtx || sCtx->sessionInit == CK_FALSE)
		return CKR_SESSION_HANDLE_INVALID;

	if (sCtx->findCtx.init == CK_FALSE)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (phObject == NULL || ulMaxObjectCount == 0 || pulObjectCount == NULL)
		return CKR_ARGUMENTS_BAD;

	if (!list_iterator_hasnext(&gCtx->object_list)) {
		*pulObjectCount = 0;
		return CKR_OK;
	}

	finder = &sCtx->findCtx;
	i = 0;
	do {
		key = (struct hse_keyObject *)list_iterator_next(&gCtx->object_list);

		if (finder->obj_class == NULL || key->key_class == *finder->obj_class) {
			phObject[i] = key->key_handle;
			i++;
		}

		if (i >= ulMaxObjectCount)
			break;
	} while (list_iterator_hasnext(&gCtx->object_list));

	*pulObjectCount = i;

	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsFinal)(
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
	list_iterator_stop(&gCtx->object_list);

	return CKR_OK;
}
