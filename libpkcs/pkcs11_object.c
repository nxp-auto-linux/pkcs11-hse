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
#include "pkcs11_util.h"

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
	CK_OBJECT_HANDLE search_obj;
	CK_BBOOL obj_found = CK_FALSE;
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

	if (getattr_len(pTemplate, CKA_LABEL, ulCount) <= 0 ||
	    getattr_len(pTemplate, CKA_LABEL, ulCount) > MAX_LABEL_LEN)
		return CKR_ARGUMENTS_BAD;

	key_info = (hseKeyInfo_t *)hse_mem_alloc(sizeof(hseKeyInfo_t));
	if (key_info == NULL)
		return CKR_HOST_MEMORY;
	hse_memset((void *)key_info, 0, sizeof(hseKeyInfo_t));

	/* error if id_len doesn't conform to hse expectations */
	id_len = getattr_len(pTemplate, CKA_ID, ulCount);
	if (!id_len || id_len != 3) {
		return CKR_ARGUMENTS_BAD;
		goto err_free_key_info;
	}

	idtemp = (CK_BYTE *)getattr_pval(pTemplate, CKA_ID, ulCount);
	if (idtemp == NULL) {
		rc = CKR_ARGUMENTS_BAD;
		goto err_free_key_info;
	}

	search_obj = GET_KEY_HANDLE(idtemp[2], idtemp[1], idtemp[0]);
	gCtx->mtxFns.lock(gCtx->keyMtx);
	key = (struct hse_keyObject *)list_seek(&gCtx->object_list, &search_obj);
	gCtx->mtxFns.unlock(gCtx->keyMtx);
	if (!key) {
		key = (struct hse_keyObject *)hse_intl_mem_alloc(sizeof(struct hse_keyObject));
		if (!key) {
			rc = CKR_HOST_MEMORY;
			goto err_free_key_info;
		}
	} else if (idtemp[2] == HSE_KEY_CATALOG_ID_NVM) {
		printf("ERROR: NVM Slot is already occupied.");
		printf(" The slot should be cleared, before a new key can be added\n");
		rc = CKR_ARGUMENTS_BAD;
		goto err_free_key_info;
	} else obj_found = CK_TRUE;

	/* get key handle for CKA_ID */
	key->key_handle = search_obj;

	/* key handles are unique in HSE; use them for UID */
	key->key_uid = key->key_handle;

	if ((CK_KEY_TYPE *)getattr_pval(pTemplate, CKA_KEY_TYPE, ulCount) == NULL) {
		rc = CKR_ARGUMENTS_BAD;
		goto err_free_key_intl;
	} else {
		key->key_type = *(CK_KEY_TYPE *)getattr_pval(pTemplate, CKA_KEY_TYPE, ulCount);
	}

	/* if key is not RSA or EC, it cannot be either private or public, so object class is optional */
	if (((CK_OBJECT_CLASS *)getattr_pval(pTemplate, CKA_CLASS, ulCount) == NULL) &&
	    (key->key_type == CKK_RSA || key->key_type == CKK_EC)) {
		rc = CKR_ARGUMENTS_BAD;
		goto err_free_key_intl;
	} else if (getattr_pval(pTemplate, CKA_CLASS, ulCount)) {
		key->key_class = *(CK_OBJECT_CLASS *)getattr_pval(pTemplate, CKA_CLASS, ulCount);
	} else {
		key->key_class = CK_UNAVAILABLE_INFORMATION;
	}

	hse_memset(key->key_label, 0, MAX_LABEL_LEN);
	label = (char *)getattr_pval(pTemplate, CKA_LABEL, ulCount);
	if (label != NULL) {
		hse_memcpy(key->key_label, label, getattr_len(pTemplate, CKA_LABEL, ulCount));
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
			key_info->keyFlags = HSE_KF_USAGE_VERIFY | HSE_KF_USAGE_ENCRYPT | HSE_KF_ACCESS_EXPORTABLE;
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

				key_info->keyFlags = HSE_KF_USAGE_SIGN | HSE_KF_USAGE_DECRYPT | HSE_KF_ACCESS_EXPORTABLE;
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
			key_info->keyFlags = HSE_KF_USAGE_VERIFY | HSE_KF_ACCESS_EXPORTABLE;
			key_info->specific.eccCurveId = ecparam2curveid((char *)ecc_oid, 
							(uint8_t)getattr_len(pTemplate, CKA_EC_PARAMS, ulCount));
			key_info->keyBitLen = hse_get_ec_key_bitlen(key_info->specific.eccCurveId);
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
	/* append object to list if not already found */
	if (obj_found == CK_FALSE)
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

	if (ulCount > 0 && !pTemplate)
		return CKR_ARGUMENTS_BAD;

	if (ulCount > 0 && pTemplate) {
		sCtx->findCtx.obj_class = (CK_OBJECT_CLASS *)getattr_pval(pTemplate, CKA_CLASS, ulCount);
		sCtx->findCtx.obj_uid = (CK_ULONG *)getattr_pval(pTemplate, CKA_UNIQUE_ID, ulCount);
		sCtx->findCtx.label = (CK_UTF8CHAR *)getattr_pval(pTemplate, CKA_LABEL, ulCount);
		if (getattr_len(pTemplate, CKA_ID, ulCount) == 3)
			sCtx->findCtx.key_id = (CK_BYTE *)getattr_pval(pTemplate, CKA_ID, ulCount);
		else 
			sCtx->findCtx.key_id = NULL;
	} else {
		sCtx->findCtx.obj_class = NULL;
		sCtx->findCtx.obj_uid = NULL;
		sCtx->findCtx.label = NULL;
		sCtx->findCtx.key_id = NULL;
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
	CK_BYTE *key_id;

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

		/* either ALL attributes match, or no attributes match (empty template -> return all) */
		if (finder->obj_class && key->key_class != *finder->obj_class)
			continue;
		if(finder->obj_uid && key->key_uid != *finder->obj_uid)
			continue;

		if ((finder->label != NULL) && (strcmp(key->key_label, (const char *)finder->label)))
				continue;
		
		if (finder->key_id != NULL) {
			key_id = finder->key_id;
			if (GET_KEY_HANDLE(key_id[2], key_id[1], key_id[0]) != key->key_uid)
				continue;
		}

		/* found a match */
		phObject[i] = key->key_handle;
		i++;

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
