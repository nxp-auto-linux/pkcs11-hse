// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2025 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pkcs11_context.h"
#include "hse-internal.h"
#include "pkcs11_util.h"


int is_valid_key_length(CK_KEY_TYPE type, uint32_t key_bit_len) {
	switch (type) {
		case CKK_RSA:
			return !(key_bit_len < HSE_MIN_RSA_KEY_BITS_LEN || key_bit_len > HSE_MAX_RSA_KEY_BITS_LEN);
		case CKK_EC:
			return !(key_bit_len < HSE_MIN_ECC_KEY_BITS_LEN || key_bit_len > HSE_MAX_ECC_KEY_BITS_LEN);
		case CKK_AES_XTS:
			return (key_bit_len == 256 || key_bit_len == 512);
		case CKK_AES:
			return (key_bit_len == 128 || key_bit_len == 192 || key_bit_len == 256);
		case CKK_SHA_1_HMAC:
		case CKK_SHA224_HMAC:
		case CKK_SHA256_HMAC:
			return !(key_bit_len < HSE_MIN_HMAC_KEY_BITS_LEN ||
					(key_bit_len > HSE_MAX_HMAC_KEY_BITS_LEN && key_bit_len < HSE_BYTES_TO_BITS(SHA256_BLOCK_SIZE)));
		case CKK_SHA384_HMAC:
		case CKK_SHA512_HMAC:
			return !(key_bit_len < HSE_MIN_HMAC_KEY_BITS_LEN ||
					(key_bit_len > HSE_MAX_HMAC_KEY_BITS_LEN && key_bit_len < HSE_BYTES_TO_BITS(SHA512_BLOCK_SIZE)));
		default:
			return 0;
	}
}

CK_DECLARE_FUNCTION(CK_RV, C_CreateObject)(
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
	hseKeyInfo_t key_info;
	uint32_t pkey0_len, pkey1_len, pkey2_len;
	void *ecc_oid, *ec_point;
	struct hse_keyObject *key;
	CK_BYTE *idtemp;
	CK_ULONG id_len;
	CK_OBJECT_HANDLE search_obj;
	char *label = NULL;
	CK_RV rc = CKR_OK;
	int err, key_info_handle = -1, key_handle = -1;
	int pkey0_handle = -1, pkey1_handle = -1, pkey2_handle = -1;
	uint32_t key_bit_len;

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

	key_info_handle = hse_mem_alloc(sizeof(key_info));
	if (key_info_handle < 0)
		return CKR_HOST_MEMORY;
	hse_memset(key_info_handle, 0, sizeof(key_info), 0);

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
	key_handle = get_key_object_handle(search_obj);
	gCtx->mtxFns.unlock(gCtx->keyMtx);
	if (key_handle < 0) {
		key_handle = hse_intl_mem_alloc(sizeof(*key), HSE_KEY_OBJ);
		if (key_handle < 0) {
			rc = CKR_HOST_MEMORY;
			goto err_free_key_info;
		}
	} else if (idtemp[2] == HSE_KEY_CATALOG_ID_NVM) {
		printf("ERROR: NVM Slot is already occupied.");
		printf(" The slot should be cleared, before a new key can be added\n");
		rc = CKR_ARGUMENTS_BAD;
		goto err_free_key_info;
	}
	key = (struct hse_keyObject *)hse_get_node_mem_addr(key_handle, true);

	/* get key handle for CKA_ID */
	key->attrs.key_handle = search_obj;

	/* key handles are unique in HSE; use them for UID */
	key->attrs.key_uid = key->attrs.key_handle;
	key->dyn_attrs_handle = -1;

	if ((CK_KEY_TYPE *)getattr_pval(pTemplate, CKA_KEY_TYPE, ulCount) == NULL) {
		rc = CKR_ARGUMENTS_BAD;
		goto err_free_key_intl;
	} else {
		key->attrs.key_type = *(CK_KEY_TYPE *)getattr_pval(pTemplate, CKA_KEY_TYPE, ulCount);
	}

	/* if key is not RSA or EC, it cannot be either private or public, so object class is optional */
	if (((CK_OBJECT_CLASS *)getattr_pval(pTemplate, CKA_CLASS, ulCount) == NULL) &&
	    (key->attrs.key_type == CKK_RSA || key->attrs.key_type == CKK_EC)) {
		rc = CKR_ARGUMENTS_BAD;
		goto err_free_key_intl;
	} else if (getattr_pval(pTemplate, CKA_CLASS, ulCount)) {
		key->attrs.key_class = *(CK_OBJECT_CLASS *)getattr_pval(pTemplate, CKA_CLASS, ulCount);
	} else {
		key->attrs.key_class = CK_UNAVAILABLE_INFORMATION;
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

			/* rsa can be used for sign/verify */
			key_info.keyFlags = HSE_KF_USAGE_VERIFY | HSE_KF_USAGE_ENCRYPT | HSE_KF_ACCESS_EXPORTABLE;
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

				key_info.keyFlags = HSE_KF_USAGE_SIGN | HSE_KF_USAGE_DECRYPT | HSE_KF_ACCESS_EXPORTABLE;
				key_info.keyType = HSE_KEY_TYPE_RSA_PAIR;

				import_key_req->pKey[2] = hse_virt_to_dma(pkey2_handle, 0); /* private exponent */
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

			/* ecc keys can only be used for sign/verify */
			key_info.keyFlags = HSE_KF_USAGE_VERIFY | HSE_KF_ACCESS_EXPORTABLE;
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

				key_info.keyFlags |= HSE_KF_USAGE_SIGN;
				key_info.keyType = HSE_KEY_TYPE_ECC_PAIR;

				import_key_req->pKey[2] = hse_virt_to_dma(pkey2_handle, 0); /* ec private scalar/order */
				import_key_req->keyLen[2] = pkey2_len;
			}

			break;
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
			pkey2_handle = hse_mem_alloc(pkey2_len);
			if (pkey2_handle < 0) {
				rc = CKR_HOST_MEMORY;
				goto err_free_key_intl;
			}
			hse_memcpy_to_dev(pkey2_handle, getattr_pval(pTemplate, CKA_VALUE, ulCount), pkey2_len, 0);

			if (key->attrs.key_type == CKK_AES) {
				/* aes keys can only be used for encrypt/decrypt */
				key_info.keyFlags = (HSE_KF_USAGE_ENCRYPT | HSE_KF_USAGE_DECRYPT | HSE_KF_USAGE_SIGN | HSE_KF_USAGE_VERIFY);
				key_info.keyType = HSE_KEY_TYPE_AES;
			} else {
				/* HMAC key */
				key_info.keyFlags = (HSE_KF_USAGE_SIGN | HSE_KF_USAGE_VERIFY);
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

	gCtx->mtxFns.lock(gCtx->keyMtx);
	hse_key_object_write(key);
	*phObject = key->attrs.key_handle;
	gCtx->mtxFns.unlock(gCtx->keyMtx);

	hse_mem_free(pkey2_handle);
	hse_mem_free(pkey1_handle);
	hse_mem_free(pkey0_handle);
	hse_mem_free(key_info_handle);

	return CKR_OK;

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
	return rc;
}

CK_DECLARE_FUNCTION(CK_RV, C_DestroyObject)(
		CK_SESSION_HANDLE hSession,
		CK_OBJECT_HANDLE hObject
)
{
	struct globalCtx *gCtx = getCtx();
	struct sessionCtx *sCtx = getSessionCtx(hSession);
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	struct hse_keyObject *pkey;
	int err, key_handle;

	if (gCtx->cryptokiInit == CK_FALSE)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!sCtx || sCtx->sessionInit == CK_FALSE)
		return CKR_SESSION_HANDLE_INVALID;

	gCtx->mtxFns.lock(gCtx->keyMtx);
	key_handle = get_key_object_handle(hObject);
	gCtx->mtxFns.unlock(gCtx->keyMtx);
	if (key_handle < 0)
		return CKR_OBJECT_HANDLE_INVALID;
	pkey = (struct hse_keyObject *)hse_get_node_mem_addr(key_handle, true);

	srv_desc.srvId = HSE_SRV_ID_ERASE_KEY;
	srv_desc.hseSrv.eraseKeyReq.keyHandle = pkey->attrs.key_handle;
	srv_desc.hseSrv.eraseKeyReq.eraseKeyOptions = 0u;

	err = hse_srv_req_sync(sCtx->sID, &srv_desc, sizeof(srv_desc), NULL);
	if (err)
		return CKR_FUNCTION_FAILED;

	gCtx->mtxFns.lock(gCtx->keyMtx);
	hse_key_object_remove(pkey);
	hse_intl_mem_free(key_handle);
	gCtx->mtxFns.unlock(gCtx->keyMtx);

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
		sCtx->findCtx.obj_uid = (CK_ULONG *)getattr_pval(pTemplate, CKA_UNIQUE_ID, ulCount);
		sCtx->findCtx.label = (CK_UTF8CHAR *)getattr_pval(pTemplate, CKA_LABEL, ulCount);
		if (getattr_len(pTemplate, CKA_ID, ulCount) == 3)
			sCtx->findCtx.key_id = (CK_BYTE *)getattr_pval(pTemplate, CKA_ID, ulCount);
		else 
			sCtx->findCtx.key_id = NULL;
		sCtx->findCtx.search_template = pTemplate;
	} else {
		sCtx->findCtx.obj_class = NULL;
		sCtx->findCtx.obj_uid = NULL;
		sCtx->findCtx.label = NULL;
		sCtx->findCtx.key_id = NULL;
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
	CK_BYTE *key_id;

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

		if(finder->obj_uid && key->attrs.key_uid != *finder->obj_uid)
			continue;
		else if (finder->obj_uid)
			found++;

		if (finder->label && (strcmp(key->attrs.key_label, (const char *)finder->label)))
			continue;
		else if (finder->label)
			found++;
		
		if (finder->key_id) {
			key_id = finder->key_id;
			if (GET_KEY_HANDLE(key_id[2], key_id[1], key_id[0]) != key->attrs.key_uid)
				continue;
			else
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
