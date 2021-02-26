// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021 NXP
 */

#include <stdio.h>
#include <stdlib.h>

#include "pkcs11_context.h"
#include "simclist.h"

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

	return -1;
}

static inline void memcpy(void *dst, void *src, size_t n)
{
	uint8_t *s = (uint8_t *)src;
	uint8_t *d = (uint8_t *)dst;

	if (!dst || !src || n == 0)
		return;

	for (int i = 0; i < n; i++)
		d[i] = s[i];
}

static int attrcpy(void *dest, CK_ATTRIBUTE_PTR template,
		CK_ATTRIBUTE_TYPE attr,
		CK_ULONG attrCount)
{
	void *temp;
	CK_ULONG temp_size;

	temp_size = getattr_len(template, attr, attrCount);
	temp = getattr_pval(template, attr, attrCount);
	if (temp == NULL)
		return 1;

	memcpy(dest, temp, temp_size);

	return 0;
}

CK_DEFINE_FUNCTION(CK_RV, C_CreateObject)(
		CK_SESSION_HANDLE hSession,
		CK_ATTRIBUTE_PTR pTemplate,
		CK_ULONG ulCount,
		CK_OBJECT_HANDLE_PTR phObject
)
{
	void *key_info_sram;
	hseKeyInfo_t key_info;

	void *srv_desc_sram;
	hseSrvDescriptor_t srv_desc;

	CK_UTF8CHAR *labeltemp;
	CK_BYTE *idtemp;
	void *mod, *pub_exp, *priv_exp;

	struct hse_keyObject *key;
	hseImportKeySrv_t *import_key_req;
	int err;
	CK_RV rc = CKR_OK;

	if (gCtx.cryptokiInit == CK_FALSE) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto gen_err;
	}

	if (pTemplate == NULL || ulCount == 0) {
		rc = CKR_ARGUMENTS_BAD;
		goto gen_err;
	}

	if (hSession != SESSION_ID) {
		rc = CKR_SESSION_HANDLE_INVALID;
		goto gen_err;
	}

	srv_desc_sram = hse_get_shared_mem_addr(HSE_SRV_DESC_SRAM);
	key_info_sram = hse_get_shared_mem_addr(HSE_KEY_INFO_SRAM);
	mod = hse_get_shared_mem_addr(HSE_MODULUS_SRAM);
	pub_exp = hse_get_shared_mem_addr(HSE_PUB_EXP_SRAM);
	priv_exp = hse_get_shared_mem_addr(HSE_PRIV_EXP_SRAM);

	if (attrcpy(mod, pTemplate, CKA_MODULUS, ulCount)) {
		rc = CKR_ARGUMENTS_BAD;
		goto gen_err;
	}
	if (attrcpy(pub_exp, pTemplate, CKA_PUBLIC_EXPONENT, ulCount)) {
		rc = CKR_ARGUMENTS_BAD;
		goto gen_err;
	}
	if (attrcpy(priv_exp, pTemplate, CKA_PRIVATE_EXPONENT, ulCount)) {
		rc = CKR_ARGUMENTS_BAD;
		goto gen_err;
	}
	
	key = malloc(sizeof(*key));
	if (key == NULL) {
		rc = CKR_HOST_MEMORY;
		goto gen_err;
	}

	/* get key data and create key object struct */
	key->id_len = getattr_len(pTemplate, CKA_ID, ulCount);
	key->id = malloc(key->id_len);
	if (key->id == NULL) {
		rc = CKR_HOST_MEMORY;
		goto id_err;
	}
	idtemp = (CK_BYTE *)getattr_pval(pTemplate, CKA_ID, ulCount);
	if (idtemp == NULL) {
		rc = CKR_ARGUMENTS_BAD;
		goto id_err;
	}
	memcpy(key->id, idtemp, key->id_len);

	key->key_handle = GET_KEY_HANDLE(key->id[2], key->id[1], key->id[0]);

	if ((CK_KEY_TYPE *)getattr_pval(pTemplate, CKA_KEY_TYPE, ulCount) == NULL) {
		rc = CKR_ARGUMENTS_BAD;
		goto id_err;
	} else {
		key->key_type = *(CK_KEY_TYPE *)getattr_pval(pTemplate, CKA_KEY_TYPE, ulCount);
	}

	if ((CK_OBJECT_CLASS *)getattr_pval(pTemplate, CKA_CLASS, ulCount) == NULL) {
		rc = CKR_ARGUMENTS_BAD;
		goto id_err;
	} else {
		key->key_class = *(CK_OBJECT_CLASS *)getattr_pval(pTemplate, CKA_CLASS, ulCount);
	}

	key->label_len = getattr_len(pTemplate, CKA_LABEL, ulCount);
	key->label = (CK_UTF8CHAR *)malloc(key->label_len);
	if (key->label == NULL) {
		rc = CKR_HOST_MEMORY;
		goto label_err;
	}
	labeltemp = (CK_UTF8CHAR *)getattr_pval(pTemplate, CKA_LABEL, ulCount);
	if (labeltemp == NULL) {
		rc = CKR_ARGUMENTS_BAD;
		goto label_err;
	}
	memcpy(key->label, labeltemp, key->label_len);

	if ((CK_ULONG *)getattr_pval(pTemplate, CKA_CLASS, ulCount) == NULL || 
		*(CK_ULONG *)getattr_pval(pTemplate, CKA_CLASS, ulCount) != CKO_PRIVATE_KEY) {
		rc = CKR_ARGUMENTS_BAD;
		goto class_err;
	}

	import_key_req = &srv_desc.hseSrv.importKeyReq;

	/* extract info needed for hse */
	key_info.keyFlags = (HSE_KF_USAGE_VERIFY | HSE_KF_USAGE_AUTHORIZATION);
	key_info.keyBitLen = getattr_len(pTemplate, CKA_MODULUS, ulCount) * 8;
	key_info.keyCounter = 0ul;
	key_info.smrFlags = 0ul;
	key_info.keyType = HSE_KEY_TYPE_RSA_PAIR;
	key_info.specific.pubExponentSize = getattr_len(pTemplate, CKA_PUBLIC_EXPONENT, ulCount);

	srv_desc.srvId = HSE_SRV_ID_IMPORT_KEY;
	import_key_req->targetKeyHandle = GET_KEY_HANDLE(key->id[2], key->id[1], key->id[0]);
	import_key_req->pKeyInfo = hse_virt_to_phys(key_info_sram);
	import_key_req->pKey[0] = hse_virt_to_phys(mod);
	import_key_req->pKey[1] = hse_virt_to_phys(pub_exp);
	import_key_req->pKey[2] = hse_virt_to_phys(priv_exp);
	import_key_req->keyLen[0] = getattr_len(pTemplate, CKA_MODULUS, ulCount);
	import_key_req->keyLen[1] = getattr_len(pTemplate, CKA_PUBLIC_EXPONENT, ulCount);
	import_key_req->keyLen[2] = getattr_len(pTemplate, CKA_PRIVATE_EXPONENT, ulCount);
	import_key_req->cipher.cipherKeyHandle = HSE_INVALID_KEY_HANDLE;
	import_key_req->keyContainer.authKeyHandle = HSE_INVALID_KEY_HANDLE;

	memcpy(srv_desc_sram, &srv_desc, sizeof(srv_desc));
	memcpy(key_info_sram, &key_info, sizeof(key_info));

	err = hse_srv_req_sync(HSE_CHANNEL_ANY, hse_virt_to_phys(srv_desc_sram));
	if (err) {
		rc = CKR_FUNCTION_FAILED;
		goto class_err;
	}

	*phObject = GET_KEY_HANDLE(key->id[2], key->id[1], key->id[0]);

	list_append(&gCtx.objects, key);

	return CKR_OK;
class_err:
	free(key->label);
label_err:
	free(key->id);
id_err:
	free(key);
gen_err:
	return rc;
}

CK_DEFINE_FUNCTION(CK_RV, C_DestroyObject)(
		CK_SESSION_HANDLE hSession,
		CK_OBJECT_HANDLE hObject
)
{
	struct hse_keyObject *pkey;
	void *srv_desc_sram;
	hseSrvDescriptor_t srv_desc;
	int err;

	if (gCtx.cryptokiInit == CK_FALSE)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (hSession != SESSION_ID)
		return CKR_SESSION_HANDLE_INVALID;

	srv_desc_sram = hse_get_shared_mem_addr(HSE_SRV_DESC_SRAM);

	pkey = (struct hse_keyObject *)list_seek(&gCtx.objects, &hObject);
	if (pkey == NULL)
		return CKR_OBJECT_HANDLE_INVALID;

	srv_desc.srvId = HSE_SRV_ID_ERASE_KEY;
	srv_desc.hseSrv.eraseKeyReq.keyHandle = GET_KEY_HANDLE(pkey->id[2], pkey->id[1], pkey->id[0]);
	srv_desc.hseSrv.eraseKeyReq.eraseKeyOptions = 0u;

	memcpy(srv_desc_sram, &srv_desc, sizeof(srv_desc));
	err = hse_srv_req_sync(HSE_CHANNEL_ANY, hse_virt_to_phys(srv_desc_sram));
	if (err)
		return CKR_FUNCTION_FAILED;

	if (list_delete(&gCtx.objects, pkey) != 0)
		return CKR_FUNCTION_FAILED;

	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsInit)(
	CK_SESSION_HANDLE hSession,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount
)
{
	if (gCtx.cryptokiInit == CK_FALSE)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (gCtx.findCtx.init == CK_TRUE)
		return CKR_OPERATION_ACTIVE;

	if (hSession != SESSION_ID)
		return CKR_SESSION_HANDLE_INVALID;

	if (ulCount != 0) {
		if (pTemplate != NULL)
			gCtx.findCtx.obj_class = (CK_OBJECT_CLASS *)getattr_pval(pTemplate, CKA_CLASS, ulCount);
		else
			return CKR_ARGUMENTS_BAD;
	}

	gCtx.findCtx.init = CK_TRUE;
	list_iterator_start(&gCtx.objects);

	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_FindObjects)(
	CK_SESSION_HANDLE hSession,
	CK_OBJECT_HANDLE_PTR phObject,
	CK_ULONG ulMaxObjectCount,
	CK_ULONG_PTR pulObjectCount
)
{
	struct hse_keyObject *key;
	struct hse_findCtx *finder;
	int i;

	if (gCtx.cryptokiInit == CK_FALSE)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (gCtx.findCtx.init == CK_FALSE)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (hSession != SESSION_ID)
		return CKR_SESSION_HANDLE_INVALID;

	if (phObject == NULL || ulMaxObjectCount == 0 || pulObjectCount == NULL)
		return CKR_ARGUMENTS_BAD;

	if (!list_iterator_hasnext(&gCtx.objects)) {
		*pulObjectCount = 0;
		return CKR_OK;
	}

	finder = &gCtx.findCtx;
	i = 0;
	do {
		key = (struct hse_keyObject *)list_iterator_next(&gCtx.objects);

		if (finder->obj_class == NULL || key->key_class == *finder->obj_class) {
			phObject[i] = key->key_handle;
			i++;
		}

		if (i > ulMaxObjectCount)
			break;
	} while (list_iterator_hasnext(&gCtx.objects));

	*pulObjectCount = i;

	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsFinal)(
	CK_SESSION_HANDLE hSession
)
{
	if (gCtx.cryptokiInit == CK_FALSE)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if(gCtx.findCtx.init == CK_FALSE)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (hSession != SESSION_ID)
		return CKR_SESSION_HANDLE_INVALID;

	gCtx.findCtx.init = CK_FALSE;
	list_iterator_stop(&gCtx.objects);

	return CKR_OK;
}
