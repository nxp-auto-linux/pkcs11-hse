// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <libhse.h>

#include "pkcs11_context.h"
#include "hse_interface.h"
#include "pkcs11_util.h"
#include "hse-internal.h"

#ifndef INFO
#define INFO(fmt, ...) printf("[INFO] " fmt, ##__VA_ARGS__)
#endif

CK_DECLARE_FUNCTION(CK_RV, C_DeriveKey)(
    CK_SESSION_HANDLE       hSession,
    CK_MECHANISM_PTR        pMechanism,
    CK_OBJECT_HANDLE        hBaseKey,
    CK_ATTRIBUTE_PTR        pTemplate,
    CK_ULONG                ulAttributeCount,
    CK_OBJECT_HANDLE_PTR    phKey
)
{
	struct globalCtx  *gCtx;
	struct sessionCtx *sCtx;
	struct tokenCtx *tCtx;
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	hseKeyDeriveSrv_t        *keyDeriveReq;
	hseKeyDeriveCopyKeySrv_t *copyReq;
	hseKeyInfo_t              keyInfo;

	struct hse_keyObject *key = NULL;
	CK_OBJECT_HANDLE tmp_prk, tmp_okm, final_obj;
	int key_handle = -1;

	CK_HKDF_PARAMS_PTR hkdf;
	CK_BYTE     *id;
	CK_KEY_TYPE *kt;
	CK_BBOOL    *f;
	char        *label;

	CK_ULONG id_len, val_len, label_len;
	CK_ULONG *val_len_p;
	int err;

	tCtx = getTokenCtx();
	gCtx = getCtx();
	sCtx = getSessionCtx(hSession);

	if (!gCtx || gCtx->cryptokiInit == CK_FALSE)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!sCtx || sCtx->sessionInit == CK_FALSE)
		return CKR_SESSION_HANDLE_INVALID;

	if (!pMechanism || !phKey)
		return CKR_ARGUMENTS_BAD;

	if (!pTemplate && ulAttributeCount != 0)
		return CKR_TEMPLATE_INCOMPLETE;

    switch (pMechanism->mechanism) {
		case CKM_HKDF_DERIVE:
			hkdf = (CK_HKDF_PARAMS_PTR)pMechanism->pParameter;
			if (!hkdf)
				return CKR_MECHANISM_PARAM_INVALID;

			if (!(hkdf->bExtract == CK_TRUE && hkdf->bExpand == CK_TRUE))
				return CKR_MECHANISM_INVALID;

			id = (CK_BYTE *)getattr_pval(pTemplate, CKA_ID, ulAttributeCount);
			id_len = getattr_len(pTemplate, CKA_ID, ulAttributeCount);
			if (!id || id_len != 3)
				return CKR_TEMPLATE_INCONSISTENT;

			kt = (CK_KEY_TYPE *)getattr_pval(pTemplate, CKA_KEY_TYPE, ulAttributeCount);

			if (!kt || !( *kt == CKK_AES ||
						  *kt == CKK_SHA_1_HMAC ||
						  *kt == CKK_SHA224_HMAC ||
						  *kt == CKK_SHA256_HMAC ||
						  *kt == CKK_SHA384_HMAC ||
						  *kt == CKK_SHA512_HMAC))
				return CKR_TEMPLATE_INCONSISTENT;

			val_len_p = (CK_ULONG *)getattr_pval(pTemplate, CKA_VALUE_LEN, ulAttributeCount);
			if (!val_len_p)
				return CKR_TEMPLATE_INCOMPLETE;

			val_len = *val_len_p;

			if (!is_valid_key_length(*kt, val_len * 8))
				return CKR_KEY_SIZE_RANGE;

			label = (char *)getattr_pval(pTemplate, CKA_LABEL, ulAttributeCount);
			label_len = getattr_len(pTemplate, CKA_LABEL, ulAttributeCount);
			if (label && label_len > MAX_LABEL_LEN)
				return CKR_ARGUMENTS_BAD;

			if (hkdf->ulInfoLen > 256 || (hkdf->ulInfoLen > 0 && hkdf->pInfo == NULL))
				return CKR_MECHANISM_PARAM_INVALID;

			final_obj = GET_KEY_HANDLE(id[2], id[1], id[0]);
			tmp_prk   = GET_KEY_HANDLE(0x02, 0x04, 0x00);
			tmp_okm   = GET_KEY_HANDLE(0x02, 0x04, 0x00);

			/* HKDF EXTRACT */
			memset(&srv_desc, 0, sizeof(srv_desc));
			srv_desc.srvId = HSE_SRV_ID_KEY_DERIVE;

			keyDeriveReq = &srv_desc.hseSrv.keyDeriveReq;
			keyDeriveReq->kdfAlgo = HSE_KDF_ALGO_EXTRACT_STEP;
			keyDeriveReq->sch.extractStep.secretKeyHandle = hBaseKey;
			keyDeriveReq->sch.extractStep.targetKeyHandle = tmp_prk;
			keyDeriveReq->sch.extractStep.kdfPrf = HSE_KDF_PRF_HMAC;
			keyDeriveReq->sch.extractStep.prfAlgo.hmacHash = hse_pkcs_hash_alg_translate(hkdf->prfHashMechanism);

			if (hkdf->ulSaltType == CKF_HKDF_SALT_KEY) {
				keyDeriveReq->sch.extractStep.salt.saltKeyHandle = hkdf->hSaltKey;
			} else if (hkdf->ulSaltType == CKF_HKDF_SALT_DATA) {
				keyDeriveReq->sch.extractStep.salt.saltKeyHandle = HSE_INVALID_KEY_HANDLE;
				keyDeriveReq->sch.extractStep.salt.saltLength    = hkdf->ulSaltLen;
				keyDeriveReq->sch.extractStep.salt.pSalt         = (HOST_ADDR)hkdf->pSalt;
			} else if (hkdf->ulSaltType == CKF_HKDF_SALT_NULL) {
				keyDeriveReq->sch.extractStep.salt.saltKeyHandle = HSE_INVALID_KEY_HANDLE;
			} else {
				return CKR_MECHANISM_PARAM_INVALID;
			}

			err = hse_srv_req_sync(sCtx->sID, &srv_desc, sizeof(srv_desc), NULL);
			if (err)
				return CKR_FUNCTION_FAILED;

			/* HKDF EXPAND */
			memset(&srv_desc, 0, sizeof(srv_desc));
			srv_desc.srvId = HSE_SRV_ID_KEY_DERIVE;

			keyDeriveReq = &srv_desc.hseSrv.keyDeriveReq;
			keyDeriveReq->kdfAlgo = HSE_KDF_ALGO_HKDF_EXPAND;
			keyDeriveReq->sch.HKDF_Expand.kdfCommon.srcKeyHandle = tmp_prk;
			keyDeriveReq->sch.HKDF_Expand.kdfCommon.targetKeyHandle = tmp_okm;
			keyDeriveReq->sch.HKDF_Expand.kdfCommon.keyMatLen = (uint16_t)val_len;
			keyDeriveReq->sch.HKDF_Expand.kdfCommon.kdfPrf = HSE_KDF_PRF_HMAC;
			keyDeriveReq->sch.HKDF_Expand.kdfCommon.prfAlgo.hmacHash = hse_pkcs_hash_alg_translate(hkdf->prfHashMechanism);
			keyDeriveReq->sch.HKDF_Expand.kdfCommon.pInfo = (HOST_ADDR)hkdf->pInfo;
			keyDeriveReq->sch.HKDF_Expand.kdfCommon.infoLength = (uint32_t)hkdf->ulInfoLen;

			err = hse_srv_req_sync(sCtx->sID, &srv_desc, sizeof(srv_desc), NULL);
			if (err)
				return CKR_FUNCTION_FAILED;

			/* KEY COPY */
			memset(&srv_desc, 0, sizeof(srv_desc));
			srv_desc.srvId = HSE_SRV_ID_KEY_DERIVE_COPY;
			copyReq = &srv_desc.hseSrv.keyDeriveCopyKeyReq;

			memset(&keyInfo, 0, sizeof(keyInfo));
			keyInfo.keyBitLen = (uint16_t)(val_len * 8);

			if (*kt == CKK_AES) {
				keyInfo.keyType = HSE_KEY_TYPE_AES;

				f = getattr_pval(pTemplate, CKA_ENCRYPT, ulAttributeCount);
				if (f && *f) keyInfo.keyFlags |= HSE_KF_USAGE_ENCRYPT;

				f = getattr_pval(pTemplate, CKA_DECRYPT, ulAttributeCount);
				if (f && *f) keyInfo.keyFlags |= HSE_KF_USAGE_DECRYPT;

				f = getattr_pval(pTemplate, CKA_SIGN, ulAttributeCount);
				if (f && *f) keyInfo.keyFlags |= HSE_KF_USAGE_SIGN;

				f = getattr_pval(pTemplate, CKA_VERIFY, ulAttributeCount);
				if (f && *f) keyInfo.keyFlags |= HSE_KF_USAGE_VERIFY;

			} else { /* HMAC */
				keyInfo.keyType = HSE_KEY_TYPE_HMAC;

				f = getattr_pval(pTemplate, CKA_ENCRYPT, ulAttributeCount);
				if (f && *f) return CKR_TEMPLATE_INCONSISTENT;

				f = getattr_pval(pTemplate, CKA_DECRYPT, ulAttributeCount);
				if (f && *f) return CKR_TEMPLATE_INCONSISTENT;

				f = getattr_pval(pTemplate, CKA_SIGN, ulAttributeCount);
				if (f && *f) keyInfo.keyFlags |= HSE_KF_USAGE_SIGN;

				f = getattr_pval(pTemplate, CKA_VERIFY, ulAttributeCount);
				if (f && *f) keyInfo.keyFlags |= HSE_KF_USAGE_VERIFY;
			}

			f = getattr_pval(pTemplate, CKA_DERIVE, ulAttributeCount);
			if (f && *f) keyInfo.keyFlags |= HSE_KF_USAGE_DERIVE;

			copyReq->keyHandle = tmp_okm;
			copyReq->targetKeyHandle = final_obj;
			copyReq->startOffset = 0;
			copyReq->keyInfo = keyInfo;

			err = hse_srv_req_sync(sCtx->sID, &srv_desc, sizeof(srv_desc), NULL);
			if (err)
				return CKR_FUNCTION_FAILED;

			/* Key object creation */		
			gCtx->mtxFns.lock(tCtx->keyMtx);
			key_handle = get_key_object_handle(final_obj);
			gCtx->mtxFns.unlock(tCtx->keyMtx);

			if (key_handle < 0) {
				key_handle = hse_intl_mem_alloc(sizeof(struct hse_keyObject), HSE_KEY_OBJ);
				if (key_handle < 0) {
					err = CKR_HOST_MEMORY;
					goto err_free_key_intl;
				}
			}

			key = (struct hse_keyObject *) hse_get_node_mem_addr(key_handle, true);

			memset(key, 0, sizeof(*key));
			key->attrs.key_handle = final_obj;
			key->attrs.key_uid = final_obj;
			key->attrs.key_type = *kt;
			key->attrs.key_class = CKO_SECRET_KEY;

			if (label && label_len)
				memcpy(key->attrs.key_label, label, label_len);

			key->dyn_attrs_handle = -1;
			err = hse_add_dyn_attr_list(key, pTemplate, ulAttributeCount);
			if (err)
				goto err_free_key_intl;
			
			gCtx->mtxFns.lock(tCtx->keyMtx);
			hse_key_object_write(key);
			gCtx->mtxFns.unlock(tCtx->keyMtx);

			*phKey = final_obj;

			return CKR_OK;
		default:
			return CKR_MECHANISM_INVALID;
	}

err_free_key_intl:
	hse_free_dyn_attr_list(key->dyn_attrs_handle);
	hse_intl_mem_free(key_handle);
return err;
}
