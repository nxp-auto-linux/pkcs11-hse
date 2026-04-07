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
	hseDHComputeSharedSecretSrv_t *dhReq;
	hseKeyDeriveCopyKeySrv_t *copyReq;
	hseKeyInfo_t              keyInfo;
	hseKeyInfo_t              localKeyInfo;
	hseKeyInfo_t              baseKeyInfo;
	hseHashAlgo_t             hash_algo;

	struct hse_keyObject *key = NULL;
	CK_OBJECT_HANDLE final_obj;
	CK_OBJECT_HANDLE peer_pub_key_handle, shared_secret_handle;
	int key_handle = -1;
	int salt_handle = -1;
	int info_handle = -1;
	int shared_data_handle = -1;
	int keyinfo_handle = -1;
	int pubkey_handle = -1;
	int base_keyinfo_handle = -1;

	CK_HKDF_PARAMS_PTR hkdf;
	CK_ECDH1_DERIVE_PARAMS_PTR ecdh;
	CK_BYTE     *id;
	CK_KEY_TYPE *kt;
	CK_BBOOL    *f;
	char        *label;

	CK_ULONG id_len, val_len, label_len;
	CK_ULONG *val_len_p;
	CK_BYTE_PTR pub_data;
	CK_ULONG pub_data_len;
	uint16_t coord_bytes;
	CK_ULONG expected_point_len;
	CK_RV rv = CKR_OK;
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

	final_obj = GET_KEY_HANDLE(id[2], id[1], id[0]);
	shared_secret_handle = GET_KEY_HANDLE(0x02, 0x04, 0x00);
	peer_pub_key_handle = GET_KEY_HANDLE(0x02, 0x05, 0x00);

	switch (pMechanism->mechanism) {
		case CKM_HKDF_DERIVE:
			hkdf = (CK_HKDF_PARAMS_PTR)pMechanism->pParameter;
			if (!hkdf) {
				rv = CKR_MECHANISM_PARAM_INVALID;
				goto cleanup;
			}

			if (!(hkdf->bExtract == CK_TRUE && hkdf->bExpand == CK_TRUE)) {
				rv = CKR_MECHANISM_INVALID;
				goto cleanup;
			}

			if (hkdf->ulInfoLen > 256 || (hkdf->ulInfoLen > 0 && hkdf->pInfo == NULL)) {
				rv = CKR_MECHANISM_PARAM_INVALID;
				goto cleanup;
			}

			if (hkdf->ulInfoLen > 0 && hkdf->pInfo != NULL) {
				info_handle = hse_mem_alloc(hkdf->ulInfoLen);
				if (info_handle < 0) {
					rv = CKR_HOST_MEMORY;
					goto cleanup;
				}
				hse_memcpy_to_dev(info_handle, hkdf->pInfo, hkdf->ulInfoLen, 0);
			}

			if (hkdf->ulSaltType == CKF_HKDF_SALT_DATA && hkdf->ulSaltLen > 0 && hkdf->pSalt != NULL) {
				salt_handle = hse_mem_alloc(hkdf->ulSaltLen);
				if (salt_handle < 0) {
					rv = CKR_HOST_MEMORY;
					goto cleanup;
				}
				hse_memcpy_to_dev(salt_handle, hkdf->pSalt, hkdf->ulSaltLen, 0);
			}

			/* HKDF extract */
			memset(&srv_desc, 0, sizeof(srv_desc));
			srv_desc.srvId = HSE_SRV_ID_KEY_DERIVE;

			keyDeriveReq = &srv_desc.hseSrv.keyDeriveReq;
			keyDeriveReq->kdfAlgo = HSE_KDF_ALGO_EXTRACT_STEP;
			keyDeriveReq->sch.extractStep.secretKeyHandle = hBaseKey;
			keyDeriveReq->sch.extractStep.targetKeyHandle = shared_secret_handle; /* prk */
			keyDeriveReq->sch.extractStep.kdfPrf = HSE_KDF_PRF_HMAC;
			keyDeriveReq->sch.extractStep.prfAlgo.hmacHash = hse_pkcs_hash_alg_translate(hkdf->prfHashMechanism);

			if (hkdf->ulSaltType == CKF_HKDF_SALT_KEY) {
				keyDeriveReq->sch.extractStep.salt.saltKeyHandle = hkdf->hSaltKey;
			} else if (hkdf->ulSaltType == CKF_HKDF_SALT_DATA) {
				keyDeriveReq->sch.extractStep.salt.saltKeyHandle = HSE_INVALID_KEY_HANDLE;
				keyDeriveReq->sch.extractStep.salt.saltLength    = hkdf->ulSaltLen;
				keyDeriveReq->sch.extractStep.salt.pSalt         = hse_virt_to_dma(salt_handle, 0);
			} else if (hkdf->ulSaltType == CKF_HKDF_SALT_NULL) {
				keyDeriveReq->sch.extractStep.salt.saltKeyHandle = HSE_INVALID_KEY_HANDLE;
			} else {
				rv = CKR_MECHANISM_PARAM_INVALID;
				goto cleanup;
			}

			err = hse_srv_req_sync(sCtx->sID, &srv_desc, sizeof(srv_desc), NULL);
			if (err) {
				rv = CKR_FUNCTION_FAILED;
				goto cleanup;
			}

			/* HKDF expand */
			memset(&srv_desc, 0, sizeof(srv_desc));
			srv_desc.srvId = HSE_SRV_ID_KEY_DERIVE;

			keyDeriveReq = &srv_desc.hseSrv.keyDeriveReq;
			keyDeriveReq->kdfAlgo = HSE_KDF_ALGO_HKDF_EXPAND;
			keyDeriveReq->sch.HKDF_Expand.kdfCommon.srcKeyHandle = shared_secret_handle; /* prk */
			keyDeriveReq->sch.HKDF_Expand.kdfCommon.targetKeyHandle = shared_secret_handle; /* okm */
			keyDeriveReq->sch.HKDF_Expand.kdfCommon.keyMatLen = (uint16_t)val_len;
			keyDeriveReq->sch.HKDF_Expand.kdfCommon.kdfPrf = HSE_KDF_PRF_HMAC;
			keyDeriveReq->sch.HKDF_Expand.kdfCommon.prfAlgo.hmacHash = hse_pkcs_hash_alg_translate(hkdf->prfHashMechanism);
			keyDeriveReq->sch.HKDF_Expand.kdfCommon.pInfo = hse_virt_to_dma(info_handle, 0);
			keyDeriveReq->sch.HKDF_Expand.kdfCommon.infoLength = (uint32_t)hkdf->ulInfoLen;

			err = hse_srv_req_sync(sCtx->sID, &srv_desc, sizeof(srv_desc), NULL);
			if (err) {
				rv = CKR_FUNCTION_FAILED;
				goto cleanup;
			}

			break;

		case CKM_ECDH1_DERIVE:
			ecdh = (CK_ECDH1_DERIVE_PARAMS_PTR)pMechanism->pParameter;
			if (!ecdh) {
				rv = CKR_MECHANISM_PARAM_INVALID;
				goto cleanup;
			}

			if (!ecdh->pPublicData || ecdh->ulPublicDataLen == 0) {
				rv = CKR_MECHANISM_PARAM_INVALID;
				goto cleanup;
			}

			/* get base key info to determine curve parameters */
			base_keyinfo_handle = hse_mem_alloc(sizeof(hseKeyInfo_t));
			if (base_keyinfo_handle < 0) {
				rv = CKR_HOST_MEMORY;
				goto cleanup;
			}

			memset(&srv_desc, 0, sizeof(srv_desc));
			srv_desc.srvId = HSE_SRV_ID_GET_KEY_INFO;
			srv_desc.hseSrv.getKeyInfoReq.keyHandle = hBaseKey;
			srv_desc.hseSrv.getKeyInfoReq.pKeyInfo = hse_virt_to_dma(base_keyinfo_handle, 0);

			err = hse_srv_req_sync(sCtx->sID, &srv_desc, sizeof(srv_desc), NULL);
			if (err) {
				rv = CKR_KEY_HANDLE_INVALID;
				goto cleanup;
			}

			hse_memcpy_from_dev(&baseKeyInfo, base_keyinfo_handle, sizeof(hseKeyInfo_t), 0);

			coord_bytes = (baseKeyInfo.keyBitLen + 7) / 8;
			expected_point_len = 2 * coord_bytes;

			pub_data = ecdh->pPublicData;
			pub_data_len = ecdh->ulPublicDataLen;

			if (pub_data_len > 0 && pub_data[0] == 0x04) {
				pub_data = pub_data + 1;
				pub_data_len = pub_data_len - 1;
			}

			if (pub_data_len != expected_point_len) {
				rv = CKR_MECHANISM_PARAM_INVALID;
				goto cleanup;
			}

			/* import peer public key */
			keyinfo_handle = hse_mem_alloc(sizeof(hseKeyInfo_t));
			if (keyinfo_handle < 0) {
				rv = CKR_HOST_MEMORY;
				goto cleanup;
			}

			pubkey_handle = hse_mem_alloc(pub_data_len);
			if (pubkey_handle < 0) {
				rv = CKR_HOST_MEMORY;
				goto cleanup;
			}

			hse_memcpy_to_dev(pubkey_handle, pub_data, pub_data_len, 0);

			memset(&localKeyInfo, 0, sizeof(hseKeyInfo_t));
			localKeyInfo.keyType = HSE_KEY_TYPE_ECC_PUB;
			localKeyInfo.keyFlags = HSE_KF_USAGE_EXCHANGE;
			localKeyInfo.keyBitLen = baseKeyInfo.keyBitLen;
			localKeyInfo.specific.eccCurveId = baseKeyInfo.specific.eccCurveId;

			hse_memcpy_to_dev(keyinfo_handle, &localKeyInfo, sizeof(hseKeyInfo_t), 0);

			memset(&srv_desc, 0, sizeof(srv_desc));
			srv_desc.srvId = HSE_SRV_ID_IMPORT_KEY;
			srv_desc.hseSrv.importKeyReq.targetKeyHandle = peer_pub_key_handle;
			srv_desc.hseSrv.importKeyReq.pKeyInfo = hse_virt_to_dma(keyinfo_handle, 0);
			srv_desc.hseSrv.importKeyReq.pKey[0] = hse_virt_to_dma(pubkey_handle, 0);
			srv_desc.hseSrv.importKeyReq.keyLen[0] = (uint16_t)pub_data_len;
			srv_desc.hseSrv.importKeyReq.pKey[1] = 0;
			srv_desc.hseSrv.importKeyReq.keyLen[1] = 0;
			srv_desc.hseSrv.importKeyReq.pKey[2] = 0;
			srv_desc.hseSrv.importKeyReq.keyLen[2] = 0;
			srv_desc.hseSrv.importKeyReq.cipher.cipherKeyHandle = HSE_INVALID_KEY_HANDLE;
			srv_desc.hseSrv.importKeyReq.keyContainer.authKeyHandle = HSE_INVALID_KEY_HANDLE;

			err = hse_srv_req_sync(sCtx->sID, &srv_desc, sizeof(srv_desc), NULL);
			if (err) {
				rv = CKR_FUNCTION_FAILED;
				goto cleanup;
			}

			/* DH shared secret */
			memset(&srv_desc, 0, sizeof(srv_desc));
			srv_desc.srvId = HSE_SRV_ID_DH_COMPUTE_SHARED_SECRET;

			dhReq = &srv_desc.hseSrv.dhComputeSecretReq;
			dhReq->privKeyHandle = hBaseKey;
			dhReq->peerPubKeyHandle = peer_pub_key_handle;
			dhReq->targetKeyHandle = shared_secret_handle;

			err = hse_srv_req_sync(sCtx->sID, &srv_desc, sizeof(srv_desc), NULL);
			if (err) {
				rv = CKR_FUNCTION_FAILED;
				goto cleanup;
			}

			/* KDF */
			if (ecdh->kdf != CKD_NULL) {
				switch (ecdh->kdf) {
				case CKD_SHA1_KDF:
					hash_algo = HSE_HASH_ALGO_SHA_1;
					break;
				case CKD_SHA224_KDF:
					hash_algo = HSE_HASH_ALGO_SHA2_224;
					break;
				case CKD_SHA256_KDF:
					hash_algo = HSE_HASH_ALGO_SHA2_256;
					break;
				case CKD_SHA384_KDF:
					hash_algo = HSE_HASH_ALGO_SHA2_384;
					break;
				case CKD_SHA512_KDF:
					hash_algo = HSE_HASH_ALGO_SHA2_512;
					break;
				default:
					rv = CKR_MECHANISM_PARAM_INVALID;
					goto cleanup;
				}

				if (ecdh->ulSharedDataLen > 0 && ecdh->pSharedData != NULL) {
					shared_data_handle = hse_mem_alloc(ecdh->ulSharedDataLen);
					if (shared_data_handle < 0) {
						rv = CKR_HOST_MEMORY;
						goto cleanup;
					}
					hse_memcpy_to_dev(shared_data_handle, ecdh->pSharedData, ecdh->ulSharedDataLen, 0);
				}

				memset(&srv_desc, 0, sizeof(srv_desc));
				srv_desc.srvId = HSE_SRV_ID_KEY_DERIVE;

				keyDeriveReq = &srv_desc.hseSrv.keyDeriveReq;
				keyDeriveReq->kdfAlgo = HSE_KDF_ALGO_ANS_X963;
				keyDeriveReq->sch.ANS_X963.srcKeyHandle = shared_secret_handle;
				keyDeriveReq->sch.ANS_X963.targetKeyHandle = shared_secret_handle;
				keyDeriveReq->sch.ANS_X963.keyMatLen = (uint16_t)val_len;
				keyDeriveReq->sch.ANS_X963.kdfPrf = HSE_KDF_PRF_HASH;
				keyDeriveReq->sch.ANS_X963.prfAlgo.hash = hash_algo;
				keyDeriveReq->sch.ANS_X963.pInfo = hse_virt_to_dma(shared_data_handle, 0);
				keyDeriveReq->sch.ANS_X963.infoLength = (uint32_t)ecdh->ulSharedDataLen;

				err = hse_srv_req_sync(sCtx->sID, &srv_desc, sizeof(srv_desc), NULL);
				if (err) {
					rv = CKR_FUNCTION_FAILED;
					goto cleanup;
				}
			}

			break;

		default:
			rv = CKR_MECHANISM_INVALID;
			goto cleanup;
	}

	/* key copy */
	memset(&srv_desc, 0, sizeof(srv_desc));
	srv_desc.srvId = HSE_SRV_ID_KEY_DERIVE_COPY;
	copyReq = &srv_desc.hseSrv.keyDeriveCopyKeyReq;

	memset(&keyInfo, 0, sizeof(keyInfo));
	keyInfo.keyBitLen = (uint16_t)(val_len * 8);

	if (*kt == CKK_AES) {
		keyInfo.keyType = HSE_KEY_TYPE_AES;

		f = getattr_pval(pTemplate, CKA_ENCRYPT, ulAttributeCount);
		if (f && *f)
			keyInfo.keyFlags |= HSE_KF_USAGE_ENCRYPT;

		f = getattr_pval(pTemplate, CKA_DECRYPT, ulAttributeCount);
		if (f && *f)
			keyInfo.keyFlags |= HSE_KF_USAGE_DECRYPT;

		f = getattr_pval(pTemplate, CKA_SIGN, ulAttributeCount);
		if (f && *f)
			keyInfo.keyFlags |= HSE_KF_USAGE_SIGN;

		f = getattr_pval(pTemplate, CKA_VERIFY, ulAttributeCount);
		if (f && *f)
			keyInfo.keyFlags |= HSE_KF_USAGE_VERIFY;

	} else { /* HMAC */
		keyInfo.keyType = HSE_KEY_TYPE_HMAC;

		f = getattr_pval(pTemplate, CKA_ENCRYPT, ulAttributeCount);
		if (f && *f) {
			rv = CKR_TEMPLATE_INCONSISTENT;
			goto cleanup;
		}

		f = getattr_pval(pTemplate, CKA_DECRYPT, ulAttributeCount);
		if (f && *f) {
			rv = CKR_TEMPLATE_INCONSISTENT;
			goto cleanup;
		}

		f = getattr_pval(pTemplate, CKA_SIGN, ulAttributeCount);
		if (f && *f)
			keyInfo.keyFlags |= HSE_KF_USAGE_SIGN;

		f = getattr_pval(pTemplate, CKA_VERIFY, ulAttributeCount);
		if (f && *f)
			keyInfo.keyFlags |= HSE_KF_USAGE_VERIFY;
	}

	f = getattr_pval(pTemplate, CKA_DERIVE, ulAttributeCount);
	if (f && *f)
		keyInfo.keyFlags |= HSE_KF_USAGE_DERIVE;

	copyReq->keyHandle = shared_secret_handle;
	copyReq->targetKeyHandle = final_obj;
	copyReq->startOffset = 0;
	copyReq->keyInfo = keyInfo;

	err = hse_srv_req_sync(sCtx->sID, &srv_desc, sizeof(srv_desc), NULL);
	if (err) {
		rv = CKR_FUNCTION_FAILED;
		goto cleanup;
	}

	/* key object creation */
	gCtx->mtxFns.lock(tCtx->keyMtx);
	key_handle = get_key_object_handle(final_obj);
	gCtx->mtxFns.unlock(tCtx->keyMtx);

	if (key_handle < 0) {
		key_handle = hse_intl_mem_alloc(sizeof(struct hse_keyObject), HSE_KEY_OBJ);
		if (key_handle < 0) {
			rv = CKR_HOST_MEMORY;
			goto cleanup;
		}
	}

	key = (struct hse_keyObject *)hse_get_node_mem_addr(key_handle, true);

	memset(key, 0, sizeof(*key));
	key->attrs.key_handle = final_obj;
	key->attrs.key_uid = final_obj;
	key->attrs.key_type = *kt;
	key->attrs.key_class = CKO_SECRET_KEY;

	if (label && label_len)
		memcpy(key->attrs.key_label, label, label_len);

	key->dyn_attrs_handle = -1;
	err = hse_add_dyn_attr_list(key, pTemplate, ulAttributeCount);
	if (err) {
		hse_free_dyn_attr_list(key->dyn_attrs_handle);
		hse_intl_mem_free(key_handle);
		rv = CKR_FUNCTION_FAILED;
		goto cleanup;
	}

	gCtx->mtxFns.lock(tCtx->keyMtx);
	hse_key_object_write(key);
	gCtx->mtxFns.unlock(tCtx->keyMtx);

	*phKey = final_obj;

cleanup:
	memset(&srv_desc, 0, sizeof(srv_desc));
	srv_desc.srvId = HSE_SRV_ID_ERASE_KEY;
	srv_desc.hseSrv.eraseKeyReq.keyHandle = peer_pub_key_handle;
	srv_desc.hseSrv.eraseKeyReq.eraseKeyOptions = 0u;
	hse_srv_req_sync(sCtx->sID, &srv_desc, sizeof(srv_desc), NULL);

	memset(&srv_desc, 0, sizeof(srv_desc));
	srv_desc.srvId = HSE_SRV_ID_ERASE_KEY;
	srv_desc.hseSrv.eraseKeyReq.keyHandle = shared_secret_handle;
	srv_desc.hseSrv.eraseKeyReq.eraseKeyOptions = 0u;
	hse_srv_req_sync(sCtx->sID, &srv_desc, sizeof(srv_desc), NULL);

	if (salt_handle >= 0)
		hse_mem_free(salt_handle);
	if (info_handle >= 0)
		hse_mem_free(info_handle);
	if (shared_data_handle >= 0)
		hse_mem_free(shared_data_handle);
	if (keyinfo_handle >= 0)
		hse_mem_free(keyinfo_handle);
	if (pubkey_handle >= 0)
		hse_mem_free(pubkey_handle);
	if (base_keyinfo_handle >= 0)
		hse_mem_free(base_keyinfo_handle);

	return rv;
}
