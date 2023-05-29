// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2023 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pkcs11_context.h"
#include "pkcs11_util.h"

CK_DEFINE_FUNCTION(CK_RV, C_EncryptInit)(
		CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,
		CK_OBJECT_HANDLE hKey
)
{
	struct globalCtx *gCtx = getCtx();
	struct sessionCtx *sCtx = getSessionCtx(hSession);

	if (gCtx->cryptokiInit == CK_FALSE)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!sCtx || sCtx->sessionInit == CK_FALSE)
		return CKR_SESSION_HANDLE_INVALID;

	if ((sCtx->cryptCtx.init == CK_TRUE) && (pMechanism == NULL)) {
		/* condition to terminate an active encryption operation */
		if (sCtx->cryptCtx.cache != NULL) {
			free(sCtx->cryptCtx.cache);
			sCtx->cryptCtx.cache = NULL;
		}
		sCtx->cryptCtx.init = CK_FALSE;
		sCtx->cryptCtx.stream_start = CK_TRUE;
		return CKR_OK;
	}

	if (sCtx->cryptCtx.init == CK_TRUE)
		return CKR_OPERATION_ACTIVE;

	if (pMechanism == NULL)
		return CKR_ARGUMENTS_BAD;

	gCtx->mtxFns.lock(gCtx->keyMtx);
	if (list_seek(&gCtx->object_list, &hKey) == NULL) {
		gCtx->mtxFns.unlock(gCtx->keyMtx);
		return CKR_KEY_HANDLE_INVALID;
	}
	gCtx->mtxFns.unlock(gCtx->keyMtx);

	/* IV is optional for AES-ECB */
	if (pMechanism->pParameter == NULL)
	    if ((pMechanism->mechanism != CKM_AES_ECB) &&
			(pMechanism->mechanism != CKM_RSA_PKCS))
			return CKR_ARGUMENTS_BAD;

	sCtx->cryptCtx.blockSize = HSE_AES_BLOCK_LEN;
	sCtx->cryptCtx.cache = malloc(sCtx->cryptCtx.blockSize);
	if (sCtx->cryptCtx.cache == NULL)
		return CKR_HOST_MEMORY;

	sCtx->cryptCtx.init = CK_TRUE;
	sCtx->cryptCtx.mechanism = pMechanism;
	sCtx->cryptCtx.keyHandle = hKey;
	sCtx->cryptCtx.stream_start = CK_TRUE;
	sCtx->cryptCtx.cache_idx = 0;

	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_Encrypt)(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pData,
		CK_ULONG ulDataLen,
		CK_BYTE_PTR pEncryptedData,
		CK_ULONG_PTR pulEncryptedDataLen
)
{
	struct globalCtx *gCtx = getCtx();
	struct sessionCtx *sCtx = getSessionCtx(hSession);
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	hseSymCipherSrv_t *sym_cipher_srv;
	hseRsaCipherSrv_t *rsa_cipher_srv;
	hseAeadSrv_t *aead_srv;
	void *input, *output, *output_len, *pIV = NULL;
	void *gcm_tag = NULL;
	struct hse_keyObject *key;
	CK_RV rc = CKR_OK;
	int err;
	uint16_t key_bit_length;
	CK_RSA_PKCS_OAEP_PARAMS *oaep_params;

	if (gCtx->cryptokiInit == CK_FALSE)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!sCtx || sCtx->sessionInit == CK_FALSE)
		return CKR_SESSION_HANDLE_INVALID;

	if (sCtx->cryptCtx.init == CK_FALSE)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (pData == NULL || pEncryptedData == NULL || pulEncryptedDataLen == NULL) {
		rc = CKR_ARGUMENTS_BAD;
		goto err_uninit;
	}

	/* Check for input length: For ECB, CBC & CFB cipher block modes, must be a multiple of block length. Cannot be zero. */
	if (ulDataLen == 0) {
		rc = CKR_ARGUMENTS_BAD;
		goto err_uninit;
	}

	if ((sCtx->cryptCtx.mechanism->mechanism == CKM_AES_ECB) ||
		(sCtx->cryptCtx.mechanism->mechanism == CKM_AES_CBC) ) {
			if ((ulDataLen & (HSE_AES_BLOCK_LEN - 1)) != 0) {
				rc = CKR_ARGUMENTS_BAD;
				goto err_uninit;
			}
	}

	gCtx->mtxFns.lock(gCtx->keyMtx);
	key = (struct hse_keyObject *)list_seek(&gCtx->object_list, &sCtx->cryptCtx.keyHandle);
	gCtx->mtxFns.unlock(gCtx->keyMtx);
	if (key == NULL) {
		rc = CKR_KEY_HANDLE_INVALID;
		goto err_uninit;
	}

	/* check for input length for RSA ciphering */
	if ((sCtx->cryptCtx.mechanism->mechanism == CKM_RSA_PKCS) ||
		(sCtx->cryptCtx.mechanism->mechanism == CKM_RSA_PKCS_OAEP)) {
		key_bit_length = hse_get_key_bit_length(key);
		if (key_bit_length == 0) {
			rc = CKR_GENERAL_ERROR;
			goto err_uninit;
		}

		if (rsa_ciphering_get_max_input_length(key_bit_length, sCtx->cryptCtx.mechanism) < ulDataLen)
		{
			rc = CKR_DATA_LEN_RANGE;
			goto err_uninit;
		}
	}

	input = hse_mem_alloc(ulDataLen);
	if (input == NULL) {
		rc = CKR_HOST_MEMORY;
		goto err_uninit;
	}
	hse_memcpy(input, pData, ulDataLen);

	output_len = hse_mem_alloc(sizeof(uint32_t));
	if (output_len == NULL) {
		rc = CKR_HOST_MEMORY;
		goto err_free_input;
	}

	/* Check the output length */
	if ((sCtx->cryptCtx.mechanism->mechanism == CKM_AES_ECB) ||
		(sCtx->cryptCtx.mechanism->mechanism == CKM_AES_CBC) ||
		(sCtx->cryptCtx.mechanism->mechanism == CKM_AES_CTR) ||
		(sCtx->cryptCtx.mechanism->mechanism == CKM_AES_GCM)) {
		/* For AES, the output length is equal to the input length  */
		hse_memcpy(output_len, &ulDataLen, sizeof(uint32_t));
	} else if ((sCtx->cryptCtx.mechanism->mechanism == CKM_RSA_PKCS) ||
			   (sCtx->cryptCtx.mechanism->mechanism == CKM_RSA_PKCS_OAEP)) {
		/* get the output length based on the RSA key length */
		*(uint32_t *)output_len = rsa_ciphering_get_out_length(key_bit_length);
	}

	if (*pulEncryptedDataLen < *(uint32_t *)output_len) {
		/* tell the required size */
		*pulEncryptedDataLen = *(uint32_t *)output_len;

		rc = CKR_BUFFER_TOO_SMALL;
		goto err_free_output_len;
	}

	output = hse_mem_alloc(*(uint32_t *)output_len);
	if (output == NULL) {
		rc = CKR_HOST_MEMORY;
		goto err_free_output_len;
	}

	if (sCtx->cryptCtx.mechanism->pParameter != NULL) {
		if (sCtx->cryptCtx.mechanism->mechanism == CKM_RSA_PKCS_OAEP) {
			oaep_params = (CK_RSA_PKCS_OAEP_PARAMS *)sCtx->cryptCtx.mechanism->pParameter;
		} else {
			pIV = hse_mem_alloc(sCtx->cryptCtx.mechanism->ulParameterLen);
			if (pIV == NULL) {
				rc = CKR_HOST_MEMORY;
				goto err_free_output;
			}
			hse_memcpy(pIV, sCtx->cryptCtx.mechanism->pParameter, sCtx->cryptCtx.mechanism->ulParameterLen);
		}
	}

	if (sCtx->cryptCtx.mechanism->mechanism == CKM_AES_GCM) {
		/* HSE requires GCM valid Tag sizes 4, 8, 12, 13, 14, 15, 16 bytes. Can not be 0.
		 * Use the length 16 for the tag here. */
		gcm_tag = hse_mem_alloc(16u);
		if (gcm_tag == NULL) {
			rc = CKR_HOST_MEMORY;
			goto err_free_piv;
		}
	}

	switch (sCtx->cryptCtx.mechanism->mechanism) {
		case CKM_AES_ECB:

			sym_cipher_srv = &srv_desc.hseSrv.symCipherReq;

			srv_desc.srvId = HSE_SRV_ID_SYM_CIPHER;
			sym_cipher_srv->accessMode = HSE_ACCESS_MODE_ONE_PASS;
			sym_cipher_srv->streamId = 0u;
			sym_cipher_srv->cipherAlgo = HSE_CIPHER_ALGO_AES;
			sym_cipher_srv->cipherBlockMode = HSE_CIPHER_BLOCK_MODE_ECB;
			sym_cipher_srv->cipherDir = HSE_CIPHER_DIR_ENCRYPT;
			sym_cipher_srv->sgtOption = HSE_SGT_OPTION_NONE;
			sym_cipher_srv->keyHandle = key->key_handle;

			if (sCtx->cryptCtx.mechanism->pParameter != NULL) {
				sym_cipher_srv->pIV = hse_virt_to_dma(pIV);
			} else {
				sym_cipher_srv->pIV = 0u; /* IV is not required for ecb */
			}

			sym_cipher_srv->inputLength = ulDataLen;
			sym_cipher_srv->pInput = hse_virt_to_dma(input);
			sym_cipher_srv->pOutput= hse_virt_to_dma(output);

			break;

		case CKM_AES_CBC:

			sym_cipher_srv = &srv_desc.hseSrv.symCipherReq;

			srv_desc.srvId = HSE_SRV_ID_SYM_CIPHER;
			sym_cipher_srv->accessMode = HSE_ACCESS_MODE_ONE_PASS;
			sym_cipher_srv->streamId = 0u;
			sym_cipher_srv->cipherAlgo = HSE_CIPHER_ALGO_AES;
			sym_cipher_srv->cipherBlockMode = HSE_CIPHER_BLOCK_MODE_CBC;
			sym_cipher_srv->cipherDir = HSE_CIPHER_DIR_ENCRYPT;
			sym_cipher_srv->sgtOption = HSE_SGT_OPTION_NONE;
			sym_cipher_srv->keyHandle = key->key_handle;
			sym_cipher_srv->pIV = hse_virt_to_dma(pIV);
			sym_cipher_srv->inputLength = ulDataLen;
			sym_cipher_srv->pInput = hse_virt_to_dma(input);
			sym_cipher_srv->pOutput= hse_virt_to_dma(output);

			break;

		case CKM_AES_CTR:

			sym_cipher_srv = &srv_desc.hseSrv.symCipherReq;

			srv_desc.srvId = HSE_SRV_ID_SYM_CIPHER;
			sym_cipher_srv->accessMode = HSE_ACCESS_MODE_ONE_PASS;
			sym_cipher_srv->streamId = 0u;
			sym_cipher_srv->cipherAlgo = HSE_CIPHER_ALGO_AES;
			sym_cipher_srv->cipherBlockMode = HSE_CIPHER_BLOCK_MODE_CTR;
			sym_cipher_srv->cipherDir = HSE_CIPHER_DIR_ENCRYPT;
			sym_cipher_srv->sgtOption = HSE_SGT_OPTION_NONE;
			sym_cipher_srv->keyHandle = key->key_handle;
			sym_cipher_srv->pIV = hse_virt_to_dma(pIV);
			sym_cipher_srv->inputLength = ulDataLen;
			sym_cipher_srv->pInput = hse_virt_to_dma(input);
			sym_cipher_srv->pOutput= hse_virt_to_dma(output);

			break;

		case CKM_AES_GCM:

			aead_srv = &srv_desc.hseSrv.aeadReq;

			srv_desc.srvId = HSE_SRV_ID_AEAD;
			aead_srv->accessMode = HSE_ACCESS_MODE_ONE_PASS;
			aead_srv->streamId = 0u;
			aead_srv->authCipherMode = HSE_AUTH_CIPHER_MODE_GCM;
			aead_srv->cipherDir = HSE_CIPHER_DIR_ENCRYPT;
			aead_srv->keyHandle = key->key_handle;
			aead_srv->ivLength = sCtx->cryptCtx.mechanism->ulParameterLen;
			aead_srv->pIV = hse_virt_to_dma(pIV);
			aead_srv->aadLength = 0u;
			aead_srv->pAAD = 0u;
			aead_srv->sgtOption = HSE_SGT_OPTION_NONE;
			aead_srv->inputLength = ulDataLen;
			aead_srv->pInput = hse_virt_to_dma(input);
			aead_srv->tagLength = 16u;
			aead_srv->pTag = hse_virt_to_dma(gcm_tag);
			aead_srv->pOutput = hse_virt_to_dma(output);

			break;

		case CKM_RSA_PKCS:
			rsa_cipher_srv = &srv_desc.hseSrv.rsaCipherReq;

			srv_desc.srvId = HSE_SRV_ID_RSA_CIPHER;
			rsa_cipher_srv->cipherDir = HSE_CIPHER_DIR_ENCRYPT;
			rsa_cipher_srv->keyHandle = key->key_handle;
			rsa_cipher_srv->inputLength = ulDataLen;
			rsa_cipher_srv->pInput = hse_virt_to_dma(input);
			rsa_cipher_srv->pOutputLength = hse_virt_to_dma(output_len);
			rsa_cipher_srv->pOutput = hse_virt_to_dma(output);

			rsa_cipher_srv->rsaScheme.rsaAlgo = HSE_RSA_ALGO_RSAES_PKCS1_V15;
			break;

		case CKM_RSA_PKCS_OAEP:
			rsa_cipher_srv = &srv_desc.hseSrv.rsaCipherReq;

			srv_desc.srvId = HSE_SRV_ID_RSA_CIPHER;
			rsa_cipher_srv->cipherDir = HSE_CIPHER_DIR_ENCRYPT;
			rsa_cipher_srv->keyHandle = key->key_handle;
			rsa_cipher_srv->inputLength = ulDataLen;
			rsa_cipher_srv->pInput = hse_virt_to_dma(input);
			rsa_cipher_srv->pOutputLength = hse_virt_to_dma(output_len);
			rsa_cipher_srv->pOutput = hse_virt_to_dma(output);

			rsa_cipher_srv->rsaScheme.rsaAlgo = HSE_RSA_ALGO_RSAES_OAEP;
			rsa_cipher_srv->rsaScheme.sch.rsaOAEP.hashAlgo = hse_pkcs_hash_alg_translate(oaep_params->hashAlg);
			rsa_cipher_srv->rsaScheme.sch.rsaOAEP.labelLength = 0;
			rsa_cipher_srv->rsaScheme.sch.rsaOAEP.pLabel = 0;
			break;

		default:
			rc = CKR_ARGUMENTS_BAD;
			goto err_free_tag;
	}

	err = hse_srv_req_sync(sCtx->sID, &srv_desc, sizeof(srv_desc));
	if (err) {
		rc = CKR_FUNCTION_FAILED;
		goto err_free_tag;
	}

	hse_memcpy(pEncryptedData, output, *(uint32_t *)output_len);
	hse_memcpy(pulEncryptedDataLen, output_len, sizeof(uint32_t));

err_free_tag:
	hse_mem_free(gcm_tag);
err_free_piv:
	hse_mem_free(pIV);
err_free_output:
	hse_mem_free(output);
err_free_output_len:
	hse_mem_free(output_len);
err_free_input:
	hse_mem_free(input);
err_uninit:
	if (rc != CKR_BUFFER_TOO_SMALL) {
		sCtx->cryptCtx.init = CK_FALSE;
		if (sCtx->cryptCtx.cache != NULL) {
			free(sCtx->cryptCtx.cache);
			sCtx->cryptCtx.cache = NULL;
		}
	}

	return rc;
}

CK_DEFINE_FUNCTION(CK_RV, C_DecryptInit)(
		CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,
		CK_OBJECT_HANDLE hKey
)
{
	struct globalCtx *gCtx = getCtx();
	struct sessionCtx *sCtx = getSessionCtx(hSession);

	if (gCtx->cryptokiInit == CK_FALSE)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!sCtx || sCtx->sessionInit == CK_FALSE)
		return CKR_SESSION_HANDLE_INVALID;

	if ((sCtx->cryptCtx.init == CK_TRUE) && (pMechanism == NULL)) {
		/* condition to terminate an active decryption operation */
		if (sCtx->cryptCtx.cache != NULL) {
			free(sCtx->cryptCtx.cache);
			sCtx->cryptCtx.cache = NULL;
		}
		sCtx->cryptCtx.init = CK_FALSE;
		sCtx->cryptCtx.stream_start = CK_TRUE;
		return CKR_OK;
	}

	if (sCtx->cryptCtx.init == CK_TRUE)
		return CKR_OPERATION_ACTIVE;

	if (pMechanism == NULL)
		return CKR_ARGUMENTS_BAD;

	gCtx->mtxFns.lock(gCtx->keyMtx);
	if (list_seek(&gCtx->object_list, &hKey) == NULL) {
		gCtx->mtxFns.unlock(gCtx->keyMtx);
		return CKR_KEY_HANDLE_INVALID;
	}
	gCtx->mtxFns.unlock(gCtx->keyMtx);

	/* IV is optional for AES-ECB */
	if (pMechanism->pParameter == NULL)
	    if ((pMechanism->mechanism != CKM_AES_ECB) &&
			(pMechanism->mechanism != CKM_RSA_PKCS))
			return CKR_ARGUMENTS_BAD;

	sCtx->cryptCtx.blockSize = HSE_AES_BLOCK_LEN;
	sCtx->cryptCtx.cache = malloc(sCtx->cryptCtx.blockSize);
	if (sCtx->cryptCtx.cache == NULL)
		return CKR_HOST_MEMORY;

	sCtx->cryptCtx.init = CK_TRUE;
	sCtx->cryptCtx.mechanism = pMechanism;
	sCtx->cryptCtx.keyHandle = hKey;
	sCtx->cryptCtx.stream_start = CK_TRUE;
	sCtx->cryptCtx.cache_idx = 0;

	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_Decrypt)(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pEncryptedData,
		CK_ULONG ulEncryptedDataLen,
		CK_BYTE_PTR pData,
		CK_ULONG_PTR pulDataLen
)
{
	struct globalCtx *gCtx = getCtx();
	struct sessionCtx *sCtx = getSessionCtx(hSession);
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	hseSymCipherSrv_t *sym_cipher_srv;
	hseRsaCipherSrv_t *rsa_cipher_srv;
	hseAeadSrv_t *aead_srv;
	void *input, *output, *output_len, *pIV = NULL;
	void *gcm_tag = NULL;
	struct hse_keyObject *key;
	CK_RV rc = CKR_OK;
	int err;
	uint16_t key_bit_length = 0;
	CK_RSA_PKCS_OAEP_PARAMS *oaep_params;

	if (gCtx->cryptokiInit == CK_FALSE)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!sCtx || sCtx->sessionInit == CK_FALSE)
		return CKR_SESSION_HANDLE_INVALID;

	if (sCtx->cryptCtx.init == CK_FALSE)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (pData == NULL || pEncryptedData == NULL || pulDataLen == NULL) {
		rc = CKR_ARGUMENTS_BAD;
		goto err_uninit;
	}

	/* Check for input length: For ECB, CBC & CFB cipher block modes, must be a multiple of block length. Cannot be zero. */
	if (ulEncryptedDataLen == 0) {
		rc = CKR_ARGUMENTS_BAD;
		goto err_uninit;
	}

	if ((sCtx->cryptCtx.mechanism->mechanism == CKM_AES_ECB) ||
		(sCtx->cryptCtx.mechanism->mechanism == CKM_AES_CBC) ) {
			if ((ulEncryptedDataLen & (HSE_AES_BLOCK_LEN - 1)) != 0) {
				rc = CKR_ARGUMENTS_BAD;
				goto err_uninit;
			}
	}

	gCtx->mtxFns.lock(gCtx->keyMtx);
	key = (struct hse_keyObject *)list_seek(&gCtx->object_list, &sCtx->cryptCtx.keyHandle);
	gCtx->mtxFns.unlock(gCtx->keyMtx);
	if (key == NULL) {
		rc = CKR_KEY_HANDLE_INVALID;
		goto err_uninit;
	}

	if ((sCtx->cryptCtx.mechanism->mechanism == CKM_RSA_PKCS) ||
		(sCtx->cryptCtx.mechanism->mechanism == CKM_RSA_PKCS_OAEP)) {
		key_bit_length = hse_get_key_bit_length(key);
		/* The input cipher text length should be equal to the key size */
		if (ulEncryptedDataLen != (key_bit_length >> 3)) {
			rc = CKR_ARGUMENTS_BAD;
			goto err_uninit;
		}
	}

	input = hse_mem_alloc(ulEncryptedDataLen);
	if (input == NULL) {
		rc = CKR_HOST_MEMORY;
		goto err_uninit;
	}
	hse_memcpy(input, pEncryptedData, ulEncryptedDataLen);

	output_len = hse_mem_alloc(sizeof(uint32_t));
	if (output_len == NULL) {
		rc = CKR_HOST_MEMORY;
		goto err_free_input;
	}

	if ((sCtx->cryptCtx.mechanism->mechanism == CKM_AES_ECB) ||
		(sCtx->cryptCtx.mechanism->mechanism == CKM_AES_CBC) ||
		(sCtx->cryptCtx.mechanism->mechanism == CKM_AES_CTR) ||
		(sCtx->cryptCtx.mechanism->mechanism == CKM_AES_GCM)) {
		/* For AES, the output length is equal to the input length  */
		hse_memcpy(output_len, &ulEncryptedDataLen, sizeof(uint32_t));
		if (*(uint32_t *)output_len > *pulDataLen) {
			/* tell the required size */
			*pulDataLen = *(uint32_t *)output_len;

			rc = CKR_BUFFER_TOO_SMALL;
			goto err_free_output_len;
		}
	} else if ((sCtx->cryptCtx.mechanism->mechanism == CKM_RSA_PKCS) ||
				(sCtx->cryptCtx.mechanism->mechanism == CKM_RSA_PKCS_OAEP)) {
		/* to be safe, we allocate the max. length */
		*(uint32_t *)output_len = rsa_ciphering_get_max_input_length(key_bit_length, sCtx->cryptCtx.mechanism);
	}

	output = hse_mem_alloc(*(uint32_t *)output_len);
	if (output == NULL) {
		rc = CKR_HOST_MEMORY;
		goto err_free_output_len;
	}

	if (sCtx->cryptCtx.mechanism->pParameter != NULL) {
		if (sCtx->cryptCtx.mechanism->mechanism == CKM_RSA_PKCS_OAEP) {
			oaep_params = (CK_RSA_PKCS_OAEP_PARAMS *)sCtx->cryptCtx.mechanism->pParameter;
		} else {
			pIV = hse_mem_alloc(sCtx->cryptCtx.mechanism->ulParameterLen);
			if (pIV == NULL) {
				rc = CKR_HOST_MEMORY;
				goto err_free_output;
			}
			hse_memcpy(pIV, sCtx->cryptCtx.mechanism->pParameter, sCtx->cryptCtx.mechanism->ulParameterLen);
		}
	}

	if (sCtx->cryptCtx.mechanism->mechanism == CKM_AES_GCM) {
		/* HSE requires GCM valid Tag sizes 4, 8, 12, 13, 14, 15, 16 bytes. Can not be 0.
		 * Use the length 16 for the tag here. */
		gcm_tag = hse_mem_alloc(16u);
		if (gcm_tag == NULL) {
			rc = CKR_HOST_MEMORY;
			goto err_free_piv;
		}
	}

	switch (sCtx->cryptCtx.mechanism->mechanism) {
		case CKM_AES_ECB:

			sym_cipher_srv = &srv_desc.hseSrv.symCipherReq;

			srv_desc.srvId = HSE_SRV_ID_SYM_CIPHER;
			sym_cipher_srv->accessMode = HSE_ACCESS_MODE_ONE_PASS;
			sym_cipher_srv->streamId = 0u;
			sym_cipher_srv->cipherAlgo = HSE_CIPHER_ALGO_AES;
			sym_cipher_srv->cipherBlockMode = HSE_CIPHER_BLOCK_MODE_ECB;
			sym_cipher_srv->cipherDir = HSE_CIPHER_DIR_DECRYPT;
			sym_cipher_srv->sgtOption = HSE_SGT_OPTION_NONE;
			sym_cipher_srv->keyHandle = key->key_handle;

			if (sCtx->cryptCtx.mechanism->pParameter != NULL) {
				sym_cipher_srv->pIV = hse_virt_to_dma(pIV);
			} else {
				sym_cipher_srv->pIV = 0u; /* IV is not required for ecb */
			}

			sym_cipher_srv->inputLength = ulEncryptedDataLen;
			sym_cipher_srv->pInput = hse_virt_to_dma(input);
			sym_cipher_srv->pOutput= hse_virt_to_dma(output);

			break;

		case CKM_AES_CBC:

			sym_cipher_srv = &srv_desc.hseSrv.symCipherReq;

			srv_desc.srvId = HSE_SRV_ID_SYM_CIPHER;
			sym_cipher_srv->accessMode = HSE_ACCESS_MODE_ONE_PASS;
			sym_cipher_srv->streamId = 0u;
			sym_cipher_srv->cipherAlgo = HSE_CIPHER_ALGO_AES;
			sym_cipher_srv->cipherBlockMode = HSE_CIPHER_BLOCK_MODE_CBC;
			sym_cipher_srv->cipherDir = HSE_CIPHER_DIR_DECRYPT;
			sym_cipher_srv->sgtOption = HSE_SGT_OPTION_NONE;
			sym_cipher_srv->keyHandle = key->key_handle;
			sym_cipher_srv->pIV = hse_virt_to_dma(pIV);
			sym_cipher_srv->inputLength = ulEncryptedDataLen;
			sym_cipher_srv->pInput = hse_virt_to_dma(input);
			sym_cipher_srv->pOutput= hse_virt_to_dma(output);

			break;

		case CKM_AES_CTR:

			sym_cipher_srv = &srv_desc.hseSrv.symCipherReq;

			srv_desc.srvId = HSE_SRV_ID_SYM_CIPHER;
			sym_cipher_srv->accessMode = HSE_ACCESS_MODE_ONE_PASS;
			sym_cipher_srv->streamId = 0u;
			sym_cipher_srv->cipherAlgo = HSE_CIPHER_ALGO_AES;
			sym_cipher_srv->cipherBlockMode = HSE_CIPHER_BLOCK_MODE_CTR;
			sym_cipher_srv->cipherDir = HSE_CIPHER_DIR_DECRYPT;
			sym_cipher_srv->sgtOption = HSE_SGT_OPTION_NONE;
			sym_cipher_srv->keyHandle = key->key_handle;
			sym_cipher_srv->pIV = hse_virt_to_dma(pIV);
			sym_cipher_srv->inputLength = ulEncryptedDataLen;
			sym_cipher_srv->pInput = hse_virt_to_dma(input);
			sym_cipher_srv->pOutput= hse_virt_to_dma(output);

			break;
		case CKM_AES_GCM:

			aead_srv = &srv_desc.hseSrv.aeadReq;

			srv_desc.srvId = HSE_SRV_ID_AEAD;
			aead_srv->accessMode = HSE_ACCESS_MODE_ONE_PASS;
			aead_srv->streamId = 0u;
			aead_srv->authCipherMode = HSE_AUTH_CIPHER_MODE_GCM;
			aead_srv->cipherDir = HSE_CIPHER_DIR_DECRYPT;
			aead_srv->keyHandle = key->key_handle;
			aead_srv->ivLength = sCtx->cryptCtx.mechanism->ulParameterLen;
			aead_srv->pIV = hse_virt_to_dma(pIV);
			aead_srv->aadLength = 0u;
			aead_srv->pAAD = 0u;
			aead_srv->sgtOption = HSE_SGT_OPTION_NONE;
			aead_srv->inputLength = ulEncryptedDataLen;
			aead_srv->pInput = hse_virt_to_dma(input);
			aead_srv->tagLength = 16u;
			aead_srv->pTag = hse_virt_to_dma(gcm_tag);
			aead_srv->pOutput = hse_virt_to_dma(output);

			break;

		case CKM_RSA_PKCS:
			rsa_cipher_srv = &srv_desc.hseSrv.rsaCipherReq;

			srv_desc.srvId = HSE_SRV_ID_RSA_CIPHER;
			rsa_cipher_srv->cipherDir = HSE_CIPHER_DIR_DECRYPT;
			rsa_cipher_srv->keyHandle = key->key_handle;
			rsa_cipher_srv->inputLength = ulEncryptedDataLen;
			rsa_cipher_srv->pInput = hse_virt_to_dma(input);
			rsa_cipher_srv->pOutputLength = hse_virt_to_dma(output_len);
			rsa_cipher_srv->pOutput = hse_virt_to_dma(output);

			rsa_cipher_srv->rsaScheme.rsaAlgo = HSE_RSA_ALGO_RSAES_PKCS1_V15;
			break;

		case CKM_RSA_PKCS_OAEP:
			rsa_cipher_srv = &srv_desc.hseSrv.rsaCipherReq;

			srv_desc.srvId = HSE_SRV_ID_RSA_CIPHER;
			rsa_cipher_srv->cipherDir = HSE_CIPHER_DIR_DECRYPT;
			rsa_cipher_srv->keyHandle = key->key_handle;
			rsa_cipher_srv->inputLength = ulEncryptedDataLen;
			rsa_cipher_srv->pInput = hse_virt_to_dma(input);
			rsa_cipher_srv->pOutputLength = hse_virt_to_dma(output_len);
			rsa_cipher_srv->pOutput = hse_virt_to_dma(output);

			rsa_cipher_srv->rsaScheme.rsaAlgo = HSE_RSA_ALGO_RSAES_OAEP;
			rsa_cipher_srv->rsaScheme.sch.rsaOAEP.hashAlgo = hse_pkcs_hash_alg_translate(oaep_params->hashAlg);
			rsa_cipher_srv->rsaScheme.sch.rsaOAEP.labelLength = 0;
			rsa_cipher_srv->rsaScheme.sch.rsaOAEP.pLabel = 0;
			break;

		default:
			rc = CKR_ARGUMENTS_BAD;
			goto err_free_tag;
	}

	err = hse_srv_req_sync(sCtx->sID, &srv_desc, sizeof(srv_desc));
	if (err) {
		rc = CKR_FUNCTION_FAILED;
		goto err_free_tag;
	}

	/* check for output buffer length */
	if ((sCtx->cryptCtx.mechanism->mechanism == CKM_RSA_PKCS) ||
		(sCtx->cryptCtx.mechanism->mechanism == CKM_RSA_PKCS_OAEP)) {
		if (*(uint32_t *)output_len > *pulDataLen) {
			/* tell the required size */
			*pulDataLen = *(uint32_t *)output_len;

			rc = CKR_BUFFER_TOO_SMALL;
			goto err_free_tag;
		}
	}

	hse_memcpy(pData, output, *(uint32_t *)output_len);
	hse_memcpy(pulDataLen, output_len, sizeof(uint32_t));

err_free_tag:
	hse_mem_free(gcm_tag);
err_free_piv:
	hse_mem_free(pIV);
err_free_output:
	hse_mem_free(output);
err_free_output_len:
	hse_mem_free(output_len);
err_free_input:
	hse_mem_free(input);
err_uninit:
	if (rc != CKR_BUFFER_TOO_SMALL) {
		sCtx->cryptCtx.init = CK_FALSE;
		if (sCtx->cryptCtx.cache != NULL) {
			free(sCtx->cryptCtx.cache);
			sCtx->cryptCtx.cache = NULL;
		}
	}

	return rc;
}

CK_DEFINE_FUNCTION(CK_RV, C_SignInit)(
		CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,
		CK_OBJECT_HANDLE hKey
)
{
	struct globalCtx *gCtx = getCtx();
	struct sessionCtx *sCtx = getSessionCtx(hSession);

	if (gCtx->cryptokiInit == CK_FALSE)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!sCtx || sCtx->sessionInit == CK_FALSE)
		return CKR_SESSION_HANDLE_INVALID;

	if (sCtx->signCtx.init == CK_TRUE)
		return CKR_OPERATION_ACTIVE;

	if (pMechanism == NULL)
		return CKR_ARGUMENTS_BAD;

	gCtx->mtxFns.lock(gCtx->keyMtx);
	if (list_seek(&gCtx->object_list, &hKey) == NULL) {
		gCtx->mtxFns.unlock(gCtx->keyMtx);
		return CKR_KEY_HANDLE_INVALID;
	}
	gCtx->mtxFns.unlock(gCtx->keyMtx);

	sCtx->signCtx.init = CK_TRUE;
	sCtx->signCtx.mechanism = pMechanism;
	sCtx->signCtx.keyHandle = hKey;

	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_Sign)(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pData,
		CK_ULONG ulDataLen,
		CK_BYTE_PTR pSignature,
		CK_ULONG_PTR pulSignatureLen
)
{
	struct globalCtx *gCtx = getCtx();
	struct sessionCtx *sCtx = getSessionCtx(hSession);
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	hseSignSrv_t *sign_srv;
	hseSignScheme_t *sign_scheme;
	void *input, *sign0 = NULL, *sign1 = NULL, *output_len;
	struct hse_keyObject *key;
	CK_RV rc = CKR_OK;
	int err;
	CK_RSA_PKCS_PSS_PARAMS *rsa_pss_param;
	hseMacSrv_t *mac_srv = NULL;

	if (gCtx->cryptokiInit == CK_FALSE)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!sCtx || sCtx->sessionInit == CK_FALSE)
		return CKR_SESSION_HANDLE_INVALID;

	if (sCtx->signCtx.init == CK_FALSE)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (pData == NULL) {
		rc = CKR_DATA_INVALID;
		goto err_uninit;
	}

	if (ulDataLen == 0) {
		rc = CKR_DATA_LEN_RANGE;
		goto err_uninit;
	}

	if (pSignature == NULL) {
		rc = CKR_SIGNATURE_INVALID;
		goto err_uninit;
	}

	if (pulSignatureLen == NULL) {
		rc = CKR_SIGNATURE_LEN_RANGE;
		goto err_uninit;
	}

	gCtx->mtxFns.lock(gCtx->keyMtx);
	key = (struct hse_keyObject *)list_seek(&gCtx->object_list, &sCtx->signCtx.keyHandle);
	gCtx->mtxFns.unlock(gCtx->keyMtx);
	if (key == NULL) {
		rc = CKR_KEY_HANDLE_INVALID;
		goto err_uninit;
	}

	input = hse_mem_alloc(ulDataLen);
	if (input == NULL) {
		rc = CKR_HOST_MEMORY;
		goto err_uninit;
	}
	hse_memcpy(input, pData, ulDataLen);

	output_len = hse_mem_alloc(sizeof(uint32_t));
	if (output_len == NULL) {
		rc = CKR_HOST_MEMORY;
		goto err_free_input;
	}

	/* check the output length */
	*(uint32_t *)output_len = sig_get_out_length(key, sCtx->signCtx.mechanism);
	if (*(uint32_t *)output_len > *pulSignatureLen) {
		*pulSignatureLen = *(uint32_t *)output_len;
		rc = CKR_BUFFER_TOO_SMALL;
		goto err_free_output_len;
	}
	hse_memcpy(output_len, pulSignatureLen, sizeof(uint32_t));

	sign0 = hse_mem_alloc(*(uint32_t *)output_len);
	if (sign0 == NULL) {
		rc = CKR_HOST_MEMORY;
		goto err_free_output_len;
	}

	sign_srv = &srv_desc.hseSrv.signReq;
	sign_scheme = &sign_srv->signScheme;

	switch (sCtx->signCtx.mechanism->mechanism) {
		case CKM_RSA_PKCS:
		case CKM_SHA1_RSA_PKCS:
		case CKM_SHA256_RSA_PKCS:
		case CKM_SHA384_RSA_PKCS:
		case CKM_SHA512_RSA_PKCS:
			sign_scheme->signSch = HSE_SIGN_RSASSA_PKCS1_V15;
			sign_scheme->sch.rsaPkcs1v15.hashAlgo = hse_get_hash_alg(sCtx->signCtx.mechanism->mechanism);
			sign_srv->pSignatureLength[0] = hse_virt_to_dma(output_len);
			sign_srv->pSignatureLength[1] = 0u;
			sign_srv->pSignature[0] = hse_virt_to_dma(sign0);
			sign_srv->pSignature[1] = 0u;
			if (CKM_RSA_PKCS == sCtx->signCtx.mechanism->mechanism) {
				sign_srv->bInputIsHashed = 1u;
				/* The hashing algorithm must still be provided as it is included in the signature for various schemes
				 * But there is no input parameter for CKM_RSA_PKCS. Use the hardcode value (SHA512).  */
				sign_scheme->sch.rsaPkcs1v15.hashAlgo = HSE_HASH_ALGO_SHA2_512;
			} else
				sign_srv->bInputIsHashed = 0u;

			break;
		case CKM_RSA_PKCS_PSS:
		case CKM_SHA1_RSA_PKCS_PSS:
		case CKM_SHA256_RSA_PKCS_PSS:
		case CKM_SHA384_RSA_PKCS_PSS:
		case CKM_SHA512_RSA_PKCS_PSS:
			rsa_pss_param = (CK_RSA_PKCS_PSS_PARAMS *)sCtx->signCtx.mechanism->pParameter;
			if (rsa_pss_param == NULL) {
				rc = CKR_ARGUMENTS_BAD;
				goto err_free_sign0;
			}

			sign_scheme->signSch = HSE_SIGN_RSASSA_PSS;
			sign_scheme->sch.rsaPss.hashAlgo = hse_pkcs_hash_alg_translate(rsa_pss_param->hashAlg);
			sign_scheme->sch.rsaPss.saltLength = rsa_pss_param->sLen;
			sign_srv->pSignatureLength[0] = hse_virt_to_dma(output_len);
			sign_srv->pSignatureLength[1] = 0u;
			sign_srv->pSignature[0] = hse_virt_to_dma(sign0);
			sign_srv->pSignature[1] = 0u;

			if (CKM_RSA_PKCS_PSS == sCtx->signCtx.mechanism->mechanism)
				sign_srv->bInputIsHashed = 1u;
			else
				sign_srv->bInputIsHashed = 0u;

			break;
		case CKM_ECDSA:
		case CKM_ECDSA_SHA1:
		case CKM_ECDSA_SHA224:
		case CKM_ECDSA_SHA256:
		case CKM_ECDSA_SHA384:
		case CKM_ECDSA_SHA512:
			/* we only get one output length, which has to hold (r,s)
			 * (r,s) are both the length of the used curve in bytes - equal
			 * as such, assume it is doubled, and halve it */
			*(uint32_t *)output_len = *(uint32_t *)output_len / 2;
			sign1 = (uint8_t *)sign0 + (*(uint32_t *)output_len);

			sign_scheme->signSch = HSE_SIGN_ECDSA;
			sign_scheme->sch.ecdsa.hashAlgo = hse_get_hash_alg(sCtx->signCtx.mechanism->mechanism);
			sign_srv->pSignatureLength[0] = hse_virt_to_dma(output_len);
			sign_srv->pSignatureLength[1] = hse_virt_to_dma(output_len);
			sign_srv->pSignature[0] = hse_virt_to_dma(sign0);
			sign_srv->pSignature[1] = hse_virt_to_dma(sign1);

			if (CKM_ECDSA == sCtx->signCtx.mechanism->mechanism)
				sign_srv->bInputIsHashed = 1u;
			else
				sign_srv->bInputIsHashed = 0u;

			break;
		case CKM_AES_CMAC:
			mac_srv = &srv_desc.hseSrv.macReq;
			mac_srv->macScheme.macAlgo = HSE_MAC_ALGO_CMAC;
			mac_srv->macScheme.sch.cmac.cipherAlgo = HSE_CIPHER_ALGO_AES;
			break;
		case CKM_SHA224_HMAC:
		case CKM_SHA256_HMAC:
		case CKM_SHA384_HMAC:
		case CKM_SHA512_HMAC:
			mac_srv = &srv_desc.hseSrv.macReq;
			mac_srv->macScheme.macAlgo = HSE_MAC_ALGO_HMAC;
			mac_srv->macScheme.sch.hmac.hashAlgo = hse_get_hash_alg(sCtx->signCtx.mechanism->mechanism);
			break;
		default:
			rc = CKR_ARGUMENTS_BAD;
			goto err_free_sign0;
	}

	if (!mac_srv) {
		srv_desc.srvId = HSE_SRV_ID_SIGN;
		sign_srv->accessMode = HSE_ACCESS_MODE_ONE_PASS;
		sign_srv->streamId = 0u;
		sign_srv->authDir = HSE_AUTH_DIR_GENERATE;
		sign_srv->keyHandle = key->key_handle;
		sign_srv->sgtOption = HSE_SGT_OPTION_NONE;
		sign_srv->inputLength = ulDataLen;
		sign_srv->pInput = hse_virt_to_dma(input);
	} else {
		srv_desc.srvId = HSE_SRV_ID_MAC;
		mac_srv->accessMode = HSE_ACCESS_MODE_ONE_PASS;
		mac_srv->streamId = 0u;
		mac_srv->authDir = HSE_AUTH_DIR_GENERATE;
		mac_srv->sgtOption = HSE_SGT_OPTION_NONE;
		mac_srv->keyHandle = key->key_handle;
		mac_srv->inputLength = ulDataLen;
		mac_srv->pInput = hse_virt_to_dma(input);
		mac_srv->pTagLength = hse_virt_to_dma(output_len);
		mac_srv->pTag = hse_virt_to_dma(sign0);
	}

	err = hse_srv_req_sync(sCtx->sID, &srv_desc, sizeof(srv_desc));
	if (err) {
		rc = CKR_FUNCTION_FAILED;
		goto err_free_sign0;
	}

	switch (sCtx->signCtx.mechanism->mechanism) {
		case CKM_RSA_PKCS:
		case CKM_SHA1_RSA_PKCS:
		case CKM_SHA256_RSA_PKCS:
		case CKM_SHA384_RSA_PKCS:
		case CKM_SHA512_RSA_PKCS:
		case CKM_RSA_PKCS_PSS:
		case CKM_SHA1_RSA_PKCS_PSS:
		case CKM_SHA256_RSA_PKCS_PSS:
		case CKM_SHA384_RSA_PKCS_PSS:
		case CKM_SHA512_RSA_PKCS_PSS:
		case CKM_AES_CMAC:
		case CKM_SHA224_HMAC:
		case CKM_SHA256_HMAC:
		case CKM_SHA384_HMAC:
		case CKM_SHA512_HMAC:

			hse_memcpy(pSignature, sign0, *(uint32_t *)output_len);
			hse_memcpy(pulSignatureLen, output_len, sizeof(uint32_t));

			break;
		case CKM_ECDSA:
		case CKM_ECDSA_SHA1:
		case CKM_ECDSA_SHA224:
		case CKM_ECDSA_SHA256:
		case CKM_ECDSA_SHA384:
		case CKM_ECDSA_SHA512:

			hse_memcpy(pSignature, sign0, *(uint32_t *)output_len);
			hse_memcpy(pSignature + *(uint32_t *)output_len, sign1, *(uint32_t *)output_len);

			/* restore actual length */
			*(uint32_t *)output_len = *(uint32_t *)output_len * 2;
			hse_memcpy(pulSignatureLen, output_len, sizeof(uint32_t));

			break;
		default:
			rc = CKR_ARGUMENTS_BAD;
			goto err_free_sign0;
	}

err_free_sign0:
	hse_mem_free(sign0);
err_free_output_len:
	hse_mem_free(output_len);
err_free_input:
	hse_mem_free(input);
err_uninit:
	if (rc != CKR_BUFFER_TOO_SMALL)
		sCtx->signCtx.init = CK_FALSE;

	return rc;
}

CK_DEFINE_FUNCTION(CK_RV, C_VerifyInit)(
		CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,
		CK_OBJECT_HANDLE hKey
)
{
	struct globalCtx *gCtx = getCtx();
	struct sessionCtx *sCtx = getSessionCtx(hSession);

	if (gCtx->cryptokiInit == CK_FALSE)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!sCtx || sCtx->sessionInit == CK_FALSE)
		return CKR_SESSION_HANDLE_INVALID;

	if (sCtx->signCtx.init == CK_TRUE)
		return CKR_OPERATION_ACTIVE;

	if (pMechanism == NULL)
		return CKR_ARGUMENTS_BAD;

	gCtx->mtxFns.lock(gCtx->keyMtx);
	if (list_seek(&gCtx->object_list, &hKey) == NULL) {
		gCtx->mtxFns.unlock(gCtx->keyMtx);
		return CKR_KEY_HANDLE_INVALID;
	}
	gCtx->mtxFns.unlock(gCtx->keyMtx);

	sCtx->signCtx.init = CK_TRUE;
	sCtx->signCtx.mechanism = pMechanism;
	sCtx->signCtx.keyHandle = hKey;

	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_Verify)(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pData,
		CK_ULONG ulDataLen,
		CK_BYTE_PTR pSignature,
		CK_ULONG ulSignatureLen
)
{
	struct globalCtx *gCtx = getCtx();
	struct sessionCtx *sCtx = getSessionCtx(hSession);
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	hseSignSrv_t *sign_srv;
	hseSignScheme_t *sign_scheme;
	void *input, *sign0 = NULL, *sign1 = NULL, *output_len;
	struct hse_keyObject *key;
	CK_RV rc = CKR_OK;
	int err;
	CK_RSA_PKCS_PSS_PARAMS *rsa_pss_param;
	hseMacSrv_t *mac_srv = NULL;

	if (gCtx->cryptokiInit == CK_FALSE)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!sCtx || sCtx->sessionInit == CK_FALSE)
		return CKR_SESSION_HANDLE_INVALID;

	if (sCtx->signCtx.init == CK_FALSE)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (pData == NULL) {
		rc = CKR_DATA_INVALID;
		goto err_uninit;
	}

	if (ulDataLen == 0) {
		rc = CKR_DATA_LEN_RANGE;
		goto err_uninit;
	}

	if (pSignature == NULL) {
		rc = CKR_SIGNATURE_INVALID;
		goto err_uninit;
	}

	if (ulSignatureLen == 0) {
		rc = CKR_SIGNATURE_LEN_RANGE;
		goto err_uninit;
	}

	gCtx->mtxFns.lock(gCtx->keyMtx);
	key = (struct hse_keyObject *)list_seek(&gCtx->object_list, &sCtx->signCtx.keyHandle);
	gCtx->mtxFns.unlock(gCtx->keyMtx);
	if (key == NULL) {
		rc = CKR_KEY_HANDLE_INVALID;
		goto err_uninit;
	}

	input = hse_mem_alloc(ulDataLen);
	if (input == NULL) {
		rc = CKR_HOST_MEMORY;
		goto err_uninit;
	}
	hse_memcpy(input, pData, ulDataLen);

	output_len = hse_mem_alloc(sizeof(uint32_t));
	if (output_len == NULL) {
		rc = CKR_HOST_MEMORY;
		goto err_free_input;
	}
	hse_memcpy(output_len, &ulSignatureLen, sizeof(uint32_t));

	sign0 = hse_mem_alloc(ulSignatureLen);
	if (sign0 == NULL) {
		rc = CKR_HOST_MEMORY;
		goto err_free_output_len;
	}
	hse_memcpy(sign0, pSignature, ulSignatureLen);

	sign_srv = &srv_desc.hseSrv.signReq;
	sign_scheme = &sign_srv->signScheme;

	switch (sCtx->signCtx.mechanism->mechanism) {
		case CKM_RSA_PKCS:
		case CKM_SHA1_RSA_PKCS:
		case CKM_SHA256_RSA_PKCS:
		case CKM_SHA384_RSA_PKCS:
		case CKM_SHA512_RSA_PKCS:
			sign_scheme->signSch = HSE_SIGN_RSASSA_PKCS1_V15;
			sign_scheme->sch.rsaPkcs1v15.hashAlgo = hse_get_hash_alg(sCtx->signCtx.mechanism->mechanism);
			sign_srv->pSignatureLength[0] = hse_virt_to_dma(output_len);
			sign_srv->pSignatureLength[1] = 0u;
			sign_srv->pSignature[0] = hse_virt_to_dma(sign0); /* rsa */
			sign_srv->pSignature[1] = 0u;

			if (CKM_RSA_PKCS == sCtx->signCtx.mechanism->mechanism) {
				sign_srv->bInputIsHashed = 1u;
				/* The hashing algorithm must still be provided as it is included in the signature for various schemes
				 * But there is no input parameter for CKM_RSA_PKCS. Use the hardcode value (SHA512).  */
				sign_scheme->sch.rsaPkcs1v15.hashAlgo = HSE_HASH_ALGO_SHA2_512;
			} else
				sign_srv->bInputIsHashed = 0u;

			break;
		case CKM_RSA_PKCS_PSS:
		case CKM_SHA1_RSA_PKCS_PSS:
		case CKM_SHA256_RSA_PKCS_PSS:
		case CKM_SHA384_RSA_PKCS_PSS:
		case CKM_SHA512_RSA_PKCS_PSS:
			rsa_pss_param = (CK_RSA_PKCS_PSS_PARAMS *)sCtx->signCtx.mechanism->pParameter;
			if (rsa_pss_param == NULL) {
				rc = CKR_ARGUMENTS_BAD;
				goto err_free_sign0;
			}

			sign_scheme->signSch = HSE_SIGN_RSASSA_PSS;
			sign_scheme->sch.rsaPss.hashAlgo = hse_pkcs_hash_alg_translate(rsa_pss_param->hashAlg);
			sign_scheme->sch.rsaPss.saltLength = rsa_pss_param->sLen;
			sign_srv->pSignatureLength[0] = hse_virt_to_dma(output_len);
			sign_srv->pSignatureLength[1] = 0u;
			sign_srv->pSignature[0] = hse_virt_to_dma(sign0);
			sign_srv->pSignature[1] = 0u;

			if (CKM_RSA_PKCS_PSS == sCtx->signCtx.mechanism->mechanism)
				sign_srv->bInputIsHashed = 1u;
			else
				sign_srv->bInputIsHashed = 0u;

			break;
		case CKM_ECDSA:
		case CKM_ECDSA_SHA1:
		case CKM_ECDSA_SHA224:
		case CKM_ECDSA_SHA256:
		case CKM_ECDSA_SHA384:
		case CKM_ECDSA_SHA512:
			/* we only get one signature input and length
			 * (r,s) are the same length
			 * assume the signature contains both, one after the other */
			*(uint32_t *)output_len = *(uint32_t *)output_len / 2;
			sign1 = (uint8_t *)sign0 + (*(uint32_t *)output_len);

			sign_scheme->signSch = HSE_SIGN_ECDSA;
			sign_scheme->sch.ecdsa.hashAlgo = hse_get_hash_alg(sCtx->signCtx.mechanism->mechanism);

			sign_srv->pSignatureLength[0] = hse_virt_to_dma(output_len);
			sign_srv->pSignatureLength[1] = hse_virt_to_dma(output_len);
			sign_srv->pSignature[0] = hse_virt_to_dma(sign0);
			sign_srv->pSignature[1] = hse_virt_to_dma(sign1);

			if (CKM_ECDSA == sCtx->signCtx.mechanism->mechanism)
				sign_srv->bInputIsHashed = 1u;
			else
				sign_srv->bInputIsHashed = 0u;

			break;
		case CKM_AES_CMAC:
			mac_srv = &srv_desc.hseSrv.macReq;
			mac_srv->macScheme.macAlgo = HSE_MAC_ALGO_CMAC;
			mac_srv->macScheme.sch.cmac.cipherAlgo = HSE_CIPHER_ALGO_AES;
			break;
		case CKM_SHA224_HMAC:
		case CKM_SHA256_HMAC:
		case CKM_SHA384_HMAC:
		case CKM_SHA512_HMAC:
			mac_srv = &srv_desc.hseSrv.macReq;
			mac_srv->macScheme.macAlgo = HSE_MAC_ALGO_HMAC;
			mac_srv->macScheme.sch.hmac.hashAlgo = hse_get_hash_alg(sCtx->signCtx.mechanism->mechanism);
			break;
		default:
			rc = CKR_ARGUMENTS_BAD;
			goto err_free_sign0;
	}

	if (!mac_srv) {
		srv_desc.srvId = HSE_SRV_ID_SIGN;
		sign_srv->accessMode = HSE_ACCESS_MODE_ONE_PASS;
		sign_srv->streamId = 0u;
		sign_srv->authDir = HSE_AUTH_DIR_VERIFY;
		sign_srv->keyHandle = key->key_handle;
		sign_srv->sgtOption = HSE_SGT_OPTION_NONE;
		sign_srv->inputLength = ulDataLen;
		sign_srv->pInput = hse_virt_to_dma(input);
	} else {
		srv_desc.srvId = HSE_SRV_ID_MAC;
		mac_srv->accessMode = HSE_ACCESS_MODE_ONE_PASS;
		mac_srv->streamId = 0u;
		mac_srv->authDir = HSE_AUTH_DIR_VERIFY;
		mac_srv->sgtOption = HSE_SGT_OPTION_NONE;
		mac_srv->keyHandle = key->key_handle;
		mac_srv->inputLength = ulDataLen;
		mac_srv->pInput = hse_virt_to_dma(input);
		mac_srv->pTagLength = hse_virt_to_dma(output_len);
		mac_srv->pTag = hse_virt_to_dma(sign0);
	}

	err = hse_srv_req_sync(sCtx->sID, &srv_desc, sizeof(srv_desc));
	if (!err) {
		rc = CKR_OK;
	} else if (err == EBADMSG) {
		rc = CKR_SIGNATURE_INVALID;
	} else {
		rc = CKR_FUNCTION_FAILED;
	}

err_free_sign0:
	hse_mem_free(sign0);
err_free_output_len:
	hse_mem_free(output_len);
err_free_input:
	hse_mem_free(input);
err_uninit:
	sCtx->signCtx.init = CK_FALSE;

	return rc;
}

CK_DEFINE_FUNCTION(CK_RV, C_EncryptUpdate)(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pPart,
		CK_ULONG ulPartLen,
		CK_BYTE_PTR pEncryptedPart,
		CK_ULONG_PTR pulEncryptedPartLen
)
{
	struct globalCtx *gCtx = getCtx();
	struct sessionCtx *sCtx = getSessionCtx(hSession);
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	hseSymCipherSrv_t *sym_cipher_srv;
	void *input = NULL, *output = NULL, *pIV = NULL;
	struct hse_keyObject *key;
	CK_RV rc = CKR_OK;
	int err;
	uint32_t bytes_left, full_blocks;
	hseAccessMode_t access_mode;

	if (gCtx->cryptokiInit == CK_FALSE)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!sCtx || sCtx->sessionInit == CK_FALSE)
		return CKR_SESSION_HANDLE_INVALID;

	if (sCtx->cryptCtx.init == CK_FALSE)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((pPart == NULL) || (ulPartLen == 0) || (pulEncryptedPartLen == NULL)) {
		rc = CKR_ARGUMENTS_BAD;
		goto err_uninit;
	}

	if (pEncryptedPart == NULL) {
		/* if NULL, upper layer expects to receive needed size */
		bytes_left = sCtx->cryptCtx.cache_idx + ulPartLen;
		full_blocks = bytes_left - (bytes_left % sCtx->cryptCtx.blockSize);
		/* the calculated length is not precise, max deviation is one block size */
		*pulEncryptedPartLen = full_blocks;
		return CKR_OK;
	}

	gCtx->mtxFns.lock(gCtx->keyMtx);
	key = (struct hse_keyObject *)list_seek(&gCtx->object_list, &sCtx->cryptCtx.keyHandle);
	gCtx->mtxFns.unlock(gCtx->keyMtx);
	if (key == NULL) {
		rc = CKR_KEY_HANDLE_INVALID;
		goto err_uninit;
	}

	if ((sCtx->cryptCtx.mechanism->mechanism != CKM_AES_ECB) &&
		(sCtx->cryptCtx.mechanism->mechanism != CKM_AES_CBC) &&
		(sCtx->cryptCtx.mechanism->mechanism != CKM_AES_CTR) ) {
		rc = CKR_FUNCTION_NOT_SUPPORTED;
		goto err_uninit;
	}

	/* input process */
	bytes_left = sCtx->cryptCtx.cache_idx + ulPartLen;
	if (bytes_left < sCtx->cryptCtx.blockSize) {
		/* cache data for next update and exit */
		memcpy(sCtx->cryptCtx.cache + sCtx->cryptCtx.cache_idx, pPart, ulPartLen);
		sCtx->cryptCtx.cache_idx = bytes_left;
		bytes_left = 0;

		/* call for START() with `0` data length */
		if (sCtx->cryptCtx.stream_start == CK_FALSE) {
			*pulEncryptedPartLen = 0;
			return CKR_OK;
		}
	}

	/* round down to nearest multiple of block size */
	full_blocks = bytes_left - (bytes_left % sCtx->cryptCtx.blockSize);

	/* Check length of output buffer. For AES, the output length is equal to the input length  */
	if (*pulEncryptedPartLen < full_blocks) {
		/* tell the required size */
		*pulEncryptedPartLen = full_blocks;

		rc = CKR_BUFFER_TOO_SMALL;
		goto err_uninit;
	}

	if (full_blocks > 0) {
		/* copy full_blocks to dynamic buffer */
		input = hse_mem_alloc(full_blocks);
		if (input == NULL) {
			rc = CKR_HOST_MEMORY;
			goto err_uninit;
		}
		hse_memcpy(input, sCtx->cryptCtx.cache, sCtx->cryptCtx.cache_idx);
		hse_memcpy(input + sCtx->cryptCtx.cache_idx, pPart, full_blocks - sCtx->cryptCtx.cache_idx);
		bytes_left -= full_blocks;

		/* copy residue to block-sized cache */
		if (bytes_left > 0)
			memcpy(sCtx->cryptCtx.cache, pPart + (full_blocks - sCtx->cryptCtx.cache_idx), bytes_left);
			
		sCtx->cryptCtx.cache_idx = bytes_left;

		/* output length is equal to the input length  */
		output = hse_mem_alloc(full_blocks);
		if (output == NULL) {
			rc = CKR_HOST_MEMORY;
			goto err_free_input;
		}
	}

	/* IV input is used only when START */
	if ((sCtx->cryptCtx.stream_start == CK_TRUE) && 
		(sCtx->cryptCtx.mechanism->pParameter != NULL)) {
		pIV = hse_mem_alloc(sCtx->cryptCtx.mechanism->ulParameterLen);
		if (pIV == NULL) {
			rc = CKR_HOST_MEMORY;
			goto err_free_output;
		}
		hse_memcpy(pIV, sCtx->cryptCtx.mechanism->pParameter, sCtx->cryptCtx.mechanism->ulParameterLen);
	}

	if (sCtx->cryptCtx.stream_start) {
		access_mode = HSE_ACCESS_MODE_START;
		sCtx->cryptCtx.stream_start = CK_FALSE;
	} else {
		access_mode = HSE_ACCESS_MODE_UPDATE;
	}

	switch (sCtx->cryptCtx.mechanism->mechanism) {
		case CKM_AES_ECB:

			sym_cipher_srv = &srv_desc.hseSrv.symCipherReq;

			srv_desc.srvId = HSE_SRV_ID_SYM_CIPHER;
			sym_cipher_srv->accessMode = access_mode;
			sym_cipher_srv->streamId = STREAM_ID_ENC_DEC;
			sym_cipher_srv->cipherAlgo = HSE_CIPHER_ALGO_AES;
			sym_cipher_srv->cipherBlockMode = HSE_CIPHER_BLOCK_MODE_ECB;
			sym_cipher_srv->cipherDir = HSE_CIPHER_DIR_ENCRYPT;
			sym_cipher_srv->sgtOption = HSE_SGT_OPTION_NONE;
			sym_cipher_srv->keyHandle = key->key_handle;

			if (sCtx->cryptCtx.mechanism->pParameter != NULL) {
				sym_cipher_srv->pIV = hse_virt_to_dma(pIV);
			} else {
				sym_cipher_srv->pIV = 0u; /* IV is not required for ecb */
			}

			sym_cipher_srv->inputLength = full_blocks;
			sym_cipher_srv->pInput = hse_virt_to_dma(input);
			sym_cipher_srv->pOutput= hse_virt_to_dma(output);

			break;

		case CKM_AES_CBC:

			sym_cipher_srv = &srv_desc.hseSrv.symCipherReq;

			srv_desc.srvId = HSE_SRV_ID_SYM_CIPHER;
			sym_cipher_srv->accessMode = access_mode;
			sym_cipher_srv->streamId = STREAM_ID_ENC_DEC;
			sym_cipher_srv->cipherAlgo = HSE_CIPHER_ALGO_AES;
			sym_cipher_srv->cipherBlockMode = HSE_CIPHER_BLOCK_MODE_CBC;
			sym_cipher_srv->cipherDir = HSE_CIPHER_DIR_ENCRYPT;
			sym_cipher_srv->sgtOption = HSE_SGT_OPTION_NONE;
			sym_cipher_srv->keyHandle = key->key_handle;
			sym_cipher_srv->pIV = hse_virt_to_dma(pIV);
			sym_cipher_srv->inputLength = full_blocks;
			sym_cipher_srv->pInput = hse_virt_to_dma(input);
			sym_cipher_srv->pOutput= hse_virt_to_dma(output);

			break;

		case CKM_AES_CTR:

			sym_cipher_srv = &srv_desc.hseSrv.symCipherReq;

			srv_desc.srvId = HSE_SRV_ID_SYM_CIPHER;
			sym_cipher_srv->accessMode = access_mode;
			sym_cipher_srv->streamId = STREAM_ID_ENC_DEC;
			sym_cipher_srv->cipherAlgo = HSE_CIPHER_ALGO_AES;
			sym_cipher_srv->cipherBlockMode = HSE_CIPHER_BLOCK_MODE_CTR;
			sym_cipher_srv->cipherDir = HSE_CIPHER_DIR_ENCRYPT;
			sym_cipher_srv->sgtOption = HSE_SGT_OPTION_NONE;
			sym_cipher_srv->keyHandle = key->key_handle;
			sym_cipher_srv->pIV = hse_virt_to_dma(pIV);
			sym_cipher_srv->inputLength = full_blocks;
			sym_cipher_srv->pInput = hse_virt_to_dma(input);
			sym_cipher_srv->pOutput= hse_virt_to_dma(output);

			break;

		default:
			rc = CKR_ARGUMENTS_BAD;
			goto err_free_piv;
	}

	err = hse_srv_req_sync(sCtx->sID, &srv_desc, sizeof(srv_desc));
	if (err) {
		rc = CKR_FUNCTION_FAILED;
		goto err_free_piv;
	}

	if (full_blocks > 0)
		hse_memcpy(pEncryptedPart, output, full_blocks);
	*pulEncryptedPartLen = full_blocks;

err_free_piv:
	hse_mem_free(pIV);
err_free_output:
	hse_mem_free(output);
err_free_input:
	hse_mem_free(input);
err_uninit:
	if ((rc != CKR_OK) && (rc != CKR_BUFFER_TOO_SMALL)) {
		sCtx->cryptCtx.init = CK_FALSE;
		if (sCtx->cryptCtx.cache != NULL) {
			free(sCtx->cryptCtx.cache);
			sCtx->cryptCtx.cache = NULL;
		}
	}

	return rc;
}

CK_DEFINE_FUNCTION(CK_RV, C_EncryptFinal)(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pLastEncryptedPart,
		CK_ULONG_PTR pulLastEncryptedPartLen
)
{
	struct globalCtx *gCtx = getCtx();
	struct sessionCtx *sCtx = getSessionCtx(hSession);
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	hseSymCipherSrv_t *sym_cipher_srv;
	void *input = NULL, *output;
	uint8_t input_len = 0;
	struct hse_keyObject *key;
	CK_RV rc = CKR_OK;
	int err;

	if (gCtx->cryptokiInit == CK_FALSE)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!sCtx || sCtx->sessionInit == CK_FALSE)
		return CKR_SESSION_HANDLE_INVALID;

	if (sCtx->cryptCtx.init == CK_FALSE)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (pulLastEncryptedPartLen == NULL) {
		rc = CKR_ARGUMENTS_BAD;
		goto err_uninit;
	}

	if (pLastEncryptedPart == NULL) {
		/* if NULL, upper layer expects to receive needed size */
		*pulLastEncryptedPartLen = sCtx->cryptCtx.cache_idx;
		return CKR_OK;
	}

	gCtx->mtxFns.lock(gCtx->keyMtx);
	key = (struct hse_keyObject *)list_seek(&gCtx->object_list, &sCtx->cryptCtx.keyHandle);
	gCtx->mtxFns.unlock(gCtx->keyMtx);
	if (key == NULL) {
		rc = CKR_KEY_HANDLE_INVALID;
		goto err_uninit;
	}

	/* Check the output length */
	if ((sCtx->cryptCtx.mechanism->mechanism == CKM_AES_ECB) ||
		(sCtx->cryptCtx.mechanism->mechanism == CKM_AES_CBC) ||
		(sCtx->cryptCtx.mechanism->mechanism == CKM_AES_CTR)) {
		/* For AES, the output length is equal to the input length  */
		if (*pulLastEncryptedPartLen < sCtx->cryptCtx.cache_idx) {
			/* tell the required size */
			*pulLastEncryptedPartLen = sCtx->cryptCtx.cache_idx;

			rc = CKR_BUFFER_TOO_SMALL;
			goto err_uninit;
		}
	} else {
		rc = CKR_FUNCTION_NOT_SUPPORTED;
		goto err_uninit;
	}

	/* input length check:
	 * For ECB, CBC & CFB cipher block modes, must be a multiple of block length. Cannot be zero.
     * For remaining cipher block modes, can be any value except zero. */
	input_len = sCtx->cryptCtx.cache_idx;
	if ((sCtx->cryptCtx.mechanism->mechanism == CKM_AES_ECB) ||
		(sCtx->cryptCtx.mechanism->mechanism == CKM_AES_CBC)) {
		/* there is no data left for enc, fill dummy data */
		if (input_len == 0) {
			input_len = sCtx->cryptCtx.blockSize;
		} else if (input_len != sCtx->cryptCtx.blockSize) {
			rc = CKR_DATA_LEN_RANGE;
			goto err_uninit;
		}
	} else {
		/* there is no data left for enc, fill dummy data */
		if (input_len == 0) {
			input_len = sCtx->cryptCtx.blockSize;
		}
	}

	/* input process */
	input = hse_mem_alloc(input_len);
	if (input == NULL) {
		rc = CKR_HOST_MEMORY;
		goto err_uninit;
	}

	hse_memcpy(input, sCtx->cryptCtx.cache, input_len);

	output = hse_mem_alloc(input_len);
	if (output == NULL) {
		rc = CKR_HOST_MEMORY;
		goto err_free_input;
	}

	switch (sCtx->cryptCtx.mechanism->mechanism) {
		case CKM_AES_ECB:

			sym_cipher_srv = &srv_desc.hseSrv.symCipherReq;

			srv_desc.srvId = HSE_SRV_ID_SYM_CIPHER;
			sym_cipher_srv->accessMode = HSE_ACCESS_MODE_FINISH;
			sym_cipher_srv->streamId = STREAM_ID_ENC_DEC;
			sym_cipher_srv->cipherAlgo = HSE_CIPHER_ALGO_AES;
			sym_cipher_srv->cipherBlockMode = HSE_CIPHER_BLOCK_MODE_ECB;
			sym_cipher_srv->cipherDir = HSE_CIPHER_DIR_ENCRYPT;
			sym_cipher_srv->sgtOption = HSE_SGT_OPTION_NONE;
			sym_cipher_srv->keyHandle = key->key_handle;
			sym_cipher_srv->pIV = 0;
			sym_cipher_srv->inputLength = input_len;
			sym_cipher_srv->pInput = hse_virt_to_dma(input);
			sym_cipher_srv->pOutput= hse_virt_to_dma(output);

			break;

		case CKM_AES_CBC:

			sym_cipher_srv = &srv_desc.hseSrv.symCipherReq;

			srv_desc.srvId = HSE_SRV_ID_SYM_CIPHER;
			sym_cipher_srv->accessMode = HSE_ACCESS_MODE_FINISH;
			sym_cipher_srv->streamId = STREAM_ID_ENC_DEC;
			sym_cipher_srv->cipherAlgo = HSE_CIPHER_ALGO_AES;
			sym_cipher_srv->cipherBlockMode = HSE_CIPHER_BLOCK_MODE_CBC;
			sym_cipher_srv->cipherDir = HSE_CIPHER_DIR_ENCRYPT;
			sym_cipher_srv->sgtOption = HSE_SGT_OPTION_NONE;
			sym_cipher_srv->keyHandle = key->key_handle;
			sym_cipher_srv->pIV = 0;
			sym_cipher_srv->inputLength = input_len;
			sym_cipher_srv->pInput = hse_virt_to_dma(input);
			sym_cipher_srv->pOutput= hse_virt_to_dma(output);

			break;

		case CKM_AES_CTR:

			sym_cipher_srv = &srv_desc.hseSrv.symCipherReq;

			srv_desc.srvId = HSE_SRV_ID_SYM_CIPHER;
			sym_cipher_srv->accessMode = HSE_ACCESS_MODE_FINISH;
			sym_cipher_srv->streamId = STREAM_ID_ENC_DEC;
			sym_cipher_srv->cipherAlgo = HSE_CIPHER_ALGO_AES;
			sym_cipher_srv->cipherBlockMode = HSE_CIPHER_BLOCK_MODE_CTR;
			sym_cipher_srv->cipherDir = HSE_CIPHER_DIR_ENCRYPT;
			sym_cipher_srv->sgtOption = HSE_SGT_OPTION_NONE;
			sym_cipher_srv->keyHandle = key->key_handle;
			sym_cipher_srv->pIV = 0;
			sym_cipher_srv->inputLength = input_len;
			sym_cipher_srv->pInput = hse_virt_to_dma(input);
			sym_cipher_srv->pOutput= hse_virt_to_dma(output);

			break;
		default:
			rc = CKR_ARGUMENTS_BAD;
			goto err_free_output;
	}

	err = hse_srv_req_sync(sCtx->sID, &srv_desc, sizeof(srv_desc));
	if (err) {
		rc = CKR_FUNCTION_FAILED;
		goto err_free_output;
	}
	if (sCtx->cryptCtx.cache_idx > 0)
		hse_memcpy(pLastEncryptedPart, output, sCtx->cryptCtx.cache_idx);
	*pulLastEncryptedPartLen = sCtx->cryptCtx.cache_idx;

err_free_output:
	hse_mem_free(output);
err_free_input:
	hse_mem_free(input);
err_uninit:
	if (rc != CKR_BUFFER_TOO_SMALL) {
		sCtx->cryptCtx.init = CK_FALSE;
		if (sCtx->cryptCtx.cache != NULL) {
			free(sCtx->cryptCtx.cache);
			sCtx->cryptCtx.cache = NULL;
		}
	}

	return rc;
}

CK_DEFINE_FUNCTION(CK_RV, C_DecryptUpdate)(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pEncryptedPart,
		CK_ULONG ulEncryptedPartLen,
		CK_BYTE_PTR pPart,
		CK_ULONG_PTR pulPartLen
)
{
	struct globalCtx *gCtx = getCtx();
	struct sessionCtx *sCtx = getSessionCtx(hSession);
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	hseSymCipherSrv_t *sym_cipher_srv;
	void *input = NULL, *output = NULL, *pIV = NULL;
	struct hse_keyObject *key;
	CK_RV rc = CKR_OK;
	int err;
	uint32_t bytes_left, full_blocks;
	hseAccessMode_t access_mode;

	if (gCtx->cryptokiInit == CK_FALSE)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!sCtx || sCtx->sessionInit == CK_FALSE)
		return CKR_SESSION_HANDLE_INVALID;

	if (sCtx->cryptCtx.init == CK_FALSE)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((pEncryptedPart == NULL) || (ulEncryptedPartLen == 0) || (pulPartLen == NULL)) {
		rc = CKR_ARGUMENTS_BAD;
		goto err_uninit;
	}

	if (pPart == NULL) {
		/* if NULL, upper layer expects to receive needed size */
		bytes_left = sCtx->cryptCtx.cache_idx + ulEncryptedPartLen;
		full_blocks = bytes_left - (bytes_left % sCtx->cryptCtx.blockSize);
		/* the calculated length is not precise, max deviation is one block size */
		*pulPartLen = full_blocks;
		return CKR_OK;
	}

	gCtx->mtxFns.lock(gCtx->keyMtx);
	key = (struct hse_keyObject *)list_seek(&gCtx->object_list, &sCtx->cryptCtx.keyHandle);
	gCtx->mtxFns.unlock(gCtx->keyMtx);
	if (key == NULL) {
		rc = CKR_KEY_HANDLE_INVALID;
		goto err_uninit;
	}

	if ((sCtx->cryptCtx.mechanism->mechanism != CKM_AES_ECB) &&
		(sCtx->cryptCtx.mechanism->mechanism != CKM_AES_CBC) &&
		(sCtx->cryptCtx.mechanism->mechanism != CKM_AES_CTR)) {
		rc = CKR_FUNCTION_NOT_SUPPORTED;
		goto err_uninit;
	}

	/* input process */
	bytes_left = sCtx->cryptCtx.cache_idx + ulEncryptedPartLen;
	if (bytes_left < sCtx->cryptCtx.blockSize) {
		/* cache data for next update and exit */
		memcpy(sCtx->cryptCtx.cache + sCtx->cryptCtx.cache_idx, pEncryptedPart, ulEncryptedPartLen);
		sCtx->cryptCtx.cache_idx = bytes_left;
		bytes_left = 0;

		/* call for START() with `0` data length */
		if (sCtx->cryptCtx.stream_start == CK_FALSE) {
			*pulPartLen = 0;
			return CKR_OK;
		}
	}

	/* round down to nearest multiple of block size */
	full_blocks = bytes_left - (bytes_left % sCtx->cryptCtx.blockSize);

	/* Check for length of output buffer. For AES, the output length is equal to the input length  */
	if (*pulPartLen < full_blocks) {
		/* tell the required size */
		*pulPartLen = full_blocks;

		rc = CKR_BUFFER_TOO_SMALL;
		goto err_uninit;
	}

	/* copy full_blocks to dynamic buffer */
	if (full_blocks > 0) {
		input = hse_mem_alloc(full_blocks);
		if (input == NULL) {
			rc = CKR_HOST_MEMORY;
			goto err_uninit;
		}
		hse_memcpy(input, sCtx->cryptCtx.cache, sCtx->cryptCtx.cache_idx);
		hse_memcpy(input + sCtx->cryptCtx.cache_idx, pEncryptedPart, full_blocks - sCtx->cryptCtx.cache_idx);
		bytes_left -= full_blocks;

		/* copy residue to block-sized cache */
		if (bytes_left > 0)
			memcpy(sCtx->cryptCtx.cache, pEncryptedPart + (full_blocks - sCtx->cryptCtx.cache_idx), bytes_left);
			
		sCtx->cryptCtx.cache_idx = bytes_left;

		/* output length is equal to the input length  */
		output = hse_mem_alloc(full_blocks);
		if (output == NULL) {
			rc = CKR_HOST_MEMORY;
			goto err_free_input;
		}
	}

	/* IV input is used only when START */
	if ((sCtx->cryptCtx.stream_start == CK_TRUE) && 
		(sCtx->cryptCtx.mechanism->pParameter != NULL)) {
		pIV = hse_mem_alloc(sCtx->cryptCtx.mechanism->ulParameterLen);
		if (pIV == NULL) {
			rc = CKR_HOST_MEMORY;
			goto err_free_output;
		}
		hse_memcpy(pIV, sCtx->cryptCtx.mechanism->pParameter, sCtx->cryptCtx.mechanism->ulParameterLen);
	}

	if (sCtx->cryptCtx.stream_start) {
		access_mode = HSE_ACCESS_MODE_START;
		sCtx->cryptCtx.stream_start = CK_FALSE;
	} else {
		access_mode = HSE_ACCESS_MODE_UPDATE;
	}

	switch (sCtx->cryptCtx.mechanism->mechanism) {
		case CKM_AES_ECB:

			sym_cipher_srv = &srv_desc.hseSrv.symCipherReq;

			srv_desc.srvId = HSE_SRV_ID_SYM_CIPHER;
			sym_cipher_srv->accessMode = access_mode;
			sym_cipher_srv->streamId = STREAM_ID_ENC_DEC;
			sym_cipher_srv->cipherAlgo = HSE_CIPHER_ALGO_AES;
			sym_cipher_srv->cipherBlockMode = HSE_CIPHER_BLOCK_MODE_ECB;
			sym_cipher_srv->cipherDir = HSE_CIPHER_DIR_DECRYPT;
			sym_cipher_srv->sgtOption = HSE_SGT_OPTION_NONE;
			sym_cipher_srv->keyHandle = key->key_handle;

			if (sCtx->cryptCtx.mechanism->pParameter != NULL) {
				sym_cipher_srv->pIV = hse_virt_to_dma(pIV);
			} else {
				sym_cipher_srv->pIV = 0u; /* IV is not required for ecb */
			}

			sym_cipher_srv->inputLength = full_blocks;
			sym_cipher_srv->pInput = hse_virt_to_dma(input);
			sym_cipher_srv->pOutput= hse_virt_to_dma(output);

			break;

		case CKM_AES_CBC:

			sym_cipher_srv = &srv_desc.hseSrv.symCipherReq;

			srv_desc.srvId = HSE_SRV_ID_SYM_CIPHER;
			sym_cipher_srv->accessMode = access_mode;
			sym_cipher_srv->streamId = STREAM_ID_ENC_DEC;
			sym_cipher_srv->cipherAlgo = HSE_CIPHER_ALGO_AES;
			sym_cipher_srv->cipherBlockMode = HSE_CIPHER_BLOCK_MODE_CBC;
			sym_cipher_srv->cipherDir = HSE_CIPHER_DIR_DECRYPT;
			sym_cipher_srv->sgtOption = HSE_SGT_OPTION_NONE;
			sym_cipher_srv->keyHandle = key->key_handle;
			sym_cipher_srv->pIV = hse_virt_to_dma(pIV);
			sym_cipher_srv->inputLength = full_blocks;
			sym_cipher_srv->pInput = hse_virt_to_dma(input);
			sym_cipher_srv->pOutput= hse_virt_to_dma(output);

			break;

		case CKM_AES_CTR:

			sym_cipher_srv = &srv_desc.hseSrv.symCipherReq;

			srv_desc.srvId = HSE_SRV_ID_SYM_CIPHER;
			sym_cipher_srv->accessMode = access_mode;
			sym_cipher_srv->streamId = STREAM_ID_ENC_DEC;
			sym_cipher_srv->cipherAlgo = HSE_CIPHER_ALGO_AES;
			sym_cipher_srv->cipherBlockMode = HSE_CIPHER_BLOCK_MODE_CTR;
			sym_cipher_srv->cipherDir = HSE_CIPHER_DIR_DECRYPT;
			sym_cipher_srv->sgtOption = HSE_SGT_OPTION_NONE;
			sym_cipher_srv->keyHandle = key->key_handle;
			sym_cipher_srv->pIV = hse_virt_to_dma(pIV);
			sym_cipher_srv->inputLength = full_blocks;
			sym_cipher_srv->pInput = hse_virt_to_dma(input);
			sym_cipher_srv->pOutput= hse_virt_to_dma(output);

			break;
		default:
			rc = CKR_ARGUMENTS_BAD;
			goto err_free_piv;
	}

	err = hse_srv_req_sync(sCtx->sID, &srv_desc, sizeof(srv_desc));
	if (err) {
		rc = CKR_FUNCTION_FAILED;
		goto err_free_piv;
	}

	if (full_blocks > 0)
		hse_memcpy(pPart, output, full_blocks);
	*pulPartLen = full_blocks;

err_free_piv:
	hse_mem_free(pIV);
err_free_output:
	hse_mem_free(output);
err_free_input:
	hse_mem_free(input);
err_uninit:
	if ((rc != CKR_OK) && (rc != CKR_BUFFER_TOO_SMALL)) {
		sCtx->cryptCtx.init = CK_FALSE;
		if (sCtx->cryptCtx.cache != NULL) {
			free(sCtx->cryptCtx.cache);
			sCtx->cryptCtx.cache = NULL;
		}
	}

	return rc;
}

CK_DEFINE_FUNCTION(CK_RV, C_DecryptFinal)(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pLastPart,
		CK_ULONG_PTR pulLastPartLen
)
{
	struct globalCtx *gCtx = getCtx();
	struct sessionCtx *sCtx = getSessionCtx(hSession);
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	hseSymCipherSrv_t *sym_cipher_srv;
	void *input = NULL, *output;
	uint8_t input_len = 0;
	struct hse_keyObject *key;
	CK_RV rc = CKR_OK;
	int err;

	if (gCtx->cryptokiInit == CK_FALSE)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!sCtx || sCtx->sessionInit == CK_FALSE)
		return CKR_SESSION_HANDLE_INVALID;

	if (sCtx->cryptCtx.init == CK_FALSE)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (pulLastPartLen == NULL) {
		rc = CKR_ARGUMENTS_BAD;
		goto err_uninit;
	}

	if (pLastPart == NULL) {
		/* if NULL, upper layer expects to receive needed size */
		*pulLastPartLen = sCtx->cryptCtx.cache_idx;
		return CKR_OK; 
	}

	gCtx->mtxFns.lock(gCtx->keyMtx);
	key = (struct hse_keyObject *)list_seek(&gCtx->object_list, &sCtx->cryptCtx.keyHandle);
	gCtx->mtxFns.unlock(gCtx->keyMtx);
	if (key == NULL) {
		rc = CKR_KEY_HANDLE_INVALID;
		goto err_uninit;
	}

	/* Check the output length */
	if ((sCtx->cryptCtx.mechanism->mechanism == CKM_AES_ECB) ||
		(sCtx->cryptCtx.mechanism->mechanism == CKM_AES_CBC) ||
		(sCtx->cryptCtx.mechanism->mechanism == CKM_AES_CTR)) {
		/* For AES, the output length is equal to the input length  */
		if (*pulLastPartLen < sCtx->cryptCtx.cache_idx) {
			/* tell the required size */
			*pulLastPartLen = sCtx->cryptCtx.cache_idx;

			rc = CKR_BUFFER_TOO_SMALL;
			goto err_uninit;
		}
	} else {
		rc = CKR_FUNCTION_NOT_SUPPORTED;
		goto err_uninit;
	}

	/* input length check:
	 * For ECB, CBC & CFB cipher block modes, must be a multiple of block length. Cannot be zero.
     * For remaining cipher block modes, can be any value except zero. */
	input_len = sCtx->cryptCtx.cache_idx;
	if ((sCtx->cryptCtx.mechanism->mechanism == CKM_AES_ECB) ||
		(sCtx->cryptCtx.mechanism->mechanism == CKM_AES_CBC)) {
		if (input_len == 0) {
			/* if no data left, fill dummy data */
			input_len = sCtx->cryptCtx.blockSize;
		} else if (sCtx->cryptCtx.cache_idx != sCtx->cryptCtx.blockSize) {
			rc = CKR_DATA_LEN_RANGE;
			goto err_uninit;
		}
	} else {
		if (sCtx->cryptCtx.cache_idx == 0) {
			/* if no data left, fill dummy data */
			input_len = sCtx->cryptCtx.blockSize;
		}
	}

	input = hse_mem_alloc(input_len);
	if (input == NULL) {
		rc = CKR_HOST_MEMORY;
		goto err_uninit;
	}

	hse_memcpy(input, sCtx->cryptCtx.cache, input_len);

	output = hse_mem_alloc(input_len);
	if (output == NULL) {
		rc = CKR_HOST_MEMORY;
		goto err_free_input;
	}

	switch (sCtx->cryptCtx.mechanism->mechanism) {
		case CKM_AES_ECB:

			sym_cipher_srv = &srv_desc.hseSrv.symCipherReq;

			srv_desc.srvId = HSE_SRV_ID_SYM_CIPHER;
			sym_cipher_srv->accessMode = HSE_ACCESS_MODE_FINISH;
			sym_cipher_srv->streamId = STREAM_ID_ENC_DEC;
			sym_cipher_srv->cipherAlgo = HSE_CIPHER_ALGO_AES;
			sym_cipher_srv->cipherBlockMode = HSE_CIPHER_BLOCK_MODE_ECB;
			sym_cipher_srv->cipherDir = HSE_CIPHER_DIR_DECRYPT;
			sym_cipher_srv->sgtOption = HSE_SGT_OPTION_NONE;
			sym_cipher_srv->keyHandle = key->key_handle;
			sym_cipher_srv->pIV = 0;
			sym_cipher_srv->inputLength = input_len;
			sym_cipher_srv->pInput = hse_virt_to_dma(input);
			sym_cipher_srv->pOutput= hse_virt_to_dma(output);

			break;

		case CKM_AES_CBC:

			sym_cipher_srv = &srv_desc.hseSrv.symCipherReq;

			srv_desc.srvId = HSE_SRV_ID_SYM_CIPHER;
			sym_cipher_srv->accessMode = HSE_ACCESS_MODE_FINISH;
			sym_cipher_srv->streamId = STREAM_ID_ENC_DEC;
			sym_cipher_srv->cipherAlgo = HSE_CIPHER_ALGO_AES;
			sym_cipher_srv->cipherBlockMode = HSE_CIPHER_BLOCK_MODE_CBC;
			sym_cipher_srv->cipherDir = HSE_CIPHER_DIR_DECRYPT;
			sym_cipher_srv->sgtOption = HSE_SGT_OPTION_NONE;
			sym_cipher_srv->keyHandle = key->key_handle;
			sym_cipher_srv->pIV = 0;
			sym_cipher_srv->inputLength = input_len;
			sym_cipher_srv->pInput = hse_virt_to_dma(input);
			sym_cipher_srv->pOutput= hse_virt_to_dma(output);

			break;

		case CKM_AES_CTR:

			sym_cipher_srv = &srv_desc.hseSrv.symCipherReq;

			srv_desc.srvId = HSE_SRV_ID_SYM_CIPHER;
			sym_cipher_srv->accessMode = HSE_ACCESS_MODE_FINISH;
			sym_cipher_srv->streamId = STREAM_ID_ENC_DEC;
			sym_cipher_srv->cipherAlgo = HSE_CIPHER_ALGO_AES;
			sym_cipher_srv->cipherBlockMode = HSE_CIPHER_BLOCK_MODE_CTR;
			sym_cipher_srv->cipherDir = HSE_CIPHER_DIR_DECRYPT;
			sym_cipher_srv->sgtOption = HSE_SGT_OPTION_NONE;
			sym_cipher_srv->keyHandle = key->key_handle;
			sym_cipher_srv->pIV = 0;
			sym_cipher_srv->inputLength = input_len;
			sym_cipher_srv->pInput = hse_virt_to_dma(input);
			sym_cipher_srv->pOutput= hse_virt_to_dma(output);

			break;
		default:
			rc = CKR_ARGUMENTS_BAD;
			goto err_free_output;
	}

	err = hse_srv_req_sync(sCtx->sID, &srv_desc, sizeof(srv_desc));
	if (err) {
		rc = CKR_FUNCTION_FAILED;
		goto err_free_output;
	}

	if (sCtx->cryptCtx.cache_idx > 0)
		hse_memcpy(pLastPart, output, sCtx->cryptCtx.cache_idx);
	*pulLastPartLen = sCtx->cryptCtx.cache_idx;

err_free_output:
	hse_mem_free(output);
err_free_input:
	hse_mem_free(input);
err_uninit:
	if (rc != CKR_BUFFER_TOO_SMALL) {
		sCtx->cryptCtx.init = CK_FALSE;
		if (sCtx->cryptCtx.cache != NULL) {
			free(sCtx->cryptCtx.cache);
			sCtx->cryptCtx.cache = NULL;
		}
	}

	return rc;
}

CK_DEFINE_FUNCTION(CK_RV, C_SignUpdate)(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pPart,
		CK_ULONG ulPartLen
)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_SignFinal)(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pSignature,
		CK_ULONG_PTR pulSignatureLen
)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_SignRecoverInit)(
		CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,
		CK_OBJECT_HANDLE hKey
)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_SignRecover)(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pData,
		CK_ULONG ulDataLen,
		CK_BYTE_PTR pSignature,
		CK_ULONG_PTR pulSignatureLen
)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_VerifyUpdate)(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pPart,
		CK_ULONG ulPartLen
)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_VerifyFinal)(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pSignature,
		CK_ULONG ulSignatureLen
)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_VerifyRecoverInit)(
		CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,
		CK_OBJECT_HANDLE hKey
)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_VerifyRecover)(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pSignature,
		CK_ULONG ulSignatureLen,
		CK_BYTE_PTR pData,
		CK_ULONG_PTR pulDataLen
)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}
