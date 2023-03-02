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

	if (gCtx->cryptokiInit == CK_FALSE)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (gCtx->cryptCtx.init == CK_TRUE)
		return CKR_OPERATION_ACTIVE;

	if (hSession != SESSION_ID)
		return CKR_SESSION_HANDLE_INVALID;

	if (pMechanism == NULL)
		return CKR_ARGUMENTS_BAD;

	if (list_seek(&gCtx->object_list, &hKey) == NULL)
		return CKR_KEY_HANDLE_INVALID;

	/* IV is optional for AES-ECB */
	if (pMechanism->pParameter == NULL)
	    if ((pMechanism->mechanism != CKM_AES_ECB) &&  
			(pMechanism->mechanism != CKM_RSA_PKCS))
			return CKR_ARGUMENTS_BAD;

	gCtx->cryptCtx.init = CK_TRUE;
	gCtx->cryptCtx.mechanism = pMechanism;
	gCtx->cryptCtx.keyHandle = hKey;

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

	if (gCtx->cryptCtx.init == CK_FALSE)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (hSession != SESSION_ID)
		return CKR_SESSION_HANDLE_INVALID;

	if (pData == NULL || pEncryptedData == NULL || pulEncryptedDataLen == NULL)
		return CKR_ARGUMENTS_BAD;

	/* Check for input length: For ECB, CBC & CFB cipher block modes, must be a multiple of block length. Cannot be zero. */
	if (ulDataLen == 0)
		return CKR_ARGUMENTS_BAD;

	if ((gCtx->cryptCtx.mechanism->mechanism == CKM_AES_ECB) || 
		(gCtx->cryptCtx.mechanism->mechanism == CKM_AES_CBC) ) {
			if ((ulDataLen & (HSE_AES_BLOCK_LEN - 1)) != 0)
				return CKR_ARGUMENTS_BAD;
	}

	key = (struct hse_keyObject *)list_seek(&gCtx->object_list, &gCtx->cryptCtx.keyHandle);
	if (key == NULL)
		return CKR_KEY_HANDLE_INVALID;

	/* check for input length for RSA ciphering */
	if ((gCtx->cryptCtx.mechanism->mechanism == CKM_RSA_PKCS) || 
		(gCtx->cryptCtx.mechanism->mechanism == CKM_RSA_PKCS_OAEP)) {
		key_bit_length = hse_get_key_bit_length(key);
		if (key_bit_length == 0) 
			return CKR_GENERAL_ERROR;

		if (rsa_ciphering_get_max_input_length(key_bit_length, gCtx->cryptCtx.mechanism) < ulDataLen)
			return CKR_DATA_LEN_RANGE;
	}

	input = hse_mem_alloc(ulDataLen);
	if (input == NULL) 
		return CKR_HOST_MEMORY;
	hse_memcpy(input, pData, ulDataLen);

	output_len = hse_mem_alloc(sizeof(uint32_t));
	if (output_len == NULL) {
		rc = CKR_HOST_MEMORY;
		goto err_free_input;
	}

	/* Check the output length */
	if ((gCtx->cryptCtx.mechanism->mechanism == CKM_AES_ECB) || 
		(gCtx->cryptCtx.mechanism->mechanism == CKM_AES_CBC) || 
		(gCtx->cryptCtx.mechanism->mechanism == CKM_AES_CTR) || 
		(gCtx->cryptCtx.mechanism->mechanism == CKM_AES_GCM)) {
		/* For AES, the output length is equal to the input length  */
		hse_memcpy(output_len, &ulDataLen, sizeof(uint32_t));
	} else if ((gCtx->cryptCtx.mechanism->mechanism == CKM_RSA_PKCS) || 
			   (gCtx->cryptCtx.mechanism->mechanism == CKM_RSA_PKCS_OAEP)) {
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

	if (gCtx->cryptCtx.mechanism->pParameter != NULL) {
		if (gCtx->cryptCtx.mechanism->mechanism == CKM_RSA_PKCS_OAEP) {
			oaep_params = (CK_RSA_PKCS_OAEP_PARAMS *)gCtx->cryptCtx.mechanism->pParameter;
		} else {
			pIV = hse_mem_alloc(gCtx->cryptCtx.mechanism->ulParameterLen);
			if (pIV == NULL) {
				rc = CKR_HOST_MEMORY;
				goto err_free_output;
			}
			hse_memcpy(pIV, gCtx->cryptCtx.mechanism->pParameter, gCtx->cryptCtx.mechanism->ulParameterLen);
		}
	}

	if (gCtx->cryptCtx.mechanism->mechanism == CKM_AES_GCM) {
		/* HSE requires GCM valid Tag sizes 4, 8, 12, 13, 14, 15, 16 bytes. Can not be 0.
		 * Use the length 16 for the tag here. */
		gcm_tag = hse_mem_alloc(16u);
		if (gcm_tag == NULL) {
			rc = CKR_HOST_MEMORY;
			goto err_free_piv;
		}
	}

	switch (gCtx->cryptCtx.mechanism->mechanism) {
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

			if (gCtx->cryptCtx.mechanism->pParameter != NULL) {
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
			aead_srv->ivLength = gCtx->cryptCtx.mechanism->ulParameterLen;
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

	err = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc, sizeof(srv_desc));
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

	gCtx->cryptCtx.init = CK_FALSE;

	return rc;
}

CK_DEFINE_FUNCTION(CK_RV, C_DecryptInit)(
		CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,
		CK_OBJECT_HANDLE hKey
)
{
	struct globalCtx *gCtx = getCtx();

	if (gCtx->cryptokiInit == CK_FALSE)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (gCtx->cryptCtx.init == CK_TRUE)
		return CKR_OPERATION_ACTIVE;

	if (hSession != SESSION_ID)
		return CKR_SESSION_HANDLE_INVALID;

	if (pMechanism == NULL)
		return CKR_ARGUMENTS_BAD;

	if (list_seek(&gCtx->object_list, &hKey) == NULL)
		return CKR_KEY_HANDLE_INVALID;

	/* IV is optional for AES-ECB */
	if (pMechanism->pParameter == NULL)
	    if ((pMechanism->mechanism != CKM_AES_ECB) &&  
			(pMechanism->mechanism != CKM_RSA_PKCS))
			return CKR_ARGUMENTS_BAD;

	gCtx->cryptCtx.init = CK_TRUE;
	gCtx->cryptCtx.mechanism = pMechanism;
	gCtx->cryptCtx.keyHandle = hKey;

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

	if (gCtx->cryptCtx.init == CK_FALSE)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (hSession != SESSION_ID)
		return CKR_SESSION_HANDLE_INVALID;

	if (pData == NULL || pEncryptedData == NULL || pulDataLen == NULL)
		return CKR_ARGUMENTS_BAD;

	/* Check for input length: For ECB, CBC & CFB cipher block modes, must be a multiple of block length. Cannot be zero. */
	if (ulEncryptedDataLen == 0)
		return CKR_ARGUMENTS_BAD;

	if ((gCtx->cryptCtx.mechanism->mechanism == CKM_AES_ECB) || 
		(gCtx->cryptCtx.mechanism->mechanism == CKM_AES_CBC) ) {
			if ((ulEncryptedDataLen & (HSE_AES_BLOCK_LEN - 1)) != 0)
				return CKR_ARGUMENTS_BAD;
	}

	key = (struct hse_keyObject *)list_seek(&gCtx->object_list, &gCtx->cryptCtx.keyHandle);
	if (key == NULL)
		return CKR_KEY_HANDLE_INVALID;

	if ((gCtx->cryptCtx.mechanism->mechanism == CKM_RSA_PKCS) || 
		(gCtx->cryptCtx.mechanism->mechanism == CKM_RSA_PKCS_OAEP)) {
		key_bit_length = hse_get_key_bit_length(key);
		/* The input cipher text length should be equal to the key size */
		if (ulEncryptedDataLen != (key_bit_length >> 3))
			return CKR_ARGUMENTS_BAD;
	}

	input = hse_mem_alloc(ulEncryptedDataLen);
	if (input == NULL)
		return CKR_HOST_MEMORY;
	hse_memcpy(input, pEncryptedData, ulEncryptedDataLen);

	output_len = hse_mem_alloc(sizeof(uint32_t));
	if (output_len == NULL) {
		rc = CKR_HOST_MEMORY;
		goto err_free_input;
	}

	if ((gCtx->cryptCtx.mechanism->mechanism == CKM_AES_ECB) || 
		(gCtx->cryptCtx.mechanism->mechanism == CKM_AES_CBC) || 
		(gCtx->cryptCtx.mechanism->mechanism == CKM_AES_CTR) || 
		(gCtx->cryptCtx.mechanism->mechanism == CKM_AES_GCM)) {
		/* For AES, the output length is equal to the input length  */
		hse_memcpy(output_len, &ulEncryptedDataLen, sizeof(uint32_t));
		if (*(uint32_t *)output_len > *pulDataLen) {
			/* tell the required size */
			*pulDataLen = *(uint32_t *)output_len;

			rc = CKR_BUFFER_TOO_SMALL;
			goto err_free_output_len;
		}
	} else if ((gCtx->cryptCtx.mechanism->mechanism == CKM_RSA_PKCS) || 
				(gCtx->cryptCtx.mechanism->mechanism == CKM_RSA_PKCS_OAEP)) {
		/* to be safe, we allocate the max. length */
		*(uint32_t *)output_len = rsa_ciphering_get_max_input_length(key_bit_length, gCtx->cryptCtx.mechanism);
	}

	output = hse_mem_alloc(*(uint32_t *)output_len);
	if (output == NULL) {
		rc = CKR_HOST_MEMORY;
		goto err_free_output_len;
	}

	if (gCtx->cryptCtx.mechanism->pParameter != NULL) {
		if (gCtx->cryptCtx.mechanism->mechanism == CKM_RSA_PKCS_OAEP) {
			oaep_params = (CK_RSA_PKCS_OAEP_PARAMS *)gCtx->cryptCtx.mechanism->pParameter;
		} else {
			pIV = hse_mem_alloc(gCtx->cryptCtx.mechanism->ulParameterLen);
			if (pIV == NULL) {
				rc = CKR_HOST_MEMORY;
				goto err_free_output;
			}
			hse_memcpy(pIV, gCtx->cryptCtx.mechanism->pParameter, gCtx->cryptCtx.mechanism->ulParameterLen);
		}
	}

	if (gCtx->cryptCtx.mechanism->mechanism == CKM_AES_GCM) {
		/* HSE requires GCM valid Tag sizes 4, 8, 12, 13, 14, 15, 16 bytes. Can not be 0.
		 * Use the length 16 for the tag here. */
		gcm_tag = hse_mem_alloc(16u);
		if (gcm_tag == NULL) {
			rc = CKR_HOST_MEMORY;
			goto err_free_piv;
		}
	}

	switch (gCtx->cryptCtx.mechanism->mechanism) {
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

			if (gCtx->cryptCtx.mechanism->pParameter != NULL) {
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
			aead_srv->ivLength = gCtx->cryptCtx.mechanism->ulParameterLen;
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

	err = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc, sizeof(srv_desc));
	if (err) {
		rc = CKR_FUNCTION_FAILED;
		goto err_free_tag;
	}

	/* check for output buffer length */
	if ((gCtx->cryptCtx.mechanism->mechanism == CKM_RSA_PKCS) || 
		(gCtx->cryptCtx.mechanism->mechanism == CKM_RSA_PKCS_OAEP)) {
		if (*(uint32_t *)output_len > *pulDataLen) {
			/* tell the required size */
			*pulDataLen = *(uint32_t *)output_len;

			rc = CKR_BUFFER_TOO_SMALL;
			goto err_free_output_len;
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

	gCtx->cryptCtx.init = CK_FALSE;

	return rc;
}

CK_DEFINE_FUNCTION(CK_RV, C_SignInit)(
		CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,
		CK_OBJECT_HANDLE hKey
)
{
	struct globalCtx *gCtx = getCtx();

	if (gCtx->cryptokiInit == CK_FALSE)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (hSession != SESSION_ID)
		return CKR_SESSION_HANDLE_INVALID;

	if (pMechanism == NULL)
		return CKR_ARGUMENTS_BAD;

	if (list_seek(&gCtx->object_list, &hKey) == NULL)
		return CKR_KEY_HANDLE_INVALID;

	if (gCtx->signCtx.init == CK_TRUE)
		return CKR_OPERATION_ACTIVE;

	gCtx->signCtx.init = CK_TRUE;
	gCtx->signCtx.mechanism = pMechanism;
	gCtx->signCtx.keyHandle = hKey;

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
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	hseSignSrv_t *sign_srv;
	hseSignScheme_t *sign_scheme;
	void *input, *sign0 = NULL, *sign1 = NULL, *output_len;
	struct hse_keyObject *key;
	CK_RV rc = CKR_OK;
	int err;
	CK_RSA_PKCS_PSS_PARAMS *rsa_pss_param;

	if (gCtx->cryptokiInit == CK_FALSE)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (hSession != SESSION_ID)
		return CKR_SESSION_HANDLE_INVALID;

	if (pData == NULL)
		return CKR_DATA_INVALID;

	if (ulDataLen == 0)
		return CKR_DATA_LEN_RANGE;

	if (pSignature == NULL)
		return CKR_SIGNATURE_INVALID;

	if (pulSignatureLen == NULL)
		return CKR_SIGNATURE_LEN_RANGE;

	if (gCtx->signCtx.init == CK_FALSE)
		return CKR_OPERATION_NOT_INITIALIZED;

	key = (struct hse_keyObject *)list_seek(&gCtx->object_list, &gCtx->signCtx.keyHandle);
	if (key == NULL) 
		return CKR_KEY_HANDLE_INVALID;

	input = hse_mem_alloc(ulDataLen);
	if (input == NULL)
		return CKR_HOST_MEMORY;
	hse_memcpy(input, pData, ulDataLen);

	output_len = hse_mem_alloc(sizeof(uint32_t));
	if (output_len == NULL) {
		rc = CKR_HOST_MEMORY;
		goto err_free_input;
	}

	/* check the output length */
	*(uint32_t *)output_len = sig_get_out_length(key, gCtx->signCtx.mechanism);
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

	switch (gCtx->signCtx.mechanism->mechanism) {
		case CKM_RSA_PKCS:
		case CKM_SHA1_RSA_PKCS:
		case CKM_SHA256_RSA_PKCS:
		case CKM_SHA384_RSA_PKCS:
		case CKM_SHA512_RSA_PKCS:
			sign_scheme->signSch = HSE_SIGN_RSASSA_PKCS1_V15;
			sign_scheme->sch.rsaPkcs1v15.hashAlgo = hse_get_hash_alg(gCtx->signCtx.mechanism->mechanism);
			sign_srv->pSignatureLength[0] = hse_virt_to_dma(output_len);
			sign_srv->pSignatureLength[1] = 0u;
			sign_srv->pSignature[0] = hse_virt_to_dma(sign0);
			sign_srv->pSignature[1] = 0u;
			if (CKM_RSA_PKCS == gCtx->signCtx.mechanism->mechanism) {
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
			rsa_pss_param = (CK_RSA_PKCS_PSS_PARAMS *)gCtx->signCtx.mechanism->pParameter;
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

			if (CKM_RSA_PKCS_PSS == gCtx->signCtx.mechanism->mechanism)
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
			sign_scheme->sch.ecdsa.hashAlgo = hse_get_hash_alg(gCtx->signCtx.mechanism->mechanism);
			sign_srv->pSignatureLength[0] = hse_virt_to_dma(output_len);
			sign_srv->pSignatureLength[1] = hse_virt_to_dma(output_len);
			sign_srv->pSignature[0] = hse_virt_to_dma(sign0);
			sign_srv->pSignature[1] = hse_virt_to_dma(sign1);

			if (CKM_ECDSA == gCtx->signCtx.mechanism->mechanism)
				sign_srv->bInputIsHashed = 1u;
			else
				sign_srv->bInputIsHashed = 0u;

			break;
		default:
			rc = CKR_ARGUMENTS_BAD;
			goto err_free_sign0;
	}

	srv_desc.srvId = HSE_SRV_ID_SIGN;
	sign_srv->accessMode = HSE_ACCESS_MODE_ONE_PASS;
	sign_srv->streamId = 0u;
	sign_srv->authDir = HSE_AUTH_DIR_GENERATE;
	sign_srv->keyHandle = key->key_handle;
	sign_srv->sgtOption = HSE_SGT_OPTION_NONE;
	sign_srv->inputLength = ulDataLen;
	sign_srv->pInput = hse_virt_to_dma(input);

	err = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc, sizeof(srv_desc));
	if (err) {
		rc = CKR_FUNCTION_FAILED;
		goto err_free_sign0;
	}

	switch (gCtx->signCtx.mechanism->mechanism) {
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

	gCtx->signCtx.init = CK_FALSE;

	return rc;
}

CK_DEFINE_FUNCTION(CK_RV, C_VerifyInit)(
		CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,
		CK_OBJECT_HANDLE hKey
)
{
	struct globalCtx *gCtx = getCtx();

	if (gCtx->cryptokiInit == CK_FALSE)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (hSession != SESSION_ID)
		return CKR_SESSION_HANDLE_INVALID;

	if (pMechanism == NULL)
		return CKR_ARGUMENTS_BAD;

	if (list_seek(&gCtx->object_list, &hKey) == NULL)
		return CKR_KEY_HANDLE_INVALID;

	if (gCtx->signCtx.init == CK_TRUE)
		return CKR_OPERATION_ACTIVE;

	gCtx->signCtx.init = CK_TRUE;
	gCtx->signCtx.mechanism = pMechanism;
	gCtx->signCtx.keyHandle = hKey;

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
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	hseSignSrv_t *sign_srv;
	hseSignScheme_t *sign_scheme;
	void *input, *sign0 = NULL, *sign1 = NULL, *output_len;
	struct hse_keyObject *key;
	CK_RV rc = CKR_OK;
	int err;
	CK_RSA_PKCS_PSS_PARAMS *rsa_pss_param;

	if (gCtx->cryptokiInit == CK_FALSE)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (hSession != SESSION_ID)
		return CKR_SESSION_HANDLE_INVALID;

	if (pData == NULL)
		return CKR_DATA_INVALID;

	if (ulDataLen == 0)
		return CKR_DATA_LEN_RANGE;

	if (pSignature == NULL)
		return CKR_SIGNATURE_INVALID;

	if (ulSignatureLen == 0)
		return CKR_SIGNATURE_LEN_RANGE;

	if (gCtx->signCtx.init == CK_FALSE) 
		return CKR_OPERATION_NOT_INITIALIZED;

	key = (struct hse_keyObject *)list_seek(&gCtx->object_list, &gCtx->signCtx.keyHandle);
	if (key == NULL) 
		return CKR_KEY_HANDLE_INVALID;

	input = hse_mem_alloc(ulDataLen);
	if (input == NULL)
		return CKR_HOST_MEMORY;
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

	switch (gCtx->signCtx.mechanism->mechanism) {
		case CKM_RSA_PKCS:
		case CKM_SHA1_RSA_PKCS:
		case CKM_SHA256_RSA_PKCS:
		case CKM_SHA384_RSA_PKCS:
		case CKM_SHA512_RSA_PKCS:
			sign_scheme->signSch = HSE_SIGN_RSASSA_PKCS1_V15;
			sign_scheme->sch.rsaPkcs1v15.hashAlgo = hse_get_hash_alg(gCtx->signCtx.mechanism->mechanism);
			sign_srv->pSignatureLength[0] = hse_virt_to_dma(output_len);
			sign_srv->pSignatureLength[1] = 0u;
			sign_srv->pSignature[0] = hse_virt_to_dma(sign0); /* rsa */
			sign_srv->pSignature[1] = 0u;

			if (CKM_RSA_PKCS == gCtx->signCtx.mechanism->mechanism) {
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
			rsa_pss_param = (CK_RSA_PKCS_PSS_PARAMS *)gCtx->signCtx.mechanism->pParameter;
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

			if (CKM_RSA_PKCS_PSS == gCtx->signCtx.mechanism->mechanism)
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
			sign_scheme->sch.ecdsa.hashAlgo = hse_get_hash_alg(gCtx->signCtx.mechanism->mechanism);

			sign_srv->pSignatureLength[0] = hse_virt_to_dma(output_len);
			sign_srv->pSignatureLength[1] = hse_virt_to_dma(output_len);
			sign_srv->pSignature[0] = hse_virt_to_dma(sign0);
			sign_srv->pSignature[1] = hse_virt_to_dma(sign1);

			if (CKM_ECDSA == gCtx->signCtx.mechanism->mechanism)
				sign_srv->bInputIsHashed = 1u;
			else
				sign_srv->bInputIsHashed = 0u;

			break;
		default:
			rc = CKR_ARGUMENTS_BAD;
			goto err_free_sign0;
	}

	srv_desc.srvId = HSE_SRV_ID_SIGN;
	sign_srv->accessMode = HSE_ACCESS_MODE_ONE_PASS;
	sign_srv->streamId = 0u;
	sign_srv->authDir = HSE_AUTH_DIR_VERIFY;
	sign_srv->keyHandle = key->key_handle;
	sign_srv->sgtOption = HSE_SGT_OPTION_NONE;
	sign_srv->inputLength = ulDataLen;
	sign_srv->pInput = hse_virt_to_dma(input);

	err = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc, sizeof(srv_desc));
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

	gCtx->signCtx.init = CK_FALSE;

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
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_EncryptFinal)(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pLastEncryptedPart,
		CK_ULONG_PTR pulLastEncryptedPartLen
)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DecryptUpdate)(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pEncryptedPart,
		CK_ULONG ulEncryptedPartLen,
		CK_BYTE_PTR pPart,
		CK_ULONG_PTR pulPartLen
)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DecryptFinal)(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pLastPart,
		CK_ULONG_PTR pulLastPartLen
)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
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
