// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pkcs11_context.h"

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

	if (list_seek(&gCtx->objects, &hKey) == NULL)
		return CKR_KEY_HANDLE_INVALID;

	/* IV is optional for AES-ECB */
	if (pMechanism->pParameter == NULL &&
	    pMechanism->mechanism != CKM_AES_ECB)
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
	hseSrvDescriptor_t srv_desc;
	hseSymCipherSrv_t *sym_cipher_srv;
	hseAeadSrv_t *aead_srv;
	void *input, *output, *output_len, *pIV = NULL;
	struct hse_keyObject *key;
	CK_RV rc = CKR_OK;
	int err;

	if (gCtx->cryptokiInit == CK_FALSE)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (gCtx->cryptCtx.init == CK_FALSE)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (hSession != SESSION_ID)
		return CKR_SESSION_HANDLE_INVALID;

	if (pData == NULL || pEncryptedData == NULL || pulEncryptedDataLen == NULL)
		return CKR_ARGUMENTS_BAD;

	key = (struct hse_keyObject *)list_seek(&gCtx->objects, &gCtx->cryptCtx.keyHandle);

	input = hse_mem_alloc(ulDataLen);
	if (input == NULL) 
		return CKR_HOST_MEMORY;
	memcpy(input, pData, ulDataLen);

	output_len = hse_mem_alloc(sizeof(uint32_t));
	if (output_len == NULL) {
		rc = CKR_HOST_MEMORY;
		goto err_free_input;
	}
	memcpy(output_len, pulEncryptedDataLen, sizeof(uint32_t));
	output = hse_mem_alloc(*(uint32_t *)output_len);
	if (output == NULL) {
		rc = CKR_HOST_MEMORY;
		goto err_free_output_len;
	}

	if (gCtx->cryptCtx.mechanism->pParameter != NULL) {
		pIV = hse_mem_alloc(gCtx->cryptCtx.mechanism->ulParameterLen);
		if (pIV == NULL) {
			rc = CKR_HOST_MEMORY;
			goto err_free_output;
		}
		memcpy(pIV, gCtx->cryptCtx.mechanism->pParameter, gCtx->cryptCtx.mechanism->ulParameterLen);
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
			aead_srv->tagLength = 0u;
			aead_srv->pTag = 0u;
			aead_srv->pOutput = hse_virt_to_dma(output);

		default:
			rc = CKR_ARGUMENTS_BAD;
			goto err_free_piv;
	}

	err = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc);
	if (err) {
		rc = CKR_FUNCTION_FAILED;
		goto err_free_piv;
	}

	memcpy(pEncryptedData, output, *(uint32_t *)output_len);
	memcpy(pulEncryptedDataLen, output_len, sizeof(uint32_t));

err_free_piv:
	hse_mem_free(pIV);
err_free_output:
	hse_mem_free(output);
err_free_output_len:
	hse_mem_free(output_len);
err_free_input:
	hse_mem_free(input);
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

	if (list_seek(&gCtx->objects, &hKey) == NULL)
		return CKR_KEY_HANDLE_INVALID;

	/* IV is optional for AES-ECB */
	if (pMechanism->pParameter == NULL &&
		pMechanism->mechanism != CKM_AES_ECB)
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
	hseSrvDescriptor_t srv_desc;
	hseSymCipherSrv_t *sym_cipher_srv;
	hseAeadSrv_t *aead_srv;
	void *input, *output, *output_len, *pIV = NULL;
	struct hse_keyObject *key;
	CK_RV rc = CKR_OK;
	int err;

	if (gCtx->cryptokiInit == CK_FALSE)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (gCtx->cryptCtx.init == CK_FALSE)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (hSession != SESSION_ID)
		return CKR_SESSION_HANDLE_INVALID;

	if (pData == NULL || pEncryptedData == NULL || pulDataLen == NULL)
		return CKR_ARGUMENTS_BAD;

	key = (struct hse_keyObject *)list_seek(&gCtx->objects, &gCtx->cryptCtx.keyHandle);

	input = hse_mem_alloc(ulEncryptedDataLen);
	if (input == NULL)
		return CKR_HOST_MEMORY;
	memcpy(input, pEncryptedData, ulEncryptedDataLen);

	output_len = hse_mem_alloc(sizeof(uint32_t));
	if (output_len == NULL) {
		rc = CKR_HOST_MEMORY;
		goto err_free_input;
	}
	memcpy(output_len, pulDataLen, sizeof(uint32_t));
	output = hse_mem_alloc(*(uint32_t *)output_len);
	if (output == NULL) {
		rc = CKR_HOST_MEMORY;
		goto err_free_output_len;
	}

	if (gCtx->cryptCtx.mechanism->pParameter != NULL) {
		pIV = hse_mem_alloc(gCtx->cryptCtx.mechanism->ulParameterLen);
		if (pIV == NULL) {
			rc = CKR_HOST_MEMORY;
			goto err_free_output;
		}
		memcpy(pIV, gCtx->cryptCtx.mechanism->pParameter, gCtx->cryptCtx.mechanism->ulParameterLen);
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
			aead_srv->tagLength = 0u;
			aead_srv->pTag = 0u;
			aead_srv->pOutput = hse_virt_to_dma(output);

		default:
			rc = CKR_ARGUMENTS_BAD;
			goto err_free_piv;
	}

	err = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc);
	if (err) {
		rc = CKR_FUNCTION_FAILED;
		goto err_free_piv;
	}

	memcpy(pData, output, *(uint32_t *)output_len);
	memcpy(pulDataLen, output_len, sizeof(uint32_t));

err_free_piv:
	hse_mem_free(pIV);
err_free_output:
	hse_mem_free(output);
err_free_output_len:
	hse_mem_free(output_len);
err_free_input:
	hse_mem_free(input);
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

	if (list_seek(&gCtx->objects, &hKey) == NULL)
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
	hseSrvDescriptor_t srv_desc;
	hseSignSrv_t *sign_srv;
	hseSignScheme_t *sign_scheme;
	void *input, *sign0 = NULL, *sign1 = NULL, *output_len;
	struct hse_keyObject *key;
	CK_RV rc = CKR_OK;
	int err;

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

	key = (struct hse_keyObject *)list_seek(&gCtx->objects, &gCtx->signCtx.keyHandle);

	input = hse_mem_alloc(ulDataLen);
	if (input == NULL)
		return CKR_HOST_MEMORY;
	memcpy(input, pData, ulDataLen);

	output_len = hse_mem_alloc(sizeof(uint32_t));
	if (output_len == NULL) {
		rc = CKR_HOST_MEMORY;
		goto err_free_input;
	}
	memcpy(output_len, pulSignatureLen, sizeof(uint32_t));

	sign_srv = &srv_desc.hseSrv.signReq;
	sign_scheme = &sign_srv->signScheme;

	switch (gCtx->signCtx.mechanism->mechanism) {
		case CKM_SHA256_RSA_PKCS:

			sign0 = hse_mem_alloc(*(uint32_t *)output_len);
			if (sign0 == NULL) {
				rc = CKR_HOST_MEMORY;
				goto err_free_output_len;
			}

			sign_scheme->signSch = HSE_SIGN_RSASSA_PKCS1_V15;
			sign_scheme->sch.rsaPkcs1v15.hashAlgo = HSE_HASH_ALGO_SHA2_256;

			sign_srv->pSignatureLength[0] = hse_virt_to_dma(output_len);
			sign_srv->pSignatureLength[1] = 0u;
			sign_srv->pSignature[0] = hse_virt_to_dma(sign0); /* rsa */
			sign_srv->pSignature[1] = 0u;

			break;
		case CKM_ECDSA_SHA1:

			/* we only get one output length, which has to hold (r,s)
			 * (r,s) are both the length of the used curve in bytes - equal
			 * as such, assume it is doubled, and halve it */
			*(uint32_t *)output_len = *(uint32_t *)output_len / 2;

			sign0 = hse_mem_alloc(*(uint32_t *)output_len);
			if (sign0 == NULL) {
				rc = CKR_HOST_MEMORY;
				goto err_free_output_len;
			}
			sign1 = hse_mem_alloc(*(uint32_t *)output_len);
			if (sign1 == NULL) {
				rc = CKR_HOST_MEMORY;
				goto err_free_sign0;
			}

			sign_scheme->signSch = HSE_SIGN_ECDSA;
			sign_scheme->sch.ecdsa.hashAlgo = HSE_HASH_ALGO_SHA_1;

			sign_srv->pSignatureLength[0] = hse_virt_to_dma(output_len);
			sign_srv->pSignatureLength[1] = hse_virt_to_dma(output_len);
			sign_srv->pSignature[0] = hse_virt_to_dma(sign0);
			sign_srv->pSignature[1] = hse_virt_to_dma(sign1);

			break;
		default:
			rc = CKR_ARGUMENTS_BAD;
			goto err_free_output_len;
	}

	srv_desc.srvId = HSE_SRV_ID_SIGN;
	sign_srv->accessMode = HSE_ACCESS_MODE_ONE_PASS;
	sign_srv->streamId = 0u;
	sign_srv->authDir = HSE_AUTH_DIR_GENERATE;
	sign_srv->bInputIsHashed = 0u;
	sign_srv->keyHandle = key->key_handle;
	sign_srv->sgtOption = HSE_SGT_OPTION_NONE;
	sign_srv->inputLength = ulDataLen;
	sign_srv->pInput = hse_virt_to_dma(input);

	err = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc);
	if (err) {
		rc = CKR_FUNCTION_FAILED;
		goto err_free_sign1;
	}

	switch (gCtx->signCtx.mechanism->mechanism) {
		case CKM_SHA256_RSA_PKCS:

			memcpy(pSignature, sign0, *(uint32_t *)output_len);
			memcpy(pulSignatureLen, output_len, sizeof(uint32_t));

			break;
		case CKM_ECDSA_SHA1:

			memcpy(pSignature, sign0, *(uint32_t *)output_len);
			memcpy(pSignature + *(uint32_t *)output_len, sign1, *(uint32_t *)output_len);

			/* restore actual length */
			*(uint32_t *)output_len = *(uint32_t *)output_len * 2;
			memcpy(pulSignatureLen, output_len, sizeof(uint32_t));

			break;
		default:
			rc = CKR_ARGUMENTS_BAD;
			goto err_free_sign1;
	}

err_free_sign1:
	hse_mem_free(sign1);
err_free_sign0:
	hse_mem_free(sign0);
err_free_output_len:
	hse_mem_free(output_len);
err_free_input:
	hse_mem_free(input);
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

	if (list_seek(&gCtx->objects, &hKey) == NULL)
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
	hseSrvDescriptor_t srv_desc;
	hseSignSrv_t *sign_srv;
	hseSignScheme_t *sign_scheme;
	void *input, *sign0 = NULL, *sign1 = NULL, *output_len;
	struct hse_keyObject *key;
	CK_RV rc = CKR_OK;
	int err;

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

	key = (struct hse_keyObject *)list_seek(&gCtx->objects, &gCtx->signCtx.keyHandle);

	input = hse_mem_alloc(ulDataLen);
	if (input == NULL)
		return CKR_HOST_MEMORY;
	memcpy(input, pData, ulDataLen);

	output_len = hse_mem_alloc(sizeof(uint32_t));
	if (output_len == NULL) {
		rc = CKR_HOST_MEMORY;
		goto err_free_input;
	}
	memcpy(output_len, &ulSignatureLen, sizeof(uint32_t));

	sign_srv = &srv_desc.hseSrv.signReq;
	sign_scheme = &sign_srv->signScheme;

	switch (gCtx->signCtx.mechanism->mechanism) {
		case CKM_SHA256_RSA_PKCS:

			sign0 = hse_mem_alloc(ulSignatureLen);
			if (sign0 == NULL) {
				rc = CKR_HOST_MEMORY;
				goto err_free_output_len;
			}
			memcpy(sign0, pSignature, ulSignatureLen);

			sign_scheme->signSch = HSE_SIGN_RSASSA_PKCS1_V15;
			sign_scheme->sch.rsaPkcs1v15.hashAlgo = HSE_HASH_ALGO_SHA2_256;

			sign_srv->pSignatureLength[0] = hse_virt_to_dma(output_len);
			sign_srv->pSignatureLength[1] = 0u;
			sign_srv->pSignature[0] = hse_virt_to_dma(sign0); /* rsa */
			sign_srv->pSignature[1] = 0u;

			break;
		case CKM_ECDSA_SHA1:

			/* we only get one signature input and length
			 * (r,s) are the same length
			 * assume the signature contains both, one after the other */
			*(uint32_t *)output_len = *(uint32_t *)output_len / 2;

			sign0 = hse_mem_alloc(*(uint32_t *)output_len);
			if (sign0 == NULL) {
				rc = CKR_HOST_MEMORY;
				goto err_free_output_len;
			}
			sign1 = hse_mem_alloc(*(uint32_t *)output_len);
			if (sign1 == NULL) {
				rc = CKR_HOST_MEMORY;
				goto err_free_sign0;
			}
			memcpy(sign0, pSignature, *(uint32_t *)output_len);
			memcpy(sign1, pSignature + *(uint32_t *)output_len, *(uint32_t *)output_len);

			sign_scheme->signSch = HSE_SIGN_ECDSA;
			sign_scheme->sch.ecdsa.hashAlgo = HSE_HASH_ALGO_SHA_1;

			sign_srv->pSignatureLength[0] = hse_virt_to_dma(output_len);
			sign_srv->pSignatureLength[1] = hse_virt_to_dma(output_len);
			sign_srv->pSignature[0] = hse_virt_to_dma(sign0);
			sign_srv->pSignature[1] = hse_virt_to_dma(sign1);

		default:
			rc = CKR_ARGUMENTS_BAD;
			goto err_free_output_len;
	}

	srv_desc.srvId = HSE_SRV_ID_SIGN;
	sign_srv->accessMode = HSE_ACCESS_MODE_ONE_PASS;
	sign_srv->streamId = 0u;
	sign_srv->authDir = HSE_AUTH_DIR_VERIFY;
	sign_srv->bInputIsHashed = 0u;
	sign_srv->keyHandle = key->key_handle;
	sign_srv->sgtOption = HSE_SGT_OPTION_NONE;
	sign_srv->inputLength = ulDataLen;
	sign_srv->pInput = hse_virt_to_dma(input);

	err = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc);
	if (err == EBADMSG) {
		rc = CKR_SIGNATURE_INVALID;
		goto err_free_sign1;
	} else {
		rc = CKR_FUNCTION_FAILED;
		goto err_free_sign1;
	}

err_free_sign1:
	hse_mem_free(sign1);
err_free_sign0:
	hse_mem_free(sign0);
err_free_output_len:
	hse_mem_free(output_len);
err_free_input:
	hse_mem_free(input);
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
