// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021 NXP
 */

#include <stdio.h>
#include <stdlib.h>

#include "pkcs11_context.h"

static inline void hse_memcpy(void *dst, void *src, size_t n)
{
	uint8_t *s = (uint8_t *)src;
	uint8_t *d = (uint8_t *)dst;

	if (!dst || !src || n == 0)
		return;

	for (int i = 0; i < n; i++)
		d[i] = s[i];
}

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
	void *_srv_desc, *_input, *_output, *_output_len, *_pIV;
	struct hse_keyObject *key;
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

	_input = hse_get_shared_mem_addr(HSE_INPUT_SRAM);
	_output = hse_get_shared_mem_addr(HSE_OUTPUT_SRAM);
	_output_len = hse_get_shared_mem_addr(HSE_OUTPUTLEN_SRAM);
	hse_memcpy(_output_len, pulEncryptedDataLen, sizeof(uint32_t));
	hse_memcpy(_input, pData, ulDataLen);

	if (gCtx->cryptCtx.mechanism->pParameter != NULL) {
		_pIV = hse_get_shared_mem_addr(HSE_IV_SRAM);
		hse_memcpy(_pIV, gCtx->cryptCtx.mechanism->pParameter,
		                 gCtx->cryptCtx.mechanism->ulParameterLen);
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
				sym_cipher_srv->pIV = hse_virt_to_phys(_pIV);
			} else {
				sym_cipher_srv->pIV = 0u; /* IV is not required for ecb */
			}

			sym_cipher_srv->inputLength = ulDataLen;
			sym_cipher_srv->pInput = hse_virt_to_phys(_input);
			sym_cipher_srv->pOutput= hse_virt_to_phys(_output);

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
			aead_srv->pIV = hse_virt_to_phys(_pIV);
			aead_srv->aadLength = 0u;
			aead_srv->pAAD = 0u;
			aead_srv->sgtOption = HSE_SGT_OPTION_NONE;
			aead_srv->inputLength = ulDataLen;
			aead_srv->pInput = hse_virt_to_phys(_input);
			aead_srv->tagLength = 0u;
			aead_srv->pTag = 0u;
			aead_srv->pOutput = hse_virt_to_phys(_output);

		default:
			return CKR_ARGUMENTS_BAD;
	}

	_srv_desc = hse_get_shared_mem_addr(HSE_SRVDESC_SRAM);
	hse_memcpy(_srv_desc, &srv_desc, sizeof(hseSrvDescriptor_t));

	err = hse_srv_req_sync(HSE_CHANNEL_ANY, hse_virt_to_phys(_srv_desc));
	if (err)
		return CKR_FUNCTION_FAILED;

	hse_memcpy(pEncryptedData, _output, *(uint32_t *)_output_len);
	hse_memcpy(pulEncryptedDataLen, _output_len, sizeof(uint32_t));

	return CKR_OK;
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
	void *_srv_desc, *_input, *_output, *_output_len, *_pIV;
	struct hse_keyObject *key;
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

	_input = hse_get_shared_mem_addr(HSE_INPUT_SRAM);
	_output = hse_get_shared_mem_addr(HSE_OUTPUT_SRAM);
	_output_len = hse_get_shared_mem_addr(HSE_OUTPUTLEN_SRAM);
	hse_memcpy(_input, pEncryptedData, ulEncryptedDataLen);
	hse_memcpy(_output_len, pulDataLen, sizeof(uint32_t));

	if (gCtx->cryptCtx.mechanism->pParameter != NULL) {
		_pIV = hse_get_shared_mem_addr(HSE_IV_SRAM);
		hse_memcpy(_pIV, gCtx->cryptCtx.mechanism->pParameter,
		                 gCtx->cryptCtx.mechanism->ulParameterLen);
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
				sym_cipher_srv->pIV = hse_virt_to_phys(_pIV);
			} else {
				sym_cipher_srv->pIV = 0u; /* IV is not required for ecb */
			}

			sym_cipher_srv->inputLength = ulEncryptedDataLen;
			sym_cipher_srv->pInput = hse_virt_to_phys(_input);
			sym_cipher_srv->pOutput= hse_virt_to_phys(_output);

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
			aead_srv->pIV = hse_virt_to_phys(_pIV);
			aead_srv->aadLength = 0u;
			aead_srv->pAAD = 0u;
			aead_srv->sgtOption = HSE_SGT_OPTION_NONE;
			aead_srv->inputLength = ulEncryptedDataLen;
			aead_srv->pInput = hse_virt_to_phys(_input);
			aead_srv->tagLength = 0u;
			aead_srv->pTag = 0u;
			aead_srv->pOutput = hse_virt_to_phys(_output);

		default:
			return CKR_ARGUMENTS_BAD;
	}

	_srv_desc = hse_get_shared_mem_addr(HSE_SRVDESC_SRAM);
	hse_memcpy(_srv_desc, &srv_desc, sizeof(hseSrvDescriptor_t));

	err = hse_srv_req_sync(HSE_CHANNEL_ANY, hse_virt_to_phys(_srv_desc));
	if (err)
		return CKR_FUNCTION_FAILED;

	hse_memcpy(pData, _output, *(uint32_t *)_output_len);
	hse_memcpy(pulDataLen, _output_len, sizeof(uint32_t));

	return CKR_OK;
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

	if (gCtx->signCtx.init == CK_TRUE)
		return CKR_OPERATION_ACTIVE;

	if (hSession != SESSION_ID)
		return CKR_SESSION_HANDLE_INVALID;

	if (pMechanism == NULL)
		return CKR_ARGUMENTS_BAD;

	if (list_seek(&gCtx->objects, &hKey) == NULL)
		return CKR_KEY_HANDLE_INVALID;

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
	void *_srv_desc, *_input, *_sign0, *_sign1, *_output_len;
	struct hse_keyObject *key;
	int err;

	if (gCtx->cryptokiInit == CK_FALSE)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (gCtx->signCtx.init == CK_FALSE)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (hSession != SESSION_ID)
		return CKR_SESSION_HANDLE_INVALID;

	if (pData == NULL || pSignature == NULL || pulSignatureLen == NULL)
		return CKR_ARGUMENTS_BAD;

	key = (struct hse_keyObject *)list_seek(&gCtx->objects, &gCtx->signCtx.keyHandle);

	_input = hse_get_shared_mem_addr(HSE_INPUT_SRAM);
	_output_len = hse_get_shared_mem_addr(HSE_OUTPUTLEN_SRAM);
	hse_memcpy(_input, pData, ulDataLen);
	hse_memcpy(_output_len, pulSignatureLen, sizeof(uint32_t));

	sign_srv = &srv_desc.hseSrv.signReq;
	sign_scheme = &sign_srv->signScheme;

	switch (gCtx->signCtx.mechanism->mechanism) {
		case CKM_SHA256_RSA_PKCS:

			_sign0 = hse_get_shared_mem_addr(HSE_SIGN0_SRAM);

			sign_scheme->signSch = HSE_SIGN_RSASSA_PKCS1_V15;
			sign_scheme->sch.rsaPkcs1v15.hashAlgo = HSE_HASH_ALGO_SHA2_256;

			sign_srv->pSignatureLength[0] = hse_virt_to_phys(_output_len);
			sign_srv->pSignatureLength[1] = 0u;
			sign_srv->pSignature[0] = hse_virt_to_phys(_sign0); /* rsa */
			sign_srv->pSignature[1] = 0u;

			break;
		case CKM_ECDSA_SHA1:

			_sign0 = hse_get_shared_mem_addr(HSE_SIGN0_SRAM);
			_sign1 = hse_get_shared_mem_addr(HSE_SIGN1_SRAM);

			/* we only get one output length, which has to hold (r,s)
			 * (r,s) are both the length of the used curve in bytes - equal
			 * as such, assume it is doubled, and halve it */
			*(uint32_t *)_output_len = *(uint32_t *)_output_len / 2;

			sign_scheme->signSch = HSE_SIGN_ECDSA;
			sign_scheme->sch.ecdsa.hashAlgo = HSE_HASH_ALGO_SHA_1;

			sign_srv->pSignatureLength[0] = hse_virt_to_phys(_output_len);
			sign_srv->pSignatureLength[1] = hse_virt_to_phys(_output_len);
			sign_srv->pSignature[0] = hse_virt_to_phys(_sign0);
			sign_srv->pSignature[1] = hse_virt_to_phys(_sign1);

			break;
		default:
			return CKR_ARGUMENTS_BAD;
	}

	srv_desc.srvId = HSE_SRV_ID_SIGN;
	sign_srv->accessMode = HSE_ACCESS_MODE_ONE_PASS;
	sign_srv->streamId = 0u;
	sign_srv->authDir = HSE_AUTH_DIR_GENERATE;
	sign_srv->bInputIsHashed = 0u;
	sign_srv->keyHandle = key->key_handle;
	sign_srv->sgtOption = HSE_SGT_OPTION_NONE;
	sign_srv->inputLength = ulDataLen;
	sign_srv->pInput = hse_virt_to_phys(_input);

	_srv_desc = hse_get_shared_mem_addr(HSE_SRVDESC_SRAM);
	hse_memcpy(_srv_desc, &srv_desc, sizeof(hseSrvDescriptor_t));

	err = hse_srv_req_sync(HSE_CHANNEL_ANY, hse_virt_to_phys(_srv_desc));
	if (err)
		return CKR_FUNCTION_FAILED;

	switch (gCtx->signCtx.mechanism->mechanism) {
		case CKM_SHA256_RSA_PKCS:

			hse_memcpy(pSignature, _sign0, *(uint32_t *)_output_len);
			hse_memcpy(pulSignatureLen, _output_len, sizeof(uint32_t));

			break;
		case CKM_ECDSA_SHA1:

			hse_memcpy(pSignature, _sign0, *(uint32_t *)_output_len);
			hse_memcpy(pSignature + *(uint32_t *)_output_len, _sign1, *(uint32_t *)_output_len);

			/* restore actual length */
			*(uint32_t *)_output_len = *(uint32_t *)_output_len * 2;
			hse_memcpy(pulSignatureLen, _output_len, sizeof(uint32_t));

			break;
		default:
			return CKR_ARGUMENTS_BAD;
	}

	return CKR_OK;
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

	if (gCtx->signCtx.init == CK_TRUE)
		return CKR_OPERATION_ACTIVE;

	if (hSession != SESSION_ID)
		return CKR_SESSION_HANDLE_INVALID;

	if (pMechanism == NULL)
		return CKR_ARGUMENTS_BAD;

	if (list_seek(&gCtx->objects, &hKey) == NULL)
		return CKR_KEY_HANDLE_INVALID;

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
	void *_srv_desc, *_input, *_sign0, *_sign1, *_output_len;
	struct hse_keyObject *key;
	int err;

	if (gCtx->cryptokiInit == CK_FALSE)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (gCtx->signCtx.init == CK_FALSE)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (hSession != SESSION_ID)
		return CKR_SESSION_HANDLE_INVALID;

	if (pData == NULL || pSignature == NULL)
		return CKR_ARGUMENTS_BAD;

	key = (struct hse_keyObject *)list_seek(&gCtx->objects, &gCtx->signCtx.keyHandle);

	_input = hse_get_shared_mem_addr(HSE_INPUT_SRAM);
	_output_len = hse_get_shared_mem_addr(HSE_OUTPUTLEN_SRAM);
	hse_memcpy(_input, pData, ulDataLen);
	hse_memcpy(_output_len, &ulSignatureLen, sizeof(uint32_t));

	sign_srv = &srv_desc.hseSrv.signReq;
	sign_scheme = &sign_srv->signScheme;

	switch (gCtx->signCtx.mechanism->mechanism) {
		case CKM_SHA256_RSA_PKCS:

			_sign0 = hse_get_shared_mem_addr(HSE_SIGN0_SRAM);
			hse_memcpy(_sign0, pSignature, ulSignatureLen);

			sign_scheme->signSch = HSE_SIGN_RSASSA_PKCS1_V15;
			sign_scheme->sch.rsaPkcs1v15.hashAlgo = HSE_HASH_ALGO_SHA2_256;

			sign_srv->pSignatureLength[0] = hse_virt_to_phys(_output_len);
			sign_srv->pSignatureLength[1] = 0u;
			sign_srv->pSignature[0] = hse_virt_to_phys(_sign0); /* rsa */
			sign_srv->pSignature[1] = 0u;

			break;
		case CKM_ECDSA_SHA1:

			/* we only get one signature input and length
			 * (r,s) are the same length
			 * assume the signature contains both, one after the other */
			*(uint32_t *)_output_len = *(uint32_t *)_output_len / 2;

			_sign0 = hse_get_shared_mem_addr(HSE_SIGN0_SRAM);
			_sign1 = hse_get_shared_mem_addr(HSE_SIGN1_SRAM);
			hse_memcpy(_sign0, pSignature, *(uint32_t *)_output_len);
			hse_memcpy(_sign1, pSignature + *(uint32_t *)_output_len, *(uint32_t *)_output_len);

			sign_scheme->signSch = HSE_SIGN_ECDSA;
			sign_scheme->sch.ecdsa.hashAlgo = HSE_HASH_ALGO_SHA_1;

			sign_srv->pSignatureLength[0] = hse_virt_to_phys(_output_len);
			sign_srv->pSignatureLength[1] = hse_virt_to_phys(_output_len);
			sign_srv->pSignature[0] = hse_virt_to_phys(_sign0);
			sign_srv->pSignature[1] = hse_virt_to_phys(_sign1);

		default:
			return CKR_ARGUMENTS_BAD;
	}

	srv_desc.srvId = HSE_SRV_ID_SIGN;
	sign_srv->accessMode = HSE_ACCESS_MODE_ONE_PASS;
	sign_srv->streamId = 0u;
	sign_srv->authDir = HSE_AUTH_DIR_VERIFY;
	sign_srv->bInputIsHashed = 0u;
	sign_srv->keyHandle = key->key_handle;
	sign_srv->sgtOption = HSE_SGT_OPTION_NONE;
	sign_srv->inputLength = ulDataLen;
	sign_srv->pInput = hse_virt_to_phys(_input);

	_srv_desc = hse_get_shared_mem_addr(HSE_SRVDESC_SRAM);
	hse_memcpy(_srv_desc, &srv_desc, sizeof(hseSrvDescriptor_t));

	err = hse_srv_req_sync(HSE_CHANNEL_ANY, hse_virt_to_phys(_srv_desc));
	if (err == EBADMSG) {
		return CKR_SIGNATURE_INVALID;
	} else {
		return CKR_FUNCTION_FAILED;
	}

	return CKR_OK;
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
