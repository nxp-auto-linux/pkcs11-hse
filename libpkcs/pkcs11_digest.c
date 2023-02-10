// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pkcs11_context.h"

#define SHA1_DIGEST_SIZE 20
#define SHA1_BLOCK_SIZE  64

#define SHA224_DIGEST_SIZE 28
#define SHA224_BLOCK_SIZE  64

#define SHA256_DIGEST_SIZE 32
#define SHA256_BLOCK_SIZE  64

#define SHA384_DIGEST_SIZE 48
#define SHA384_BLOCK_SIZE  128

#define SHA512_DIGEST_SIZE 64
#define SHA512_BLOCK_SIZE  128

CK_RV check_init(CK_SESSION_HANDLE hSession, CK_BBOOL digestInit)
{
	struct globalCtx *gCtx = getCtx();

	if (hSession != SESSION_ID)
		return CKR_SESSION_HANDLE_INVALID;

	if (gCtx->cryptokiInit == CK_FALSE)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (gCtx->digestCtx.init == digestInit) {
		if (digestInit == CK_TRUE)
			return CKR_OPERATION_ACTIVE;
		else
			return CKR_OPERATION_NOT_INITIALIZED;
	}

	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_DigestInit)(
		CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism
)
{
	struct globalCtx *gCtx = getCtx();
	CK_RV rc = CKR_OK;

	rc = check_init(hSession, CK_TRUE);
	if (rc != CKR_OK) {
		/* special case: cancels in progress operation */
		if (rc == CKR_OPERATION_ACTIVE && pMechanism == NULL) {
			gCtx->digestCtx.init = CK_FALSE;
			free(gCtx->digestCtx.cache);
			gCtx->digestCtx.cache = NULL;
			return CKR_OK;
		}

		return rc;
	}

	/* special case: cancels in progress op, but return CKR_OK if no op active */
	if (pMechanism == NULL)
		return CKR_OK;

	switch (pMechanism->mechanism) {
		case CKM_SHA_1:
			gCtx->digestCtx.mechanism = HSE_HASH_ALGO_SHA_1;
			gCtx->digestCtx.blockSize = SHA1_BLOCK_SIZE;
			gCtx->digestCtx.digestSize = SHA1_DIGEST_SIZE;
			break;
		case CKM_SHA224:
			gCtx->digestCtx.mechanism = HSE_HASH_ALGO_SHA2_224;
			gCtx->digestCtx.blockSize = SHA224_BLOCK_SIZE;
			gCtx->digestCtx.digestSize = SHA224_DIGEST_SIZE;
			break;
		case CKM_SHA256:
			gCtx->digestCtx.mechanism = HSE_HASH_ALGO_SHA2_256;
			gCtx->digestCtx.blockSize = SHA256_BLOCK_SIZE;
			gCtx->digestCtx.digestSize = SHA256_DIGEST_SIZE;
			break;
		case CKM_SHA512:
			gCtx->digestCtx.mechanism = HSE_HASH_ALGO_SHA2_512;
			gCtx->digestCtx.blockSize = SHA512_BLOCK_SIZE;
			gCtx->digestCtx.digestSize = SHA512_DIGEST_SIZE;
			break;
		case CKM_SHA512_224:
			gCtx->digestCtx.mechanism = HSE_HASH_ALGO_SHA2_512_224;
			gCtx->digestCtx.blockSize = SHA512_BLOCK_SIZE;
			gCtx->digestCtx.digestSize = SHA224_DIGEST_SIZE;
			break;
		case CKM_SHA512_256:
			gCtx->digestCtx.mechanism = HSE_HASH_ALGO_SHA2_512_256;
			gCtx->digestCtx.blockSize = SHA512_BLOCK_SIZE;
			gCtx->digestCtx.digestSize = SHA256_DIGEST_SIZE;
			break;
		default:
			return CKR_MECHANISM_INVALID;
	}

	gCtx->digestCtx.cache = malloc(gCtx->digestCtx.blockSize);
	if (gCtx->digestCtx.cache == NULL)
		return CKR_HOST_MEMORY;

	gCtx->digestCtx.init = CK_TRUE;
	gCtx->digestCtx.stream_start = CK_TRUE;
	gCtx->digestCtx.cache_idx = 0;

	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_Digest)(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pData,
		CK_ULONG ulDataLen,
		CK_BYTE_PTR pDigest,
		CK_ULONG_PTR pulDigestLen
)
{
	struct globalCtx *gCtx = getCtx();
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	hseHashSrv_t *hash_req;
	void *output, *output_len, *input;
	CK_RV rc = CKR_OK;
	int err;

	rc = check_init(hSession, CK_FALSE);
	if (rc != CKR_OK) {
		if (rc == CKR_OPERATION_NOT_INITIALIZED)
			return rc;
		else
			goto err_uninit;
	}

	if (ulDataLen == 0) {
		rc = CKR_DATA_LEN_RANGE;
		goto err_uninit;
	}

	if (pData == NULL) {
		rc = CKR_DATA_INVALID;
		goto err_uninit;
	}

	if (pulDigestLen == NULL) {
		rc = CKR_ENCRYPTED_DATA_LEN_RANGE;
		goto err_uninit;
	}

	if (pDigest == NULL) {
		/* if NULL, upper layer expects to receive size needed for digest */
		*pulDigestLen = gCtx->digestCtx.digestSize;
		return CKR_OK;
	}

	if (*pulDigestLen < gCtx->digestCtx.digestSize) {
		/* pkcs11-base-3.0: section 5.2: In either case, *pulBufLen is set to hold the exact number of bytes 
		 * needed to hold the cryptographic output produced from the input to 
		 * the function.*/
		*pulDigestLen = gCtx->digestCtx.digestSize;
		return CKR_BUFFER_TOO_SMALL;
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
	hse_memcpy(output_len, pulDigestLen, sizeof(uint32_t));

	output = hse_mem_alloc(*pulDigestLen);
	if (output == NULL) {
		rc = CKR_HOST_MEMORY;
		goto err_free_output_len;
	}

	hash_req = &srv_desc.hseSrv.hashReq;

	srv_desc.srvId = HSE_SRV_ID_HASH;
	hash_req->accessMode = HSE_ACCESS_MODE_ONE_PASS;
	hash_req->streamId = 0;
	hash_req->hashAlgo = gCtx->digestCtx.mechanism;
	hash_req->sgtOption = HSE_SGT_OPTION_NONE;
	hash_req->inputLength = ulDataLen;
	hash_req->pInput = hse_virt_to_dma(input);
	hash_req->pHashLength = hse_virt_to_dma(output_len);
	hash_req->pHash = hse_virt_to_dma(output);

	err = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc, sizeof(srv_desc));
	if (err) {
		rc = CKR_FUNCTION_FAILED;
		goto err_free_output;
	}

	hse_memcpy(pDigest, output, *(uint32_t *)output_len);

	/* pkcs11-base-3.0: section 5.2: In either case, *pulBufLen is set to hold the exact number of bytes 
	* needed to hold the cryptographic output produced from the input to 
	* the function.*/
	*pulDigestLen = *(uint32_t *)output_len;

err_free_output:
	hse_mem_free(output);
err_free_output_len:
	hse_mem_free(output_len);
err_free_input:
	hse_mem_free(input);
err_uninit:
	gCtx->digestCtx.init = CK_FALSE;
	if (gCtx->digestCtx.cache != NULL) {
		free(gCtx->digestCtx.cache);
		gCtx->digestCtx.cache = NULL;
	}
	return rc;
}

CK_DEFINE_FUNCTION(CK_RV, C_DigestUpdate)(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pPart,
		CK_ULONG ulPartLen
)
{
	struct globalCtx *gCtx = getCtx();
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	hseHashSrv_t *hash_req;
	void *input;
	uint32_t bytes_left, full_blocks;
	CK_RV rc = CKR_OK;
	int err;

	rc = check_init(hSession, CK_FALSE);
	if (rc != CKR_OK) {
		if (rc == CKR_OPERATION_NOT_INITIALIZED)
			return rc;
		else
			goto err_uninit;
	}

	if (pPart == NULL) {
		rc = CKR_DATA_INVALID;
		goto err_uninit;
	}

	if (ulPartLen == 0) {
		rc = CKR_DATA_LEN_RANGE;
		goto err_uninit;
	}

	bytes_left = gCtx->digestCtx.cache_idx + ulPartLen;
	if (bytes_left < gCtx->digestCtx.blockSize) {
		/* cache data for next update and exit */
		memcpy(gCtx->digestCtx.cache + gCtx->digestCtx.cache_idx, pPart, ulPartLen);
		gCtx->digestCtx.cache_idx = bytes_left;
		return CKR_OK;
	}

	/* round down to nearest multiple of block size */
	full_blocks = bytes_left - (bytes_left % gCtx->digestCtx.blockSize);

	/* copy full_blocks to dynamic buffer */
	input = hse_mem_alloc(full_blocks);
	if (input == NULL) {
		rc = CKR_HOST_MEMORY;
		goto err_uninit;
	}
	hse_memcpy(input, gCtx->digestCtx.cache, gCtx->digestCtx.cache_idx);
	hse_memcpy(input + gCtx->digestCtx.cache_idx, pPart, full_blocks - gCtx->digestCtx.cache_idx);
	bytes_left -= full_blocks;

	hash_req = &srv_desc.hseSrv.hashReq;
	srv_desc.srvId = HSE_SRV_ID_HASH;

	if (gCtx->digestCtx.stream_start) {
		hash_req->accessMode = HSE_ACCESS_MODE_START;
		gCtx->digestCtx.stream_start = CK_FALSE;
	} else {
		hash_req->accessMode = HSE_ACCESS_MODE_UPDATE;
	}

	hash_req->streamId = 0;
	hash_req->hashAlgo = gCtx->digestCtx.mechanism;
	hash_req->sgtOption = HSE_SGT_OPTION_NONE;
	hash_req->inputLength = full_blocks;
	hash_req->pInput = hse_virt_to_dma(input);
	hash_req->pHashLength = 0;
	hash_req->pHash = 0;

	err = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc, sizeof(srv_desc));
	if (err) {
		rc = CKR_FUNCTION_FAILED;
		goto err_free_input;
	}

	/* copy residue to block-sized cache */
	memcpy(gCtx->digestCtx.cache, pPart + (full_blocks - gCtx->digestCtx.cache_idx), bytes_left);
	gCtx->digestCtx.cache_idx = bytes_left;

err_free_input:
	hse_mem_free(input);
err_uninit:
	if (rc != CKR_OK) {
		gCtx->digestCtx.init = CK_FALSE;
		if (gCtx->digestCtx.cache != NULL) {
			free(gCtx->digestCtx.cache);
			gCtx->digestCtx.cache = NULL;
		}
	}
	return rc;
}

CK_DEFINE_FUNCTION(CK_RV, C_DigestFinal)(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pDigest,
		CK_ULONG_PTR pulDigestLen
)
{
	struct globalCtx *gCtx = getCtx();
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	hseHashSrv_t *hash_req;
	void *input, *output, *output_len;
	CK_RV rc = CKR_OK;
	int err;

	rc = check_init(hSession, CK_FALSE);
	if (rc != CKR_OK) {
		if (rc == CKR_OPERATION_NOT_INITIALIZED)
			return rc;
		else
			goto err_uninit;
	}

	if (pulDigestLen == NULL) {
		rc = CKR_ENCRYPTED_DATA_LEN_RANGE;
		goto err_uninit;
	}

	if (pDigest == NULL) {
		/* if NULL, upper layer expects to receive needed size for digest */
		*pulDigestLen = gCtx->digestCtx.digestSize;
		return CKR_OK;
	}

	if (*pulDigestLen < gCtx->digestCtx.digestSize) {
		/* pkcs11-base-3.0: section 5.2: In either case, *pulBufLen is set to hold the exact number of bytes 
		 * needed to hold the cryptographic output produced from the input to 
		 * the function.*/
		*pulDigestLen = gCtx->digestCtx.digestSize;
		return CKR_BUFFER_TOO_SMALL;
	}

	output_len = hse_mem_alloc(sizeof(uint32_t));
	if (output_len == NULL) {
		rc = CKR_HOST_MEMORY;
		goto err_uninit;
	}
	hse_memcpy(output_len, pulDigestLen, sizeof(uint32_t));

	output = hse_mem_alloc(*pulDigestLen);
	if (output == NULL) {
		rc = CKR_HOST_MEMORY;
		goto err_free_output_len;
	}

	if (gCtx->digestCtx.cache_idx > 0) {
		input = hse_mem_alloc(gCtx->digestCtx.cache_idx);
		if (input == NULL) {
			rc = CKR_HOST_MEMORY;
			goto err_free_output;
		}

		/* copy remaining data to buffer */
		hse_memcpy(input, gCtx->digestCtx.cache, gCtx->digestCtx.cache_idx);
	}

	hash_req = &srv_desc.hseSrv.hashReq;
	srv_desc.srvId = HSE_SRV_ID_HASH;

	hash_req->streamId = 0;
	hash_req->accessMode = HSE_ACCESS_MODE_FINISH;
	hash_req->hashAlgo = gCtx->digestCtx.mechanism;
	hash_req->sgtOption = HSE_SGT_OPTION_NONE;
	hash_req->inputLength = gCtx->digestCtx.cache_idx;
	hash_req->pInput = hse_virt_to_dma(input);
	hash_req->pHashLength = hse_virt_to_dma(output_len);
	hash_req->pHash = hse_virt_to_dma(output);

	err = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc, sizeof(srv_desc));
	if (err) {
		rc = CKR_FUNCTION_FAILED;
		goto err_free_input;
	}

	/* copy result back to pDigest */
	hse_memcpy(pDigest, output, *(uint32_t *)output_len);

	/* pkcs11-base-3.0: section 5.2: In either case, *pulBufLen is set to hold the exact number of bytes 
	* needed to hold the cryptographic output produced from the input to 
	* the function.*/
	*pulDigestLen = *(uint32_t *)output_len;

err_free_input:
	hse_mem_free(input);
err_free_output:
	hse_mem_free(output);
err_free_output_len:
	hse_mem_free(output_len);
err_uninit:
	gCtx->digestCtx.init = CK_FALSE;
	if (gCtx->digestCtx.cache != NULL) {
		free(gCtx->digestCtx.cache);
		gCtx->digestCtx.cache = NULL;
	}
	return rc;
}

CK_DEFINE_FUNCTION(CK_RV, C_DigestKey)(
		CK_SESSION_HANDLE hSession,
		CK_OBJECT_HANDLE hKey
)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}
