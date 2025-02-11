// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2024 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "pkcs11_context.h"
#include "pkcs11_util.h"
#include "hse-internal.h"

CK_DECLARE_FUNCTION(CK_RV, C_EncryptInit)(
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
		hse_stream_free(sCtx->cryptCtx.streamID);
		sCtx->cryptCtx.stream_start = CK_TRUE;
		return CKR_OK;
	}

	if (sCtx->cryptCtx.init == CK_TRUE)
		return CKR_OPERATION_ACTIVE;

	if (pMechanism == NULL)
		return CKR_ARGUMENTS_BAD;

	gCtx->mtxFns.lock(gCtx->keyMtx);
	if (get_key_object_handle(hKey) < 0) {
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
	sCtx->cryptCtx.streamID = INVALID_STREAM_ID;
	sCtx->cryptCtx.cache_idx = 0;

	return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_Encrypt)(
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
	struct hse_keyObject *key;
	CK_RV rc = CKR_OK;
	int err, key_handle = -1, input_handle = -1, output_handle = -1;
	int output_len_handle = -1, pIV_handle = -1, pAAD_handle = -1;
	uint16_t key_bit_length = 0;
	uint32_t output_len = 0;
	CK_RSA_PKCS_OAEP_PARAMS *oaep_params = NULL;
	CK_CCM_PARAMS *ccm_params = NULL;
	CK_GCM_PARAMS *gcm_params = NULL;

	if (gCtx->cryptokiInit == CK_FALSE)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!sCtx || sCtx->sessionInit == CK_FALSE)
		return CKR_SESSION_HANDLE_INVALID;

	if (sCtx->cryptCtx.init == CK_FALSE)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (sCtx->cryptCtx.stream_start == CK_FALSE)
		return CKR_FUNCTION_FAILED;

	if (pData == NULL || pEncryptedData == NULL || pulEncryptedDataLen == NULL) {
		rc = CKR_ARGUMENTS_BAD;
		goto out_uninit;
	}

	/* Check for input length: For ECB, CBC & CFB cipher block modes, must be a multiple of block length. Cannot be zero. */
	if (ulDataLen == 0) {
		rc = CKR_ARGUMENTS_BAD;
		goto out_uninit;
	}

	if ((sCtx->cryptCtx.mechanism->mechanism == CKM_AES_ECB) ||
		(sCtx->cryptCtx.mechanism->mechanism == CKM_AES_CBC) ) {
			if ((ulDataLen & (HSE_AES_BLOCK_LEN - 1)) != 0) {
				rc = CKR_ARGUMENTS_BAD;
				goto out_uninit;
			}
	}

	gCtx->mtxFns.lock(gCtx->keyMtx);
	key_handle = get_key_object_handle(sCtx->cryptCtx.keyHandle);
	gCtx->mtxFns.unlock(gCtx->keyMtx);
	if (key_handle < 0) {
		rc = CKR_KEY_HANDLE_INVALID;
		goto out_uninit;
	}
	key = (struct hse_keyObject *)hse_get_node_mem_addr(key_handle, true);

	/* check for input length for RSA ciphering */
	if ((sCtx->cryptCtx.mechanism->mechanism == CKM_RSA_PKCS) ||
		(sCtx->cryptCtx.mechanism->mechanism == CKM_RSA_PKCS_OAEP)) {
		key_bit_length = hse_get_key_bit_length(sCtx->sID, key);
		if (key_bit_length == 0) {
			rc = CKR_GENERAL_ERROR;
			goto out_uninit;
		}

		if (rsa_ciphering_get_max_input_length(key_bit_length, sCtx->cryptCtx.mechanism) < ulDataLen) {
			rc = CKR_DATA_LEN_RANGE;
			goto out_uninit;
		}
	}

	if (sCtx->cryptCtx.mechanism->mechanism == CKM_AES_GCM) {
		gcm_params = (CK_GCM_PARAMS *)sCtx->cryptCtx.mechanism->pParameter;
	} else if (sCtx->cryptCtx.mechanism->mechanism == CKM_AES_CCM) {
		ccm_params = (CK_CCM_PARAMS *)sCtx->cryptCtx.mechanism->pParameter;
		if (ccm_params->ulDataLen != ulDataLen)
			printf("WARNING: CCM mechanism's input length not equal to encrypt input length.\n");
	}

	/* Check the output length */
	if ((sCtx->cryptCtx.mechanism->mechanism == CKM_AES_ECB) ||
		(sCtx->cryptCtx.mechanism->mechanism == CKM_AES_CBC) ||
		(sCtx->cryptCtx.mechanism->mechanism == CKM_AES_CTR)) {
		/* For AES, the output length is equal to the input length  */
		output_len = ulDataLen;
	} else if ((sCtx->cryptCtx.mechanism->mechanism == CKM_RSA_PKCS) ||
			   (sCtx->cryptCtx.mechanism->mechanism == CKM_RSA_PKCS_OAEP)) {
		/* get the output length based on the RSA key length */
		output_len = rsa_ciphering_get_out_length(key_bit_length);
	} else if(sCtx->cryptCtx.mechanism->mechanism == CKM_AES_CBC_PAD) {
		/* PKCS requires that, even for multiples of block size, padding must be applied.
		 * If the input is a multiple of block length, we add an entire block of padded values.
		 */
		output_len = sCtx->cryptCtx.blockSize * (ulDataLen / sCtx->cryptCtx.blockSize + 1);
	} else if (sCtx->cryptCtx.mechanism->mechanism == CKM_AES_CCM) {
		if (ccm_params->ulMACLen < 4 || ccm_params->ulMACLen > 16 || ccm_params->ulMACLen % 2) {
			rc =  CKR_ATTRIBUTE_VALUE_INVALID;
			goto out_uninit;
		}
		output_len = ccm_params->ulDataLen + ccm_params->ulMACLen;
	} else if (sCtx->cryptCtx.mechanism->mechanism == CKM_AES_GCM) {
		if (gcm_params->ulTagBits > 128) {
			rc = CKR_ATTRIBUTE_VALUE_INVALID;
			goto out_uninit;
		}
		output_len = ulDataLen + hse_get_tag_length(gcm_params->ulTagBits);
	}

	if (*pulEncryptedDataLen < output_len) {
		/* tell the required size */
		*pulEncryptedDataLen = output_len;

		rc = CKR_BUFFER_TOO_SMALL;
		goto out_uninit;
	}

	input_handle = hse_mem_alloc(ulDataLen);
	if (input_handle < 0) {
		rc = CKR_HOST_MEMORY;
		goto out_uninit;
	}
	hse_memcpy_to_dev(input_handle, pData, ulDataLen, 0);

	output_len_handle = hse_mem_alloc(sizeof(uint32_t));
	if (output_len_handle < 0) {
		rc = CKR_HOST_MEMORY;
		goto out_free_input;
	}
	hse_memcpy_to_dev(output_len_handle, (void *)&output_len, sizeof(output_len), 0);

	output_handle = hse_mem_alloc(output_len);
	if (output_handle < 0) {
		rc = CKR_HOST_MEMORY;
		goto out_free_output_len;
	}

	if (sCtx->cryptCtx.mechanism->mechanism == CKM_AES_CBC_PAD) {
		/* PKCS#11 standard requires filling the vector with the number of padded bytes */
		hse_mem_free(input_handle);
		input_handle = hse_mem_alloc(output_len);
		if (input_handle < 0) {
			rc = CKR_HOST_MEMORY;
			goto out_free_output;
		}
		hse_memcpy_to_dev(input_handle, pData, ulDataLen, 0);
		uint8_t val = output_len - ulDataLen / sCtx->cryptCtx.blockSize * sCtx->cryptCtx.blockSize;
		hse_memset(input_handle, val, val, output_len - val);
	}

	if (sCtx->cryptCtx.mechanism->pParameter != NULL) {
		if (sCtx->cryptCtx.mechanism->mechanism == CKM_RSA_PKCS_OAEP) {
			oaep_params = (CK_RSA_PKCS_OAEP_PARAMS *)sCtx->cryptCtx.mechanism->pParameter;
		} else if(sCtx->cryptCtx.mechanism->mechanism == CKM_AES_CCM) {
			if (ccm_params->ulNonceLen < 7 || ccm_params->ulNonceLen > 13 || !ccm_params->pNonce) {
				rc = CKR_ATTRIBUTE_VALUE_INVALID;
				goto out_free_output;
			}

			pIV_handle = hse_mem_alloc(ccm_params->ulNonceLen);
			if (pIV_handle < 0) {
				rc = CKR_HOST_MEMORY;
				goto out_free_output;
			}
			hse_memcpy_to_dev(pIV_handle, ccm_params->pNonce, ccm_params->ulNonceLen, 0);

			if (ccm_params->ulAADLen != 0) {
				if (ccm_params->ulAADLen > AAD_MAX_LEN || !ccm_params->pAAD) {
					rc = CKR_ATTRIBUTE_VALUE_INVALID;
					goto out_free_piv;
				}

				pAAD_handle = hse_mem_alloc(ccm_params->ulAADLen);
				if (pAAD_handle < 0) {
					rc = CKR_HOST_MEMORY;
					goto out_free_piv;
				}

				hse_memcpy_to_dev(pAAD_handle, ccm_params->pAAD, ccm_params->ulAADLen, 0);
			}
		} else if(sCtx->cryptCtx.mechanism->mechanism == CKM_AES_GCM) {
			if (!gcm_params->ulIvLen || gcm_params->ulIvLen > AAD_MAX_LEN || !gcm_params->pIv) {
				rc = CKR_HOST_MEMORY;
				goto out_free_output;
			}

			pIV_handle = hse_mem_alloc(gcm_params->ulIvLen);
			if (pIV_handle < 0) {
				rc = CKR_HOST_MEMORY;
				goto out_free_output;
			}
			hse_memcpy_to_dev(pIV_handle, gcm_params->pIv, gcm_params->ulIvLen, 0);

			if (gcm_params->ulAADLen != 0) {
				if (gcm_params->ulAADLen > AAD_MAX_LEN || !gcm_params->pAAD) {
					rc = CKR_ATTRIBUTE_VALUE_INVALID;
					goto out_free_piv;
				}

				pAAD_handle = hse_mem_alloc(gcm_params->ulAADLen);
				if (pAAD_handle < 0) {
					rc = CKR_HOST_MEMORY;
					goto out_free_piv;
				}
				hse_memcpy_to_dev(pAAD_handle, gcm_params->pAAD, gcm_params->ulAADLen, 0);
			}
		} else {
			pIV_handle = hse_mem_alloc(sCtx->cryptCtx.mechanism->ulParameterLen);
			if (pIV_handle < 0) {
				rc = CKR_HOST_MEMORY;
				goto out_free_output;
			}
			hse_memcpy_to_dev(pIV_handle, sCtx->cryptCtx.mechanism->pParameter,
							  sCtx->cryptCtx.mechanism->ulParameterLen, 0);
		}
	}

	switch (sCtx->cryptCtx.mechanism->mechanism) {
		case CKM_AES_ECB:

			sym_cipher_srv = &srv_desc.hseSrv.symCipherReq;

			srv_desc.srvId = HSE_SRV_ID_SYM_CIPHER;
			sym_cipher_srv->accessMode = HSE_ACCESS_MODE_ONE_PASS;
			sym_cipher_srv->streamId = sCtx->cryptCtx.streamID;
			sym_cipher_srv->cipherAlgo = HSE_CIPHER_ALGO_AES;
			sym_cipher_srv->cipherBlockMode = HSE_CIPHER_BLOCK_MODE_ECB;
			sym_cipher_srv->cipherDir = HSE_CIPHER_DIR_ENCRYPT;
			sym_cipher_srv->sgtOption = HSE_SGT_OPTION_NONE;
			sym_cipher_srv->keyHandle = key->key_handle;

			if (sCtx->cryptCtx.mechanism->pParameter != NULL) {
				sym_cipher_srv->pIV = hse_virt_to_dma(pIV_handle, 0);
			} else {
				sym_cipher_srv->pIV = 0u; /* IV is not required for ecb */
			}

			sym_cipher_srv->inputLength = ulDataLen;
			sym_cipher_srv->pInput = hse_virt_to_dma(input_handle, 0);
			sym_cipher_srv->pOutput= hse_virt_to_dma(output_handle, 0);

			break;

		case CKM_AES_CBC:
		case CKM_AES_CBC_PAD:

			sym_cipher_srv = &srv_desc.hseSrv.symCipherReq;

			srv_desc.srvId = HSE_SRV_ID_SYM_CIPHER;
			sym_cipher_srv->accessMode = HSE_ACCESS_MODE_ONE_PASS;
			sym_cipher_srv->streamId = sCtx->cryptCtx.streamID;
			sym_cipher_srv->cipherAlgo = HSE_CIPHER_ALGO_AES;
			sym_cipher_srv->cipherBlockMode = HSE_CIPHER_BLOCK_MODE_CBC;
			sym_cipher_srv->cipherDir = HSE_CIPHER_DIR_ENCRYPT;
			sym_cipher_srv->sgtOption = HSE_SGT_OPTION_NONE;
			sym_cipher_srv->keyHandle = key->key_handle;
			sym_cipher_srv->pIV = hse_virt_to_dma(pIV_handle, 0);
			sym_cipher_srv->inputLength = ulDataLen;
			if (sCtx->cryptCtx.mechanism->mechanism == CKM_AES_CBC_PAD)
				sym_cipher_srv->inputLength = output_len;
			sym_cipher_srv->pInput = hse_virt_to_dma(input_handle, 0);
			sym_cipher_srv->pOutput= hse_virt_to_dma(output_handle, 0);

			break;

		case CKM_AES_CTR:

			sym_cipher_srv = &srv_desc.hseSrv.symCipherReq;

			srv_desc.srvId = HSE_SRV_ID_SYM_CIPHER;
			sym_cipher_srv->accessMode = HSE_ACCESS_MODE_ONE_PASS;
			sym_cipher_srv->streamId = sCtx->cryptCtx.streamID;
			sym_cipher_srv->cipherAlgo = HSE_CIPHER_ALGO_AES;
			sym_cipher_srv->cipherBlockMode = HSE_CIPHER_BLOCK_MODE_CTR;
			sym_cipher_srv->cipherDir = HSE_CIPHER_DIR_ENCRYPT;
			sym_cipher_srv->sgtOption = HSE_SGT_OPTION_NONE;
			sym_cipher_srv->keyHandle = key->key_handle;
			sym_cipher_srv->pIV = hse_virt_to_dma(pIV_handle, 0);
			sym_cipher_srv->inputLength = ulDataLen;
			sym_cipher_srv->pInput = hse_virt_to_dma(input_handle, 0);
			sym_cipher_srv->pOutput= hse_virt_to_dma(output_handle, 0);

			break;

		case CKM_AES_GCM:

			aead_srv = &srv_desc.hseSrv.aeadReq;

			srv_desc.srvId = HSE_SRV_ID_AEAD;
			aead_srv->accessMode = HSE_ACCESS_MODE_ONE_PASS;
			aead_srv->streamId = sCtx->cryptCtx.streamID;
			aead_srv->authCipherMode = HSE_AUTH_CIPHER_MODE_GCM;
			aead_srv->cipherDir = HSE_CIPHER_DIR_ENCRYPT;
			aead_srv->keyHandle = key->key_handle;
			aead_srv->ivLength = gcm_params->ulIvLen;
			aead_srv->pIV = hse_virt_to_dma(pIV_handle, 0);
			aead_srv->aadLength = gcm_params->ulAADLen;
			aead_srv->pAAD = hse_virt_to_dma(pAAD_handle, 0);
			aead_srv->sgtOption = HSE_SGT_OPTION_NONE;
			aead_srv->inputLength = ulDataLen;
			aead_srv->pInput = hse_virt_to_dma(input_handle, 0);
			aead_srv->tagLength = hse_get_tag_length(gcm_params->ulTagBits);
			aead_srv->pTag = hse_virt_to_dma(output_handle, ulDataLen);
			aead_srv->pOutput = hse_virt_to_dma(output_handle, 0);

			break;
		case CKM_AES_CCM:
			aead_srv = &srv_desc.hseSrv.aeadReq;

			srv_desc.srvId = HSE_SRV_ID_AEAD;
			aead_srv->accessMode = HSE_ACCESS_MODE_ONE_PASS;
			aead_srv->streamId = sCtx->cryptCtx.streamID;
			aead_srv->authCipherMode = HSE_AUTH_CIPHER_MODE_CCM;
			aead_srv->cipherDir = HSE_CIPHER_DIR_ENCRYPT;
			aead_srv->keyHandle = key->key_handle;
			aead_srv->ivLength = ccm_params->ulNonceLen;
			aead_srv->pIV = hse_virt_to_dma(pIV_handle, 0);
			aead_srv->aadLength = ccm_params->ulAADLen;
			aead_srv->pAAD = hse_virt_to_dma(pAAD_handle, 0);
			aead_srv->sgtOption = HSE_SGT_OPTION_NONE;
			aead_srv->inputLength = ulDataLen;
			aead_srv->pInput = hse_virt_to_dma(input_handle, 0);
			aead_srv->tagLength = ccm_params->ulMACLen;
			aead_srv->pTag = hse_virt_to_dma(output_handle, ulDataLen);
			aead_srv->pOutput = hse_virt_to_dma(output_handle, 0);

			break;
		case CKM_RSA_PKCS:
			rsa_cipher_srv = &srv_desc.hseSrv.rsaCipherReq;

			srv_desc.srvId = HSE_SRV_ID_RSA_CIPHER;
			rsa_cipher_srv->cipherDir = HSE_CIPHER_DIR_ENCRYPT;
			rsa_cipher_srv->keyHandle = key->key_handle;
			rsa_cipher_srv->inputLength = ulDataLen;
			rsa_cipher_srv->pInput = hse_virt_to_dma(input_handle, 0);
			rsa_cipher_srv->pOutputLength = hse_virt_to_dma(output_len_handle, 0);
			rsa_cipher_srv->pOutput = hse_virt_to_dma(output_handle, 0);

			rsa_cipher_srv->rsaScheme.rsaAlgo = HSE_RSA_ALGO_RSAES_PKCS1_V15;
			break;

		case CKM_RSA_PKCS_OAEP:
			rsa_cipher_srv = &srv_desc.hseSrv.rsaCipherReq;

			srv_desc.srvId = HSE_SRV_ID_RSA_CIPHER;
			rsa_cipher_srv->cipherDir = HSE_CIPHER_DIR_ENCRYPT;
			rsa_cipher_srv->keyHandle = key->key_handle;
			rsa_cipher_srv->inputLength = ulDataLen;
			rsa_cipher_srv->pInput = hse_virt_to_dma(input_handle, 0);
			rsa_cipher_srv->pOutputLength = hse_virt_to_dma(output_len_handle, 0);
			rsa_cipher_srv->pOutput = hse_virt_to_dma(output_handle, 0);

			rsa_cipher_srv->rsaScheme.rsaAlgo = HSE_RSA_ALGO_RSAES_OAEP;
			rsa_cipher_srv->rsaScheme.sch.rsaOAEP.hashAlgo = hse_pkcs_hash_alg_translate(oaep_params->hashAlg);
			rsa_cipher_srv->rsaScheme.sch.rsaOAEP.labelLength = 0;
			rsa_cipher_srv->rsaScheme.sch.rsaOAEP.pLabel = 0;
			break;

		default:
			rc = CKR_ARGUMENTS_BAD;
			goto out_free_paad;
	}

	err = hse_srv_req_sync(sCtx->sID, &srv_desc, sizeof(srv_desc));
	if (err) {
		rc = CKR_FUNCTION_FAILED;
		goto out_free_paad;
	}

	hse_memcpy_from_dev(pulEncryptedDataLen, output_len_handle, sizeof(output_len), 0);
	hse_memcpy_from_dev(pEncryptedData, output_handle, *pulEncryptedDataLen, 0);

out_free_paad:
	hse_mem_free(pAAD_handle);
out_free_piv:
	hse_mem_free(pIV_handle);
out_free_output:
	hse_mem_free(output_handle);
out_free_output_len:
	hse_mem_free(output_len_handle);
out_free_input:
	hse_mem_free(input_handle);
out_uninit:
	if (rc != CKR_BUFFER_TOO_SMALL) {
		sCtx->cryptCtx.init = CK_FALSE;
		if (sCtx->cryptCtx.cache != NULL) {
			free(sCtx->cryptCtx.cache);
			sCtx->cryptCtx.cache = NULL;
		}
	}

	return rc;
}

CK_DECLARE_FUNCTION(CK_RV, C_DecryptInit)(
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
		hse_stream_free(sCtx->cryptCtx.streamID);
		sCtx->cryptCtx.stream_start = CK_TRUE;
		return CKR_OK;
	}

	if (sCtx->cryptCtx.init == CK_TRUE)
		return CKR_OPERATION_ACTIVE;

	if (pMechanism == NULL)
		return CKR_ARGUMENTS_BAD;

	gCtx->mtxFns.lock(gCtx->keyMtx);
	if (get_key_object_handle(hKey) < 0) {
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
	sCtx->cryptCtx.streamID = INVALID_STREAM_ID;
	sCtx->cryptCtx.cache_idx = 0;

	return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_Decrypt)(
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
	struct hse_keyObject *key;
	CK_RV rc = CKR_OK;
	int err, key_handle = -1, input_handle = -1, output_handle = -1;
	int output_len_handle = -1, pIV_handle = -1, pAAD_handle = -1;
	uint16_t key_bit_length = 0;
	uint32_t output_len;
	CK_RSA_PKCS_OAEP_PARAMS *oaep_params = NULL;
	CK_CCM_PARAMS *ccm_params = NULL;
	CK_GCM_PARAMS *gcm_params = NULL;

	if (gCtx->cryptokiInit == CK_FALSE)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!sCtx || sCtx->sessionInit == CK_FALSE)
		return CKR_SESSION_HANDLE_INVALID;

	if (sCtx->cryptCtx.init == CK_FALSE)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (sCtx->cryptCtx.stream_start == CK_FALSE)
		return CKR_FUNCTION_FAILED;

	if (pData == NULL || pEncryptedData == NULL || pulDataLen == NULL) {
		rc = CKR_ARGUMENTS_BAD;
		goto out_uninit;
	}

	/* Check for input length: For ECB, CBC & CFB cipher block modes, must be a multiple of block length. Cannot be zero. */
	if (ulEncryptedDataLen == 0) {
		rc = CKR_ARGUMENTS_BAD;
		goto out_uninit;
	}

	if ((sCtx->cryptCtx.mechanism->mechanism == CKM_AES_ECB) ||
		(sCtx->cryptCtx.mechanism->mechanism == CKM_AES_CBC) ) {
		if ((ulEncryptedDataLen & (HSE_AES_BLOCK_LEN - 1)) != 0) {
			rc = CKR_ARGUMENTS_BAD;
			goto out_uninit;
		}
	}

	gCtx->mtxFns.lock(gCtx->keyMtx);
	key_handle = get_key_object_handle(sCtx->cryptCtx.keyHandle);
	gCtx->mtxFns.unlock(gCtx->keyMtx);
	if (key_handle < 0) {
		rc = CKR_KEY_HANDLE_INVALID;
		goto out_uninit;
	}
	key = (struct hse_keyObject *)hse_get_node_mem_addr(key_handle, true);

	if (sCtx->cryptCtx.mechanism->mechanism == CKM_AES_GCM) {
		gcm_params = (CK_GCM_PARAMS *)sCtx->cryptCtx.mechanism->pParameter;
	} else if (sCtx->cryptCtx.mechanism->mechanism == CKM_AES_CCM) {
		ccm_params = (CK_CCM_PARAMS *)sCtx->cryptCtx.mechanism->pParameter;
		if (ccm_params->ulDataLen != ulEncryptedDataLen - ccm_params->ulMACLen)
			printf("WARNING: CCM mechanism's output length not equal to decrypt output length.\n");
	}

	if ((sCtx->cryptCtx.mechanism->mechanism == CKM_RSA_PKCS) ||
		(sCtx->cryptCtx.mechanism->mechanism == CKM_RSA_PKCS_OAEP)) {
		key_bit_length = hse_get_key_bit_length(sCtx->sID, key);
		/* The input cipher text length should be equal to the key size */
		if (ulEncryptedDataLen != (key_bit_length >> 3)) {
			rc = CKR_ARGUMENTS_BAD;
			goto out_uninit;
		}
	}

	input_handle = hse_mem_alloc(ulEncryptedDataLen);
	if (input_handle < 0) {
		rc = CKR_HOST_MEMORY;
		goto out_uninit;
	}
	hse_memcpy_to_dev(input_handle, pEncryptedData, ulEncryptedDataLen, 0);

	output_len_handle = hse_mem_alloc(sizeof(output_len));
	if (output_len_handle < 0) {
		rc = CKR_HOST_MEMORY;
		goto out_free_input;
	}

	if ((sCtx->cryptCtx.mechanism->mechanism == CKM_AES_ECB) ||
		(sCtx->cryptCtx.mechanism->mechanism == CKM_AES_CBC) ||
		(sCtx->cryptCtx.mechanism->mechanism == CKM_AES_CTR)) {
		/* For AES, the output length is equal to the input length  */
		output_len = ulEncryptedDataLen;
		if (output_len > *pulDataLen) {
			/* tell the required size */
			*pulDataLen = output_len;

			rc = CKR_BUFFER_TOO_SMALL;
			goto out_free_output_len;
		}
	} else if ((sCtx->cryptCtx.mechanism->mechanism == CKM_RSA_PKCS) ||
				(sCtx->cryptCtx.mechanism->mechanism == CKM_RSA_PKCS_OAEP)) {
		/* to be safe, we allocate the max. length */
		output_len = rsa_ciphering_get_max_input_length(key_bit_length, sCtx->cryptCtx.mechanism);
	} else if (sCtx->cryptCtx.mechanism->mechanism == CKM_AES_CCM) {
		if (ccm_params->ulMACLen < 4 || ccm_params->ulMACLen > 16 || ccm_params->ulMACLen % 2) {
			rc =  CKR_ATTRIBUTE_VALUE_INVALID;
			goto out_free_input;
		}
		output_len = ulEncryptedDataLen - ccm_params->ulMACLen;
	} else if(sCtx->cryptCtx.mechanism->mechanism == CKM_AES_GCM) {
		if (gcm_params->ulTagBits > 128 || hse_get_tag_length(gcm_params->ulTagBits) > ulEncryptedDataLen) {
			rc = CKR_ATTRIBUTE_VALUE_INVALID;
			goto out_free_input;
		}
		output_len = ulEncryptedDataLen - hse_get_tag_length(gcm_params->ulTagBits);
	}
	hse_memcpy_to_dev(output_len_handle, (void *)&output_len, sizeof(output_len), 0);

	output_handle = hse_mem_alloc(output_len);
	if (output_handle < 0) {
		rc = CKR_HOST_MEMORY;
		goto out_free_output_len;
	}

	if (sCtx->cryptCtx.mechanism->pParameter != NULL) {
		if (sCtx->cryptCtx.mechanism->mechanism == CKM_RSA_PKCS_OAEP) {
			oaep_params = (CK_RSA_PKCS_OAEP_PARAMS *)sCtx->cryptCtx.mechanism->pParameter;
		} else if(sCtx->cryptCtx.mechanism->mechanism == CKM_AES_CCM) {
			if (ccm_params->ulNonceLen < 7 || ccm_params->ulNonceLen > 13 || !ccm_params->pNonce) {
				rc = CKR_ATTRIBUTE_VALUE_INVALID;
				goto out_free_output;
			}

			pIV_handle = hse_mem_alloc(ccm_params->ulNonceLen);
			if (pIV_handle < 0) {
				rc = CKR_HOST_MEMORY;
				goto out_free_output;
			}
			hse_memcpy_to_dev(pIV_handle, ccm_params->pNonce, ccm_params->ulNonceLen, 0);

			if (ccm_params->ulAADLen != 0) {
				if (ccm_params->ulAADLen > AAD_MAX_LEN || !ccm_params->pAAD) {
					rc = CKR_ATTRIBUTE_VALUE_INVALID;
					goto out_free_piv;
				}

				pAAD_handle = hse_mem_alloc(ccm_params->ulAADLen);
				if (pAAD_handle < 0) {
					rc = CKR_HOST_MEMORY;
					goto out_free_piv;
				}

				hse_memcpy_to_dev(pAAD_handle, ccm_params->pAAD, ccm_params->ulAADLen, 0);
			}
		} else if(sCtx->cryptCtx.mechanism->mechanism == CKM_AES_GCM) {
			if (!gcm_params->ulIvLen || gcm_params->ulIvLen > AAD_MAX_LEN || !gcm_params->pIv) {
				rc = CKR_HOST_MEMORY;
				goto out_free_output;
			}

			pIV_handle = hse_mem_alloc(gcm_params->ulIvLen);
			if (pIV_handle < 0) {
				rc = CKR_HOST_MEMORY;
				goto out_free_output;
			}
			hse_memcpy_to_dev(pIV_handle, gcm_params->pIv, gcm_params->ulIvLen, 0);

			if (gcm_params->ulAADLen != 0) {
				if (gcm_params->ulAADLen > AAD_MAX_LEN || !gcm_params->pAAD) {
					rc = CKR_ATTRIBUTE_VALUE_INVALID;
					goto out_free_piv;
				}

				pAAD_handle = hse_mem_alloc(gcm_params->ulAADLen);
				if (pAAD_handle < 0) {
					rc = CKR_HOST_MEMORY;
					goto out_free_piv;
				}
				hse_memcpy_to_dev(pAAD_handle, gcm_params->pAAD, gcm_params->ulAADLen, 0);
			}
		} else {
			pIV_handle = hse_mem_alloc(sCtx->cryptCtx.mechanism->ulParameterLen);
			if (pIV_handle < 0) {
				rc = CKR_HOST_MEMORY;
				goto out_free_output;
			}
			hse_memcpy_to_dev(pIV_handle, sCtx->cryptCtx.mechanism->pParameter,
							  sCtx->cryptCtx.mechanism->ulParameterLen, 0);
		}
	}

	switch (sCtx->cryptCtx.mechanism->mechanism) {
		case CKM_AES_ECB:

			sym_cipher_srv = &srv_desc.hseSrv.symCipherReq;

			srv_desc.srvId = HSE_SRV_ID_SYM_CIPHER;
			sym_cipher_srv->accessMode = HSE_ACCESS_MODE_ONE_PASS;
			sym_cipher_srv->streamId = sCtx->cryptCtx.streamID;
			sym_cipher_srv->cipherAlgo = HSE_CIPHER_ALGO_AES;
			sym_cipher_srv->cipherBlockMode = HSE_CIPHER_BLOCK_MODE_ECB;
			sym_cipher_srv->cipherDir = HSE_CIPHER_DIR_DECRYPT;
			sym_cipher_srv->sgtOption = HSE_SGT_OPTION_NONE;
			sym_cipher_srv->keyHandle = key->key_handle;

			if (sCtx->cryptCtx.mechanism->pParameter != NULL) {
				sym_cipher_srv->pIV = hse_virt_to_dma(pIV_handle, 0);
			} else {
				sym_cipher_srv->pIV = 0u; /* IV is not required for ecb */
			}

			sym_cipher_srv->inputLength = ulEncryptedDataLen;
			sym_cipher_srv->pInput = hse_virt_to_dma(input_handle, 0);
			sym_cipher_srv->pOutput= hse_virt_to_dma(output_handle, 0);

			break;

		case CKM_AES_CBC:
		case CKM_AES_CBC_PAD:

			sym_cipher_srv = &srv_desc.hseSrv.symCipherReq;

			srv_desc.srvId = HSE_SRV_ID_SYM_CIPHER;
			sym_cipher_srv->accessMode = HSE_ACCESS_MODE_ONE_PASS;
			sym_cipher_srv->streamId = sCtx->cryptCtx.streamID;
			sym_cipher_srv->cipherAlgo = HSE_CIPHER_ALGO_AES;
			sym_cipher_srv->cipherBlockMode = HSE_CIPHER_BLOCK_MODE_CBC;
			sym_cipher_srv->cipherDir = HSE_CIPHER_DIR_DECRYPT;
			sym_cipher_srv->sgtOption = HSE_SGT_OPTION_NONE;
			sym_cipher_srv->keyHandle = key->key_handle;
			sym_cipher_srv->pIV = hse_virt_to_dma(pIV_handle, 0);
			sym_cipher_srv->inputLength = ulEncryptedDataLen;
			sym_cipher_srv->pInput = hse_virt_to_dma(input_handle, 0);
			sym_cipher_srv->pOutput= hse_virt_to_dma(output_handle, 0);

			break;

		case CKM_AES_CTR:

			sym_cipher_srv = &srv_desc.hseSrv.symCipherReq;

			srv_desc.srvId = HSE_SRV_ID_SYM_CIPHER;
			sym_cipher_srv->accessMode = HSE_ACCESS_MODE_ONE_PASS;
			sym_cipher_srv->streamId = sCtx->cryptCtx.streamID;
			sym_cipher_srv->cipherAlgo = HSE_CIPHER_ALGO_AES;
			sym_cipher_srv->cipherBlockMode = HSE_CIPHER_BLOCK_MODE_CTR;
			sym_cipher_srv->cipherDir = HSE_CIPHER_DIR_DECRYPT;
			sym_cipher_srv->sgtOption = HSE_SGT_OPTION_NONE;
			sym_cipher_srv->keyHandle = key->key_handle;
			sym_cipher_srv->pIV = hse_virt_to_dma(pIV_handle, 0);
			sym_cipher_srv->inputLength = ulEncryptedDataLen;
			sym_cipher_srv->pInput = hse_virt_to_dma(input_handle, 0);
			sym_cipher_srv->pOutput= hse_virt_to_dma(output_handle, 0);

			break;
		case CKM_AES_GCM:

			aead_srv = &srv_desc.hseSrv.aeadReq;

			srv_desc.srvId = HSE_SRV_ID_AEAD;
			aead_srv->accessMode = HSE_ACCESS_MODE_ONE_PASS;
			aead_srv->streamId = sCtx->cryptCtx.streamID;
			aead_srv->authCipherMode = HSE_AUTH_CIPHER_MODE_GCM;
			aead_srv->cipherDir = HSE_CIPHER_DIR_DECRYPT;
			aead_srv->keyHandle = key->key_handle;
			aead_srv->ivLength = gcm_params->ulIvLen;
			aead_srv->pIV = hse_virt_to_dma(pIV_handle, 0);
			aead_srv->aadLength = gcm_params->ulAADLen;
			aead_srv->pAAD = hse_virt_to_dma(pAAD_handle, 0);
			aead_srv->sgtOption = HSE_SGT_OPTION_NONE;
			aead_srv->inputLength = output_len;
			aead_srv->pInput = hse_virt_to_dma(input_handle, 0);
			aead_srv->tagLength = hse_get_tag_length(gcm_params->ulTagBits);
			aead_srv->pTag = hse_virt_to_dma(input_handle, output_len);
			aead_srv->pOutput = hse_virt_to_dma(output_handle, 0);

			break;
		case CKM_AES_CCM:

			aead_srv = &srv_desc.hseSrv.aeadReq;

			srv_desc.srvId = HSE_SRV_ID_AEAD;
			aead_srv->accessMode = HSE_ACCESS_MODE_ONE_PASS;
			aead_srv->streamId = sCtx->cryptCtx.streamID;
			aead_srv->authCipherMode = HSE_AUTH_CIPHER_MODE_CCM;
			aead_srv->cipherDir = HSE_CIPHER_DIR_DECRYPT;
			aead_srv->keyHandle = key->key_handle;
			aead_srv->ivLength = ccm_params->ulNonceLen;
			aead_srv->pIV = hse_virt_to_dma(pIV_handle, 0);
			aead_srv->aadLength = ccm_params->ulAADLen;
			aead_srv->pAAD = hse_virt_to_dma(pAAD_handle, 0);
			aead_srv->sgtOption = HSE_SGT_OPTION_NONE;
			aead_srv->inputLength = output_len;
			aead_srv->pInput = hse_virt_to_dma(input_handle, 0);
			aead_srv->tagLength = ccm_params->ulMACLen;
			aead_srv->pTag = hse_virt_to_dma(input_handle, output_len);
			aead_srv->pOutput = hse_virt_to_dma(output_handle, 0);

			break;
		case CKM_RSA_PKCS:
			rsa_cipher_srv = &srv_desc.hseSrv.rsaCipherReq;

			srv_desc.srvId = HSE_SRV_ID_RSA_CIPHER;
			rsa_cipher_srv->cipherDir = HSE_CIPHER_DIR_DECRYPT;
			rsa_cipher_srv->keyHandle = key->key_handle;
			rsa_cipher_srv->inputLength = ulEncryptedDataLen;
			rsa_cipher_srv->pInput = hse_virt_to_dma(input_handle, 0);
			rsa_cipher_srv->pOutputLength = hse_virt_to_dma(output_len_handle, 0);
			rsa_cipher_srv->pOutput = hse_virt_to_dma(output_handle, 0);

			rsa_cipher_srv->rsaScheme.rsaAlgo = HSE_RSA_ALGO_RSAES_PKCS1_V15;
			break;

		case CKM_RSA_PKCS_OAEP:
			rsa_cipher_srv = &srv_desc.hseSrv.rsaCipherReq;

			srv_desc.srvId = HSE_SRV_ID_RSA_CIPHER;
			rsa_cipher_srv->cipherDir = HSE_CIPHER_DIR_DECRYPT;
			rsa_cipher_srv->keyHandle = key->key_handle;
			rsa_cipher_srv->inputLength = ulEncryptedDataLen;
			rsa_cipher_srv->pInput = hse_virt_to_dma(input_handle, 0);
			rsa_cipher_srv->pOutputLength = hse_virt_to_dma(output_len_handle, 0);
			rsa_cipher_srv->pOutput = hse_virt_to_dma(output_handle, 0);

			rsa_cipher_srv->rsaScheme.rsaAlgo = HSE_RSA_ALGO_RSAES_OAEP;
			rsa_cipher_srv->rsaScheme.sch.rsaOAEP.hashAlgo = hse_pkcs_hash_alg_translate(oaep_params->hashAlg);
			rsa_cipher_srv->rsaScheme.sch.rsaOAEP.labelLength = 0;
			rsa_cipher_srv->rsaScheme.sch.rsaOAEP.pLabel = 0;
			break;

		default:
			rc = CKR_ARGUMENTS_BAD;
			goto out_free_paad;
	}

	err = hse_srv_req_sync(sCtx->sID, &srv_desc, sizeof(srv_desc));
	if (err) {
		rc = CKR_FUNCTION_FAILED;
		goto out_free_paad;
	}

	hse_memcpy_from_dev((void *)&output_len, output_len_handle, sizeof(output_len), 0);
	/* check for output buffer length */
	if ((sCtx->cryptCtx.mechanism->mechanism == CKM_RSA_PKCS) ||
		(sCtx->cryptCtx.mechanism->mechanism == CKM_RSA_PKCS_OAEP)) {
		if (output_len > *pulDataLen) {
			/* tell the required size */
			*pulDataLen = output_len;

			rc = CKR_BUFFER_TOO_SMALL;
			goto out_free_paad;
		}
	}
	if (sCtx->cryptCtx.mechanism->mechanism == CKM_AES_CBC_PAD) {
		hse_memcpy_from_dev(pData, output_handle, *pulDataLen, 0);
		goto out_free_paad;
	}
	hse_memcpy_from_dev(pulDataLen, output_len_handle, sizeof(uint32_t), 0);
	hse_memcpy_from_dev(pData, output_handle, *pulDataLen, 0);

out_free_paad:
	hse_mem_free(pAAD_handle);
out_free_piv:
	hse_mem_free(pIV_handle);
out_free_output:
	hse_mem_free(output_handle);
out_free_output_len:
	hse_mem_free(output_len_handle);
out_free_input:
	hse_mem_free(input_handle);
out_uninit:
	if (rc != CKR_BUFFER_TOO_SMALL) {
		sCtx->cryptCtx.init = CK_FALSE;
		if (sCtx->cryptCtx.cache != NULL) {
			free(sCtx->cryptCtx.cache);
			sCtx->cryptCtx.cache = NULL;
		}
	}
	return rc;
}

CK_DECLARE_FUNCTION(CK_RV, C_SignInit)(
		CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,
		CK_OBJECT_HANDLE hKey
)
{
	struct globalCtx *gCtx = getCtx();
	struct sessionCtx *sCtx = getSessionCtx(hSession);
	uint32_t blockSize = 0;

	if (gCtx->cryptokiInit == CK_FALSE)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!sCtx || sCtx->sessionInit == CK_FALSE)
		return CKR_SESSION_HANDLE_INVALID;

	if ((sCtx->signCtx.init == CK_TRUE) && (pMechanism == NULL)) {
		/* condition to terminate an active operation */
		if (sCtx->signCtx.cache != NULL) {
			free(sCtx->signCtx.cache);
			sCtx->signCtx.cache = NULL;
		}
		sCtx->signCtx.init = CK_FALSE;
		hse_stream_free(sCtx->signCtx.streamID);
		sCtx->signCtx.stream_start = CK_TRUE;
		return CKR_OK;
	}

	if (sCtx->signCtx.init == CK_TRUE)
		return CKR_OPERATION_ACTIVE;

	if (pMechanism == NULL)
		return CKR_ARGUMENTS_BAD;

	gCtx->mtxFns.lock(gCtx->keyMtx);
	if (get_key_object_handle(hKey) < 0) {
		gCtx->mtxFns.unlock(gCtx->keyMtx);
		return CKR_KEY_HANDLE_INVALID;
	}
	gCtx->mtxFns.unlock(gCtx->keyMtx);

	if (hse_get_hash_block_size(pMechanism->mechanism, &blockSize)) 
		return CKR_ARGUMENTS_BAD;

	sCtx->signCtx.blockSize = blockSize;
	sCtx->signCtx.cache = malloc(sCtx->signCtx.blockSize);
	if (!sCtx->signCtx.cache)
		return CKR_HOST_MEMORY;

	sCtx->signCtx.init = CK_TRUE;
	sCtx->signCtx.stream_start = CK_TRUE;
	sCtx->signCtx.mechanism = pMechanism;
	sCtx->signCtx.keyHandle = hKey;
	sCtx->signCtx.streamID = INVALID_STREAM_ID;
	sCtx->signCtx.cache_idx = 0;

	return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_Sign)(
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
	struct hse_keyObject *key;
	CK_RV rc = CKR_OK;
	int err, key_handle = -1, input_handle = -1, sign0_handle = -1, output_len_handle = -1;
	uint32_t output_len = 0;
	CK_RSA_PKCS_PSS_PARAMS *rsa_pss_param;
	hseMacSrv_t *mac_srv = NULL;

	if (gCtx->cryptokiInit == CK_FALSE)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!sCtx || sCtx->sessionInit == CK_FALSE)
		return CKR_SESSION_HANDLE_INVALID;

	if (sCtx->signCtx.init == CK_FALSE)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (sCtx->signCtx.stream_start == CK_FALSE)
		return CKR_FUNCTION_FAILED;

	if (pData == NULL) {
		rc = CKR_DATA_INVALID;
		goto out_uninit;
	}

	if (ulDataLen == 0) {
		rc = CKR_DATA_LEN_RANGE;
		goto out_uninit;
	}

	if (pSignature == NULL) {
		rc = CKR_SIGNATURE_INVALID;
		goto out_uninit;
	}

	if (pulSignatureLen == NULL) {
		rc = CKR_SIGNATURE_LEN_RANGE;
		goto out_uninit;
	}

	gCtx->mtxFns.lock(gCtx->keyMtx);
	key_handle = get_key_object_handle(sCtx->signCtx.keyHandle);
	gCtx->mtxFns.unlock(gCtx->keyMtx);
	if (key_handle < 0) {
		rc = CKR_KEY_HANDLE_INVALID;
		goto out_uninit;
	}
	key = (struct hse_keyObject *)hse_get_node_mem_addr(key_handle, true);

	input_handle = hse_mem_alloc(ulDataLen);
	if (input_handle < 0) {
		rc = CKR_HOST_MEMORY;
		goto out_uninit;
	}
	hse_memcpy_to_dev(input_handle, pData, ulDataLen, 0);

	/* check the output length */
	output_len = sig_get_out_length(sCtx->sID, key, sCtx->signCtx.mechanism);
	if (output_len > *pulSignatureLen) {
		*pulSignatureLen = output_len;
		rc = CKR_BUFFER_TOO_SMALL;
		goto out_free_input;
	}

	output_len_handle = hse_mem_alloc(sizeof(output_len));
	if (output_len_handle < 0) {
		rc = CKR_HOST_MEMORY;
		goto out_free_input;
	}
	hse_memcpy_to_dev(output_len_handle, pulSignatureLen, sizeof(output_len), 0);

	sign0_handle = hse_mem_alloc(*pulSignatureLen);
	if (sign0_handle < 0) {
		rc = CKR_HOST_MEMORY;
		goto out_free_output_len;
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
			sign_srv->pSignatureLength[0] = hse_virt_to_dma(output_len_handle, 0);
			sign_srv->pSignatureLength[1] = 0u;
			sign_srv->pSignature[0] = hse_virt_to_dma(sign0_handle, 0);
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
				goto out_free_sign0;
			}

			sign_scheme->signSch = HSE_SIGN_RSASSA_PSS;
			sign_scheme->sch.rsaPss.hashAlgo = hse_pkcs_hash_alg_translate(rsa_pss_param->hashAlg);
			sign_scheme->sch.rsaPss.saltLength = rsa_pss_param->sLen;
			sign_srv->pSignatureLength[0] = hse_virt_to_dma(output_len_handle, 0);
			sign_srv->pSignatureLength[1] = 0u;
			sign_srv->pSignature[0] = hse_virt_to_dma(sign0_handle, 0);
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
			output_len = output_len / 2;
			hse_memcpy_to_dev(output_len_handle, (void *)&output_len, sizeof(output_len), 0);

			sign_scheme->signSch = HSE_SIGN_ECDSA;
			sign_scheme->sch.ecdsa.hashAlgo = hse_get_hash_alg(sCtx->signCtx.mechanism->mechanism);
			sign_srv->pSignatureLength[0] = hse_virt_to_dma(output_len_handle, 0);
			sign_srv->pSignatureLength[1] = hse_virt_to_dma(output_len_handle, 0);
			sign_srv->pSignature[0] = hse_virt_to_dma(sign0_handle, 0);
			sign_srv->pSignature[1] = hse_virt_to_dma(sign0_handle, output_len);

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
		case CKM_SHA_1_HMAC:
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
			goto out_free_sign0;
	}

	if (!mac_srv) {
		srv_desc.srvId = HSE_SRV_ID_SIGN;
		sign_srv->accessMode = HSE_ACCESS_MODE_ONE_PASS;
		sign_srv->streamId = sCtx->signCtx.streamID;
		sign_srv->authDir = HSE_AUTH_DIR_GENERATE;
		sign_srv->keyHandle = key->key_handle;
		sign_srv->sgtOption = HSE_SGT_OPTION_NONE;
		sign_srv->inputLength = ulDataLen;
		sign_srv->pInput = hse_virt_to_dma(input_handle, 0);
	} else {
		srv_desc.srvId = HSE_SRV_ID_MAC;
		mac_srv->accessMode = HSE_ACCESS_MODE_ONE_PASS;
		mac_srv->streamId = sCtx->signCtx.streamID;
		mac_srv->authDir = HSE_AUTH_DIR_GENERATE;
		mac_srv->sgtOption = HSE_SGT_OPTION_NONE;
		mac_srv->keyHandle = key->key_handle;
		mac_srv->inputLength = ulDataLen;
		mac_srv->pInput = hse_virt_to_dma(input_handle, 0);
		mac_srv->pTagLength = hse_virt_to_dma(output_len_handle, 0);
		mac_srv->pTag = hse_virt_to_dma(sign0_handle, 0);
	}

	err = hse_srv_req_sync(sCtx->sID, &srv_desc, sizeof(srv_desc));
	if (err) {
		rc = CKR_FUNCTION_FAILED;
		goto out_free_sign0;
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
		case CKM_SHA_1_HMAC:
		case CKM_SHA224_HMAC:
		case CKM_SHA256_HMAC:
		case CKM_SHA384_HMAC:
		case CKM_SHA512_HMAC:

			hse_memcpy_from_dev(pulSignatureLen, output_len_handle, sizeof(output_len), 0);
			hse_memcpy_from_dev(pSignature, sign0_handle, *pulSignatureLen, 0);

			break;
		case CKM_ECDSA:
		case CKM_ECDSA_SHA1:
		case CKM_ECDSA_SHA224:
		case CKM_ECDSA_SHA256:
		case CKM_ECDSA_SHA384:
		case CKM_ECDSA_SHA512:

			/* restore actual length */
			hse_memcpy_from_dev(pulSignatureLen, output_len_handle, sizeof(output_len), 0);
			*pulSignatureLen *= 2;

			hse_memcpy_from_dev(pSignature, sign0_handle, *pulSignatureLen, 0);

			break;
		default:
			rc = CKR_ARGUMENTS_BAD;
			goto out_free_sign0;
	}

out_free_sign0:
	hse_mem_free(sign0_handle);
out_free_output_len:
	hse_mem_free(output_len_handle);
out_free_input:
	hse_mem_free(input_handle);
out_uninit:
	if (rc != CKR_BUFFER_TOO_SMALL) {
 		sCtx->signCtx.init = CK_FALSE;
		if (sCtx->signCtx.cache != NULL) {
			free(sCtx->signCtx.cache);
			sCtx->signCtx.cache = NULL;
		}
	}

	return rc;
}

CK_DECLARE_FUNCTION(CK_RV, C_VerifyInit)(
		CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,
		CK_OBJECT_HANDLE hKey
)
{
	struct globalCtx *gCtx = getCtx();
	struct sessionCtx *sCtx = getSessionCtx(hSession);
	uint32_t blockSize = 0;

	if (gCtx->cryptokiInit == CK_FALSE)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!sCtx || sCtx->sessionInit == CK_FALSE)
		return CKR_SESSION_HANDLE_INVALID;

	if ((sCtx->signCtx.init == CK_TRUE) && (pMechanism == NULL)) {
		/* condition to terminate an active operation */
		if (sCtx->signCtx.cache != NULL) {
			free(sCtx->signCtx.cache);
			sCtx->signCtx.cache = NULL;
		}
		sCtx->signCtx.init = CK_FALSE;
		hse_stream_free(sCtx->signCtx.streamID);
		sCtx->signCtx.stream_start = CK_TRUE;
		return CKR_OK;
	}

	if (sCtx->signCtx.init == CK_TRUE)
		return CKR_OPERATION_ACTIVE;

	if (pMechanism == NULL)
		return CKR_ARGUMENTS_BAD;

	gCtx->mtxFns.lock(gCtx->keyMtx);
	if (get_key_object_handle(hKey) < 0) {
		gCtx->mtxFns.unlock(gCtx->keyMtx);
		return CKR_KEY_HANDLE_INVALID;
	}
	gCtx->mtxFns.unlock(gCtx->keyMtx);

	if (hse_get_hash_block_size(pMechanism->mechanism, &blockSize)) 
		return CKR_ARGUMENTS_BAD;

	sCtx->signCtx.blockSize = blockSize;
	sCtx->signCtx.cache = malloc(sCtx->signCtx.blockSize);
	if (!sCtx->signCtx.cache)
		return CKR_HOST_MEMORY;

	sCtx->signCtx.init = CK_TRUE;
	sCtx->signCtx.stream_start = CK_TRUE;
	sCtx->signCtx.mechanism = pMechanism;
	sCtx->signCtx.keyHandle = hKey;
	sCtx->signCtx.streamID = INVALID_STREAM_ID;
	sCtx->signCtx.cache_idx = 0;

	return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_Verify)(
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
	struct hse_keyObject *key;
	CK_RV rc = CKR_OK;
	int err, key_handle = -1, input_handle = -1, sign0_handle = -1, output_len_handle = -1;
	uint32_t output_len = 0;
	CK_RSA_PKCS_PSS_PARAMS *rsa_pss_param;
	hseMacSrv_t *mac_srv = NULL;

	if (gCtx->cryptokiInit == CK_FALSE)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!sCtx || sCtx->sessionInit == CK_FALSE)
		return CKR_SESSION_HANDLE_INVALID;

	if (sCtx->signCtx.init == CK_FALSE)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (sCtx->signCtx.stream_start == CK_FALSE)
		return CKR_FUNCTION_FAILED;

	if (pData == NULL) {
		rc = CKR_DATA_INVALID;
		goto out_uninit;
	}

	if (ulDataLen == 0) {
		rc = CKR_DATA_LEN_RANGE;
		goto out_uninit;
	}

	if (pSignature == NULL) {
		rc = CKR_SIGNATURE_INVALID;
		goto out_uninit;
	}

	if (ulSignatureLen == 0) {
		rc = CKR_SIGNATURE_LEN_RANGE;
		goto out_uninit;
	}

	gCtx->mtxFns.lock(gCtx->keyMtx);
	key_handle = get_key_object_handle(sCtx->signCtx.keyHandle);
	gCtx->mtxFns.unlock(gCtx->keyMtx);
	if (key_handle < 0) {
		rc = CKR_KEY_HANDLE_INVALID;
		goto out_uninit;
	}
	key = (struct hse_keyObject *)hse_get_node_mem_addr(key_handle, true);

	input_handle = hse_mem_alloc(ulDataLen);
	if (input_handle < 0) {
		rc = CKR_HOST_MEMORY;
		goto out_uninit;
	}
	hse_memcpy_to_dev(input_handle, pData, ulDataLen, 0);

	output_len_handle = hse_mem_alloc(sizeof(output_len));
	if (output_len_handle < 0) {
		rc = CKR_HOST_MEMORY;
		goto out_free_input;
	}
	hse_memcpy_to_dev(output_len_handle, &ulSignatureLen, sizeof(output_len), 0);

	sign0_handle = hse_mem_alloc(ulSignatureLen);
	if (sign0_handle < 0) {
		rc = CKR_HOST_MEMORY;
		goto out_free_output_len;
	}
	hse_memcpy_to_dev(sign0_handle, pSignature, ulSignatureLen, 0);

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
			sign_srv->pSignatureLength[0] = hse_virt_to_dma(output_len_handle, 0);
			sign_srv->pSignatureLength[1] = 0u;
			sign_srv->pSignature[0] = hse_virt_to_dma(sign0_handle, 0); /* rsa */
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
				goto out_free_sign0;
			}

			sign_scheme->signSch = HSE_SIGN_RSASSA_PSS;
			sign_scheme->sch.rsaPss.hashAlgo = hse_pkcs_hash_alg_translate(rsa_pss_param->hashAlg);
			sign_scheme->sch.rsaPss.saltLength = rsa_pss_param->sLen;
			sign_srv->pSignatureLength[0] = hse_virt_to_dma(output_len_handle, 0);
			sign_srv->pSignatureLength[1] = 0u;
			sign_srv->pSignature[0] = hse_virt_to_dma(sign0_handle, 0);
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
			 * assume the signature contains both, one after the other
			 */
			hse_memcpy_from_dev((void *)&output_len, output_len_handle, sizeof(output_len), 0);
			output_len = output_len / 2;
			hse_memcpy_to_dev(output_len_handle, (void *)&output_len, sizeof(output_len), 0);

			sign_scheme->signSch = HSE_SIGN_ECDSA;
			sign_scheme->sch.ecdsa.hashAlgo = hse_get_hash_alg(sCtx->signCtx.mechanism->mechanism);

			sign_srv->pSignatureLength[0] = hse_virt_to_dma(output_len_handle, 0);
			sign_srv->pSignatureLength[1] = hse_virt_to_dma(output_len_handle, 0);
			sign_srv->pSignature[0] = hse_virt_to_dma(sign0_handle, 0);
			sign_srv->pSignature[1] = hse_virt_to_dma(sign0_handle, output_len);

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
		case CKM_SHA_1_HMAC:
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
			goto out_free_sign0;
	}

	if (!mac_srv) {
		srv_desc.srvId = HSE_SRV_ID_SIGN;
		sign_srv->accessMode = HSE_ACCESS_MODE_ONE_PASS;
		sign_srv->streamId = sCtx->signCtx.streamID;
		sign_srv->authDir = HSE_AUTH_DIR_VERIFY;
		sign_srv->keyHandle = key->key_handle;
		sign_srv->sgtOption = HSE_SGT_OPTION_NONE;
		sign_srv->inputLength = ulDataLen;
		sign_srv->pInput = hse_virt_to_dma(input_handle, 0);
	} else {
		srv_desc.srvId = HSE_SRV_ID_MAC;
		mac_srv->accessMode = HSE_ACCESS_MODE_ONE_PASS;
		mac_srv->streamId = sCtx->signCtx.streamID;
		mac_srv->authDir = HSE_AUTH_DIR_VERIFY;
		mac_srv->sgtOption = HSE_SGT_OPTION_NONE;
		mac_srv->keyHandle = key->key_handle;
		mac_srv->inputLength = ulDataLen;
		mac_srv->pInput = hse_virt_to_dma(input_handle, 0);
		mac_srv->pTagLength = hse_virt_to_dma(output_len_handle, 0);
		mac_srv->pTag = hse_virt_to_dma(sign0_handle, 0);
	}

	err = hse_srv_req_sync(sCtx->sID, &srv_desc, sizeof(srv_desc));
	if (!err) {
		rc = CKR_OK;
	} else if (err == EBADMSG) {
		rc = CKR_SIGNATURE_INVALID;
	} else {
		rc = CKR_FUNCTION_FAILED;
	}

out_free_sign0:
	hse_mem_free(sign0_handle);
out_free_output_len:
	hse_mem_free(output_len_handle);
out_free_input:
	hse_mem_free(input_handle);
out_uninit:
	sCtx->signCtx.init = CK_FALSE;
	if (sCtx->signCtx.cache != NULL) {
		free(sCtx->signCtx.cache);
		sCtx->signCtx.cache = NULL;
	}

	return rc;
}

CK_DECLARE_FUNCTION(CK_RV, C_EncryptUpdate)(
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
	struct hse_keyObject *key;
	CK_RV rc = CKR_OK;
	int err, key_handle = -1, input_handle = -1, output_handle = -1, pIV_handle = -1;
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
		goto out_uninit;
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
	key_handle = get_key_object_handle(sCtx->cryptCtx.keyHandle);
	gCtx->mtxFns.unlock(gCtx->keyMtx);
	if (key_handle < 0) {
		rc = CKR_KEY_HANDLE_INVALID;
		goto out_uninit;
	}
	key = (struct hse_keyObject *)hse_get_node_mem_addr(key_handle, true);

	if ((sCtx->cryptCtx.mechanism->mechanism != CKM_AES_ECB) &&
		(sCtx->cryptCtx.mechanism->mechanism != CKM_AES_CBC) &&
		(sCtx->cryptCtx.mechanism->mechanism != CKM_AES_CTR) &&
		(sCtx->cryptCtx.mechanism->mechanism != CKM_AES_CBC_PAD)) {
		rc = CKR_FUNCTION_NOT_SUPPORTED;
		goto out_uninit;
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
		goto out_uninit;
	}

	if (full_blocks > 0) {
		/* copy full_blocks to dynamic buffer */
		input_handle = hse_mem_alloc(full_blocks);
		if (input_handle < 0) {
			rc = CKR_HOST_MEMORY;
			goto out_uninit;
		}
		hse_memcpy_to_dev(input_handle, sCtx->cryptCtx.cache, sCtx->cryptCtx.cache_idx, 0);
		hse_memcpy_to_dev(input_handle, pPart, full_blocks - sCtx->cryptCtx.cache_idx, sCtx->cryptCtx.cache_idx);
		bytes_left -= full_blocks;

		/* copy residue to block-sized cache */
		if (bytes_left > 0)
			memcpy(sCtx->cryptCtx.cache, pPart + (full_blocks - sCtx->cryptCtx.cache_idx), bytes_left);
			
		sCtx->cryptCtx.cache_idx = bytes_left;

		/* output length is equal to the input length  */
		output_handle = hse_mem_alloc(full_blocks);
		if (output_handle < 0) {
			rc = CKR_HOST_MEMORY;
			goto out_free_input;
		}
	}

	if (sCtx->cryptCtx.stream_start == CK_TRUE) {
		/* IV input is used only when START */
		if (sCtx->cryptCtx.mechanism->pParameter != NULL) {
			pIV_handle = hse_mem_alloc(sCtx->cryptCtx.mechanism->ulParameterLen);
			if (pIV_handle < 0) {
				rc = CKR_HOST_MEMORY;
				goto out_free_output;
			}
			hse_memcpy_to_dev(pIV_handle, sCtx->cryptCtx.mechanism->pParameter,
							  sCtx->cryptCtx.mechanism->ulParameterLen, 0);
		}

		access_mode = HSE_ACCESS_MODE_START;
		sCtx->cryptCtx.stream_start = CK_FALSE;

		err = hse_stream_acquire(&sCtx->cryptCtx.streamID);
		if (err) {
			rc = CKR_STATE_UNSAVEABLE;
			goto out_free_piv;
		}
	} else {
		access_mode = HSE_ACCESS_MODE_UPDATE;
	}

	switch (sCtx->cryptCtx.mechanism->mechanism) {
		case CKM_AES_ECB:

			sym_cipher_srv = &srv_desc.hseSrv.symCipherReq;

			srv_desc.srvId = HSE_SRV_ID_SYM_CIPHER;
			sym_cipher_srv->accessMode = access_mode;
			sym_cipher_srv->streamId = sCtx->cryptCtx.streamID;
			sym_cipher_srv->cipherAlgo = HSE_CIPHER_ALGO_AES;
			sym_cipher_srv->cipherBlockMode = HSE_CIPHER_BLOCK_MODE_ECB;
			sym_cipher_srv->cipherDir = HSE_CIPHER_DIR_ENCRYPT;
			sym_cipher_srv->sgtOption = HSE_SGT_OPTION_NONE;
			sym_cipher_srv->keyHandle = key->key_handle;

			if (sCtx->cryptCtx.mechanism->pParameter != NULL) {
				sym_cipher_srv->pIV = hse_virt_to_dma(pIV_handle, 0);
			} else {
				sym_cipher_srv->pIV = 0u; /* IV is not required for ecb */
			}

			sym_cipher_srv->inputLength = full_blocks;
			sym_cipher_srv->pInput = hse_virt_to_dma(input_handle, 0);
			sym_cipher_srv->pOutput= hse_virt_to_dma(output_handle, 0);

			break;

		case CKM_AES_CBC:
		case CKM_AES_CBC_PAD:

			sym_cipher_srv = &srv_desc.hseSrv.symCipherReq;

			srv_desc.srvId = HSE_SRV_ID_SYM_CIPHER;
			sym_cipher_srv->accessMode = access_mode;
			sym_cipher_srv->streamId = sCtx->cryptCtx.streamID;
			sym_cipher_srv->cipherAlgo = HSE_CIPHER_ALGO_AES;
			sym_cipher_srv->cipherBlockMode = HSE_CIPHER_BLOCK_MODE_CBC;
			sym_cipher_srv->cipherDir = HSE_CIPHER_DIR_ENCRYPT;
			sym_cipher_srv->sgtOption = HSE_SGT_OPTION_NONE;
			sym_cipher_srv->keyHandle = key->key_handle;
			sym_cipher_srv->pIV = hse_virt_to_dma(pIV_handle, 0);
			sym_cipher_srv->inputLength = full_blocks;
			sym_cipher_srv->pInput = hse_virt_to_dma(input_handle, 0);
			sym_cipher_srv->pOutput= hse_virt_to_dma(output_handle, 0);

			break;

		case CKM_AES_CTR:

			sym_cipher_srv = &srv_desc.hseSrv.symCipherReq;

			srv_desc.srvId = HSE_SRV_ID_SYM_CIPHER;
			sym_cipher_srv->accessMode = access_mode;
			sym_cipher_srv->streamId = sCtx->cryptCtx.streamID;
			sym_cipher_srv->cipherAlgo = HSE_CIPHER_ALGO_AES;
			sym_cipher_srv->cipherBlockMode = HSE_CIPHER_BLOCK_MODE_CTR;
			sym_cipher_srv->cipherDir = HSE_CIPHER_DIR_ENCRYPT;
			sym_cipher_srv->sgtOption = HSE_SGT_OPTION_NONE;
			sym_cipher_srv->keyHandle = key->key_handle;
			sym_cipher_srv->pIV = hse_virt_to_dma(pIV_handle, 0);
			sym_cipher_srv->inputLength = full_blocks;
			sym_cipher_srv->pInput = hse_virt_to_dma(input_handle, 0);
			sym_cipher_srv->pOutput= hse_virt_to_dma(output_handle, 0);

			break;

		default:
			rc = CKR_ARGUMENTS_BAD;
			goto out_free_piv;
	}

	err = hse_srv_req_sync(sCtx->sID, &srv_desc, sizeof(srv_desc));
	if (err) {
		rc = CKR_FUNCTION_FAILED;
		goto out_free_piv;
	}

	if (full_blocks > 0)
		hse_memcpy_from_dev(pEncryptedPart, output_handle, full_blocks, 0);
	*pulEncryptedPartLen = full_blocks;

out_free_piv:
	hse_mem_free(pIV_handle);
out_free_output:
	hse_mem_free(output_handle);
out_free_input:
	hse_mem_free(input_handle);
out_uninit:
	if ((rc != CKR_OK) && (rc != CKR_BUFFER_TOO_SMALL)) {
		hse_stream_free(sCtx->cryptCtx.streamID);
		sCtx->cryptCtx.init = CK_FALSE;
		if (sCtx->cryptCtx.cache != NULL) {
			free(sCtx->cryptCtx.cache);
			sCtx->cryptCtx.cache = NULL;
		}
	}

	return rc;
}

CK_DECLARE_FUNCTION(CK_RV, C_EncryptFinal)(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pLastEncryptedPart,
		CK_ULONG_PTR pulLastEncryptedPartLen
)
{
	struct globalCtx *gCtx = getCtx();
	struct sessionCtx *sCtx = getSessionCtx(hSession);
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	hseSymCipherSrv_t *sym_cipher_srv;
	uint8_t input_len = 0, pad_value = 0, pad_len = 0;
	struct hse_keyObject *key;
	CK_RV rc = CKR_OK;
	int err, key_handle = -1, input_handle = -1, output_handle = -1;

	if (gCtx->cryptokiInit == CK_FALSE)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!sCtx || sCtx->sessionInit == CK_FALSE)
		return CKR_SESSION_HANDLE_INVALID;

	if (sCtx->cryptCtx.init == CK_FALSE)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (pulLastEncryptedPartLen == NULL) {
		rc = CKR_ARGUMENTS_BAD;
		goto out_uninit;
	}

	if (pLastEncryptedPart == NULL) {
		/* if NULL, upper layer expects to receive needed size */
		*pulLastEncryptedPartLen = sCtx->cryptCtx.cache_idx;
		return CKR_OK;
	}

	gCtx->mtxFns.lock(gCtx->keyMtx);
	key_handle = get_key_object_handle(sCtx->cryptCtx.keyHandle);
	gCtx->mtxFns.unlock(gCtx->keyMtx);
	if (key_handle < 0) {
		rc = CKR_KEY_HANDLE_INVALID;
		goto out_uninit;
	}
	key = (struct hse_keyObject *)hse_get_node_mem_addr(key_handle, true);

	/* Check the output length */
	if ((sCtx->cryptCtx.mechanism->mechanism == CKM_AES_ECB) ||
		(sCtx->cryptCtx.mechanism->mechanism == CKM_AES_CBC) ||
		(sCtx->cryptCtx.mechanism->mechanism == CKM_AES_CTR)) {
		/* For AES, the output length is equal to the input length  */
		if (*pulLastEncryptedPartLen < sCtx->cryptCtx.cache_idx) {
			/* tell the required size */
			*pulLastEncryptedPartLen = sCtx->cryptCtx.cache_idx;

			rc = CKR_BUFFER_TOO_SMALL;
			goto out_uninit;
		}
	} else if (sCtx->cryptCtx.mechanism->mechanism == CKM_AES_CBC_PAD) {
		pad_len = sCtx->cryptCtx.blockSize * (sCtx->cryptCtx.cache_idx / sCtx->cryptCtx.blockSize + 1);
		if (*pulLastEncryptedPartLen < pad_len) {
			*pulLastEncryptedPartLen = pad_len;

			rc = CKR_BUFFER_TOO_SMALL;
			goto out_uninit;
		}
	} else {
		rc = CKR_FUNCTION_NOT_SUPPORTED;
		goto out_uninit;
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
			goto out_uninit;
		}
	} else if(sCtx->cryptCtx.mechanism->mechanism == CKM_AES_CBC_PAD) {
		pad_value = sCtx->cryptCtx.blockSize - input_len;
		input_len = pad_len;
	} else {
		/* there is no data left for enc, fill dummy data */
		if (input_len == 0) {
			input_len = sCtx->cryptCtx.blockSize;
		}
	}

	/* input process */
	input_handle = hse_mem_alloc(input_len);
	if (input_handle < 0) {
		rc = CKR_HOST_MEMORY;
		goto out_uninit;
	}
	hse_memcpy_to_dev(input_handle, sCtx->cryptCtx.cache, input_len - pad_value, 0);

	if (sCtx->cryptCtx.mechanism->mechanism == CKM_AES_CBC_PAD)
		hse_memset(input_handle, pad_value, pad_value, input_len - pad_value);

	output_handle = hse_mem_alloc(input_len);
	if (output_handle < 0) {
		rc = CKR_HOST_MEMORY;
		goto out_free_input;
	}

	switch (sCtx->cryptCtx.mechanism->mechanism) {
		case CKM_AES_ECB:

			sym_cipher_srv = &srv_desc.hseSrv.symCipherReq;

			srv_desc.srvId = HSE_SRV_ID_SYM_CIPHER;
			sym_cipher_srv->accessMode = HSE_ACCESS_MODE_FINISH;
			sym_cipher_srv->streamId = sCtx->cryptCtx.streamID;
			sym_cipher_srv->cipherAlgo = HSE_CIPHER_ALGO_AES;
			sym_cipher_srv->cipherBlockMode = HSE_CIPHER_BLOCK_MODE_ECB;
			sym_cipher_srv->cipherDir = HSE_CIPHER_DIR_ENCRYPT;
			sym_cipher_srv->sgtOption = HSE_SGT_OPTION_NONE;
			sym_cipher_srv->keyHandle = key->key_handle;
			sym_cipher_srv->pIV = 0;
			sym_cipher_srv->inputLength = input_len;
			sym_cipher_srv->pInput = hse_virt_to_dma(input_handle, 0);
			sym_cipher_srv->pOutput= hse_virt_to_dma(output_handle, 0);

			break;

		case CKM_AES_CBC:
		case CKM_AES_CBC_PAD:

			sym_cipher_srv = &srv_desc.hseSrv.symCipherReq;

			srv_desc.srvId = HSE_SRV_ID_SYM_CIPHER;
			sym_cipher_srv->accessMode = HSE_ACCESS_MODE_FINISH;
			sym_cipher_srv->streamId = sCtx->cryptCtx.streamID;
			sym_cipher_srv->cipherAlgo = HSE_CIPHER_ALGO_AES;
			sym_cipher_srv->cipherBlockMode = HSE_CIPHER_BLOCK_MODE_CBC;
			sym_cipher_srv->cipherDir = HSE_CIPHER_DIR_ENCRYPT;
			sym_cipher_srv->sgtOption = HSE_SGT_OPTION_NONE;
			sym_cipher_srv->keyHandle = key->key_handle;
			sym_cipher_srv->pIV = 0;
			sym_cipher_srv->inputLength = input_len;
			sym_cipher_srv->pInput = hse_virt_to_dma(input_handle, 0);
			sym_cipher_srv->pOutput= hse_virt_to_dma(output_handle, 0);

			break;

		case CKM_AES_CTR:

			sym_cipher_srv = &srv_desc.hseSrv.symCipherReq;

			srv_desc.srvId = HSE_SRV_ID_SYM_CIPHER;
			sym_cipher_srv->accessMode = HSE_ACCESS_MODE_FINISH;
			sym_cipher_srv->streamId = sCtx->cryptCtx.streamID;
			sym_cipher_srv->cipherAlgo = HSE_CIPHER_ALGO_AES;
			sym_cipher_srv->cipherBlockMode = HSE_CIPHER_BLOCK_MODE_CTR;
			sym_cipher_srv->cipherDir = HSE_CIPHER_DIR_ENCRYPT;
			sym_cipher_srv->sgtOption = HSE_SGT_OPTION_NONE;
			sym_cipher_srv->keyHandle = key->key_handle;
			sym_cipher_srv->pIV = 0;
			sym_cipher_srv->inputLength = input_len;
			sym_cipher_srv->pInput = hse_virt_to_dma(input_handle, 0);
			sym_cipher_srv->pOutput= hse_virt_to_dma(output_handle, 0);

			break;
		default:
			rc = CKR_ARGUMENTS_BAD;
			goto out_free_output;
	}

	err = hse_srv_req_sync(sCtx->sID, &srv_desc, sizeof(srv_desc));
	if (err) {
		rc = CKR_FUNCTION_FAILED;
		goto out_free_output;
	}
	if (sCtx->cryptCtx.mechanism->mechanism == CKM_AES_CBC_PAD) {
		hse_memcpy_from_dev(pLastEncryptedPart, output_handle, input_len, 0);
		*pulLastEncryptedPartLen = input_len;
		goto out_free_output;
	}
	if (sCtx->cryptCtx.cache_idx > 0)
		hse_memcpy_from_dev(pLastEncryptedPart, output_handle, sCtx->cryptCtx.cache_idx, 0);
	*pulLastEncryptedPartLen = sCtx->cryptCtx.cache_idx;

out_free_output:
	hse_mem_free(output_handle);
out_free_input:
	hse_mem_free(input_handle);
out_uninit:
	if (rc != CKR_BUFFER_TOO_SMALL) {
		hse_stream_free(sCtx->cryptCtx.streamID);
		sCtx->cryptCtx.init = CK_FALSE;
		if (sCtx->cryptCtx.cache != NULL) {
			free(sCtx->cryptCtx.cache);
			sCtx->cryptCtx.cache = NULL;
		}
	}

	return rc;
}

CK_DECLARE_FUNCTION(CK_RV, C_DecryptUpdate)(
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
	struct hse_keyObject *key;
	CK_RV rc = CKR_OK;
	int err, key_handle = -1, input_handle = -1, output_handle = -1, pIV_handle = -1;
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
		goto out_uninit;
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
	key_handle = get_key_object_handle(sCtx->cryptCtx.keyHandle);
	gCtx->mtxFns.unlock(gCtx->keyMtx);
	if (key_handle < 0) {
		rc = CKR_KEY_HANDLE_INVALID;
		goto out_uninit;
	}
	key = (struct hse_keyObject *)hse_get_node_mem_addr(key_handle, true);

	if ((sCtx->cryptCtx.mechanism->mechanism != CKM_AES_ECB) &&
		(sCtx->cryptCtx.mechanism->mechanism != CKM_AES_CBC) &&
		(sCtx->cryptCtx.mechanism->mechanism != CKM_AES_CTR) &&
		(sCtx->cryptCtx.mechanism->mechanism != CKM_AES_CBC_PAD)) {
		rc = CKR_FUNCTION_NOT_SUPPORTED;
		goto out_uninit;
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
		goto out_uninit;
	}

	/* copy full_blocks to dynamic buffer */
	if (full_blocks > 0) {
		input_handle = hse_mem_alloc(full_blocks);
		if (input_handle < 0) {
			rc = CKR_HOST_MEMORY;
			goto out_uninit;
		}
		hse_memcpy_to_dev(input_handle, sCtx->cryptCtx.cache, sCtx->cryptCtx.cache_idx, 0);
		hse_memcpy_to_dev(input_handle, pEncryptedPart, full_blocks - sCtx->cryptCtx.cache_idx, sCtx->cryptCtx.cache_idx);
		bytes_left -= full_blocks;

		/* copy residue to block-sized cache */
		if (bytes_left > 0)
			memcpy(sCtx->cryptCtx.cache, pEncryptedPart + (full_blocks - sCtx->cryptCtx.cache_idx), bytes_left);
			
		sCtx->cryptCtx.cache_idx = bytes_left;

		/* output length is equal to the input length  */
		output_handle = hse_mem_alloc(full_blocks);
		if (output_handle < 0) {
			rc = CKR_HOST_MEMORY;
			goto out_free_input;
		}
	}

	if (sCtx->cryptCtx.stream_start == CK_TRUE) {
		/* IV input is used only when START */
		if (sCtx->cryptCtx.mechanism->pParameter != NULL) {
			pIV_handle = hse_mem_alloc(sCtx->cryptCtx.mechanism->ulParameterLen);
			if (pIV_handle < 0) {
				rc = CKR_HOST_MEMORY;
				goto out_free_output;
			}
			hse_memcpy_to_dev(pIV_handle, sCtx->cryptCtx.mechanism->pParameter,
							  sCtx->cryptCtx.mechanism->ulParameterLen, 0);
		}

		access_mode = HSE_ACCESS_MODE_START;
		sCtx->cryptCtx.stream_start = CK_FALSE;

		err = hse_stream_acquire(&sCtx->cryptCtx.streamID);
		if (err) {
			rc = CKR_STATE_UNSAVEABLE;
			goto out_free_piv;
		}
	} else {
		access_mode = HSE_ACCESS_MODE_UPDATE;
	}

	switch (sCtx->cryptCtx.mechanism->mechanism) {
		case CKM_AES_ECB:

			sym_cipher_srv = &srv_desc.hseSrv.symCipherReq;

			srv_desc.srvId = HSE_SRV_ID_SYM_CIPHER;
			sym_cipher_srv->accessMode = access_mode;
			sym_cipher_srv->streamId = sCtx->cryptCtx.streamID;
			sym_cipher_srv->cipherAlgo = HSE_CIPHER_ALGO_AES;
			sym_cipher_srv->cipherBlockMode = HSE_CIPHER_BLOCK_MODE_ECB;
			sym_cipher_srv->cipherDir = HSE_CIPHER_DIR_DECRYPT;
			sym_cipher_srv->sgtOption = HSE_SGT_OPTION_NONE;
			sym_cipher_srv->keyHandle = key->key_handle;

			if (sCtx->cryptCtx.mechanism->pParameter != NULL) {
				sym_cipher_srv->pIV = hse_virt_to_dma(pIV_handle, 0);
			} else {
				sym_cipher_srv->pIV = 0u; /* IV is not required for ecb */
			}

			sym_cipher_srv->inputLength = full_blocks;
			sym_cipher_srv->pInput = hse_virt_to_dma(input_handle, 0);
			sym_cipher_srv->pOutput= hse_virt_to_dma(output_handle, 0);

			break;

		case CKM_AES_CBC:
		case CKM_AES_CBC_PAD:
			sym_cipher_srv = &srv_desc.hseSrv.symCipherReq;

			srv_desc.srvId = HSE_SRV_ID_SYM_CIPHER;
			sym_cipher_srv->accessMode = access_mode;
			sym_cipher_srv->streamId = sCtx->cryptCtx.streamID;
			sym_cipher_srv->cipherAlgo = HSE_CIPHER_ALGO_AES;
			sym_cipher_srv->cipherBlockMode = HSE_CIPHER_BLOCK_MODE_CBC;
			sym_cipher_srv->cipherDir = HSE_CIPHER_DIR_DECRYPT;
			sym_cipher_srv->sgtOption = HSE_SGT_OPTION_NONE;
			sym_cipher_srv->keyHandle = key->key_handle;
			sym_cipher_srv->pIV = hse_virt_to_dma(pIV_handle, 0);
			sym_cipher_srv->inputLength = full_blocks;
			sym_cipher_srv->pInput = hse_virt_to_dma(input_handle, 0);
			sym_cipher_srv->pOutput= hse_virt_to_dma(output_handle, 0);

			break;

		case CKM_AES_CTR:

			sym_cipher_srv = &srv_desc.hseSrv.symCipherReq;

			srv_desc.srvId = HSE_SRV_ID_SYM_CIPHER;
			sym_cipher_srv->accessMode = access_mode;
			sym_cipher_srv->streamId = sCtx->cryptCtx.streamID;
			sym_cipher_srv->cipherAlgo = HSE_CIPHER_ALGO_AES;
			sym_cipher_srv->cipherBlockMode = HSE_CIPHER_BLOCK_MODE_CTR;
			sym_cipher_srv->cipherDir = HSE_CIPHER_DIR_DECRYPT;
			sym_cipher_srv->sgtOption = HSE_SGT_OPTION_NONE;
			sym_cipher_srv->keyHandle = key->key_handle;
			sym_cipher_srv->pIV = hse_virt_to_dma(pIV_handle, 0);
			sym_cipher_srv->inputLength = full_blocks;
			sym_cipher_srv->pInput = hse_virt_to_dma(input_handle, 0);
			sym_cipher_srv->pOutput= hse_virt_to_dma(output_handle, 0);

			break;
		default:
			rc = CKR_ARGUMENTS_BAD;
			goto out_free_piv;
	}

	err = hse_srv_req_sync(sCtx->sID, &srv_desc, sizeof(srv_desc));
	if (err) {
		rc = CKR_FUNCTION_FAILED;
		goto out_free_piv;
	}

	if (full_blocks > 0)
		hse_memcpy_from_dev(pPart, output_handle, full_blocks, 0);
	*pulPartLen = full_blocks;

out_free_piv:
	hse_mem_free(pIV_handle);
out_free_output:
	hse_mem_free(output_handle);
out_free_input:
	hse_mem_free(input_handle);
out_uninit:
	if ((rc != CKR_OK) && (rc != CKR_BUFFER_TOO_SMALL)) {
		hse_stream_free(sCtx->cryptCtx.streamID);
		sCtx->cryptCtx.init = CK_FALSE;
		if (sCtx->cryptCtx.cache != NULL) {
			free(sCtx->cryptCtx.cache);
			sCtx->cryptCtx.cache = NULL;
		}
	}

	return rc;
}

CK_DECLARE_FUNCTION(CK_RV, C_DecryptFinal)(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pLastPart,
		CK_ULONG_PTR pulLastPartLen
)
{
	struct globalCtx *gCtx = getCtx();
	struct sessionCtx *sCtx = getSessionCtx(hSession);
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	hseSymCipherSrv_t *sym_cipher_srv;
	uint8_t input_len = 0;
	struct hse_keyObject *key;
	CK_RV rc = CKR_OK;
	int err, key_handle = -1, input_handle = -1, output_handle = -1;

	if (gCtx->cryptokiInit == CK_FALSE)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!sCtx || sCtx->sessionInit == CK_FALSE)
		return CKR_SESSION_HANDLE_INVALID;

	if (sCtx->cryptCtx.init == CK_FALSE)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (pulLastPartLen == NULL) {
		rc = CKR_ARGUMENTS_BAD;
		goto out_uninit;
	}

	if (pLastPart == NULL) {
		/* if NULL, upper layer expects to receive needed size */
		*pulLastPartLen = sCtx->cryptCtx.cache_idx;
		return CKR_OK; 
	}

	gCtx->mtxFns.lock(gCtx->keyMtx);
	key_handle = get_key_object_handle(sCtx->cryptCtx.keyHandle);
	gCtx->mtxFns.unlock(gCtx->keyMtx);
	if (key_handle < 0) {
		rc = CKR_KEY_HANDLE_INVALID;
		goto out_uninit;
	}
	key = (struct hse_keyObject *)hse_get_node_mem_addr(key_handle, true);

	/* Check the output length */
	if ((sCtx->cryptCtx.mechanism->mechanism == CKM_AES_ECB) ||
		(sCtx->cryptCtx.mechanism->mechanism == CKM_AES_CBC) ||
		(sCtx->cryptCtx.mechanism->mechanism == CKM_AES_CTR)) {
		/* For AES, the output length is equal to the input length  */
		if (*pulLastPartLen < sCtx->cryptCtx.cache_idx) {
			/* tell the required size */
			*pulLastPartLen = sCtx->cryptCtx.cache_idx;

			rc = CKR_BUFFER_TOO_SMALL;
			goto out_uninit;
		}
	} else if (sCtx->cryptCtx.mechanism->mechanism != CKM_AES_CBC_PAD) {
		rc = CKR_FUNCTION_NOT_SUPPORTED;
		goto out_uninit;
	}

	/* input length check:
	 * For ECB, CBC & CFB cipher block modes, must be a multiple of block length. Cannot be zero.
     * For remaining cipher block modes, can be any value except zero. */
	input_len = sCtx->cryptCtx.cache_idx;
	if ((sCtx->cryptCtx.mechanism->mechanism == CKM_AES_ECB) ||
		(sCtx->cryptCtx.mechanism->mechanism == CKM_AES_CBC) ||
		(sCtx->cryptCtx.mechanism->mechanism == CKM_AES_CBC_PAD)) {
		if (input_len == 0) {
			/* if no data left, fill dummy data */
			input_len = sCtx->cryptCtx.blockSize;
		} else if (sCtx->cryptCtx.cache_idx != sCtx->cryptCtx.blockSize) {
			rc = CKR_DATA_LEN_RANGE;
			goto out_uninit;
		}
	} else {
		if (sCtx->cryptCtx.cache_idx == 0) {
			/* if no data left, fill dummy data */
			input_len = sCtx->cryptCtx.blockSize;
		}
	}

	input_handle = hse_mem_alloc(input_len);
	if (input_handle < 0) {
		rc = CKR_HOST_MEMORY;
		goto out_uninit;
	}

	hse_memcpy_to_dev(input_handle, sCtx->cryptCtx.cache, input_len, 0);

	output_handle = hse_mem_alloc(input_len);
	if (output_handle < 0) {
		rc = CKR_HOST_MEMORY;
		goto out_free_input;
	}

	switch (sCtx->cryptCtx.mechanism->mechanism) {
		case CKM_AES_ECB:

			sym_cipher_srv = &srv_desc.hseSrv.symCipherReq;

			srv_desc.srvId = HSE_SRV_ID_SYM_CIPHER;
			sym_cipher_srv->accessMode = HSE_ACCESS_MODE_FINISH;
			sym_cipher_srv->streamId = sCtx->cryptCtx.streamID;
			sym_cipher_srv->cipherAlgo = HSE_CIPHER_ALGO_AES;
			sym_cipher_srv->cipherBlockMode = HSE_CIPHER_BLOCK_MODE_ECB;
			sym_cipher_srv->cipherDir = HSE_CIPHER_DIR_DECRYPT;
			sym_cipher_srv->sgtOption = HSE_SGT_OPTION_NONE;
			sym_cipher_srv->keyHandle = key->key_handle;
			sym_cipher_srv->pIV = 0;
			sym_cipher_srv->inputLength = input_len;
			sym_cipher_srv->pInput = hse_virt_to_dma(input_handle, 0);
			sym_cipher_srv->pOutput= hse_virt_to_dma(output_handle, 0);

			break;

		case CKM_AES_CBC:
		case CKM_AES_CBC_PAD:

			sym_cipher_srv = &srv_desc.hseSrv.symCipherReq;

			srv_desc.srvId = HSE_SRV_ID_SYM_CIPHER;
			sym_cipher_srv->accessMode = HSE_ACCESS_MODE_FINISH;
			sym_cipher_srv->streamId = sCtx->cryptCtx.streamID;
			sym_cipher_srv->cipherAlgo = HSE_CIPHER_ALGO_AES;
			sym_cipher_srv->cipherBlockMode = HSE_CIPHER_BLOCK_MODE_CBC;
			sym_cipher_srv->cipherDir = HSE_CIPHER_DIR_DECRYPT;
			sym_cipher_srv->sgtOption = HSE_SGT_OPTION_NONE;
			sym_cipher_srv->keyHandle = key->key_handle;
			sym_cipher_srv->pIV = 0;
			sym_cipher_srv->inputLength = input_len;
			sym_cipher_srv->pInput = hse_virt_to_dma(input_handle, 0);
			sym_cipher_srv->pOutput= hse_virt_to_dma(output_handle, 0);

			break;

		case CKM_AES_CTR:

			sym_cipher_srv = &srv_desc.hseSrv.symCipherReq;

			srv_desc.srvId = HSE_SRV_ID_SYM_CIPHER;
			sym_cipher_srv->accessMode = HSE_ACCESS_MODE_FINISH;
			sym_cipher_srv->streamId = sCtx->cryptCtx.streamID;
			sym_cipher_srv->cipherAlgo = HSE_CIPHER_ALGO_AES;
			sym_cipher_srv->cipherBlockMode = HSE_CIPHER_BLOCK_MODE_CTR;
			sym_cipher_srv->cipherDir = HSE_CIPHER_DIR_DECRYPT;
			sym_cipher_srv->sgtOption = HSE_SGT_OPTION_NONE;
			sym_cipher_srv->keyHandle = key->key_handle;
			sym_cipher_srv->pIV = 0;
			sym_cipher_srv->inputLength = input_len;
			sym_cipher_srv->pInput = hse_virt_to_dma(input_handle, 0);
			sym_cipher_srv->pOutput= hse_virt_to_dma(output_handle, 0);

			break;
		default:
			rc = CKR_ARGUMENTS_BAD;
			goto out_free_output;
	}

	err = hse_srv_req_sync(sCtx->sID, &srv_desc, sizeof(srv_desc));
	if (err) {
		rc = CKR_FUNCTION_FAILED;
		goto out_free_output;
	}

	if (sCtx->cryptCtx.cache_idx > 0)
		hse_memcpy_from_dev(pLastPart, output_handle, sCtx->cryptCtx.cache_idx, 0);
	*pulLastPartLen = sCtx->cryptCtx.cache_idx;

out_free_output:
	hse_mem_free(output_handle);
out_free_input:
	hse_mem_free(input_handle);
out_uninit:
	if (rc != CKR_BUFFER_TOO_SMALL) {
		hse_stream_free(sCtx->cryptCtx.streamID);
		sCtx->cryptCtx.init = CK_FALSE;
		if (sCtx->cryptCtx.cache != NULL) {
			free(sCtx->cryptCtx.cache);
			sCtx->cryptCtx.cache = NULL;
		}
	}

	return rc;
}

CK_DECLARE_FUNCTION(CK_RV, C_SignUpdate)(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pPart,
		CK_ULONG ulPartLen
)
{
	struct globalCtx *gCtx = getCtx();
	struct sessionCtx *sCtx = getSessionCtx(hSession);
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	hseSignSrv_t *sign_srv;
	hseSignScheme_t *sign_scheme;
	CK_RSA_PKCS_PSS_PARAMS *rsa_pss_param;
	hseMacSrv_t *mac_srv = NULL;
	struct hse_keyObject *key;
	CK_RV rc = CKR_OK;
	int err, key_handle = -1, input_handle = -1;
	uint32_t bytes_left, full_blocks;
	hseAccessMode_t access_mode;

	if (gCtx->cryptokiInit == CK_FALSE)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!sCtx || sCtx->sessionInit == CK_FALSE)
		return CKR_SESSION_HANDLE_INVALID;

	if (sCtx->signCtx.init == CK_FALSE)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (ulPartLen == 0)
		return rc;
	
	if ((ulPartLen > 0) && (!pPart)) {
		rc = CKR_ARGUMENTS_BAD;
		goto out_uninit;
	}

	gCtx->mtxFns.lock(gCtx->keyMtx);
	key_handle = get_key_object_handle(sCtx->signCtx.keyHandle);
	gCtx->mtxFns.unlock(gCtx->keyMtx);
	if (key_handle < 0) {
		rc = CKR_KEY_HANDLE_INVALID;
		goto out_uninit;
	}
	key = (struct hse_keyObject *)hse_get_node_mem_addr(key_handle, true);

	/* input process */
	bytes_left = sCtx->signCtx.cache_idx + ulPartLen;
	if (bytes_left < sCtx->signCtx.blockSize) {
		/* cache data for next update and exit */
		memcpy(sCtx->signCtx.cache + sCtx->signCtx.cache_idx, pPart, ulPartLen);
		sCtx->signCtx.cache_idx = bytes_left;
		return CKR_OK;
	}

	/* round down to nearest multiple of block size */
	full_blocks = bytes_left - (bytes_left % sCtx->signCtx.blockSize);
	if (full_blocks > 0) {
		/* copy full_blocks to dynamic buffer */
		input_handle = hse_mem_alloc(full_blocks);
		if (input_handle < 0) {
			rc = CKR_HOST_MEMORY;
			return rc;
		}
		hse_memcpy_to_dev(input_handle, sCtx->signCtx.cache, sCtx->signCtx.cache_idx, 0);
		hse_memcpy_to_dev(input_handle, pPart, full_blocks - sCtx->signCtx.cache_idx, sCtx->signCtx.cache_idx);
		bytes_left -= full_blocks;

		/* copy residue to block-sized cache */
		if (bytes_left > 0)
			memcpy(sCtx->signCtx.cache, pPart + (full_blocks - sCtx->signCtx.cache_idx), bytes_left);
			
		sCtx->signCtx.cache_idx = bytes_left;
	}

	if (sCtx->signCtx.stream_start) {
		access_mode = HSE_ACCESS_MODE_START;
		sCtx->signCtx.stream_start = CK_FALSE;

		err = hse_stream_acquire(&sCtx->signCtx.streamID);
		if (err) {
			rc = CKR_STATE_UNSAVEABLE;
			goto out_free_input;
		}
	} else {
		access_mode = HSE_ACCESS_MODE_UPDATE;
	}

	sign_srv = &srv_desc.hseSrv.signReq;
	sign_scheme = &sign_srv->signScheme;

	switch (sCtx->signCtx.mechanism->mechanism) {
		case CKM_SHA1_RSA_PKCS:
		case CKM_SHA256_RSA_PKCS:
		case CKM_SHA384_RSA_PKCS:
		case CKM_SHA512_RSA_PKCS:
			sign_scheme->signSch = HSE_SIGN_RSASSA_PKCS1_V15;
			sign_scheme->sch.rsaPkcs1v15.hashAlgo = hse_get_hash_alg(sCtx->signCtx.mechanism->mechanism);
			break;
		case CKM_SHA1_RSA_PKCS_PSS:
		case CKM_SHA256_RSA_PKCS_PSS:
		case CKM_SHA384_RSA_PKCS_PSS:
		case CKM_SHA512_RSA_PKCS_PSS:
			rsa_pss_param = (CK_RSA_PKCS_PSS_PARAMS *)sCtx->signCtx.mechanism->pParameter;
			if (rsa_pss_param == NULL) {
				rc = CKR_ARGUMENTS_BAD;
				goto out_free_input;
			}
			sign_scheme->signSch = HSE_SIGN_RSASSA_PSS;
			sign_scheme->sch.rsaPss.hashAlgo = hse_pkcs_hash_alg_translate(rsa_pss_param->hashAlg);
			sign_scheme->sch.rsaPss.saltLength = rsa_pss_param->sLen;
			break;
		case CKM_ECDSA_SHA1:
		case CKM_ECDSA_SHA224:
		case CKM_ECDSA_SHA256:
		case CKM_ECDSA_SHA384:
		case CKM_ECDSA_SHA512:
			sign_scheme->signSch = HSE_SIGN_ECDSA;
			sign_scheme->sch.ecdsa.hashAlgo = hse_get_hash_alg(sCtx->signCtx.mechanism->mechanism);
			break;
		case CKM_AES_CMAC:
			mac_srv = &srv_desc.hseSrv.macReq;
			mac_srv->macScheme.macAlgo = HSE_MAC_ALGO_CMAC;
			mac_srv->macScheme.sch.cmac.cipherAlgo = HSE_CIPHER_ALGO_AES;
			break;
		case CKM_SHA_1_HMAC:
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
			goto out_free_input;
	}

	if (!mac_srv) {
		srv_desc.srvId = HSE_SRV_ID_SIGN;
		sign_srv->accessMode = access_mode;
		sign_srv->streamId = sCtx->signCtx.streamID;
		sign_srv->authDir = HSE_AUTH_DIR_GENERATE;
		sign_srv->bInputIsHashed = 0u;
		sign_srv->keyHandle = key->key_handle;
		sign_srv->sgtOption = HSE_SGT_OPTION_NONE;
		sign_srv->inputLength = full_blocks;
		sign_srv->pInput = hse_virt_to_dma(input_handle, 0);
	} else {
		srv_desc.srvId = HSE_SRV_ID_MAC;
		mac_srv->accessMode = access_mode;
		mac_srv->streamId = sCtx->signCtx.streamID;
		mac_srv->authDir = HSE_AUTH_DIR_GENERATE;
		mac_srv->sgtOption = HSE_SGT_OPTION_NONE;
		mac_srv->keyHandle = key->key_handle;
		mac_srv->inputLength = full_blocks;
		mac_srv->pInput = hse_virt_to_dma(input_handle, 0);
	}

	err = hse_srv_req_sync(sCtx->sID, &srv_desc, sizeof(srv_desc));
	if (err)
		rc = CKR_FUNCTION_FAILED;

out_free_input:
	hse_mem_free(input_handle);
out_uninit:
	if (rc != CKR_OK) {
		hse_stream_free(sCtx->signCtx.streamID);
		sCtx->signCtx.init = CK_FALSE;
		if (sCtx->signCtx.cache != NULL) {
			free(sCtx->signCtx.cache);
			sCtx->signCtx.cache = NULL;
		}
	}

	return rc;
}

CK_DECLARE_FUNCTION(CK_RV, C_SignFinal)(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pSignature,
		CK_ULONG_PTR pulSignatureLen
)
{
	struct globalCtx *gCtx = getCtx();
	struct sessionCtx *sCtx = getSessionCtx(hSession);
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	hseSignSrv_t *sign_srv;
	hseSignScheme_t *sign_scheme;
	hseMacSrv_t *mac_srv = NULL;
	struct hse_keyObject *key = NULL;
	uint32_t bytes_left, sig_len;
	CK_RV rc = CKR_OK;
	int err, key_handle = -1, input_handle = -1, sign0_handle = -1, sig_len_handle = -1;

	if (gCtx->cryptokiInit == CK_FALSE)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!sCtx || sCtx->sessionInit == CK_FALSE)
		return CKR_SESSION_HANDLE_INVALID;

	if (sCtx->signCtx.init == CK_FALSE)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (!pSignature || !pulSignatureLen) {
		rc = CKR_ARGUMENTS_BAD;
		goto out_uninit;
	}

	gCtx->mtxFns.lock(gCtx->keyMtx);
	key_handle = get_key_object_handle(sCtx->signCtx.keyHandle);
	gCtx->mtxFns.unlock(gCtx->keyMtx);
	if (key_handle < 0) {
		rc = CKR_KEY_HANDLE_INVALID;
		goto out_uninit;
	}
	key = (struct hse_keyObject *)hse_get_node_mem_addr(key_handle, true);

	/* the stream should be already started */
	if (sCtx->signCtx.stream_start) {
		rc = CKR_FUNCTION_FAILED;
		goto out_uninit;
	}

	sig_len_handle = hse_mem_alloc(sizeof(sig_len));
	if (sig_len_handle < 0) {
		rc = CKR_HOST_MEMORY;
		goto out_uninit;
	}

	/* Get required length of out buffer */
	sig_len = sig_get_out_length(sCtx->sID, key, sCtx->signCtx.mechanism);

	/* Signature length shouldn't be 0 at this point */
	if (sig_len == 0) {
		rc = CKR_ARGUMENTS_BAD;
		goto out_free_sig_len;
	}

	/* check output buffer length */
	if (*pulSignatureLen < sig_len) {
		rc = CKR_BUFFER_TOO_SMALL;
		*pulSignatureLen = sig_len;
		goto out_free_sig_len;
	}
	hse_memcpy_to_dev(sig_len_handle, (void *)&sig_len, sizeof(sig_len), 0);

	/* process the left cache */
	bytes_left = sCtx->signCtx.cache_idx;
	if (bytes_left > 0) {
		input_handle = hse_mem_alloc(bytes_left);
		if (input_handle < 0) {
			rc = CKR_HOST_MEMORY;
			goto out_free_sig_len;
		}
		hse_memcpy_to_dev(input_handle, sCtx->signCtx.cache, sCtx->signCtx.cache_idx, 0);
		sCtx->signCtx.cache_idx = 0;
	}

	sign0_handle = hse_mem_alloc(sig_len);
	if (sign0_handle < 0) {
		rc = CKR_HOST_MEMORY;
		goto out_free_input;
	}

	sign_srv = &srv_desc.hseSrv.signReq;
	sign_scheme = &sign_srv->signScheme;

	switch (sCtx->signCtx.mechanism->mechanism) {
		case CKM_SHA1_RSA_PKCS:
		case CKM_SHA256_RSA_PKCS:
		case CKM_SHA384_RSA_PKCS:
		case CKM_SHA512_RSA_PKCS:
			sign_srv->pSignatureLength[0] = hse_virt_to_dma(sig_len_handle, 0);
			sign_srv->pSignatureLength[1] = 0u;
			sign_srv->pSignature[0] = hse_virt_to_dma(sign0_handle, 0);
			sign_srv->pSignature[1] = 0u;
			break;
		case CKM_SHA1_RSA_PKCS_PSS:
		case CKM_SHA256_RSA_PKCS_PSS:
		case CKM_SHA384_RSA_PKCS_PSS:
		case CKM_SHA512_RSA_PKCS_PSS:
			sign_srv->pSignatureLength[0] = hse_virt_to_dma(sig_len_handle, 0);
			sign_srv->pSignatureLength[1] = 0u;
			sign_srv->pSignature[0] = hse_virt_to_dma(sign0_handle, 0);
			sign_srv->pSignature[1] = 0u;
			break;
		case CKM_ECDSA_SHA1:
		case CKM_ECDSA_SHA224:
		case CKM_ECDSA_SHA256:
		case CKM_ECDSA_SHA384:
		case CKM_ECDSA_SHA512:
			sign_scheme->signSch = HSE_SIGN_ECDSA;
			sign_scheme->sch.ecdsa.hashAlgo = hse_get_hash_alg(sCtx->signCtx.mechanism->mechanism);
			sig_len = sig_len / 2;
			hse_memcpy_to_dev(sig_len_handle, (void *)&sig_len, sizeof(sig_len), 0);
			
			sign_srv->pSignatureLength[0] = hse_virt_to_dma(sig_len_handle, 0);
			sign_srv->pSignatureLength[1] = hse_virt_to_dma(sig_len_handle, 0);
			sign_srv->pSignature[0] = hse_virt_to_dma(sign0_handle, 0);
			sign_srv->pSignature[1] = hse_virt_to_dma(sign0_handle, sig_len);
			break;
		case CKM_AES_CMAC:
			mac_srv = &srv_desc.hseSrv.macReq;
			mac_srv->macScheme.macAlgo = HSE_MAC_ALGO_CMAC;
			mac_srv->macScheme.sch.cmac.cipherAlgo = HSE_CIPHER_ALGO_AES;
			break;
		case CKM_SHA_1_HMAC:
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
			goto out_free_sign0;
	}

	if (!mac_srv) {
		srv_desc.srvId = HSE_SRV_ID_SIGN;
		sign_srv->accessMode = HSE_ACCESS_MODE_FINISH;
		sign_srv->streamId = sCtx->signCtx.streamID;
		sign_srv->authDir = HSE_AUTH_DIR_GENERATE;
		sign_srv->keyHandle = key->key_handle;
		sign_srv->sgtOption = HSE_SGT_OPTION_NONE;
		sign_srv->inputLength = bytes_left;
		sign_srv->pInput = hse_virt_to_dma(input_handle, 0);
	} else {
		srv_desc.srvId = HSE_SRV_ID_MAC;
		mac_srv->accessMode = HSE_ACCESS_MODE_FINISH;
		mac_srv->streamId = sCtx->signCtx.streamID;
		mac_srv->authDir = HSE_AUTH_DIR_GENERATE;
		mac_srv->sgtOption = HSE_SGT_OPTION_NONE;
		mac_srv->keyHandle = key->key_handle;
		mac_srv->inputLength = bytes_left;
		mac_srv->pInput = hse_virt_to_dma(input_handle, 0);
		mac_srv->pTagLength = hse_virt_to_dma(sig_len_handle, 0);
		mac_srv->pTag = hse_virt_to_dma(sign0_handle, 0);
	}

	err = hse_srv_req_sync(sCtx->sID, &srv_desc, sizeof(srv_desc));
	if (err) {
		rc = CKR_FUNCTION_FAILED;

		if (err == EBADMSG)
			rc = CKR_SIGNATURE_INVALID;

		goto out_free_sign0;
	}

	switch (sCtx->signCtx.mechanism->mechanism) {
		case CKM_SHA1_RSA_PKCS:
		case CKM_SHA256_RSA_PKCS:
		case CKM_SHA384_RSA_PKCS:
		case CKM_SHA512_RSA_PKCS:
		case CKM_SHA1_RSA_PKCS_PSS:
		case CKM_SHA256_RSA_PKCS_PSS:
		case CKM_SHA384_RSA_PKCS_PSS:
		case CKM_SHA512_RSA_PKCS_PSS:
		case CKM_AES_CMAC:
		case CKM_SHA_1_HMAC:
		case CKM_SHA224_HMAC:
		case CKM_SHA256_HMAC:
		case CKM_SHA384_HMAC:
		case CKM_SHA512_HMAC:

			hse_memcpy_from_dev(pulSignatureLen, sig_len_handle, sizeof(sig_len), 0);
			hse_memcpy_from_dev(pSignature, sign0_handle, *pulSignatureLen, 0);

			break;
		case CKM_ECDSA_SHA1:
		case CKM_ECDSA_SHA224:
		case CKM_ECDSA_SHA256:
		case CKM_ECDSA_SHA384:
		case CKM_ECDSA_SHA512:

			/* restore actual length */
			hse_memcpy_from_dev(pulSignatureLen, sig_len_handle, sizeof(sig_len), 0);
			*pulSignatureLen *= 2;

			hse_memcpy_from_dev(pSignature, sign0_handle, *pulSignatureLen, 0);

			break;
		default:
			rc = CKR_ARGUMENTS_BAD;
	}

out_free_sign0:
	hse_mem_free(sign0_handle);
out_free_input:
	hse_mem_free(input_handle);
out_free_sig_len:
	hse_mem_free(sig_len_handle);
out_uninit:
	if (rc != CKR_BUFFER_TOO_SMALL) {
		hse_stream_free(sCtx->signCtx.streamID);
		sCtx->signCtx.init = CK_FALSE;
		if (sCtx->signCtx.cache != NULL) {
			free(sCtx->signCtx.cache);
			sCtx->signCtx.cache = NULL;
		}
	}

	return rc;
}

CK_DECLARE_FUNCTION(CK_RV, C_SignRecoverInit)(
		CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,
		CK_OBJECT_HANDLE hKey
)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_SignRecover)(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pData,
		CK_ULONG ulDataLen,
		CK_BYTE_PTR pSignature,
		CK_ULONG_PTR pulSignatureLen
)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_VerifyUpdate)(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pPart,
		CK_ULONG ulPartLen
)
{
	struct globalCtx *gCtx = getCtx();
	struct sessionCtx *sCtx = getSessionCtx(hSession);
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	hseSignSrv_t *sign_srv;
	hseSignScheme_t *sign_scheme;
	CK_RSA_PKCS_PSS_PARAMS *rsa_pss_param;
	hseMacSrv_t *mac_srv = NULL;
	struct hse_keyObject *key;
	CK_RV rc = CKR_OK;
	int err, key_handle = -1, input_handle = -1;
	uint32_t bytes_left, full_blocks;
	hseAccessMode_t access_mode;

	if (gCtx->cryptokiInit == CK_FALSE)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!sCtx || sCtx->sessionInit == CK_FALSE)
		return CKR_SESSION_HANDLE_INVALID;

	if (sCtx->signCtx.init == CK_FALSE)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (ulPartLen == 0)
		return rc;
	
	if ((ulPartLen > 0) && (!pPart)) {
		rc = CKR_ARGUMENTS_BAD;
		goto out_uninit;
	}

	gCtx->mtxFns.lock(gCtx->keyMtx);
	key_handle = get_key_object_handle(sCtx->signCtx.keyHandle);
	gCtx->mtxFns.unlock(gCtx->keyMtx);
	if (key_handle < 0) {
		rc = CKR_KEY_HANDLE_INVALID;
		goto out_uninit;
	}
	key = (struct hse_keyObject *)hse_get_node_mem_addr(key_handle, true);

	/* input process */
	bytes_left = sCtx->signCtx.cache_idx + ulPartLen;
	if (bytes_left < sCtx->signCtx.blockSize) {
		/* cache data for next update and exit */
		memcpy(sCtx->signCtx.cache + sCtx->signCtx.cache_idx, pPart, ulPartLen);
		sCtx->signCtx.cache_idx = bytes_left;
		return CKR_OK;
	}

	/* round down to nearest multiple of block size */
	full_blocks = bytes_left - (bytes_left % sCtx->signCtx.blockSize);
	if (full_blocks > 0) {
		/* copy full_blocks to dynamic buffer */
		input_handle = hse_mem_alloc(full_blocks);
		if (input_handle < 0) {
			rc = CKR_HOST_MEMORY;
			return rc;
		}
		hse_memcpy_to_dev(input_handle, sCtx->signCtx.cache, sCtx->signCtx.cache_idx, 0);
		hse_memcpy_to_dev(input_handle, pPart, full_blocks - sCtx->signCtx.cache_idx, sCtx->signCtx.cache_idx);
		bytes_left -= full_blocks;

		/* copy residue to block-sized cache */
		if (bytes_left > 0)
			memcpy(sCtx->signCtx.cache, pPart + (full_blocks - sCtx->signCtx.cache_idx), bytes_left);
			
		sCtx->signCtx.cache_idx = bytes_left;
	}

	if (sCtx->signCtx.stream_start) {
		access_mode = HSE_ACCESS_MODE_START;
		sCtx->signCtx.stream_start = CK_FALSE;

		err = hse_stream_acquire(&sCtx->signCtx.streamID);
		if (err) {
			rc = CKR_STATE_UNSAVEABLE;
			goto out_free_input;
		}
	} else {
		access_mode = HSE_ACCESS_MODE_UPDATE;
	}

	sign_srv = &srv_desc.hseSrv.signReq;
	sign_scheme = &sign_srv->signScheme;

	switch (sCtx->signCtx.mechanism->mechanism) {
		case CKM_SHA1_RSA_PKCS:
		case CKM_SHA256_RSA_PKCS:
		case CKM_SHA384_RSA_PKCS:
		case CKM_SHA512_RSA_PKCS:
			sign_scheme->signSch = HSE_SIGN_RSASSA_PKCS1_V15;
			sign_scheme->sch.rsaPkcs1v15.hashAlgo = hse_get_hash_alg(sCtx->signCtx.mechanism->mechanism);
			break;
		case CKM_SHA1_RSA_PKCS_PSS:
		case CKM_SHA256_RSA_PKCS_PSS:
		case CKM_SHA384_RSA_PKCS_PSS:
		case CKM_SHA512_RSA_PKCS_PSS:
			rsa_pss_param = (CK_RSA_PKCS_PSS_PARAMS *)sCtx->signCtx.mechanism->pParameter;
			if (rsa_pss_param == NULL) {
				rc = CKR_ARGUMENTS_BAD;
				goto out_free_input;
			}
			sign_scheme->signSch = HSE_SIGN_RSASSA_PSS;
			sign_scheme->sch.rsaPss.hashAlgo = hse_pkcs_hash_alg_translate(rsa_pss_param->hashAlg);
			sign_scheme->sch.rsaPss.saltLength = rsa_pss_param->sLen;
			break;
		case CKM_ECDSA_SHA1:
		case CKM_ECDSA_SHA224:
		case CKM_ECDSA_SHA256:
		case CKM_ECDSA_SHA384:
		case CKM_ECDSA_SHA512:
			sign_scheme->signSch = HSE_SIGN_ECDSA;
			sign_scheme->sch.ecdsa.hashAlgo = hse_get_hash_alg(sCtx->signCtx.mechanism->mechanism);
			break;
		case CKM_AES_CMAC:
			mac_srv = &srv_desc.hseSrv.macReq;
			mac_srv->macScheme.macAlgo = HSE_MAC_ALGO_CMAC;
			mac_srv->macScheme.sch.cmac.cipherAlgo = HSE_CIPHER_ALGO_AES;
			break;
		case CKM_SHA_1_HMAC:
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
			goto out_free_input;
	}

	if (!mac_srv) {
		srv_desc.srvId = HSE_SRV_ID_SIGN;
		sign_srv->accessMode = access_mode;
		sign_srv->streamId = sCtx->signCtx.streamID;
		sign_srv->authDir = HSE_AUTH_DIR_VERIFY;
		sign_srv->bInputIsHashed = 0u;
		sign_srv->keyHandle = key->key_handle;
		sign_srv->sgtOption = HSE_SGT_OPTION_NONE;
		sign_srv->inputLength = full_blocks;
		sign_srv->pInput = hse_virt_to_dma(input_handle, 0);
	} else {
		srv_desc.srvId = HSE_SRV_ID_MAC;
		mac_srv->accessMode = access_mode;
		mac_srv->streamId = sCtx->signCtx.streamID;
		mac_srv->authDir = HSE_AUTH_DIR_VERIFY;
		mac_srv->keyHandle = key->key_handle;
		mac_srv->sgtOption = HSE_SGT_OPTION_NONE;
		mac_srv->inputLength = full_blocks;
		mac_srv->pInput = hse_virt_to_dma(input_handle, 0);
	}

	err = hse_srv_req_sync(sCtx->sID, &srv_desc, sizeof(srv_desc));
	if (err)
		rc = CKR_FUNCTION_FAILED;

out_free_input:
	hse_mem_free(input_handle);
out_uninit:
	if (rc != CKR_OK) {
		hse_stream_free(sCtx->signCtx.streamID);
		sCtx->signCtx.init = CK_FALSE;
		if (sCtx->signCtx.cache != NULL) {
			free(sCtx->signCtx.cache);
			sCtx->signCtx.cache = NULL;
		}
	}

	return rc;
}

CK_DECLARE_FUNCTION(CK_RV, C_VerifyFinal)(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pSignature,
		CK_ULONG ulSignatureLen
)
{
	struct globalCtx *gCtx = getCtx();
	struct sessionCtx *sCtx = getSessionCtx(hSession);
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	hseSignSrv_t *sign_srv;
	hseSignScheme_t *sign_scheme;
	hseMacSrv_t *mac_srv = NULL;
	struct hse_keyObject *key = NULL;
	uint32_t bytes_left, sig_len = 0;
	CK_RV rc = CKR_OK;
	int err, key_handle = -1, input_handle = -1, sign0_handle = -1, sig_len_handle = -1;

	if (gCtx->cryptokiInit == CK_FALSE)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!sCtx || sCtx->sessionInit == CK_FALSE)
		return CKR_SESSION_HANDLE_INVALID;

	if (sCtx->signCtx.init == CK_FALSE)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (!pSignature) {
		rc = CKR_ARGUMENTS_BAD;
		goto out_uninit;
	}

	gCtx->mtxFns.lock(gCtx->keyMtx);
	key_handle = get_key_object_handle(sCtx->signCtx.keyHandle);
	gCtx->mtxFns.unlock(gCtx->keyMtx);
	if (key_handle < 0) {
		rc = CKR_KEY_HANDLE_INVALID;
		goto out_uninit;
	}
	key = (struct hse_keyObject *)hse_get_node_mem_addr(key_handle, true);

	/* the stream should be already started */
	if (sCtx->signCtx.stream_start) {
		rc = CKR_FUNCTION_FAILED;
		goto out_uninit;
	}

	sig_len_handle = hse_mem_alloc(sizeof(sig_len));
	if (sig_len_handle < 0) {
		rc = CKR_HOST_MEMORY;
		goto out_uninit;
	}

	/* Get required length of out buffer */
	sig_len = sig_get_out_length(sCtx->sID, key, sCtx->signCtx.mechanism);

	/* Signature length shouldn't be 0 at this point */
	if (sig_len == 0) {
		rc = CKR_ARGUMENTS_BAD;
		goto out_free_sig_len;
	}

	/* check output buffer length */
	if (ulSignatureLen != sig_len) {
		rc = CKR_SIGNATURE_LEN_RANGE;
		goto out_free_sig_len;
	}
	hse_memcpy_to_dev(sig_len_handle, (void *)&sig_len, sizeof(sig_len), 0);

	/* process the left cache */
	bytes_left = sCtx->signCtx.cache_idx;
	if (bytes_left > 0) {
		input_handle = hse_mem_alloc(bytes_left);
		if (input_handle < 0) {
			rc = CKR_HOST_MEMORY;
			goto out_free_sig_len;
		}
		hse_memcpy_to_dev(input_handle, sCtx->signCtx.cache, sCtx->signCtx.cache_idx, 0);
		sCtx->signCtx.cache_idx = 0;
	}

	sign0_handle = hse_mem_alloc(sig_len);
	if (sign0_handle < 0) {
		rc = CKR_HOST_MEMORY;
		goto out_free_input;
	}

	hse_memcpy_to_dev(sign0_handle, pSignature, sig_len, 0);

	sign_srv = &srv_desc.hseSrv.signReq;
	sign_scheme = &sign_srv->signScheme;

	switch (sCtx->signCtx.mechanism->mechanism) {
		case CKM_SHA1_RSA_PKCS:
		case CKM_SHA256_RSA_PKCS:
		case CKM_SHA384_RSA_PKCS:
		case CKM_SHA512_RSA_PKCS:
			sign_srv->pSignatureLength[0] = hse_virt_to_dma(sig_len_handle, 0);
			sign_srv->pSignatureLength[1] = 0u;
			sign_srv->pSignature[0] = hse_virt_to_dma(sign0_handle, 0);
			sign_srv->pSignature[1] = 0u;
			break;
		case CKM_SHA1_RSA_PKCS_PSS:
		case CKM_SHA256_RSA_PKCS_PSS:
		case CKM_SHA384_RSA_PKCS_PSS:
		case CKM_SHA512_RSA_PKCS_PSS:
			sign_srv->pSignatureLength[0] = hse_virt_to_dma(sig_len_handle, 0);
			sign_srv->pSignatureLength[1] = 0u;
			sign_srv->pSignature[0] = hse_virt_to_dma(sign0_handle, 0);
			sign_srv->pSignature[1] = 0u;
			break;
		case CKM_ECDSA_SHA1:
		case CKM_ECDSA_SHA224:
		case CKM_ECDSA_SHA256:
		case CKM_ECDSA_SHA384:
		case CKM_ECDSA_SHA512:
			sign_scheme->signSch = HSE_SIGN_ECDSA;
			sign_scheme->sch.ecdsa.hashAlgo = hse_get_hash_alg(sCtx->signCtx.mechanism->mechanism);

			sig_len = sig_len / 2;
			hse_memcpy_to_dev(sig_len_handle, (void *)&sig_len, sizeof(sig_len), 0);
			
			sign_srv->pSignatureLength[0] = hse_virt_to_dma(sig_len_handle, 0);
			sign_srv->pSignatureLength[1] = hse_virt_to_dma(sig_len_handle, 0);
			sign_srv->pSignature[0] = hse_virt_to_dma(sign0_handle, 0);
			sign_srv->pSignature[1] = hse_virt_to_dma(sign0_handle, sig_len);
			break;
		case CKM_AES_CMAC:
			mac_srv = &srv_desc.hseSrv.macReq;
			mac_srv->macScheme.macAlgo = HSE_MAC_ALGO_CMAC;
			mac_srv->macScheme.sch.cmac.cipherAlgo = HSE_CIPHER_ALGO_AES;
			break;
		case CKM_SHA_1_HMAC:
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
			goto out_free_sign0;
	}

	if (!mac_srv) {
		srv_desc.srvId = HSE_SRV_ID_SIGN;
		sign_srv->accessMode = HSE_ACCESS_MODE_FINISH;
		sign_srv->streamId = sCtx->signCtx.streamID;
		sign_srv->authDir = HSE_AUTH_DIR_VERIFY;
		sign_srv->keyHandle = key->key_handle;
		sign_srv->sgtOption = HSE_SGT_OPTION_NONE;
		sign_srv->inputLength = bytes_left;
		sign_srv->pInput = hse_virt_to_dma(input_handle, 0);
	} else {
		srv_desc.srvId = HSE_SRV_ID_MAC;
		mac_srv->accessMode = HSE_ACCESS_MODE_FINISH;
		mac_srv->streamId = sCtx->signCtx.streamID;
		mac_srv->authDir = HSE_AUTH_DIR_VERIFY;
		mac_srv->keyHandle = key->key_handle;
		mac_srv->sgtOption = HSE_SGT_OPTION_NONE;
		mac_srv->inputLength = bytes_left;
		mac_srv->pInput = hse_virt_to_dma(input_handle, 0);
		mac_srv->pTagLength = hse_virt_to_dma(sig_len_handle, 0);
		mac_srv->pTag = hse_virt_to_dma(sign0_handle, 0);
	}

	err = hse_srv_req_sync(sCtx->sID, &srv_desc, sizeof(srv_desc));
	if (err) {
		rc = CKR_FUNCTION_FAILED;

		if (err == EBADMSG)
			rc = CKR_SIGNATURE_INVALID;
	}

out_free_sign0:
	hse_mem_free(sign0_handle);
out_free_input:
	hse_mem_free(input_handle);
out_free_sig_len:
	hse_mem_free(sig_len_handle);
out_uninit:
	if (rc != CKR_BUFFER_TOO_SMALL) {
		hse_stream_free(sCtx->signCtx.streamID);
		sCtx->signCtx.init = CK_FALSE;
		if (sCtx->signCtx.cache != NULL) {
			free(sCtx->signCtx.cache);
			sCtx->signCtx.cache = NULL;
		}
	}

	return rc;
}

CK_DECLARE_FUNCTION(CK_RV, C_VerifyRecoverInit)(
		CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,
		CK_OBJECT_HANDLE hKey
)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_VerifyRecover)(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pSignature,
		CK_ULONG ulSignatureLen,
		CK_BYTE_PTR pData,
		CK_ULONG_PTR pulDataLen
)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}
