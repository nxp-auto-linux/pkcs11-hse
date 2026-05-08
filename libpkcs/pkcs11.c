// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2026 NXP
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>

#include "libhse.h"
#include "pkcs11_context.h"
#include "hse-internal.h"
#include "pkcs11_util.h"

#define PKCS_HSE_FILE PKCS_DIR "/pkcs-hse-objs"
#define PKCS_TOKEN PKCS_DIR "/pkcs-token"

#define MIN_PIN_LEN 16
#define MAX_PIN_LEN 512

static struct globalCtx globalContext = {
	.cryptokiInit = CK_FALSE,
};

static struct tokenCtx tokenContext;
static struct sessionCtx globalSessions[HSE_NUM_CHANNELS];

static const CK_MECHANISM_TYPE mechanismList[] = {
	/* AES mechanisms */
	CKM_AES_ECB,
	CKM_AES_CBC,
	CKM_AES_CBC_PAD,
	CKM_AES_CTR,
	CKM_AES_OFB,
	CKM_AES_CFB128,
	CKM_AES_XTS,
	CKM_AES_CCM,
	CKM_AES_GCM,
	CKM_AES_CMAC,
	CKM_AES_KEY_GEN,
	/* RSA mechanisms */
	CKM_RSA_PKCS,
	CKM_RSA_PKCS_OAEP,
	CKM_SHA1_RSA_PKCS,
	CKM_SHA224_RSA_PKCS,
	CKM_SHA256_RSA_PKCS,
	CKM_SHA384_RSA_PKCS,
	CKM_SHA512_RSA_PKCS,
	CKM_RSA_PKCS_KEY_PAIR_GEN,
	/* RSA_PSS mechanisms */
	CKM_RSA_PKCS_PSS,
	CKM_SHA1_RSA_PKCS_PSS,
	CKM_SHA224_RSA_PKCS_PSS,
	CKM_SHA256_RSA_PKCS_PSS,
	CKM_SHA384_RSA_PKCS_PSS,
	CKM_SHA512_RSA_PKCS_PSS,
#if HSE_FWTYPE != 0	/* 0 - STANDARD */
	CKM_SHA3_224_RSA_PKCS_PSS,
	CKM_SHA3_256_RSA_PKCS_PSS,
	CKM_SHA3_384_RSA_PKCS_PSS,
	CKM_SHA3_512_RSA_PKCS_PSS,
#endif	/* HSE_FWTYPE != STANDARD */
	/* ECC mechanisms */
	CKM_ECDSA,
	CKM_ECDSA_SHA1,
	CKM_ECDSA_SHA224,
	CKM_ECDSA_SHA256,
	CKM_ECDSA_SHA384,
	CKM_ECDSA_SHA512,
#if HSE_FWTYPE != 0	/* 0 - STANDARD */
	CKM_ECDSA_SHA3_224,
	CKM_ECDSA_SHA3_256,
	CKM_ECDSA_SHA3_384,
	CKM_ECDSA_SHA3_512,
#endif	/* HSE_FWTYPE != STANDARD */
	CKM_ECDSA_KEY_PAIR_GEN,
	/* SHA digest mechanisms */
	CKM_SHA_1,
	CKM_SHA224,
	CKM_SHA256,
	CKM_SHA384,
	CKM_SHA512,
	CKM_SHA512_224,
	CKM_SHA512_256,
#if HSE_FWTYPE != 0	/* 0 - STANDARD */
	CKM_SHA3_224,
	CKM_SHA3_256,
	CKM_SHA3_384,
	CKM_SHA3_512,
#endif	/* HSE_FWTYPE != STANDARD */
	/* HMAC mechanisms */
	CKM_SHA_1_HMAC,
	CKM_SHA224_HMAC,
	CKM_SHA256_HMAC,
	CKM_SHA384_HMAC,
	CKM_SHA512_HMAC,
	CKM_SHA_1_KEY_GEN,
	CKM_SHA224_KEY_GEN,
	CKM_SHA256_KEY_GEN,
	CKM_SHA384_KEY_GEN,
	CKM_SHA512_KEY_GEN,
	CKM_SHA512_224_KEY_GEN,
	CKM_SHA512_256_KEY_GEN,
};

static CK_FUNCTION_LIST gFunctionList = {
	.version =                              {2, 40},
	.C_Initialize =                         C_Initialize,
	.C_Finalize  =                          C_Finalize,
	.C_GetInfo  =                           C_GetInfo,
	.C_GetFunctionList  =                   C_GetFunctionList,
	.C_GetSlotList  =                       C_GetSlotList,
	.C_GetSlotInfo  =                       C_GetSlotInfo,
	.C_GetTokenInfo  =                      C_GetTokenInfo,
	.C_GetMechanismList  =                  C_GetMechanismList,
	.C_GetMechanismInfo  =                  C_GetMechanismInfo,
	.C_GetAttributeValue  =                 C_GetAttributeValue,
	.C_InitToken  =                         C_InitToken,
	.C_InitPIN  =                           C_InitPIN,
	.C_SetPIN  =                            C_SetPIN,
	.C_OpenSession  =                       C_OpenSession,
	.C_CloseSession  =                      C_CloseSession,
	.C_CloseAllSessions  =                  C_CloseAllSessions,
	.C_GetSessionInfo  =                    C_GetSessionInfo,
	.C_Login  =                             C_Login,
	.C_Logout  =                            C_Logout,
	.C_CreateObject =                       C_CreateObject,
	.C_DestroyObject =                      C_DestroyObject,
	.C_FindObjectsInit =                    C_FindObjectsInit,
	.C_FindObjects =                        C_FindObjects,
	.C_FindObjectsFinal =                   C_FindObjectsFinal,
	.C_EncryptInit =                        C_EncryptInit,
	.C_Encrypt =                            C_Encrypt,
	.C_EncryptUpdate =                      C_EncryptUpdate,
	.C_EncryptFinal =                       C_EncryptFinal,
	.C_DecryptInit =                        C_DecryptInit,
	.C_Decrypt =                            C_Decrypt,
	.C_DecryptUpdate =                      C_DecryptUpdate,
	.C_DecryptFinal =                       C_DecryptFinal,
	.C_SignInit =                           C_SignInit,
	.C_Sign =                               C_Sign,
	.C_SignUpdate =                         C_SignUpdate,
	.C_SignFinal =                          C_SignFinal,
	.C_VerifyInit =                         C_VerifyInit,
	.C_Verify =                             C_Verify,
	.C_VerifyUpdate =                       C_VerifyUpdate,
	.C_VerifyFinal =                        C_VerifyFinal,
	.C_SeedRandom =                         C_SeedRandom,
	.C_GenerateRandom =                     C_GenerateRandom,
	.C_DigestInit =                         C_DigestInit,
	.C_Digest =                             C_Digest,
	.C_DigestUpdate =                       C_DigestUpdate,
	.C_DigestFinal =                        C_DigestFinal,
	.C_DigestKey =                          C_DigestKey,
	.C_GenerateKeyPair =                    C_GenerateKeyPair,
	.C_GenerateKey =                        C_GenerateKey,
	.C_DeriveKey =                          C_DeriveKey,
};

static CK_FUNCTION_LIST_3_0 gFunctionList_3_0 = {
	.version =                              {CRYPTOKI_VERSION_MAJOR,
	                                         CRYPTOKI_VERSION_MINOR},
	.C_Initialize =                         C_Initialize,
	.C_Finalize  =                          C_Finalize,
	.C_GetInfo  =                           C_GetInfo,
	.C_GetInterfaceList =                   C_GetInterfaceList,
	.C_GetInterface =                       C_GetInterface,
	.C_GetFunctionList  =                   C_GetFunctionList,
	.C_GetSlotList  =                       C_GetSlotList,
	.C_GetSlotInfo  =                       C_GetSlotInfo,
	.C_GetTokenInfo  =                      C_GetTokenInfo,
	.C_GetMechanismList  =                  C_GetMechanismList,
	.C_GetMechanismInfo  =                  C_GetMechanismInfo,
	.C_GetAttributeValue  =                 C_GetAttributeValue,
	.C_InitToken  =                         C_InitToken,
	.C_InitPIN  =                           C_InitPIN,
	.C_SetPIN  =                            C_SetPIN,
	.C_OpenSession  =                       C_OpenSession,
	.C_CloseSession  =                      C_CloseSession,
	.C_CloseAllSessions  =                  C_CloseAllSessions,
	.C_GetSessionInfo  =                    C_GetSessionInfo,
	.C_Login  =                             C_Login,
	.C_LoginUser =							C_LoginUser,
	.C_Logout  =                            C_Logout,
	.C_CreateObject =                       C_CreateObject,
	.C_DestroyObject =                      C_DestroyObject,
	.C_FindObjectsInit =                    C_FindObjectsInit,
	.C_FindObjects =                        C_FindObjects,
	.C_FindObjectsFinal =                   C_FindObjectsFinal,
	.C_EncryptInit =                        C_EncryptInit,
	.C_Encrypt =                            C_Encrypt,
	.C_EncryptUpdate =                      C_EncryptUpdate,
	.C_EncryptFinal =                       C_EncryptFinal,
	.C_DecryptInit =                        C_DecryptInit,
	.C_Decrypt =                            C_Decrypt,
	.C_DecryptUpdate =                      C_DecryptUpdate,
	.C_DecryptFinal =                       C_DecryptFinal,
	.C_SignInit =                           C_SignInit,
	.C_Sign =                               C_Sign,
	.C_SignUpdate =                         C_SignUpdate,
	.C_SignFinal =                          C_SignFinal,
	.C_VerifyInit =                         C_VerifyInit,
	.C_Verify =                             C_Verify,
	.C_VerifyUpdate =                       C_VerifyUpdate,
	.C_VerifyFinal =                        C_VerifyFinal,
	.C_SeedRandom =                         C_SeedRandom,
	.C_GenerateRandom =                     C_GenerateRandom,
	.C_DigestInit =                         C_DigestInit,
	.C_Digest =                             C_Digest,
	.C_DigestUpdate =                       C_DigestUpdate,
	.C_DigestFinal =                        C_DigestFinal,
	.C_DigestKey =                          C_DigestKey,
	.C_GenerateKeyPair =                    C_GenerateKeyPair,
	.C_GenerateKey =                        C_GenerateKey,
};

CK_INTERFACE pkcs_interfaces[NUM_INTERFACES] = {
	{(unsigned char *)"PKCS 11", (void *)&gFunctionList_3_0, 0},
	{(unsigned char *)"PKCS 11", (void *)&gFunctionList, 0},
};

struct globalCtx *getCtx(void)
{
	return &globalContext;
}

struct tokenCtx *getTokenCtx(void)
{
	return &tokenContext;
}

struct sessionCtx *getSessionCtx(CK_SESSION_HANDLE sID)
{
	if (sID < 1 || sID >= HSE_NUM_CHANNELS)
		return NULL;
	return &globalSessions[sID];
}

CK_RV createMutex(CK_VOID_PTR_PTR ppMutex)
{
	pthread_mutex_t *mutex;

	mutex = malloc(sizeof(*mutex));
	if (!mutex)
		return CKR_HOST_MEMORY;

	pthread_mutex_init(mutex, NULL);

	*ppMutex = mutex;

	return CKR_OK;
}

CK_RV destroyMutex(CK_VOID_PTR pMutex)
{
	if (pthread_mutex_destroy((pthread_mutex_t *)pMutex))
		return CKR_MUTEX_BAD;

	return CKR_OK;
}

CK_RV lockMutex(CK_VOID_PTR pMutex)
{
	if (pthread_mutex_lock((pthread_mutex_t *)pMutex))
		return CKR_MUTEX_BAD;

	return CKR_OK;
}

CK_RV unlockMutex(CK_VOID_PTR pMutex)
{
	if (pthread_mutex_unlock((pthread_mutex_t *)pMutex))
		return CKR_MUTEX_BAD;

	return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_Initialize) (
	CK_VOID_PTR pInitArgs
)
{
	struct globalCtx *gCtx = getCtx();
	struct tokenCtx *tCtx = getTokenCtx();
	CK_C_INITIALIZE_ARGS_PTR initArgs = pInitArgs;
	CK_BBOOL intl_token = CK_FALSE; // TODO: actually check intl_token later
	FILE *f;
	int rv;

	if (gCtx->cryptokiInit)
		return CKR_CRYPTOKI_ALREADY_INITIALIZED;

	if (initArgs) {
		if (initArgs->CreateMutex && initArgs->DestroyMutex &&
			initArgs->LockMutex && initArgs->UnlockMutex) {
			gCtx->mtxFns.create = initArgs->CreateMutex;
			gCtx->mtxFns.destroy = initArgs->DestroyMutex;
			gCtx->mtxFns.lock = initArgs->LockMutex;
			gCtx->mtxFns.unlock = initArgs->UnlockMutex;
		} else if (!initArgs->CreateMutex && !initArgs->DestroyMutex &&
			   !initArgs->LockMutex && !initArgs->UnlockMutex) {
			if (initArgs->flags & CKF_OS_LOCKING_OK) {
				gCtx->mtxFns.create = createMutex;
				gCtx->mtxFns.destroy = destroyMutex;
				gCtx->mtxFns.lock = lockMutex;
				gCtx->mtxFns.unlock = unlockMutex;
			} else {
				gCtx->mtxFns.create = NULL;
				gCtx->mtxFns.destroy = NULL;
				gCtx->mtxFns.lock = NULL;
				gCtx->mtxFns.unlock = NULL;
				tCtx->keyMtx = NULL;
			}
		} else {
			return CKR_ARGUMENTS_BAD;
		}
	} else {
		gCtx->mtxFns.create = createMutex;
		gCtx->mtxFns.destroy = destroyMutex;
		gCtx->mtxFns.lock = lockMutex;
		gCtx->mtxFns.unlock = unlockMutex;
	}

	rv = hse_dev_open();
	if (rv)
		return CKR_FUNCTION_FAILED;

	f = fopen(PKCS_TOKEN, "rb");
	if (f) {	/* the token was previously initialized */
		if (!intl_token) { /* we dont have intl_tCtx yet */
			/* if we get here it means that token was init, but there was a restart */
			/* TODO: load tCtx from file into intl shm
			(for now, we just load it into the static tCtx) */
			if (fread(tCtx, sizeof(struct tokenCtx), 1, f) != 1) {
				fclose(f);
				return CKR_FUNCTION_FAILED;
			}

			/* after restart, reset session count */
			/* tCtx->token.ulSessionCount = 0;
			 * tCtx->token.ulRwSessionCount = 0; */
		}
		/* token was init, token is (will be) in intl shm */
		printf("HSE FW Version: %d.%d.%d.%d\n",
		       tCtx->token.hardwareVersion.major,
		       tCtx->token.hardwareVersion.minor,
		       tCtx->token.firmwareVersion.major,
		       tCtx->token.firmwareVersion.minor);

		/* recreate the mutex */
		tCtx->keyMtx = NULL;  /* clear the stale pointer */
		if (gCtx->mtxFns.create(&tCtx->keyMtx)) {
			fclose(f);
			return CKR_FUNCTION_FAILED;
		}

		/* start iteration through mem contents */
		hse_intl_iterstart();
		if (!hse_intl_hasnext()) {
			hse_pkcs_read_objs_dir();
		}
		hse_intl_iterstop();

		fclose(f);
	}

	/* token was not previously init */
	gCtx->login = LOGIN_NONE;
	gCtx->cryptokiInit = CK_TRUE;

	return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_Finalize)(
	CK_VOID_PTR pReserved
)
{
	struct globalCtx *gCtx = getCtx();
	struct tokenCtx *tCtx = getTokenCtx();
	CK_RV rv = CKR_OK;

	if (!gCtx->cryptokiInit)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	hse_dev_close();

	gCtx->cryptokiInit = CK_FALSE;

	if (tCtx->keyMtx != NULL)
		rv = gCtx->mtxFns.destroy(tCtx->keyMtx);

	return rv;
}

CK_DECLARE_FUNCTION(CK_RV, C_GetInfo)(
	CK_INFO_PTR pInfo
)
{
	if (pInfo == NULL)
		return CKR_ARGUMENTS_BAD;

	pInfo->cryptokiVersion.major = CRYPTOKI_VERSION_MAJOR;
	pInfo->cryptokiVersion.minor = CRYPTOKI_VERSION_MINOR;
	strcpy_pkcs11_padding(pInfo->manufacturerID, MANUFACTURER, sizeof(pInfo->manufacturerID));
	pInfo->flags = 0;
	strcpy_pkcs11_padding(pInfo->libraryDescription, LIBRARY_DESC, sizeof(pInfo->libraryDescription));
	pInfo->libraryVersion.major = LIBRARY_VERSION_MAJOR;
	pInfo->libraryVersion.minor = LIBRARY_VERSION_MINOR;

	return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_GetInterfaceList) (
	CK_INTERFACE_PTR pInterfacesList,
	CK_ULONG_PTR pulCount
)
{
	if (pulCount == NULL_PTR)
		return CKR_ARGUMENTS_BAD;

	if (pInterfacesList == NULL_PTR) {
		*pulCount = NUM_INTERFACES;
		return CKR_OK;
	}

	if (*pulCount < NUM_INTERFACES) {
		*pulCount = NUM_INTERFACES;
		return CKR_BUFFER_TOO_SMALL;
	}

	memcpy(pInterfacesList, pkcs_interfaces, NUM_INTERFACES * sizeof(CK_INTERFACE));
	*pulCount = NUM_INTERFACES;

	return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_GetInterface) (
	CK_UTF8CHAR_PTR pInterfaceName,
	CK_VERSION_PTR pVersion,
	CK_INTERFACE_PTR_PTR ppInterface,
	CK_FLAGS flags
)
{
	CK_VERSION_PTR interface_version;
	int i;

	if (ppInterface == NULL_PTR)
		return CKR_ARGUMENTS_BAD;

	*ppInterface = NULL_PTR;

	for (i = 0; i < NUM_INTERFACES; i++) {
		interface_version = (CK_VERSION_PTR)pkcs_interfaces[i].pFunctionList;

		if (pInterfaceName != NULL_PTR &&
		    strcmp((char *)pInterfaceName, (char *)pkcs_interfaces[i].pInterfaceName) != 0)
			continue;

		if (pVersion != NULL_PTR &&
		    (pVersion->major != interface_version->major ||
		     pVersion->minor != interface_version->minor))
			continue;

		if (flags != 0 && (pkcs_interfaces[i].flags & flags) != flags)
			continue;

		*ppInterface = &pkcs_interfaces[i];
		return CKR_OK;
	}

	return CKR_ARGUMENTS_BAD;
}

CK_DECLARE_FUNCTION(CK_RV, C_GetFunctionList) (
	CK_FUNCTION_LIST_PTR_PTR ppFunctionList
)
{
	if (ppFunctionList == NULL)
		return CKR_ARGUMENTS_BAD;

	*ppFunctionList = &gFunctionList;

	return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_GetSlotList)(
	CK_BBOOL tokenPresent,
	CK_SLOT_ID_PTR pSlotList,
	CK_ULONG_PTR pulCount
)
{
	struct globalCtx *gCtx = getCtx();
	int ret = CKR_OK;

	if (!gCtx->cryptokiInit)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pulCount == NULL)
		return CKR_ARGUMENTS_BAD;

	if (pSlotList == NULL)
		goto ret_count;

	/* only support 1 slot. */
	if (*pulCount >= 1)
		pSlotList[0] = SLOT_ID;
	else
		ret = CKR_BUFFER_TOO_SMALL;

ret_count:
	*pulCount = 1;

	return ret;
}

CK_DECLARE_FUNCTION(CK_RV, C_GetSlotInfo)(
	CK_SLOT_ID slotID,
	CK_SLOT_INFO_PTR pInfo
)
{
	struct globalCtx *gCtx = getCtx();
	struct tokenCtx *tCtx = getTokenCtx();

	if (!gCtx->cryptokiInit)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!pInfo)
		return CKR_ARGUMENTS_BAD;

	if (slotID != SLOT_ID)
		return CKR_SLOT_ID_INVALID;

	memcpy(pInfo, &tCtx->slot, sizeof(CK_SLOT_INFO));

	return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_GetTokenInfo)(
	CK_SLOT_ID slotID,
	CK_TOKEN_INFO_PTR pInfo
)
{
	struct globalCtx *gCtx = getCtx();
	struct tokenCtx *tCtx = getTokenCtx();

	if (!gCtx->cryptokiInit)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!pInfo)
		return CKR_ARGUMENTS_BAD;

	if (slotID != SLOT_ID)
		return CKR_SLOT_ID_INVALID;

	memcpy(pInfo, &tCtx->token, sizeof(CK_TOKEN_INFO));

	return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_GetMechanismList)(
	CK_SLOT_ID slotID,
	CK_MECHANISM_TYPE_PTR pMechanismList,
	CK_ULONG_PTR pulCount
)
{
	struct globalCtx *gCtx = getCtx();
	CK_RV rv = CKR_OK;

	if (!gCtx->cryptokiInit)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (slotID != SLOT_ID)
		return CKR_SLOT_ID_INVALID;

	if (pulCount == NULL)
		return CKR_ARGUMENTS_BAD;

	if (pMechanismList == NULL)
		goto ret_count;

	if (*pulCount < ARRAY_SIZE(mechanismList)) {
		rv = CKR_BUFFER_TOO_SMALL;
		goto ret_count;
	}

	memcpy(pMechanismList, mechanismList,
	       ARRAY_SIZE(mechanismList) * sizeof(CK_MECHANISM_TYPE));

ret_count:
	*pulCount = ARRAY_SIZE(mechanismList);

	return rv;
}

CK_DECLARE_FUNCTION(CK_RV, C_GetMechanismInfo)(
	CK_SLOT_ID slotID,
	CK_MECHANISM_TYPE type,
	CK_MECHANISM_INFO_PTR pInfo
)
{
	struct globalCtx *gCtx = getCtx();

	if (!gCtx->cryptokiInit)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!pInfo)
		return CKR_ARGUMENTS_BAD;

	if (slotID != SLOT_ID)
		return CKR_SLOT_ID_INVALID;

	switch (type) {
		case CKM_RSA_PKCS:
			pInfo->ulMinKeySize = HSE_MIN_RSA_KEY_BITS_LEN;
			pInfo->ulMaxKeySize = HSE_MAX_RSA_KEY_BITS_LEN;
			pInfo->flags = CKF_HW | CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY;
			break;
		case CKM_RSA_PKCS_OAEP:
			pInfo->ulMinKeySize = HSE_MIN_RSA_KEY_BITS_LEN;
			pInfo->ulMaxKeySize = HSE_MAX_RSA_KEY_BITS_LEN;
			pInfo->flags = CKF_HW | CKF_ENCRYPT | CKF_DECRYPT;
			break;
		case CKM_RSA_PKCS_PSS:
		case CKM_SHA1_RSA_PKCS:
		case CKM_SHA224_RSA_PKCS:
		case CKM_SHA256_RSA_PKCS:
		case CKM_SHA384_RSA_PKCS:
		case CKM_SHA512_RSA_PKCS:
		case CKM_SHA1_RSA_PKCS_PSS:
		case CKM_SHA224_RSA_PKCS_PSS:
		case CKM_SHA256_RSA_PKCS_PSS:
		case CKM_SHA384_RSA_PKCS_PSS:
		case CKM_SHA512_RSA_PKCS_PSS:
		case CKM_SHA3_224_RSA_PKCS_PSS:
		case CKM_SHA3_256_RSA_PKCS_PSS:
		case CKM_SHA3_384_RSA_PKCS_PSS:
		case CKM_SHA3_512_RSA_PKCS_PSS:
			pInfo->ulMinKeySize = HSE_MIN_RSA_KEY_BITS_LEN;
			pInfo->ulMaxKeySize = HSE_MAX_RSA_KEY_BITS_LEN;
			pInfo->flags = CKF_HW | CKF_SIGN | CKF_VERIFY;
			break;
		case CKM_RSA_PKCS_KEY_PAIR_GEN:
			pInfo->ulMinKeySize = HSE_MIN_RSA_KEY_BITS_LEN;
			pInfo->ulMaxKeySize = HSE_MAX_RSA_KEY_BITS_LEN;
			pInfo->flags = CKF_HW | CKF_GENERATE_KEY_PAIR;
			break;
		case CKM_ECDSA:
		case CKM_ECDSA_SHA1:
		case CKM_ECDSA_SHA224: 
		case CKM_ECDSA_SHA256:
		case CKM_ECDSA_SHA384:
		case CKM_ECDSA_SHA512:
		case CKM_ECDSA_SHA3_224:
		case CKM_ECDSA_SHA3_256:
		case CKM_ECDSA_SHA3_384:
		case CKM_ECDSA_SHA3_512:
			pInfo->ulMinKeySize = HSE_MIN_ECC_KEY_BITS_LEN;
			pInfo->ulMaxKeySize = HSE_MAX_ECC_KEY_BITS_LEN;
			pInfo->flags = CKF_HW | CKF_SIGN | CKF_VERIFY;
			break;
		case CKM_ECDSA_KEY_PAIR_GEN:
			pInfo->ulMinKeySize = HSE_MIN_ECC_KEY_BITS_LEN;
			pInfo->ulMaxKeySize = HSE_MAX_ECC_KEY_BITS_LEN;
			pInfo->flags = CKF_HW | CKF_GENERATE_KEY_PAIR;
			break;
		case CKM_AES_ECB:
		case CKM_AES_CBC:
		case CKM_AES_CBC_PAD:
		case CKM_AES_CTR:
		case CKM_AES_OFB:
		case CKM_AES_CFB128:
		case CKM_AES_XTS:
		case CKM_AES_CCM:
		case CKM_AES_GCM:
			pInfo->ulMinKeySize = HSE_MIN_AES_KEY_BITS_LEN / BITS_PER_BYTE;
			pInfo->ulMaxKeySize = HSE_MAX_AES_KEY_BITS_LEN / BITS_PER_BYTE;
			pInfo->flags = CKF_HW | CKF_ENCRYPT | CKF_DECRYPT;
			break;
		case CKM_AES_CMAC:
			pInfo->ulMinKeySize = HSE_MIN_AES_KEY_BITS_LEN / BITS_PER_BYTE;
			pInfo->ulMaxKeySize = HSE_MAX_AES_KEY_BITS_LEN / BITS_PER_BYTE;
			pInfo->flags = CKF_HW | CKF_SIGN | CKF_VERIFY;
			break;
		case CKM_AES_KEY_GEN:
			pInfo->ulMinKeySize = HSE_MIN_AES_KEY_BITS_LEN / BITS_PER_BYTE;
			pInfo->ulMaxKeySize = HSE_MAX_AES_KEY_BITS_LEN / BITS_PER_BYTE;
			pInfo->flags = CKF_HW | CKF_GENERATE;
			break;
		case CKM_SHA_1:
		case CKM_SHA224:
		case CKM_SHA256:
		case CKM_SHA384:
		case CKM_SHA512:
		case CKM_SHA512_224:
		case CKM_SHA512_256:
		case CKM_SHA3_224:
		case CKM_SHA3_256:
		case CKM_SHA3_384:
		case CKM_SHA3_512:
			pInfo->flags = CKF_HW | CKF_DIGEST;
			break;
		case CKM_SHA_1_HMAC:
		case CKM_SHA224_HMAC:
		case CKM_SHA256_HMAC:
		case CKM_SHA384_HMAC:
		case CKM_SHA512_HMAC:
			pInfo->ulMinKeySize = HSE_MIN_HMAC_KEY_BITS_LEN / BITS_PER_BYTE;
			pInfo->ulMaxKeySize = HSE_MAX_HMAC_KEY_BITS_LEN / BITS_PER_BYTE;
			pInfo->flags = CKF_HW | CKF_SIGN | CKF_VERIFY;
			break;
		case CKM_SHA_1_KEY_GEN:
		case CKM_SHA224_KEY_GEN:
		case CKM_SHA256_KEY_GEN:
		case CKM_SHA384_KEY_GEN:
		case CKM_SHA512_KEY_GEN:
		case CKM_SHA512_224_KEY_GEN:
		case CKM_SHA512_256_KEY_GEN:
			pInfo->ulMinKeySize = HSE_MIN_HMAC_KEY_BITS_LEN / BITS_PER_BYTE;
			pInfo->ulMaxKeySize = HSE_MAX_HMAC_KEY_BITS_LEN / BITS_PER_BYTE;
			pInfo->flags = CKF_HW | CKF_GENERATE;
			break;
		default:
			return CKR_MECHANISM_INVALID;
	}

	return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_GetAttributeValue)(
	CK_SESSION_HANDLE hSession,
	CK_OBJECT_HANDLE hObject,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount
)
{
	struct globalCtx *gCtx = getCtx();
	struct tokenCtx *tCtx = getTokenCtx();
	struct sessionCtx *sCtx = getSessionCtx(hSession);
	struct hse_keyObject *pkey;
	struct dyn_attrHdrObject *attr_hdr;
	int i, pkey_handle;
	CK_BBOOL attr_sensitive = CK_FALSE;
	CK_BBOOL attr_type_invalid = CK_FALSE;
	CK_BBOOL buffer_too_small = CK_FALSE;

	if (!gCtx->cryptokiInit)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pTemplate == NULL || ulCount == 0)
		return CKR_ARGUMENTS_BAD;

	if (!sCtx || sCtx->sessionInit == CK_FALSE)
		return CKR_SESSION_HANDLE_INVALID;

	gCtx->mtxFns.lock(tCtx->keyMtx);
	pkey_handle = get_key_object_handle(hObject);
	gCtx->mtxFns.unlock(tCtx->keyMtx);

	if (pkey_handle < 0)
		return CKR_OBJECT_HANDLE_INVALID;
	pkey = (struct hse_keyObject *)hse_get_node_mem_addr(pkey_handle, true);

	for (i = 0; i < ulCount; i++) {
		switch (pTemplate[i].type) {
			case CKA_LABEL:
				if (pTemplate[i].pValue == NULL) {
					pTemplate[i].ulValueLen = MAX_LABEL_LEN;
				} else if (pTemplate[i].ulValueLen >= MAX_LABEL_LEN) {
					strncpy(pTemplate[i].pValue, pkey->attrs.key_label, MAX_LABEL_LEN);
					pTemplate[i].ulValueLen = MAX_LABEL_LEN;
				} else {
					pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
					buffer_too_small = CK_TRUE;
				}
				break;
			case CKA_UNIQUE_ID:
				if (pTemplate[i].pValue == NULL) {
					pTemplate[i].ulValueLen = sizeof(CK_ULONG);
				} else if (pTemplate[i].ulValueLen >= sizeof(CK_ULONG)) {
					memcpy(pTemplate[i].pValue, &pkey->attrs.key_uid, sizeof(CK_ULONG));
					pTemplate[i].ulValueLen = sizeof(CK_ULONG);
				} else {
					pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
					buffer_too_small = CK_TRUE;
				}
				break;
			case CKA_ID:
				{
					CK_ULONG id_len = 0x3u;
					if (pTemplate[i].pValue == NULL) {
						pTemplate[i].ulValueLen = id_len;
					} else if (pTemplate[i].ulValueLen >= id_len) {
						uint8_t *byte_value = (uint8_t *)pTemplate[i].pValue;
						byte_value[0] = (uint8_t)pkey->attrs.key_uid;
						byte_value[1] = (uint8_t)((pkey->attrs.key_uid) >> 8);
						byte_value[2] = (uint8_t)((pkey->attrs.key_uid) >> 16);
						pTemplate[i].ulValueLen = id_len;
					} else {
						pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
						buffer_too_small = CK_TRUE;
					}
				}
				break;
			case CKA_CLASS:
				if (pTemplate[i].pValue == NULL) {
					pTemplate[i].ulValueLen = sizeof(CK_OBJECT_CLASS);
				} else if (pTemplate[i].ulValueLen >= sizeof(CK_OBJECT_CLASS)) {
					memcpy(pTemplate[i].pValue, &pkey->attrs.key_class, sizeof(CK_OBJECT_CLASS));
					pTemplate[i].ulValueLen = sizeof(CK_OBJECT_CLASS);
				} else {
					pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
					buffer_too_small = CK_TRUE;
				}
				break;
			case CKA_KEY_TYPE:
				if (pTemplate[i].pValue == NULL) {
					pTemplate[i].ulValueLen = sizeof(CK_KEY_TYPE);
				} else if (pTemplate[i].ulValueLen >= sizeof(CK_KEY_TYPE)) {
					memcpy(pTemplate[i].pValue, &pkey->attrs.key_type, sizeof(CK_KEY_TYPE));
					pTemplate[i].ulValueLen = sizeof(CK_KEY_TYPE);
				} else {
					pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
					buffer_too_small = CK_TRUE;
				}
				break;
			case CKA_MODULUS:
				{
					CK_ULONG modulus_len = (CK_ULONG)hse_get_key_bit_length(sCtx->sID, pkey->attrs.key_handle) >> 3;
					if (pTemplate[i].pValue == NULL) {
						pTemplate[i].ulValueLen = modulus_len;
					} else if (pTemplate[i].ulValueLen >= modulus_len) {
						CK_RV rv = pkey_value_export(sCtx->sID, pkey, pTemplate[i].pValue, NULL, &pTemplate[i].ulValueLen, NULL);
						if (rv != CKR_OK) {
							pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
							attr_type_invalid = CK_TRUE;
						}
					} else {
						pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
						buffer_too_small = CK_TRUE;
					}
				}
				break;
			case CKA_PUBLIC_EXPONENT:
				{
					CK_ULONG exp_len = 0;
					CK_RV rv = pkey_value_export(sCtx->sID, pkey, NULL, NULL, NULL, &exp_len);
					if (rv != CKR_OK) {
						pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
						attr_type_invalid = CK_TRUE;
					} else if (pTemplate[i].pValue == NULL) {
						pTemplate[i].ulValueLen = exp_len;
					} else if (pTemplate[i].ulValueLen >= exp_len) {
						rv = pkey_value_export(sCtx->sID, pkey, NULL, pTemplate[i].pValue, NULL, &pTemplate[i].ulValueLen);
						if (rv != CKR_OK) {
							pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
							attr_type_invalid = CK_TRUE;
						}
					} else {
						pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
						buffer_too_small = CK_TRUE;
					}
				}
				break;
			case CKA_EC_POINT:
				{
					/* DER-encoding of ANSI X9.62 ECPoint value Q */
					CK_ULONG len = 0;
					CK_RV rv = pkey_value_export(sCtx->sID, pkey, NULL, NULL, &len, NULL);
					if (rv != CKR_OK) {
						pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
						attr_type_invalid = CK_TRUE;
						break;
					}

					CK_ULONG total_len = len + 2; /* plus 2 for TLV header */

					if (pTemplate[i].pValue == NULL) {
						pTemplate[i].ulValueLen = total_len;
					} else if (pTemplate[i].ulValueLen >= total_len) {
						uint8_t *tlv = (uint8_t *)pTemplate[i].pValue;

						/* tlv+2 to leave 2 bytes room for TLV header (DER encoding) */
						rv = pkey_value_export(sCtx->sID, pkey, tlv + 2, NULL, NULL, NULL);
						if (rv != CKR_OK) {
							pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
							attr_type_invalid = CK_TRUE;
							break;
						}

						/*
						 * EdDSA Endianness Conversion (from HSE BE to RFC 8032 LE)
						 * HSE returns public key in big-endian format.
						 * RFC 8032 requires little-endian format.
						 * For Ed25519: Public key width - 32 bytes (reversed as one scalar)
						 */
						if (pkey->attrs.key_type == CKK_EC_EDWARDS)
							reverse_bytes(tlv + 2, len);

						/* Fill the TLV header */
						*tlv++ = 0x04; /* 0x4 = OCTET_STRING */
						*tlv = (uint8_t)len;
						pTemplate[i].ulValueLen = total_len;
					} else {
						pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
						buffer_too_small = CK_TRUE;
					}
				}
				break;
			case CKA_EC_PARAMS:
				{
					const uint8_t *oid;
					uint8_t oid_len;
					hseEccCurveId_t ec_curve_id;

					if (hse_get_ec_curve_id(sCtx->sID, pkey, &ec_curve_id)) {
						pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
						attr_type_invalid = CK_TRUE;
						break;
					}

					oid = curveid2ecparam(ec_curve_id, &oid_len);
					if (oid == NULL) {
						pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
						attr_type_invalid = CK_TRUE;
						break;
					}

					if (pTemplate[i].pValue == NULL) {
						pTemplate[i].ulValueLen = (CK_ULONG)oid_len;
					} else if (pTemplate[i].ulValueLen >= (CK_ULONG)oid_len) {
						memcpy(pTemplate[i].pValue, oid, oid_len);
						pTemplate[i].ulValueLen = (CK_ULONG)oid_len;
					} else {
						pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
						buffer_too_small = CK_TRUE;
					}
				}
				break;
			/* secret and private key material should never be exported */
			case CKA_VALUE:
			case CKA_PRIVATE_EXPONENT:
			case CKA_PRIME_1:
			case CKA_PRIME_2:
			case CKA_EXPONENT_1:
			case CKA_EXPONENT_2:
			case CKA_COEFFICIENT:
			case CKA_PRIME:
			case CKA_SUBPRIME:
			case CKA_BASE:
				pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
				attr_sensitive = CK_TRUE;
				break;
			default:
				{
					attr_hdr = get_key_dyn_attr_hdr_handle(pkey->dyn_attrs_handle,
									pTemplate[i].type);
					if (attr_hdr == NULL) {
						pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
						attr_type_invalid = CK_TRUE;
						break;
					}

					if (pTemplate[i].pValue == NULL) {
						pTemplate[i].ulValueLen = attr_hdr->ulLen;
					} else if (pTemplate[i].ulValueLen >= attr_hdr->ulLen) {
						memcpy(pTemplate[i].pValue,
							   (void *)hse_get_node_mem_addr(attr_hdr->attr_handle, true),
							   attr_hdr->ulLen);
						pTemplate[i].ulValueLen = attr_hdr->ulLen;
					} else {
						pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
						buffer_too_small = CK_TRUE;
					}
				}
				break;
		}
	}

	if (attr_sensitive)
		return CKR_ATTRIBUTE_SENSITIVE;
	if (attr_type_invalid)
		return CKR_ATTRIBUTE_TYPE_INVALID;
	if (buffer_too_small)
		return CKR_BUFFER_TOO_SMALL;

	return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_InitToken)(
	CK_SLOT_ID slotID,
	CK_UTF8CHAR_PTR pPin,
	CK_ULONG ulPinLen,
	CK_UTF8CHAR_PTR pLabel
)
{
	struct globalCtx *gCtx = getCtx();
	struct tokenCtx *tCtx = getTokenCtx();
	CK_TOKEN_INFO_PTR pToken = &tCtx->token;
	CK_SLOT_INFO_PTR pSlot = &tCtx->slot;
	FILE *f;
	CK_RV rv;
	int fw_version_handle, err;
	hseAttrFwVersion_t fw_version;
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	hseKeyGenerateSrv_t *keyGenReq;
	uint32_t baseKey;
	uint8_t sID;

	if (!gCtx->cryptokiInit)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (slotID != SLOT_ID)
		return CKR_SLOT_ID_INVALID;

	if (!pPin)
		return CKR_ARGUMENTS_BAD;

	if (ulPinLen < MIN_PIN_LEN || ulPinLen > MAX_PIN_LEN)
		return CKR_PIN_LEN_RANGE;

	f = fopen(PKCS_TOKEN, "r");
	if (f) {
		fclose(f);
		/* token is already initialized, check SO pin */
		err = hse_channel_acquire(&sID);
		if (err)
			return CKR_SESSION_COUNT;

		rv = hse_process_pin(sID, pPin, ulPinLen, CKU_SO, CK_FALSE);
		hse_channel_free(sID);
		if (rv != CKR_OK)
			return CKR_PIN_INCORRECT;

		return CKR_OK;
	}

	/* token is not initialized, first time init */

	/* TODO: allocate tokenCtx in intl shm */
	/* tokenCtx should be copied into PKCS_TOKEN to be fetched after restarts */

	/* intl_tCtx = pointer to intl shm tokenCtx */
	/* tCtx = intl_tCtx; */


	/* init global flags and mutexes */
	if (!tCtx->keyMtx) {
		rv = gCtx->mtxFns.create(&tCtx->keyMtx);
		if (rv)
			return CKR_FUNCTION_FAILED;
	}

	/* TODO: init key rings */

	/* get firmware version*/
	fw_version_handle = hse_mem_alloc(sizeof(hseAttrFwVersion_t));
	if (fw_version_handle < 0)
		return CKR_HOST_MEMORY;

	srv_desc.srvId = HSE_SRV_ID_GET_ATTR;
	srv_desc.hseSrv.getAttrReq.attrId = HSE_FW_VERSION_ATTR_ID;
	srv_desc.hseSrv.getAttrReq.attrLen = sizeof(hseAttrFwVersion_t);
	srv_desc.hseSrv.getAttrReq.pAttr = hse_virt_to_dma(fw_version_handle, 0);

	err = hse_channel_acquire(&sID);
	if (err) {
		hse_mem_free(fw_version_handle);
		return CKR_SESSION_COUNT;
	}

	err = hse_srv_req_sync(sID, &srv_desc, sizeof(srv_desc), NULL);
	if (err) {
		hse_channel_free(sID);
		hse_mem_free(fw_version_handle);
		return CKR_FUNCTION_FAILED;
	}

	hse_memcpy_from_dev(&fw_version, fw_version_handle, sizeof(hseAttrFwVersion_t), 0);
	hse_mem_free(fw_version_handle);

	tCtx->fwTypeId = fw_version.fwTypeId;

	/* set slot and token info */

	strcpy_pkcs11_padding(pSlot->slotDescription, SLOT_DESC,
			      sizeof(pSlot->slotDescription));
	strcpy_pkcs11_padding(pSlot->manufacturerID, MANUFACTURER,
			      sizeof(pSlot->manufacturerID));
	pSlot->flags = CKF_TOKEN_PRESENT | CKF_HW_SLOT;

	pSlot->hardwareVersion.major = 0;
	pSlot->hardwareVersion.minor = 0;
	pSlot->firmwareVersion.major = 0;
	pSlot->firmwareVersion.minor = 0;

	strcpy_pkcs11_padding(pToken->label, TOKEN_DESC, sizeof(pToken->label));
	strcpy_pkcs11_padding(pToken->manufacturerID, MANUFACTURER, sizeof(pToken->manufacturerID));

	strcpy_pkcs11_padding(pToken->model, "N/A", sizeof(pToken->model));
	strcpy_pkcs11_padding(pToken->serialNumber, "N/A", sizeof(pToken->serialNumber));

	pToken->flags = CKF_TOKEN_INITIALIZED;
	pToken->ulMaxSessionCount = MAX_SESSIONS;
	pToken->ulSessionCount = 0;
	pToken->ulMaxRwSessionCount = MAX_SESSIONS;
	pToken->ulRwSessionCount = 0;
	pToken->ulMaxPinLen = MAX_PIN_LEN;
	pToken->ulMinPinLen = MIN_PIN_LEN;
	pToken->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
	pToken->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
	pToken->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
	pToken->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;

	/* fw version */
	pToken->hardwareVersion.major = fw_version.fwTypeId;
	pToken->hardwareVersion.minor = fw_version.majorVersion;
	pToken->firmwareVersion.major = fw_version.minorVersion;
	pToken->firmwareVersion.minor = fw_version.patchVersion;

	/* init SO pin */

	/* generate base key */
	baseKey = GET_KEY_HANDLE(0x01, 0x02, 0x01);

	memset(&srv_desc, 0, sizeof(srv_desc));
	keyGenReq = &srv_desc.hseSrv.keyGenReq;

	srv_desc.srvId = HSE_SRV_ID_KEY_GENERATE;
	keyGenReq->targetKeyHandle = baseKey;
	keyGenReq->keyGenScheme = HSE_KEY_GEN_SYM_RANDOM_KEY;
	keyGenReq->keyInfo.keyFlags = HSE_KF_USAGE_DERIVE;
	keyGenReq->keyInfo.keyType = HSE_KEY_TYPE_HMAC;
	keyGenReq->keyInfo.keyBitLen = 512;

	err = hse_srv_req_sync(sID, &srv_desc, sizeof(srv_desc), NULL);
	if (err) {
		hse_channel_free(sID);
		return CKR_FUNCTION_FAILED;
	}

	/* process pin to generate SO_verifier */
	rv = hse_process_pin(sID, pPin, ulPinLen, CKU_SO, CK_TRUE);
	hse_channel_free(sID);
	if (rv)
		return rv;

	/* set token as init (save tctx in PKCS_TOKEN) */
	f = fopen(PKCS_TOKEN, "wb");
	if (!f)
		return CKR_FUNCTION_FAILED;

	if (fwrite(tCtx, sizeof(struct tokenCtx), 1, f) != 1) {
		fclose(f);
		return CKR_FUNCTION_FAILED;
	}

	fclose(f);
	return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_InitPIN)(
	CK_SESSION_HANDLE hSession,
	CK_UTF8CHAR_PTR pPin,
	CK_ULONG ulPinLen
)
{
	struct globalCtx *gCtx = getCtx();
	struct sessionCtx *sCtx = getSessionCtx(hSession);
	CK_RV rv;

	if (!gCtx->cryptokiInit)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!pPin)
		return CKR_ARGUMENTS_BAD;

	if (ulPinLen < MIN_PIN_LEN || ulPinLen > MAX_PIN_LEN)
		return CKR_PIN_LEN_RANGE;

	if (!sCtx || sCtx->sessionInit == CK_FALSE)
		return CKR_SESSION_HANDLE_INVALID;

	if (gCtx->login != LOGIN_SO)
		return CKR_USER_NOT_LOGGED_IN;

	/* process pin to generate USER verifier */
	rv = hse_process_pin(sCtx->sID, pPin, ulPinLen, CKU_USER, CK_TRUE);
	if (rv) {
		return rv;
	}

	return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_SetPIN)(
	CK_SESSION_HANDLE hSession,
	CK_UTF8CHAR_PTR pOldPin,
	CK_ULONG ulOldLen,
	CK_UTF8CHAR_PTR pNewPin,
	CK_ULONG ulNewLen
)
{
	struct globalCtx *gCtx = getCtx();
	struct sessionCtx *sCtx = getSessionCtx(hSession);
	CK_RV rv;

	if (!gCtx->cryptokiInit)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!sCtx || sCtx->sessionInit == CK_FALSE)
		return CKR_SESSION_HANDLE_INVALID;

	if (!pOldPin || !pNewPin)
		return CKR_ARGUMENTS_BAD;

	if (ulOldLen < MIN_PIN_LEN || ulOldLen > MAX_PIN_LEN ||
		ulNewLen < MIN_PIN_LEN || ulNewLen > MAX_PIN_LEN)
	return CKR_PIN_LEN_RANGE;

	/* verify user pin */
	rv = hse_process_pin(sCtx->sID, pOldPin, ulOldLen, CKU_USER, CK_FALSE);
	if (rv) {
		return CKR_PIN_INCORRECT;
	}

	/* generate new USER verifier */
	rv = hse_process_pin(sCtx->sID, pNewPin, ulNewLen, CKU_USER, CK_TRUE);
	if (rv != CKR_OK)
		return rv;

	return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_OpenSession)(
	CK_SLOT_ID slotID,
	CK_FLAGS flags,
	CK_VOID_PTR pApplication,
	CK_NOTIFY Notify,
	CK_SESSION_HANDLE_PTR phSession
)
{
	struct globalCtx *gCtx = getCtx();
	struct tokenCtx *tCtx = getTokenCtx();
	CK_TOKEN_INFO_PTR pToken = &tCtx->token;
	unsigned char sID;
	int err;
	struct sessionCtx *sCtx;

	if (!gCtx->cryptokiInit)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (slotID != SLOT_ID)
		return CKR_SLOT_ID_INVALID;

	if (!phSession)
		return CKR_ARGUMENTS_BAD;

	if (pToken->ulSessionCount >= pToken->ulMaxSessionCount)
		return CKR_SESSION_COUNT;

	/* flag MUST be set due to legacy reasons */
	if (!(flags & CKF_SERIAL_SESSION))
		return CKR_SESSION_PARALLEL_NOT_SUPPORTED;

	if ((Notify && !pApplication) || (!Notify && pApplication))
		return CKR_ARGUMENTS_BAD;

	if (pToken->flags & CKF_WRITE_PROTECTED)
		return CKR_TOKEN_WRITE_PROTECTED;

	err = hse_channel_acquire(&sID);
	if (err)
		return CKR_SESSION_COUNT;

	sCtx = getSessionCtx(sID);
	if (!sCtx) {
		hse_channel_free(sID);
		return CKR_SESSION_COUNT;
	}

	sCtx->sessionInfo.state = CKS_RW_PUBLIC_SESSION;
	sCtx->sessionInfo.flags = flags | CKF_RW_SESSION;
	sCtx->sessionInfo.slotID = slotID;
	sCtx->sessionInit = CK_TRUE;
	sCtx->sID = sID;
	pToken->ulSessionCount++;

	*phSession = sID;

	return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_CloseSession)(
	CK_SESSION_HANDLE hSession
)
{
	struct globalCtx *gCtx = getCtx();
	struct tokenCtx *tCtx = getTokenCtx();
	CK_TOKEN_INFO_PTR pToken = &tCtx->token;
	struct sessionCtx *sCtx = getSessionCtx(hSession);

	if (!gCtx->cryptokiInit)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!sCtx || sCtx->sessionInit == CK_FALSE)
		return CKR_SESSION_HANDLE_INVALID;

	if (sCtx->cryptCtx.init) {
		/* clean context */
		sCtx->cryptCtx.init = CK_FALSE;
		if (sCtx->cryptCtx.cache)
			free(sCtx->cryptCtx.cache);
	}

	if (sCtx->digestCtx.init) {
		sCtx->digestCtx.init = CK_FALSE;
		if (sCtx->digestCtx.cache)
			free(sCtx->digestCtx.cache);
	}

	sCtx->sessionInit = CK_FALSE;
	pToken->ulSessionCount--;

	hse_channel_free(sCtx->sID);

	return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_CloseAllSessions)(
	CK_SLOT_ID slotID
)
{
	struct globalCtx *gCtx = getCtx();
	struct tokenCtx *tCtx = getTokenCtx();
	CK_TOKEN_INFO_PTR pToken = &tCtx->token;
	struct sessionCtx *sCtx;
	int sessionIter;

	if (!gCtx->cryptokiInit)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (slotID != SLOT_ID)
		return CKR_SLOT_ID_INVALID;

	if (pToken->ulSessionCount > 0)
		for (sessionIter = 0; sessionIter < pToken->ulMaxSessionCount; sessionIter++) {
			sCtx = getSessionCtx(sessionIter);
			if (!sCtx)
				continue;
			if (sCtx->sessionInit == CK_TRUE)
				C_CloseSession(sCtx->sID);
		}

	return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_GetSessionInfo)(
	CK_SESSION_HANDLE hSession,
	CK_SESSION_INFO_PTR pInfo
)
{
	struct globalCtx *gCtx = getCtx();
	struct sessionCtx *sCtx = getSessionCtx(hSession);

	if (!gCtx->cryptokiInit)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!pInfo)
		return CKR_ARGUMENTS_BAD;

	if (!sCtx || sCtx->sessionInit == CK_FALSE)
		return CKR_SESSION_HANDLE_INVALID;

	memcpy(pInfo, &sCtx->sessionInfo, sizeof(CK_SESSION_INFO));

	return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_Login)(
	CK_SESSION_HANDLE hSession,
	CK_USER_TYPE userType,
	CK_UTF8CHAR_PTR pPin,
	CK_ULONG ulPinLen
)
{
	struct globalCtx *gCtx = getCtx();
	struct sessionCtx *sCtx = getSessionCtx(hSession);
	CK_RV rv;

	if (!gCtx->cryptokiInit)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!sCtx)
		return CKR_SESSION_HANDLE_INVALID;

	if (userType != CKU_SO && userType != CKU_USER)
		return CKR_USER_TYPE_INVALID;

	if (!pPin)
		return CKR_ARGUMENTS_BAD;

	if (ulPinLen < MIN_PIN_LEN || ulPinLen > MAX_PIN_LEN)
		return CKR_PIN_LEN_RANGE;

	if (gCtx->login == LOGIN_SO && userType == CKU_SO)
		return CKR_USER_ALREADY_LOGGED_IN;

	if (gCtx->login == LOGIN_USER && userType == CKU_USER)
		return CKR_USER_ALREADY_LOGGED_IN;

	if (gCtx->login == LOGIN_SO && userType == CKU_USER)
		return CKR_USER_ANOTHER_ALREADY_LOGGED_IN;

	if (gCtx->login == LOGIN_USER && userType == CKU_SO)
		return CKR_USER_ANOTHER_ALREADY_LOGGED_IN;

	/* verify pin */
	rv = hse_process_pin(sCtx->sID, pPin, ulPinLen, userType, CK_FALSE);
	if (rv != CKR_OK)
		return rv;

	switch (userType) {
		case CKU_SO:
			gCtx->login = LOGIN_SO;
			break;
		case CKU_USER:
			gCtx->login = LOGIN_USER;
			break;
		default:
			return CKR_USER_TYPE_INVALID;
	}

	return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, C_LoginUser)(
	CK_SESSION_HANDLE hSession,
	CK_USER_TYPE userType,
	CK_UTF8CHAR_PTR pPin,
	CK_ULONG ulPinLen,
	CK_UTF8CHAR_PTR pUsername,
	CK_ULONG ulUsernameLen
)
{
	(void)pUsername;
	(void)ulUsernameLen;

	return C_Login(hSession, userType, pPin, ulPinLen);
}

CK_DECLARE_FUNCTION(CK_RV, C_Logout)(
	CK_SESSION_HANDLE hSession
)
{
	struct globalCtx *gCtx = getCtx();
	struct sessionCtx *sCtx = getSessionCtx(hSession);

	if (!gCtx->cryptokiInit)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!sCtx)
		return CKR_SESSION_HANDLE_INVALID;

	if (gCtx->login == LOGIN_NONE)
		return CKR_USER_NOT_LOGGED_IN;

	gCtx->login = LOGIN_NONE;

	return CKR_OK;
}
