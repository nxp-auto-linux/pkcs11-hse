// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2023 NXP
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
#include "simclist.h"

#define PKCS_HSE_FILE "/etc/pkcs-hse-objs"

static struct globalCtx globalContext = {
	.cryptokiInit = CK_FALSE,
};

static struct sessionCtx globalSessions[HSE_NUM_CHANNELS];

static const CK_MECHANISM_TYPE mechanismList[] = {
	CKM_AES_ECB,
	CKM_AES_GCM,
	CKM_AES_CBC,
	CKM_AES_CTR,
	CKM_RSA_PKCS,
	CKM_RSA_PKCS_OAEP,
	CKM_SHA1_RSA_PKCS,
	CKM_SHA256_RSA_PKCS,
	CKM_SHA384_RSA_PKCS,
	CKM_SHA512_RSA_PKCS,
	CKM_RSA_PKCS_PSS,
	CKM_SHA1_RSA_PKCS_PSS,
	CKM_SHA256_RSA_PKCS_PSS,
	CKM_SHA384_RSA_PKCS_PSS,
	CKM_SHA512_RSA_PKCS_PSS,
	CKM_ECDSA,
	CKM_ECDSA_SHA1,
	CKM_ECDSA_SHA224,
	CKM_ECDSA_SHA256,
	CKM_ECDSA_SHA384,
	CKM_ECDSA_SHA512,
	CKM_SHA_1, CKM_SHA224, CKM_SHA256, CKM_SHA512, CKM_SHA512_224, CKM_SHA512_256,
	CKM_AES_CMAC,
	CKM_SHA224_HMAC, CKM_SHA256_HMAC, CKM_SHA384_HMAC, CKM_SHA512_HMAC,
};

static CK_FUNCTION_LIST gFunctionList = {
	.version =                              {CRYPTOKI_VERSION_MAJOR,
	                                         CRYPTOKI_VERSION_MINOR},
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
	.C_DecryptInit =                        C_DecryptInit,
	.C_Decrypt =                            C_Decrypt,
	.C_SignInit =                           C_SignInit,
	.C_Sign =                               C_Sign,
	.C_VerifyInit =                         C_VerifyInit,
	.C_Verify =                             C_Verify,
	.C_SeedRandom =                         C_SeedRandom,
	.C_GenerateRandom =                     C_GenerateRandom,
	.C_DigestInit =                         C_DigestInit,
	.C_Digest =                             C_Digest,
	.C_DigestUpdate =                       C_DigestUpdate,
	.C_DigestFinal =                        C_DigestFinal,
	.C_DigestKey =                          C_DigestKey
};

/*
 * PKCS11 standard: char buffers MUST be padded with the blank character (' ').
 * MUST NOT be null-terminated.
 */
static void strcpy_pkcs11_padding(unsigned char *dest, const char *source, size_t dest_len)
{
	size_t src_len = strlen(source);
	strncpy((char *)dest, source, dest_len);

	if (src_len < dest_len)
		memset(dest + src_len, ' ', dest_len - src_len);
}

/* simclist helper to serialize an element */
static void *object_list_serializer(const void *el, uint32_t *packed_len)
{
	struct hse_keyObject *object = (struct hse_keyObject *)el;
	struct hse_keyObject *serialized;

	serialized = malloc(sizeof(*serialized));

	strcpy_pkcs11_padding((unsigned char *)serialized->key_label, object->key_label, MAX_LABEL_LEN);
	serialized->key_uid = object->key_uid;
	serialized->key_handle = object->key_handle;
	serialized->key_type = object->key_type;
	serialized->key_class = object->key_class;

	/* serialized struct has fixed size */
	*packed_len = sizeof(struct hse_keyObject);

	return (void *)serialized;
}

/* simclist helper to unserialize an element */
static void *object_list_unserializer(const void *data, uint32_t *data_len)
{
	struct hse_keyObject *object;
	uint8_t *s_key_label, *s_key_uid, *s_key_handle, *s_key_type, *s_key_class;

	s_key_label = (uint8_t *)data;
	s_key_uid = s_key_label + MAX_LABEL_LEN;
	s_key_handle = s_key_uid + sizeof(CK_ULONG);
	s_key_type = s_key_handle + sizeof(CK_OBJECT_HANDLE);
	s_key_class = s_key_type + sizeof(CK_KEY_TYPE);

	object = (struct hse_keyObject *)hse_intl_mem_alloc(sizeof(struct hse_keyObject));

	strcpy_pkcs11_padding((unsigned char *)object->key_label, (char *)s_key_label, MAX_LABEL_LEN);
	object->key_uid = *(CK_ULONG *)s_key_uid;
	object->key_handle = *(CK_OBJECT_HANDLE *)s_key_handle;
	object->key_type = *(CK_KEY_TYPE *)s_key_type;
	object->key_class = *(CK_OBJECT_CLASS *)s_key_class;

	/* unserialized struct has fixed size */
	*data_len = sizeof(struct hse_keyObject);

	return (void *)object;
}

/* simclist helper to locate objects by handle */
static int object_list_seeker(const void *el, const void *key)
{
	const struct hse_keyObject *object = (struct hse_keyObject *)el;

	if ((el == NULL) || (key == NULL))
		return 0;

	if (object->key_handle == *(CK_OBJECT_HANDLE *)key)
		return 1;

	return 0;
}

/* simclist helper to compare objects */
static int object_list_comparator(const void *a, const void *b)
{
	const struct hse_keyObject *key_a = (struct hse_keyObject *)a;
	const struct hse_keyObject *key_b = (struct hse_keyObject *)b;

	if (key_a->key_handle != key_b->key_handle)
		return 1;

	if (key_a->key_type != key_b->key_type)
		return 1;

	if (key_a->key_class != key_b->key_class)
		return 1;

	return 0;
}

struct globalCtx *getCtx(void)
{
	return &globalContext;
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

CK_DEFINE_FUNCTION(CK_RV, C_Initialize) (
	CK_VOID_PTR pInitArgs
)
{
	struct globalCtx *gCtx = getCtx();
	struct hse_keyObject *mem_key;
	CK_TOKEN_INFO_PTR pToken = &gCtx->token;
	CK_SLOT_INFO_PTR pSlot = &gCtx->slot;
	CK_C_INITIALIZE_ARGS_PTR initArgs = pInitArgs;
	CK_RV rv;

	if (gCtx->cryptokiInit)
		return CKR_CRYPTOKI_ALREADY_INITIALIZED;

	if (initArgs) {
		if (initArgs->CreateMutex && initArgs->DestroyMutex &&
		    initArgs->LockMutex && initArgs->UnlockMutex) {
			gCtx->mtxFns.create = initArgs->CreateMutex;
			gCtx->mtxFns.destroy = initArgs->DestroyMutex;
			gCtx->mtxFns.lock = initArgs->LockMutex;
			gCtx->mtxFns.unlock = initArgs->UnlockMutex;

			rv = gCtx->mtxFns.create(gCtx->keyMtx);
			if (rv)
				return rv;
		} else if (!initArgs->CreateMutex && !initArgs->DestroyMutex &&
			   !initArgs->LockMutex && !initArgs->UnlockMutex) {
			if (initArgs->flags & CKF_OS_LOCKING_OK) {
				gCtx->mtxFns.create = createMutex;
				gCtx->mtxFns.destroy = destroyMutex;
				gCtx->mtxFns.lock = lockMutex;
				gCtx->mtxFns.unlock = unlockMutex;

				rv = gCtx->mtxFns.create(&gCtx->keyMtx);
				if (rv)
					return rv;
			} else {
				gCtx->mtxFns.create = NULL;
				gCtx->mtxFns.destroy = NULL;
				gCtx->mtxFns.lock = NULL;
				gCtx->mtxFns.unlock = NULL;
			}
		} else {
			return CKR_ARGUMENTS_BAD;
		}
	} else {
		/* only for testing */
		/* Since our implementation doesn't accept NULL function, so by default
		 *   below function pointers should be set */
		gCtx->mtxFns.create = createMutex;
		gCtx->mtxFns.destroy = destroyMutex;
		gCtx->mtxFns.lock = lockMutex;
		gCtx->mtxFns.unlock = unlockMutex;

		rv = gCtx->mtxFns.create(&gCtx->keyMtx);
		if (rv)
			return rv;
	}

	strcpy_pkcs11_padding(pSlot->slotDescription, SLOT_DESC,
			      sizeof(pSlot->slotDescription));
	strcpy_pkcs11_padding(pSlot->manufacturerID, MANUFACTURER,
			      sizeof(pSlot->manufacturerID));
	pSlot->flags = CKF_TOKEN_PRESENT | CKF_HW_SLOT;

	/* rev2 */
	pSlot->hardwareVersion.major = 2;
	pSlot->hardwareVersion.minor = 0;
	/* libhse version 1.0 */
	pSlot->firmwareVersion.major = 1;
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
	/* we don't use a pin */
	pToken->ulMaxPinLen = 0;
	pToken->ulMinPinLen = 0;
	pToken->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
	pToken->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
	pToken->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
	pToken->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
	/* same as slot */
	pToken->hardwareVersion.major = 2;
	pToken->hardwareVersion.minor = 0;
	pToken->firmwareVersion.major = 1;
	pToken->firmwareVersion.minor = 0;

	if (list_init(&gCtx->object_list) != 0)
		return CKR_HOST_MEMORY;
	list_attributes_seeker(&gCtx->object_list, object_list_seeker);
	list_attributes_comparator(&gCtx->object_list, object_list_comparator);
	list_attributes_serializer(&gCtx->object_list, object_list_serializer);
	list_attributes_unserializer(&gCtx->object_list, object_list_unserializer);

	if (hse_dev_open())
		return CKR_HOST_MEMORY;

	/* start iteration through mem contents */
	hse_intl_iterstart();

	if (hse_intl_hasnext()) {
		while (hse_intl_hasnext()) {
			mem_key = (struct hse_keyObject *)hse_intl_next();
			list_append(&gCtx->object_list, mem_key);
		}
	} else  {
		/* fail silently - we cannot restore list from file */
		list_restore_file(&gCtx->object_list, PKCS_HSE_FILE, NULL);
	}

	hse_intl_iterstop();

	gCtx->cryptokiInit = CK_TRUE;

	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_Finalize)(
	CK_VOID_PTR pReserved
)
{
	struct globalCtx *gCtx = getCtx();
	int i;
	CK_RV rv = CKR_OK;

	if (!gCtx->cryptokiInit)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	/* serialize the object_list and save to file */
	list_dump_file(&gCtx->object_list, PKCS_HSE_FILE, NULL);

	hse_dev_close();

	for (i = 0; i < list_size(&gCtx->object_list); i++) {
		list_delete_at(&gCtx->object_list, i);
	}
	list_destroy(&gCtx->object_list);

	gCtx->cryptokiInit = CK_FALSE;

	if (gCtx->keyMtx != NULL)
		rv = gCtx->mtxFns.destroy(gCtx->keyMtx);

	return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetInfo)(
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

CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionList) (
	CK_FUNCTION_LIST_PTR_PTR ppFunctionList
)
{
	if (ppFunctionList == NULL)
		return CKR_ARGUMENTS_BAD;

	*ppFunctionList = &gFunctionList;

	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetSlotList)(
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

CK_DEFINE_FUNCTION(CK_RV, C_GetSlotInfo)(
	CK_SLOT_ID slotID,
	CK_SLOT_INFO_PTR pInfo
)
{
	struct globalCtx *gCtx = getCtx();

	if (!gCtx->cryptokiInit)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!pInfo)
		return CKR_ARGUMENTS_BAD;

	if (slotID != SLOT_ID)
		return CKR_SLOT_ID_INVALID;

	memcpy(pInfo, &gCtx->slot, sizeof(CK_SLOT_INFO));

	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetTokenInfo)(
	CK_SLOT_ID slotID,
	CK_TOKEN_INFO_PTR pInfo
)
{
	struct globalCtx *gCtx = getCtx();

	if (!gCtx->cryptokiInit)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!pInfo)
		return CKR_ARGUMENTS_BAD;

	if (slotID != SLOT_ID)
		return CKR_SLOT_ID_INVALID;

	memcpy(pInfo, &gCtx->token, sizeof(CK_TOKEN_INFO));

	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismList)(
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

CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismInfo)(
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
		case CKM_AES_ECB:
			pInfo->ulMinKeySize = 0;
			pInfo->ulMaxKeySize = 256;
			pInfo->flags = CKF_HW | CKF_ENCRYPT | CKF_DECRYPT;
			break;
		case CKM_AES_GCM:
			pInfo->ulMinKeySize = 0;
			pInfo->ulMaxKeySize = 256;
			pInfo->flags = CKF_HW | CKF_ENCRYPT | CKF_DECRYPT;
			break;
		case CKM_SHA256_RSA_PKCS:
			pInfo->ulMinKeySize = 0;
			pInfo->ulMaxKeySize = 2048;
			pInfo->flags = CKF_HW | CKF_SIGN | CKF_VERIFY;
			break;
		case CKM_ECDSA_SHA1:
			pInfo->ulMinKeySize = 0;
			pInfo->ulMaxKeySize = 256;
			pInfo->flags = CKF_HW | CKF_SIGN | CKF_VERIFY;
			break;
		default:
			return CKR_MECHANISM_INVALID;
	}

	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetAttributeValue)(
	CK_SESSION_HANDLE hSession,
	CK_OBJECT_HANDLE hObject,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount
)
{
	struct globalCtx *gCtx = getCtx();
	struct sessionCtx *sCtx = getSessionCtx(hSession);
	struct hse_keyObject *pkey;
	int i;

	if (!gCtx->cryptokiInit)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pTemplate == NULL || ulCount == 0)
		return CKR_ARGUMENTS_BAD;

	if (!sCtx || sCtx->sessionInit == CK_FALSE)
		return CKR_SESSION_HANDLE_INVALID;

	gCtx->mtxFns.lock(gCtx->keyMtx);
	pkey = (struct hse_keyObject *)list_seek(&gCtx->object_list, &hObject);
	gCtx->mtxFns.unlock(gCtx->keyMtx);
	if (pkey == NULL)
		return CKR_OBJECT_HANDLE_INVALID;

	for (i = 0; i < ulCount; i++) {
		switch (pTemplate[i].type) {
			case CKA_LABEL:
				if (pTemplate[i].pValue == NULL)
					pTemplate[i].ulValueLen = MAX_LABEL_LEN;
				else
					strcpy_pkcs11_padding(pTemplate[i].pValue, pkey->key_label, MAX_LABEL_LEN);
				break;
			case CKA_UNIQUE_ID:
				if (pTemplate[i].pValue == NULL)
					pTemplate[i].ulValueLen = sizeof(CK_ULONG);
				else
					memcpy(pTemplate[i].pValue, &pkey->key_uid, sizeof(CK_ULONG));
				break;
			case CKA_CLASS:
				if (pTemplate[i].pValue == NULL)
					pTemplate[i].ulValueLen = sizeof(CK_OBJECT_CLASS);
				else
					memcpy(pTemplate[i].pValue, &pkey->key_class, sizeof(CK_OBJECT_CLASS));
				break;
			case CKA_KEY_TYPE:
				if (pTemplate[i].pValue == NULL)
					pTemplate[i].ulValueLen = sizeof(CK_KEY_TYPE);
				else
					memcpy(pTemplate[i].pValue, &pkey->key_type, sizeof(CK_KEY_TYPE));
				break;
			default:
				pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
		}
	}

	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_InitToken)(
	CK_SLOT_ID slotID,
	CK_UTF8CHAR_PTR pPin,
	CK_ULONG ulPinLen,
	CK_UTF8CHAR_PTR pLabel
)
{
	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_InitPIN)(
	CK_SESSION_HANDLE hSession,
	CK_UTF8CHAR_PTR pPin,
	CK_ULONG ulPinLen
)
{
	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_SetPIN)(
	CK_SESSION_HANDLE hSession,
	CK_UTF8CHAR_PTR pOldPin,
	CK_ULONG ulOldLen,
	CK_UTF8CHAR_PTR pNewPin,
	CK_ULONG ulNewLen
)
{
	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_OpenSession)(
	CK_SLOT_ID slotID,
	CK_FLAGS flags,
	CK_VOID_PTR pApplication,
	CK_NOTIFY Notify,
	CK_SESSION_HANDLE_PTR phSession
)
{
	struct globalCtx *gCtx = getCtx();
	CK_TOKEN_INFO_PTR pToken = &gCtx->token;
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

CK_DEFINE_FUNCTION(CK_RV, C_CloseSession)(
	CK_SESSION_HANDLE hSession
)
{
	struct globalCtx *gCtx = getCtx();
	CK_TOKEN_INFO_PTR pToken = &gCtx->token;
	struct sessionCtx *sCtx = getSessionCtx(hSession);

	if (!gCtx->cryptokiInit)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!sCtx || sCtx->sessionInit == CK_FALSE)
		return CKR_SESSION_HANDLE_INVALID;

	sCtx->sessionInit = CK_FALSE;
	pToken->ulSessionCount--;

	hse_channel_free(sCtx->sID);

	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_CloseAllSessions)(
	CK_SLOT_ID slotID
)
{
	struct globalCtx *gCtx = getCtx();
	CK_TOKEN_INFO_PTR pToken = &gCtx->token;
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

CK_DEFINE_FUNCTION(CK_RV, C_GetSessionInfo)(
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

CK_DEFINE_FUNCTION(CK_RV, C_Login)(
	CK_SESSION_HANDLE hSession,
	CK_USER_TYPE userType,
	CK_UTF8CHAR_PTR pPin,
	CK_ULONG ulPinLen
)
{
	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_Logout)(
	CK_SESSION_HANDLE hSession
)
{
	return CKR_OK;
}
