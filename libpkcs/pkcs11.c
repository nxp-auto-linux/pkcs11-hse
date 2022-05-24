// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2022 NXP
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include "pkcs11_context.h"
#include "hse-internal.h"
#include "simclist.h"

#define PKCS_HSE_FILE "/etc/pkcs-hse-objs"

struct globalCtx context = {
	.cryptokiInit = CK_FALSE,
};

static const CK_MECHANISM_TYPE mechanismList[] = {
	CKM_AES_ECB,
	CKM_AES_GCM,
	CKM_SHA256_RSA_PKCS,
	CKM_ECDSA_SHA1
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
	.C_GenerateRandom =                     C_GenerateRandom
};

/*
 * PKCS11 standard: char buffers MUST be padded with the blank character (‘ ‘).
 * MUST NOT be null-terminated.
 */
static void strcpyPKCS11padding(
	unsigned char *dest,
	const char *source,
	size_t destSize
)
{
	size_t sLen = strlen(source);
	strncpy((char *)dest, source, destSize);

	if (sLen < destSize)
		memset(dest + sLen, ' ', destSize - sLen);
}

/* simclist helper to serialize an element */
static void *object_list_serializer(const void *el, uint32_t *packed_len)
{
	struct hse_keyObject *object = (struct hse_keyObject *)el;
	struct hse_keyObject *serialized;

	serialized = malloc(sizeof(*serialized));

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
	uint8_t *s_key_handle, *s_key_type, *s_key_class;

	s_key_handle = (uint8_t *)data;
	s_key_type = s_key_handle + sizeof(CK_OBJECT_HANDLE);
	s_key_class = s_key_type + sizeof(CK_KEY_TYPE);

	object = (struct hse_keyObject *)hse_intl_mem_alloc(sizeof(struct hse_keyObject));

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
	return &context;
}

CK_DEFINE_FUNCTION(CK_RV, C_Initialize) (
	CK_VOID_PTR pInitArgs
)
{
	struct globalCtx *gCtx = getCtx();
	struct hse_keyObject *mem_key;
	CK_TOKEN_INFO_PTR pToken = &gCtx->token;
	CK_SLOT_INFO_PTR pSlot = &gCtx->slot;

	if (gCtx->cryptokiInit)
		return CKR_CRYPTOKI_ALREADY_INITIALIZED;

	strcpyPKCS11padding(pSlot->slotDescription, SLOT_DESC,
	                    sizeof(pSlot->slotDescription));
	strcpyPKCS11padding(pSlot->manufacturerID, MANUFACTURER,
	                    sizeof(pSlot->manufacturerID));
	pSlot->flags = CKF_TOKEN_PRESENT | CKF_HW_SLOT;

	/* rev2 */
	pSlot->hardwareVersion.major = 2;
	pSlot->hardwareVersion.minor = 0;
	/* hse fw 0.9.0 */
	pSlot->firmwareVersion.major = 0;
	pSlot->firmwareVersion.minor = 9;

	strcpyPKCS11padding(pToken->label, TOKEN_DESC,
	                    sizeof(pToken->label));
	strcpyPKCS11padding(pToken->manufacturerID, MANUFACTURER,
	                    sizeof(pToken->manufacturerID));

	strcpyPKCS11padding(pToken->model, "N/A",
	                    sizeof(pToken->model));
	strcpyPKCS11padding(pToken->serialNumber, "N/A",
	                    sizeof(pToken->serialNumber));

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
	pToken->firmwareVersion.major = 0;
	pToken->firmwareVersion.minor = 9;

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

	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetInfo)(
	CK_INFO_PTR pInfo
)
{
	if (pInfo == NULL)
		return CKR_ARGUMENTS_BAD;

	pInfo->cryptokiVersion.major = CRYPTOKI_VERSION_MAJOR;
	pInfo->cryptokiVersion.minor = CRYPTOKI_VERSION_MINOR;
	strcpyPKCS11padding(pInfo->manufacturerID, MANUFACTURER,
	                    sizeof(pInfo->manufacturerID));
	pInfo->flags = 0;
	strcpyPKCS11padding(pInfo->libraryDescription, LIBRARY_DESC,
	                    sizeof(pInfo->libraryDescription));
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
	struct hse_keyObject *pkey;
	int i;

	if (!gCtx->cryptokiInit)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pTemplate == NULL || ulCount == 0)
		return CKR_ARGUMENTS_BAD;

	if (hSession != SESSION_ID)
		return CKR_SESSION_HANDLE_INVALID;

	pkey = (struct hse_keyObject *)list_seek(&gCtx->object_list, &hObject);
	if (pkey == NULL)
		return CKR_OBJECT_HANDLE_INVALID;

	for (i = 0; i < ulCount; i++) {
		switch (pTemplate[i].type) {
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
	CK_SESSION_INFO_PTR pSession = &gCtx->session;

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

	if (flags & CKF_RW_SESSION) {
		if (pToken->ulRwSessionCount >= pToken->ulMaxRwSessionCount)
			return CKR_SESSION_COUNT;

		if (pToken->flags & CKF_WRITE_PROTECTED)
			return CKR_TOKEN_WRITE_PROTECTED;

		pToken->ulRwSessionCount++;
		pSession->state = CKS_RW_PUBLIC_SESSION;
	} else {
		pSession->state = CKS_RO_PUBLIC_SESSION;
	}

	pToken->ulSessionCount++;
	pSession->flags = flags;
	pSession->slotID = slotID;
	*phSession = SESSION_ID;

	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_CloseSession)(
	CK_SESSION_HANDLE hSession
)
{
	struct globalCtx *gCtx = getCtx();
	CK_TOKEN_INFO_PTR pToken = &gCtx->token;
	CK_SESSION_INFO_PTR pSession = &gCtx->session;

	if (!gCtx->cryptokiInit)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pToken->ulSessionCount == 0 || hSession != SESSION_ID)
		return CKR_SESSION_HANDLE_INVALID;

	pToken->ulSessionCount--;

	if (pSession->flags & CKF_RW_SESSION)
		pToken->ulRwSessionCount--;

	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_CloseAllSessions)(
	CK_SLOT_ID slotID
)
{
	struct globalCtx *gCtx = getCtx();
	CK_TOKEN_INFO_PTR pToken = &gCtx->token;

	if (!gCtx->cryptokiInit)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (slotID != SLOT_ID)
		return CKR_SLOT_ID_INVALID;

	if (pToken->ulSessionCount > 0)
		return C_CloseSession(SESSION_ID);

	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetSessionInfo)(
	CK_SESSION_HANDLE hSession,
	CK_SESSION_INFO_PTR pInfo
)
{
	struct globalCtx *gCtx = getCtx();
	CK_TOKEN_INFO_PTR pToken = &gCtx->token;
	CK_SESSION_INFO_PTR pSession = &gCtx->session;

	if (!gCtx->cryptokiInit)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!pInfo)
		return CKR_ARGUMENTS_BAD;

	if (pToken->ulSessionCount == 0 || hSession != SESSION_ID)
		return CKR_SESSION_HANDLE_INVALID;

	memcpy(pInfo, pSession, sizeof(CK_SESSION_INFO));

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
