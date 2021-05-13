// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021 NXP
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include "pkcs11_context.h"
#include "simclist.h"

struct globalCtx gCtx = {
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
	.C_CreateObject =						C_CreateObject,
	.C_DestroyObject =						C_DestroyObject,
	.C_FindObjectsInit =                    C_FindObjectsInit,
	.C_FindObjects =                        C_FindObjects,
	.C_FindObjectsFinal =                   C_FindObjectsFinal,
	.C_EncryptInit =                        C_EncryptInit,
	.C_Encrypt =                            C_Encrypt,
	.C_DecryptInit =                        C_DecryptInit,
	.C_Decrypt =                            C_Decrypt,
	.C_SignInit =                           C_SignInit,
	.C_Sign =                               C_Sign,
	.C_VerifyInit =                         C_VerifyInit
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

	if (key_a->label_len != key_b->label_len)
		return 1;
	else {
		if (memcmp(key_a->label, key_b->label, key_a->label_len))
			return 1;
	}

	if (key_a->id_len != key_b->id_len)
		return 1;
	else {
		if (memcmp(key_a->id, key_b->id, key_a->id_len))
			return 1;
	}

	return 0;
}

CK_DEFINE_FUNCTION(CK_RV, C_Initialize) (
	CK_VOID_PTR pInitArgs
)
{
    CK_TOKEN_INFO_PTR pToken = &gCtx.token;
    CK_SLOT_INFO_PTR pSlot = &gCtx.slot;

	if (gCtx.cryptokiInit)
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

	if (list_init(&gCtx.objects) != 0)
		return CKR_HOST_MEMORY;
	list_attributes_seeker(&gCtx.objects, object_list_seeker);
	list_attributes_comparator(&gCtx.objects, object_list_comparator);

	if (hse_usr_initialize())
		return CKR_HOST_MEMORY;

    gCtx.cryptokiInit = CK_TRUE;

    return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_Finalize)(
	CK_VOID_PTR pReserved
)
{
	int i;

    if (!gCtx.cryptokiInit)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	hse_usr_finalize();

	for (i = 0; i < list_size(&gCtx.objects); i++) {
		list_delete_at(&gCtx.objects, i);
	}
	list_destroy(&gCtx.objects);

    gCtx.cryptokiInit = CK_FALSE;

    return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetInfo)(
    CK_INFO_PTR pInfo
)
{
    if (!gCtx.cryptokiInit)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

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
    int ret = CKR_OK;

    if (!gCtx.cryptokiInit)
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
    if (!gCtx.cryptokiInit)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (!pInfo)
		return CKR_ARGUMENTS_BAD;

    if (slotID != SLOT_ID)
		return CKR_SLOT_ID_INVALID;

    memcpy(pInfo, &gCtx.slot, sizeof(CK_SLOT_INFO));

    return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetTokenInfo)(
    CK_SLOT_ID slotID,
    CK_TOKEN_INFO_PTR pInfo
)
{
    if (!gCtx.cryptokiInit)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (!pInfo)
		return CKR_ARGUMENTS_BAD;

    if (slotID != SLOT_ID)
		return CKR_SLOT_ID_INVALID;

    memcpy(pInfo, &gCtx.token, sizeof(CK_TOKEN_INFO));

    return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismList)(
    CK_SLOT_ID slotID,
    CK_MECHANISM_TYPE_PTR pMechanismList,
    CK_ULONG_PTR pulCount
)
{
    CK_RV rv = CKR_OK;

    if (!gCtx.cryptokiInit)
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
    if (!gCtx.cryptokiInit)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (!pInfo)
		return CKR_ARGUMENTS_BAD;

    if (slotID != SLOT_ID)
		return CKR_SLOT_ID_INVALID;

    switch (type) {
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
	struct hse_keyObject *pkey;
	int i;

    if (!gCtx.cryptokiInit)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pTemplate == NULL || ulCount == 0)
		return CKR_ARGUMENTS_BAD;

	if (hSession != SESSION_ID)
		return CKR_SESSION_HANDLE_INVALID;

	pkey = (struct hse_keyObject *)list_seek(&gCtx.objects, &hObject);
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
			case CKA_LABEL:
				if (pTemplate[i].pValue == NULL)
					pTemplate[i].ulValueLen = pkey->label_len;
				else
					memcpy(pTemplate[i].pValue, pkey->label, pkey->label_len);
				break;
			case CKA_ID:
				if (pTemplate[i].pValue == NULL)
					pTemplate[i].ulValueLen = pkey->id_len;
				else
					memcpy(pTemplate[i].pValue, pkey->id, pkey->id_len);
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
    CK_TOKEN_INFO_PTR pToken = &gCtx.token;
    CK_SESSION_INFO_PTR pSession = &gCtx.session;

    if (!gCtx.cryptokiInit)
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

    if (flags & CKF_RW_SESSION) {
		if (pToken->ulRwSessionCount >= pToken->ulMaxRwSessionCount)
			return CKR_SESSION_COUNT;

		if (pToken->flags & CKF_WRITE_PROTECTED)
			return CKR_TOKEN_WRITE_PROTECTED;

		pToken->ulRwSessionCount++;
		pSession->state = CKS_RW_USER_FUNCTIONS;
    } else {
		pSession->state = CKS_RO_USER_FUNCTIONS;
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
    CK_TOKEN_INFO_PTR pToken = &gCtx.token;
    CK_SESSION_INFO_PTR pSession = &gCtx.session;

    if (!gCtx.cryptokiInit)
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
	CK_TOKEN_INFO_PTR pToken = &gCtx.token;

	if (!gCtx.cryptokiInit)
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
    CK_TOKEN_INFO_PTR pToken = &gCtx.token;
    CK_SESSION_INFO_PTR pSession = &gCtx.session;

    if (!gCtx.cryptokiInit)
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
