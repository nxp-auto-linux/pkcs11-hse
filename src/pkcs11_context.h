// SPDX-License-Identifier: BSD-3-Claus
/*
 * Copyright 2021 NXP
 */

#ifndef ___PKCS11_CONTEXT_H___
#define ___PKCS11_CONTEXT_H___

#include "pkcs11.h"
#include "simclist.h"
#include "hse-usr.h"
#include "hse_interface.h"

#define LIBRARY_VERSION_MAJOR 0u
#define LIBRARY_VERSION_MINOR 1u

#define LIBRARY_DESC    "NXP HSE PKCS11 Module"
#define MANUFACTURER    "NXP Semiconductors"
#define SLOT_DESC       "NXP HSE Slot"
#define TOKEN_DESC      "NXP HSE Token"

#define SLOT_ID         0
#define SESSION_ID      0

#define MAX_SESSIONS    1

#define HSE_KEY_HANDLE    0x00010600

#define HSE_SRV_DESC_SRAM 0x2000
#define HSE_KEY_INFO_SRAM 0x2300
#define HSE_MODULUS_SRAM  0x2500
#define HSE_PUB_EXP_SRAM  0x2700
#define HSE_PRIV_EXP_SRAM 0x2900

/*
 * struct hse_find_ctx - context used for info during object search
 *
 * @init:      check if search has been initialized
 * @obj_class: class of object to search for
 */
struct hse_findCtx {
	CK_BBOOL init;
	CK_OBJECT_CLASS *obj_class;
};

/*
 * struct globalCtx - global context for PKCS11 operations
 *
 * @cryptokiInit:     check if cryptoki has been initialized
 * @session:          session info
 * @slot:             slot info
 * @token:            token info
 * @objects:          list of objects/keys
 * @mechanismNum:     number of mechanisms supported
 * @mechanismList:    list of supported mechanisms
 * @find_ctx:         context for finding objects
 */
struct globalCtx {
        CK_BBOOL cryptokiInit;
        CK_SESSION_INFO session;
        CK_SLOT_INFO slot;
        CK_TOKEN_INFO token;
		list_t objects;
        CK_ULONG mechanismNum;
        const CK_MECHANISM_TYPE_PTR mechanismList;
		struct hse_findCtx findCtx;
};

/*
 * struct hse_keyObject - internal key object
 *
 * @key_handle: hse-provided key handle
 * @key_type:   private/pair or public key
 * @key_class:  rsa or ecc
 * @label:      key label
 * @label_len:  size of key label
 * @id:         id corresponding to key in hse
 * @id_len:     size of id
 */
struct hse_keyObject {
	CK_OBJECT_HANDLE key_handle;
	CK_KEY_TYPE key_type;
	CK_OBJECT_CLASS key_class;
	CK_UTF8CHAR *label;
	CK_ULONG label_len;
	CK_BYTE *id;
	CK_ULONG id_len;
};

extern struct globalCtx gCtx;

#endif /* ___PKCS11_CONTEXT_H___ */
