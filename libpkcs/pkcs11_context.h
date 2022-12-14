// SPDX-License-Identifier: BSD-3-Claus
/*
 * Copyright 2021-2022 NXP
 */

#ifndef ___PKCS11_CONTEXT_H___
#define ___PKCS11_CONTEXT_H___

#include <stdint.h>
#include <libhse.h>
#include "pkcs11.h"
#include "simclist.h"
#include "hse_interface.h"

#define LIBRARY_VERSION_MAJOR 0u
#define LIBRARY_VERSION_MINOR 1u

#define LIBRARY_DESC    "NXP-HSE-PKCS11-Module"
#define MANUFACTURER    "NXP-Semiconductors"
#define SLOT_DESC       "NXP-HSE-Slot"
#define TOKEN_DESC      "NXP-HSE-Token"

#define SLOT_ID         0
#define SESSION_ID      0

#define MAX_SESSIONS    1

/* missing mechanisms from the PKCS11 interface header */
#define CKM_AES_GCM        0x1087ul

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

/*
 * struct hse_cryptCtx - crypto ops context
 *
 * @init:      check if op is running
 * @keyHandle: key to use in op
 * @mechanism: mechanism to use in op
 */
struct hse_cryptCtx {
	CK_BBOOL init;
	CK_OBJECT_HANDLE keyHandle;
	CK_MECHANISM *mechanism;
};

/*
 * struct hse_signCtx - sign ops context
 *
 * @init:      check if op is running
 * @keyHandle: key to use in op
 * @mechanism: mechanism to use in op
 */
struct hse_signCtx {
	CK_BBOOL init;
	CK_OBJECT_HANDLE keyHandle;
	CK_MECHANISM *mechanism;
};

/*
 * struct hse_find_ctx - context used for info during object search
 *
 * @init:      check if search is running
 * @obj_class: class of object to search for
 */
struct hse_findCtx {
	CK_BBOOL init;
	CK_OBJECT_CLASS *obj_class;
};

/*
 * struct hse_keyObject - internal key object
 *
 * @key_handle: hse-provided key handle
 * @key_type:   private/pair or public key
 * @key_class:  rsa or ecc
 */
struct hse_keyObject {
	CK_OBJECT_HANDLE key_handle;
	CK_KEY_TYPE key_type;
	CK_OBJECT_CLASS key_class;

};

/*
 * struct globalCtx - global context for PKCS11 operations
 *
 * @cryptokiInit:     check if cryptoki has been initialized
 * @session:          session info
 * @slot:             slot info
 * @token:            token info
 * @findCtx:          context for finding objects
 * @cryptCtx:         encrypt/decrypt operations context
 * @signCtx:          sign/verify operations context
 * @object_list:      list of objects/keys
 */
struct globalCtx {
	CK_BBOOL cryptokiInit;
	CK_SESSION_INFO session;
	CK_SLOT_INFO slot;
	CK_TOKEN_INFO token;
	struct hse_findCtx findCtx;
	struct hse_cryptCtx cryptCtx;
	struct hse_signCtx signCtx;
	list_t object_list;
};

struct globalCtx *getCtx(void);

#endif /* ___PKCS11_CONTEXT_H___ */
