// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2026 NXP
 */

#ifndef ___PKCS11_CONTEXT_H___
#define ___PKCS11_CONTEXT_H___

#include <stdint.h>
#include <libhse.h>

#include "hse_interface.h"
#include "pkcs11-unix.h"

#define PKCS_TOKEN_FILE      PKCS_DIR "/pkcs-token"
#define PKCS_HSE_FILE   PKCS_DIR "/pkcs-hse-objs"

#define LIBRARY_VERSION_MAJOR 0u
#define LIBRARY_VERSION_MINOR 1u

#define NUM_INTERFACES 2
#define DEFAULT_INTERFACE 0

#define LIBRARY_DESC    "NXP-HSE-PKCS11-Module"
#define MANUFACTURER    "NXP-Semiconductors"
#define SLOT_DESC       "NXP-HSE-Slot"
#define TOKEN_DESC      "NXP-HSE-Token"

#define SLOT_ID         0

#define MAX_SESSIONS    (HSE_NUM_CHANNELS - 1)
#define MAX_LABEL_LEN   512

#if (HSE_FW_VERSION_MAJOR == 0)
#error "Invalid firmware version major"
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

#define INVALID_STREAM_ID	0xFFU
#define AAD_MAX_LEN (uint32_t)~0

#define BITS_PER_BYTE 8
#define HSE_MIN_AES_KEY_BITS_LEN 128
#define HSE_MAX_AES_KEY_BITS_LEN 256

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

#define SHA3_224_DIGEST_SIZE   28
#define SHA3_224_BLOCK_SIZE    144

#define SHA3_256_DIGEST_SIZE   32
#define SHA3_256_BLOCK_SIZE    136

#define SHA3_384_DIGEST_SIZE   48
#define SHA3_384_BLOCK_SIZE    104

#define SHA3_512_DIGEST_SIZE   64
#define SHA3_512_BLOCK_SIZE    72

#define TCTX_LOADED 0x544B4E31

enum hse_intl_obj_type {
	HSE_KEY_OBJ = 1,
	HSE_ATTR_HDR_OBJ,
	HSE_ATTR_BUF_OBJ,
};

/*
 * struct hse_cryptCtx - crypto ops context
 *
 * @streamID:  assigned streaming context ID
 * @init:      check if op is running
 * @keyHandle: key to use in op
 * @mechanism: mechanism to use in op
 */
struct hse_cryptCtx {
	CK_BYTE streamID;
	CK_BBOOL init;
	CK_OBJECT_HANDLE keyHandle;
	CK_MECHANISM *mechanism;
	uint8_t *cache;
	CK_BBOOL stream_start;
	uint8_t cache_idx;
	uint32_t blockSize;
};

/*
 * struct hse_digestCtx - digest ops context
 *
 * @streamID:     assigned streaming context ID
 * @init:         check if op is running
 * @stream_start: true if stream should be started, false if it should be updated
 * @mechanism:    mechanism to use in op
 * @cache:        cache data in case insufficient bytes are passed
 * @cache_idx:    cache index
 * @blockSize:    block size for given mechanism
 * @digestSize:   digest size for given mechanism
 */
struct hse_digestCtx {
	CK_BYTE streamID;
	CK_BBOOL init;
	CK_BBOOL stream_start;
	uint8_t mechanism;
	uint8_t *cache;
	uint8_t cache_idx;
	uint32_t blockSize;
	uint32_t digestSize;
};


/*
 * struct hse_signCtx - sign ops context
 *
 * @streamID:  assigned streaming context ID
 * @init:      check if op is running
 * @keyHandle: key to use in op
 * @mechanism: mechanism to use in op
 */
struct hse_signCtx {
	CK_BYTE streamID;
	CK_BBOOL init;
	CK_OBJECT_HANDLE keyHandle;
	CK_MECHANISM *mechanism;
	CK_BBOOL stream_start;
	uint8_t *cache;
	uint8_t cache_idx;
	uint32_t blockSize;
};

/*
 * struct hse_find_ctx - context used for info during object search
 *
 * @init:      check if search is running
 * @obj_class: class of object to search for
 * @obj_uid:       CKA_UNIQUE_ID of object to search for
 */
struct hse_findCtx {
	CK_BBOOL init;
	CK_OBJECT_CLASS *obj_class;
	CK_ULONG *obj_uid;
	CK_UTF8CHAR *label;
	CK_BYTE *key_id;
	CK_ATTRIBUTE_PTR search_template;
	CK_ULONG ulCount;
};

/*
 * struct static_attrs - default key attributes
 *
 * @key_label:  user-provided identifier for the object
 * @key_uid:    read-only unique object ID
 * @key_handle: hse-provided key handle
 * @key_type:   private/pair or public key
 * @key_class:  rsa or ecc
 */
struct static_attrs {
	char key_label[MAX_LABEL_LEN];
	CK_ULONG key_uid;
	CK_OBJECT_HANDLE key_handle;
	CK_KEY_TYPE key_type;
	CK_OBJECT_CLASS key_class;
};

/*
 * struct hse_keyObject - internal key object
 *
 * @attrs: default attributes for key object
 * @dyn_attrs_handle: memory handle to dynamic attrs list
 */
struct hse_keyObject {
	struct static_attrs attrs;
	int dyn_attrs_handle;
};

/*
 * struct dyn_attrHdrObject - internal dynamic attr hdr object
 *
 * @type:  attribute type
 * @ulLen: length of the attribute buffer
 * @attr_handle: memory handle to the attribute buffer
 * @next_attr_hdr_handle: next header of a dynamic attr
 */
struct dyn_attrHdrObject {
	CK_ATTRIBUTE_TYPE type;
	CK_ULONG ulLen;
	int attr_handle;
	int next_attr_hdr_handle;
};

/* struct mutexFns - function pointers to mutex operations
 *
 *
 */
struct mutexFns {
	CK_CREATEMUTEX create;
	CK_DESTROYMUTEX destroy;
	CK_LOCKMUTEX lock;
	CK_UNLOCKMUTEX unlock;
};

enum login_state {
	LOGIN_NONE = 0u,
	LOGIN_USER = 1u,
	LOGIN_SO = 2u,
};

/*
 * struct globalCtx - application context for PKCS11 operations
 *
 * @cryptokiInit:     check if cryptoki has been initialized
 * @mtxFns:           function pointers to mutex operations
 * @login:            current login state (NONE, USER, SO)
 */
struct globalCtx {
	CK_BBOOL cryptokiInit;
	struct mutexFns mtxFns;
	enum login_state login;
};

/*
 * struct sessionCtx - session context; 1 session = 1 HSE channel
 *
 * @sessionInit:      check if session has been initialized
 * @sessionInfo:      session information
 * @sID:              session handle/identifier
 * @findCtx:          context for finding objects
 * @cryptCtx:         encrypt/decrypt operations context
 * @digestCtx:        digest/hash operations context
 * @signCtx:          sign/verify operations context
 */
struct sessionCtx {
	CK_BBOOL sessionInit;
	CK_SESSION_INFO sessionInfo;
	CK_SESSION_HANDLE sID;
	struct hse_findCtx findCtx;
	struct hse_cryptCtx cryptCtx;
	struct hse_digestCtx digestCtx;
	struct hse_signCtx signCtx;
};

/*
 * struct key_ring - manages a single key ring (group of slots)
 *
 * @hse_key_type:    HSE key type this ring handles
 * @catalog:         HSE catalog ID (NVM=1, RAM=2)
 * @group:           HSE group ID within catalog
 * @total_slots:     Total number of slots in this ring
 * @available_mask:  Bitmask where 1 = available, 0 = acquired
 * @mtx:             Mutex for thread-safe access
 */
struct key_ring {
	hseKeyType_t hse_key_type;
	uint8_t catalog;
	uint8_t group;
	uint8_t total_slots;
	uint64_t available_mask;
	pthread_spinlock_t ring_lock;
};

struct rings {
	/* Token (NVM) rings */
	struct key_ring aes_token;
	uint32_t aes_token_handles[AES_TOKEN_GROUP_SIZE];
	struct key_ring hmac_token;
	uint32_t hmac_token_handles[HMAC_TOKEN_GROUP_SIZE];
	struct key_ring ecc_pair_token;
	uint32_t ecc_pair_token_handles[ECC_PAIR_TOKEN_GROUP_SIZE];
	struct key_ring ecc_pub_token;
	uint32_t ecc_pub_token_handles[ECC_PUB_TOKEN_GROUP_SIZE];
	struct key_ring rsa_pair_token;
	uint32_t rsa_pair_token_handles[RSA_PAIR_TOKEN_GROUP_SIZE];
	struct key_ring rsa_pub_token;
	uint32_t rsa_pub_token_handles[RSA_PUB_TOKEN_GROUP_SIZE];

	/* Session (RAM) rings */
	struct key_ring aes_session;
	uint32_t aes_session_handles[AES_SESSION_GROUP_SIZE];
	struct key_ring hmac_session;
	uint32_t hmac_session_handles[HMAC_SESSION_GROUP_SIZE];
	struct key_ring shared_secret_session;
	uint32_t shared_secret_session_handles[SHARED_SECRET_SESSION_GROUP_SIZE];
	struct key_ring ecc_pub_session;
	uint32_t ecc_pub_session_handles[ECC_PUB_SESSION_GROUP_SIZE];
	struct key_ring rsa_pub_session;
	uint32_t rsa_pub_session_handles[RSA_PUB_SESSION_GROUP_SIZE];

	/* Session key pairs stored in NVM */
	struct key_ring ecc_pair_session;
	uint32_t ecc_pair_session_handles[ECC_PAIR_SESSION_GROUP_SIZE];
	struct key_ring rsa_pair_session;
	uint32_t rsa_pair_session_handles[RSA_PAIR_SESSION_GROUP_SIZE];
};

/*
 * struct tokenCtx - token context for PKCS11 operations
 *
 * @loaded:           token initialization status
 * @slot:             slot info
 * @token:            token info
 * @keyMtx:           mutex for key operations
 * @fwTypeId:         firmware type identifier
 * @rings:            key ring management structure
 */
struct tokenCtx {
	uint32_t loaded;
	CK_SLOT_INFO slot;
	CK_TOKEN_INFO token;
	CK_VOID_PTR keyMtx;
	CK_VOID_PTR tctx_file_mtx;
	uint16_t fwTypeId;
	struct rings rings;
};

struct globalCtx *getCtx(void);
struct sessionCtx *getSessionCtx(CK_SESSION_HANDLE sID);
struct tokenCtx *getTokenCtx(void);

#endif /* ___PKCS11_CONTEXT_H___ */
