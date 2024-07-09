// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2024 NXP
 */

#ifndef ___PKCS11_EXTENSION_H___
#define ___PKCS11_EXTENSION_H___

#include "pkcs11.h"

/* add missing CKA_UNIQUE_ID from pkcs11.h */
#ifndef CKA_UNIQUE_ID
#define CKA_UNIQUE_ID 0x04ul
#endif

/* add missing HMAC key type from pkcs11.h */
#ifndef CKK_SHA256_HMAC
#define CKK_SHA256_HMAC         0x0000002BUL
#endif

#ifndef CKK_SHA384_HMAC
#define CKK_SHA384_HMAC         0x0000002CUL
#endif

#ifndef CKK_SHA512_HMAC
#define CKK_SHA512_HMAC         0x0000002DUL
#endif

#ifndef CKK_SHA224_HMAC
#define CKK_SHA224_HMAC         0x0000002EUL
#endif

/* add missing AES key gen mechanisms for HMAC from pkcs11.h */

#ifndef CKM_SHA_1_KEY_GEN
#define CKM_SHA_1_KEY_GEN              0x00004003UL
#endif

#ifndef CKM_SHA224_KEY_GEN
#define CKM_SHA224_KEY_GEN             0x00004004UL
#endif

#ifndef CKM_SHA256_KEY_GEN
#define CKM_SHA256_KEY_GEN             0x00004005UL
#endif

#ifndef CKM_SHA384_KEY_GEN
#define CKM_SHA384_KEY_GEN             0x00004006UL
#endif

#ifndef CKM_SHA512_KEY_GEN
#define CKM_SHA512_KEY_GEN             0x00004007UL
#endif

#ifndef CKM_SHA512_224_KEY_GEN
#define CKM_SHA512_224_KEY_GEN         0x00004008UL
#endif

#ifndef CKM_SHA512_256_KEY_GEN
#define CKM_SHA512_256_KEY_GEN         0x00004009UL
#endif

#ifndef CKM_SHA512_224
#define CKM_SHA512_224	0x00000048UL
#endif

#ifndef CKM_SHA512_256
#define CKM_SHA512_256	0x0000004CUL
#endif

#endif /* ___PKCS11_EXTENSION_H___ */