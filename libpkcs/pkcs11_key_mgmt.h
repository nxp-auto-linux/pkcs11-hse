// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#ifndef __PKCS11_KEY_RINGS_H__
#define __PKCS11_KEY_RINGS_H__

#include "pkcs11_context.h"
#include "pkcs11_util.h"
#include "hse_interface.h"

enum object_domain {
	SESSION_OBJ = 0x00u,
	TOKEN_OBJ   = 0x01u
};

CK_RV key_rings_init(void);
CK_RV key_rings_init_spinlocks(void);
CK_RV key_slot_acquire(hseKeyType_t hse_key_type, enum object_domain is_token,
					   uint32_t *handle);
CK_RV key_slot_release(uint32_t handle);
CK_RV key_rings_lock_all(void);
CK_RV key_rings_unlock_all(void);

#endif /* __PKCS11_KEY_RINGS_H__ */
