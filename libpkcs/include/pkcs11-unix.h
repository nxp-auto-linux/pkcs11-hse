/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2024-2025 NXP
 */

#ifndef ___PKCS11_DEFINES_H___
#define ___PKCS11_DEFINES_H___

#define CK_PTR *

#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)

#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include "pkcs11.h"

/* Vendor-specific standard extension for NXP token on S32 platforms */
#define CKA_XTS_TWEAK_HANDLE        (CKA_VENDOR_DEFINED | 0x00F5C1A2UL)

#endif /* ___PKCS11_DEFINES_H___ */
