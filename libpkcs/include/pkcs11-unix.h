/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2024 NXP
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

#pragma pack(push, cryptoki, 1)

#include "pkcs11.h"

#pragma pack(pop, cryptoki)

#endif /* ___PKCS11_DEFINES_H___ */
