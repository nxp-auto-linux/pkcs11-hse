// SPDX-License-Identifier: BSD-3-Clause
/*
 * HSE alternative key store configuration example
 * Used for secure boot and OP-TEE
 *
 * Copyright 2022-2023, 2026 NXP
 */
#include "hse_interface.h"

 /* ========================= N V M   C A T A L O G =========================
 * Groups (0-based):
 *   G0  RSA_PUB  (boot)    — 1 slot    : used for secure boot public key (RSA)
 *   G1  ECC_PUB  (boot)    — 1 slot    : used for secure boot public key (ECC)
 *   G2  HMAC               — 1 slot    : used by libhse for the RPMB HMAC key
 *   G3  AES-256            — 5 slots   : used by optee_os and optee_test
 *   G4  HMAC               — 5 slots   : used by optee_os and optee_test
 *   G5  ECC_PAIR           — 1 slot    : used by optee_os
 *   G6  ECC_PUB            — 1 slots   : used by optee_os
 *   G7  RSA_PAIR           — 2 slot    : used by optee_os
 *   G8  RSA_PUB            — 2 slots   : used by optee_os
 *   G9  RSA_PAIR           — 1 slot    : used by optee_test
 *   G10 RSA_PUB            — 1 slots   : used by optee_test
 *   G11 ECC_PAIR           — 1 slot    : used by optee_test
 *   G12 ECC_PUB            — 1 slots   : used by optee_test
 * =========================================================================
 */
 #define HSE_NVM_KEY_CATALOG_CFG \
{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_RSA_PUB,  1U, HSE_MAX_RSA_KEY_BITS_LEN   }, \
{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_ECC_PUB,  1U, HSE_MAX_ECC_KEY_BITS_LEN   }, \
{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_HMAC,     1U, HSE_MAX_HMAC_KEY_BITS_LEN  }, \
{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_AES,      5U, HSE_KEY256_BITS            }, \
{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_HMAC,     5U, HSE_MAX_HMAC_KEY_BITS_LEN  }, \
{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_ECC_PAIR, 1U, HSE_MAX_ECC_KEY_BITS_LEN   }, \
{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_ECC_PUB,  1U, HSE_MAX_ECC_KEY_BITS_LEN   }, \
{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_RSA_PAIR, 2U, HSE_MAX_RSA_KEY_BITS_LEN   }, \
{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_RSA_PUB,  2U, HSE_MAX_RSA_KEY_BITS_LEN   }, \
{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_RSA_PAIR, 1U, HSE_MAX_RSA_KEY_BITS_LEN   }, \
{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_RSA_PUB,  1U, HSE_MAX_RSA_KEY_BITS_LEN   }, \
{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_ECC_PAIR, 1U, HSE_MAX_ECC_KEY_BITS_LEN   }, \
{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_ECC_PUB,  1U, HSE_MAX_ECC_KEY_BITS_LEN   }, \
{ 0U, 0U, 0U, 0U, 0U }

/* ========================= R A M   C A T A L O G =========================
 * Groups (0-based):
 *   G0  AES-256            — 4 slots: RESERVED for kernel crypto driver
 *   G1  HMAC               — 4 slots: RESERVED for kernel crypto driver
 *   G2  AES-256            — 6 slots: used by optee_os
 *   G3  SHARED_SECRET      — 1 slot : used by optee_os
 *   G4  HMAC               — 3 slots: used by optee_os
 *   G5  AES-256            — 1 slot : used by optee_test
 *   G6  HMAC               — 1 slot : used by optee_test
 * =========================================================================
 */
#define HSE_RAM_KEY_CATALOG_CFG \
{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY, HSE_KEY_TYPE_AES,           4U, HSE_KEY256_BITS                }, \
{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY, HSE_KEY_TYPE_HMAC,          4U, HSE_MAX_HMAC_KEY_BITS_LEN      }, \
{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY, HSE_KEY_TYPE_AES,           6U, HSE_KEY256_BITS                }, \
{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY, HSE_KEY_TYPE_SHARED_SECRET, 1U, HSE_MAX_SHARED_SECRET_BITS_LEN }, \
{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY, HSE_KEY_TYPE_HMAC,          3U, HSE_MAX_HMAC_KEY_BITS_LEN      }, \
{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY, HSE_KEY_TYPE_AES,           1U, HSE_KEY256_BITS                }, \
{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY, HSE_KEY_TYPE_HMAC,          1U, HSE_MAX_HMAC_KEY_BITS_LEN      }, \
{ 0U, 0U, 0U, 0U, 0U }
