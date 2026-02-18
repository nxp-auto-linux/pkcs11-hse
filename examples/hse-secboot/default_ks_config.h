// SPDX-License-Identifier: BSD-3-Clause
/*
 * HSE default key store configuration example
 * Used for secure boot, kernel crypto, libhse and libpkcs
 *
 * Copyright 2022-2023, 2026 NXP
 */
#include "hse_interface.h"

/*
 * HSE Key Catalogs — Layout & Intended Use
 *
 * Conventions
 *   - Group IDs: 0-based, in the order of the entries below.
 *   - Slot IDs : 0-based, contiguous inside each group (0..numSlots-1).
 *   - "token"  : persistent key material stored in NVM; survives resets
 *                and power cycles;
 *   - "session": ephemeral keys held in RAM (or in dedicated NVM rings
 *                for transient use); reclaimable across a power cycle.
 */

/* ========================= N V M   C A T A L O G =========================
 * Groups (0-based):
 *   G0  RSA_PUB  (boot)    — 1 slot    : used for secure boot public key (RSA)
 *   G1  ECC_PUB  (boot)    — 1 slot    : used for secure boot public key (ECC)
 *   G2  HMAC               — 2 slots   : used by libhse
 *                            NOTE: Reserve slot 0 for the RPMB HMAC key.
 *                            The exact slot index is assigned at provisioning time.
 *   G3  AES-256            — 2 slots   : used by libhse examples
 *   G4  AES-256            — 18 slots  : libpkcs token objects AES key ring
 *   G5  HMAC               — 18 slots  : libpkcs token objects HMAC key ring
 *   G6  ECC_PAIR           — 1 slot    : libpkcs token objects ECC pair key ring
 *   G7  ECC_PAIR           — 2 slots   : libpkcs session objects ECC pair key ring
 *   G8  ECC_PUB            — 2 slots   : libpkcs token objects ECC public key ring
 *   G9  RSA_PAIR           — 1 slot    : libpkcs token objects RSA pair key ring
 *   G10 RSA_PAIR           — 2 slots   : libpkcs session objects RSA pair key ring
 *   G11 RSA_PUB            — 2 slots   : libpkcs token objects RSA public key ring
 * =========================================================================
 */
#define HSE_NVM_KEY_CATALOG_CFG \
{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_RSA_PUB,  1U,  HSE_MAX_RSA_KEY_BITS_LEN  }, \
{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_ECC_PUB,  1U,  HSE_MAX_ECC_KEY_BITS_LEN  }, \
{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_HMAC,     2U,  HSE_MAX_HMAC_KEY_BITS_LEN }, \
{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_AES,      2U,  HSE_KEY256_BITS           }, \
{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_AES,      18U, HSE_KEY256_BITS           }, \
{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_HMAC,     18U, HSE_MAX_HMAC_KEY_BITS_LEN }, \
{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_ECC_PAIR, 1U,  HSE_MAX_ECC_KEY_BITS_LEN  }, \
{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_ECC_PAIR, 2U,  HSE_MAX_ECC_KEY_BITS_LEN  }, \
{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_ECC_PUB,  2U,  HSE_MAX_ECC_KEY_BITS_LEN  }, \
{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_RSA_PAIR, 1U,  HSE_MAX_RSA_KEY_BITS_LEN  }, \
{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_RSA_PAIR, 2U,  HSE_MAX_RSA_KEY_BITS_LEN  }, \
{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_RSA_PUB,  2U,  HSE_MAX_RSA_KEY_BITS_LEN  }, \
{ 0U, 0U, 0U, 0U, 0U }

/* ========================= R A M   C A T A L O G =========================
 * Groups (0-based):
 *   G0  AES-256            — 4 slots: RESERVED for kernel crypto driver
 *   G1  HMAC               — 4 slots: RESERVED for kernel crypto driver
 *   G2  AES-256            — 3 slots: libpkcs session objects AES key ring
 *   G3  HMAC               — 2 slots: libpkcs session objects HMAC key ring
 *   G4  SHARED_SECRET      — 3 slots: libpkcs session objects shared secret key ring
 *   G5  ECC_PUB            — 2 slots: libpkcs session objects ECC public key ring
 *   G6  RSA_PUB            — 2 slots: libpkcs session objects RSA public key ring
 * =========================================================================
 */
#define HSE_RAM_KEY_CATALOG_CFG \
{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY, HSE_KEY_TYPE_AES,           4U, HSE_KEY256_BITS                }, \
{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY, HSE_KEY_TYPE_HMAC,          4U, HSE_MAX_HMAC_KEY_BITS_LEN      }, \
{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY, HSE_KEY_TYPE_AES,           3U, HSE_KEY256_BITS                }, \
{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY, HSE_KEY_TYPE_HMAC,          2U, HSE_MAX_HMAC_KEY_BITS_LEN      }, \
{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY, HSE_KEY_TYPE_SHARED_SECRET, 3U, HSE_MAX_SHARED_SECRET_BITS_LEN }, \
{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY, HSE_KEY_TYPE_ECC_PUB,       2U, HSE_MAX_ECC_KEY_BITS_LEN       }, \
{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY, HSE_KEY_TYPE_RSA_PUB,       2U, HSE_MAX_RSA_KEY_BITS_LEN       }, \
{ 0U, 0U, 0U, 0U, 0U }
