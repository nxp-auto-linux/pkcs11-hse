// SPDX-License-Identifier: BSD-3-Clause
/*
 * HSE advanced secure boot key catalog configuration
 *
 * Copyright 2022-2023 NXP
 */

/* hse nvm key catalog configuration */
#define HSE_NVM_KEY_CATALOG_CFG \
{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_AES, 5U, HSE_KEY128_BITS }, \
{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_AES, 10U, HSE_KEY256_BITS }, \
{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_HMAC, 5U, HSE_MAX_HMAC_KEY_BITS_LEN }, \
{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_ECC_PAIR, 1U, HSE_MAX_ECC_KEY_BITS_LEN }, \
{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_ECC_PUB, 1U, HSE_MAX_ECC_KEY_BITS_LEN }, \
{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_RSA_PUB, 1U, HSE_MAX_RSA_KEY_BITS_LEN}, \
{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_RSA_PAIR, 2U, HSE_MAX_RSA_KEY_BITS_LEN}, \
{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_RSA_PUB, 1U, HSE_MAX_RSA_KEY_BITS_LEN}, \
{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_AES, 5U, HSE_KEY256_BITS }, \
{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_HMAC, 5U, HSE_MAX_HMAC_KEY_BITS_LEN }, \
{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_ECC_PAIR, 1U, HSE_MAX_ECC_KEY_BITS_LEN }, \
{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_ECC_PUB, 1U, HSE_MAX_ECC_KEY_BITS_LEN }, \
{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_RSA_PAIR, 2U, HSE_MAX_RSA_KEY_BITS_LEN}, \
{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_RSA_PUB, 2U, HSE_MAX_RSA_KEY_BITS_LEN}, \
{ 0U, 0U, 0U, 0U, 0U }
#define NUM_NVM_GROUPS 15

/* hse ram key catalog configuration */
#define HSE_RAM_KEY_CATALOG_CFG \
{HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY, HSE_KEY_TYPE_AES, 4u, HSE_KEY256_BITS }, \
{HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY, HSE_KEY_TYPE_HMAC, 4u, HSE_MAX_HMAC_KEY_BITS_LEN}, \
{HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY, HSE_KEY_TYPE_AES, 7u, HSE_KEY256_BITS}, \
{HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY, HSE_KEY_TYPE_SHARED_SECRET, 1u, HSE_KEY256_BITS}, \
{HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY, HSE_KEY_TYPE_HMAC, 3u, HSE_MAX_HMAC_KEY_BITS_LEN}, \
{0u, 0u, 0u, 0u, 0u}
#define NUM_RAM_GROUPS 6
