// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef __PKCS11_UTIL_H__
#define __PKCS11_UTIL_H__

uint16_t hse_get_key_bit_length(struct hse_keyObject *key);

hseHashAlgo_t hse_get_hash_alg(CK_MECHANISM_TYPE mechanism);

uint32_t rsa_ciphering_get_max_input_length(uint16_t rsa_key_length_bit, CK_MECHANISM_PTR mechanism);
uint32_t rsa_ciphering_get_out_length(uint16_t rsa_key_length_bit);

#endif
