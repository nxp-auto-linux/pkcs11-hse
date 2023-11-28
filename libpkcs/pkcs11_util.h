// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef __PKCS11_UTIL_H__
#define __PKCS11_UTIL_H__

void *getattr_pval(CK_ATTRIBUTE_PTR template, CK_ATTRIBUTE_TYPE attribute, CK_ULONG attrCount);
CK_ULONG getattr_len(CK_ATTRIBUTE_PTR template, CK_ATTRIBUTE_TYPE attribute, CK_ULONG attrCount);

uint16_t hse_get_key_bit_length(uint8_t channel, struct hse_keyObject *key);

hseHashAlgo_t hse_pkcs_hash_alg_translate(CK_MECHANISM_TYPE mechanism);
hseHashAlgo_t hse_get_hash_alg(CK_MECHANISM_TYPE mechanism);

uint32_t rsa_ciphering_get_max_input_length(uint16_t rsa_key_length_bit, CK_MECHANISM_PTR mechanism);
uint32_t rsa_ciphering_get_out_length(uint16_t rsa_key_length_bit);

uint32_t sig_get_out_length(uint8_t channel, struct hse_keyObject *key, CK_MECHANISM_PTR mechanism);

int32_t pkey_value_export(uint8_t channel, struct hse_keyObject *key, uint8_t *pkey0, uint8_t *pkey1, CK_ULONG *pkey0_len, CK_ULONG *pkey1_len);

int hse_get_ec_curve_id(uint8_t channel, struct hse_keyObject *key, hseEccCurveId_t *ec_curve_id);
uint16_t hse_get_ec_key_bitlen(hseEccCurveId_t eccCurveId);

uint8_t ecparam2curveid(char *oid, uint8_t len);
const uint8_t* curveid2ecparam(hseEccCurveId_t curve_id, uint8_t *len);

#endif
