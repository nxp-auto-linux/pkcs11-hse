// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024-2026 NXP
 */

#ifndef __PKCS11_UTIL_H__
#define __PKCS11_UTIL_H__

void *getattr_pval(CK_ATTRIBUTE_PTR template, CK_ATTRIBUTE_TYPE attribute, CK_ULONG attrCount);
CK_ULONG getattr_len(CK_ATTRIBUTE_PTR template, CK_ATTRIBUTE_TYPE attribute, CK_ULONG attrCount);

uint16_t hse_get_key_bit_length(uint8_t channel, CK_OBJECT_HANDLE key_handle);

int32_t hse_get_hash_block_size(CK_MECHANISM_TYPE mechanism, uint32_t *block_size);

hseHashAlgo_t hse_pkcs_hash_alg_translate(CK_MECHANISM_TYPE mechanism);
hseCipherBlockMode_t hse_pkcs_cb_alg_translate(CK_MECHANISM_TYPE mechanism);
hseAuthCipherMode_t hse_pkcs_ac_alg_translate(CK_MECHANISM_TYPE mechanism);
hseRsaAlgo_t hse_pkcs_rsa_alg_translate(CK_MECHANISM_TYPE mechanism);
hseHashAlgo_t hse_get_hash_alg(CK_MECHANISM_TYPE mechanism);

uint32_t rsa_ciphering_get_max_input_length(uint16_t rsa_key_length_bit, CK_MECHANISM_PTR mechanism);
uint32_t rsa_ciphering_get_out_length(uint16_t rsa_key_length_bit);

uint32_t sig_get_out_length(uint8_t channel, CK_OBJECT_HANDLE key_handle, CK_MECHANISM_PTR mechanism);
uint16_t hse_get_tag_length(unsigned long tagBits);

int32_t pkey_value_export(uint8_t channel, struct hse_keyObject *key, uint8_t *pkey0, uint8_t *pkey1, CK_ULONG *pkey0_len, CK_ULONG *pkey1_len);

int hse_get_ec_curve_id(uint8_t channel, struct hse_keyObject *key, hseEccCurveId_t *ec_curve_id);
uint16_t hse_get_ec_key_bitlen(hseEccCurveId_t eccCurveId);

uint8_t ecparam2curveid(char *oid, uint8_t len);
const uint8_t* curveid2ecparam(hseEccCurveId_t curve_id, uint8_t *len);

void strcpy_pkcs11_padding(unsigned char *dest, const char *source, size_t dest_len);
CK_RV hse_add_dyn_attr(struct hse_keyObject *key, CK_ATTRIBUTE attr);
CK_RV hse_add_dyn_attr_list(struct hse_keyObject *key, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
void hse_free_dyn_attr(struct hse_keyObject *key, CK_ATTRIBUTE_TYPE type);
void hse_free_dyn_attr_list(int dyn_attr_head_handle);
int32_t hse_key_object_write(struct hse_keyObject *key);
int32_t hse_key_object_remove(struct hse_keyObject *key);
int32_t hse_pkcs_read_objs_dir(void);

int get_key_object_handle(CK_OBJECT_HANDLE handle);
struct dyn_attrHdrObject *get_key_dyn_attr_hdr_handle(int attr_head_handle, CK_ATTRIBUTE_TYPE type);
void *get_attr_handle_from_key(CK_OBJECT_HANDLE key_handle, CK_ATTRIBUTE_TYPE attr_type);
void reverse_bytes(uint8_t *data, size_t len);
int is_valid_key_length(CK_KEY_TYPE type, uint32_t key_bit_len);

#endif
