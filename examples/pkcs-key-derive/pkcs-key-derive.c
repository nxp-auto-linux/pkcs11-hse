// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <dlfcn.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

#include "libhse.h"
#include "hse_interface.h"
#include "pkcs11-unix.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
#endif /* ARRAY_SIZE */

#ifndef ERROR
#define ERROR(fmt, ...) printf("[ERROR] " fmt, ##__VA_ARGS__)
#endif

#ifndef INFO
#define INFO(fmt, ...) printf("[INFO] " fmt, ##__VA_ARGS__)
#endif

static unsigned char key_value_AES_256[] = {
	0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF,
	0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF
};

/* NIST P-256 curve OID */
static CK_BYTE ec_params_p256[] = {
	0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07
};

typedef struct {
	CK_EC_KDF_TYPE kdf;
	const char *name;
} kdf_info_t;

static const kdf_info_t supported_kdfs[] = {
	{ CKD_NULL,        "CKD_NULL" },
	{ CKD_SHA1_KDF,    "CKD_SHA1_KDF" },
	{ CKD_SHA224_KDF,  "CKD_SHA224_KDF" },
	{ CKD_SHA256_KDF,  "CKD_SHA256_KDF" },
	{ CKD_SHA384_KDF,  "CKD_SHA384_KDF" },
	{ CKD_SHA512_KDF,  "CKD_SHA512_KDF" },
};

static const char *get_kdf_name(CK_EC_KDF_TYPE kdf)
{
	for (size_t i = 0; i < ARRAY_SIZE(supported_kdfs); i++) {
		if (supported_kdfs[i].kdf == kdf)
			return supported_kdfs[i].name;
	}
	return "UNKNOWN_KDF";
}

void usage(const char* progname)
{
	printf("\n%s - Key derivation example\n", progname);
	printf("\n");
	printf("\t%s /home/<user>/pkcs/libpkcs-hse.so\n", progname);
	printf("\n");
	printf("Usage:\n");
	printf("%s help\n", progname);
	printf("%s <lib>\n", progname);
	printf("\n");
	printf("\t<lib>          - full path to PKCS#11 shared library\n");
	printf("\n");
}

static CK_FUNCTION_LIST_PTR util_lib_get_function_list(void *handle)
{
	CK_RV(*C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR);
	CK_FUNCTION_LIST_PTR function_list;
	CK_RV rv;

	C_GetFunctionList = dlsym(handle, "C_GetFunctionList");
	if (C_GetFunctionList) {
		rv = C_GetFunctionList(&function_list);
		if (rv == CKR_OK)
			return function_list;
	}

	return NULL;
}

static int util_lib_init(CK_FUNCTION_LIST_PTR flist)
{
	CK_RV rv;

	rv = flist->C_Initialize(NULL);
	if (rv != CKR_OK)
		return -1;

	return 0;
}

static CK_SLOT_ID util_lib_get_slot_list(CK_FUNCTION_LIST_PTR flist)
{
	CK_SLOT_ID_PTR slot_list;
	CK_SLOT_ID slot_ret = -1;
	CK_ULONG num_slots;
	CK_RV rv;

	rv = flist->C_GetSlotList(CK_TRUE, NULL, &num_slots);
	if (rv != CKR_OK)
		return -1;

	slot_list = malloc(num_slots * sizeof(CK_SLOT_ID));
	if (!slot_list)
		return -1;

	rv = flist->C_GetSlotList(CK_TRUE, slot_list, &num_slots);
	if (rv != CKR_OK)
		goto err_free_slot_list;

	slot_ret = slot_list[0];

err_free_slot_list:
	free(slot_list);
	return slot_ret;
}

static CK_SESSION_HANDLE util_lib_open_session(CK_FUNCTION_LIST_PTR flist, CK_SLOT_ID slot)
{
	CK_SESSION_HANDLE session;
	CK_RV rv;

	rv = flist->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session);
	if (rv != CKR_OK)
		return -1;

	return session;
}

static CK_RV util_lib_close_sessions(CK_FUNCTION_LIST_PTR flist, CK_SLOT_ID slot)
{
	CK_RV rv;

	rv = flist->C_CloseAllSessions(slot);

	return rv;
}

static int util_lib_finalize(CK_FUNCTION_LIST_PTR flist)
{
	CK_RV rv;

	rv = flist->C_Finalize(NULL);
	if (rv != CKR_OK)
		return -1;

	return 0;
}

static CK_OBJECT_HANDLE install_base_key(CK_FUNCTION_LIST_PTR flist, CK_SESSION_HANDLE session,
							CK_KEY_TYPE key_type, uint8_t *key_id, int key_len, uint8_t *key_value)
{
	CK_OBJECT_HANDLE key;
	CK_RV rv;
	CK_BBOOL boolean = CK_TRUE;

	CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
	CK_KEY_TYPE type = key_type;
	CK_UTF8CHAR label[] = {"HSE-BASE-KEY"};
	CK_ATTRIBUTE keyTemplate[] = {
		{ CKA_LABEL, label, sizeof(label)-1 },
		{ CKA_CLASS, &key_class, sizeof(key_class) },
		{ CKA_KEY_TYPE, &type, sizeof(type) },
		{ CKA_DERIVE, &boolean, sizeof(boolean) },
		{ CKA_ID, key_id, 3 },
		{ CKA_VALUE, (CK_BYTE_PTR)key_value, key_len }
	};

	rv = flist->C_CreateObject(session, keyTemplate, ARRAY_SIZE(keyTemplate), &key);
	if (rv != CKR_OK)
		return CK_INVALID_HANDLE;

	return key;
}

static CK_OBJECT_HANDLE util_lib_derive_key_aes(CK_FUNCTION_LIST_PTR flist, CK_SESSION_HANDLE session, CK_MECHANISM mechanism, CK_OBJECT_HANDLE baseKey)
{
	CK_OBJECT_HANDLE derived_key;
	CK_RV rv;

	/* 
	 * key_id represent the HSE key slot in the key catalog
	 *     - key_id[0] - slot ID
	 *     - key_id[1] - group ID
	 *     - key_id[2] - catalog ID
	 */
	CK_BYTE key_id[] = { 0x01, 0x02, 0x02 };
	CK_UTF8CHAR label[] = {"HSE-DERIVED-KEY-AES"};
	CK_KEY_TYPE ktype = CKK_AES;
	CK_ULONG key_len_bytes = 32;
	CK_BBOOL boolean = CK_TRUE;

	CK_ATTRIBUTE keyTemplate[] = {
		{ CKA_KEY_TYPE, &ktype, sizeof(ktype) },
		{ CKA_LABEL, label, sizeof(label) - 1 },
		{ CKA_ID, &key_id, sizeof(key_id) },
		{ CKA_ENCRYPT, &boolean, sizeof(boolean) },
		{ CKA_DECRYPT, &boolean, sizeof(boolean) },
		{ CKA_VALUE_LEN, &key_len_bytes, sizeof(key_len_bytes) },
	};
	
	rv = flist->C_DeriveKey(session, &mechanism, baseKey, keyTemplate, ARRAY_SIZE(keyTemplate), &derived_key);
	if (rv != CKR_OK) {
		ERROR("Key derivation failed: %lu\n", (unsigned long)rv);
		return CK_INVALID_HANDLE;
	}

	return derived_key;
}

static int verify_hkdf_with_ecb(CK_FUNCTION_LIST_PTR flist, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE derived_key, const unsigned char *base_key_32)
{
	int ret = -1;
	unsigned char okm[32] = { 0 };
	size_t okm_len = sizeof(okm);
	uint8_t pt[16] = {
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
	};
	uint8_t ct_hse[16]  = { 0 };
	uint8_t pt_ossl[16] = { 0 };
	CK_ULONG ct_len = sizeof(ct_hse);
	CK_MECHANISM ecb = { CKM_AES_ECB, NULL, 0 };
	CK_RV rv;
	EVP_PKEY_CTX *pctx = NULL;
	EVP_CIPHER_CTX *ctx = NULL;
	int outl1 = 0;
	int outl2 = 0;

	/* OpenSSL HKDF */
	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
	if (!pctx) {
		ERROR("OpenSSL HKDF context allocation failed\n");
		goto out;
	}

	if (EVP_PKEY_derive_init(pctx) <= 0 ||
		EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0 ||
		EVP_PKEY_CTX_set1_hkdf_salt(pctx, NULL, 0) <= 0 ||
		EVP_PKEY_CTX_set1_hkdf_key(pctx, base_key_32, 32) <= 0 ||
		EVP_PKEY_derive(pctx, okm, &okm_len) <= 0) {

		ERROR("OpenSSL HKDF derive failed\n");
		goto out;
	}

	/* Encrypt with HSE derived key */
	rv = flist->C_EncryptInit(session, &ecb, derived_key);
	if (rv != CKR_OK) {
		ERROR("C_EncryptInit failed (rv=0x%lX)\n",
			(unsigned long)rv);
		goto out;
	}

	rv = flist->C_Encrypt(session, pt, sizeof(pt), ct_hse, &ct_len);
	if (rv != CKR_OK || ct_len != sizeof(ct_hse)) {
		ERROR("C_Encrypt failed (rv=0x%lX, len=%lu)\n",
			(unsigned long)rv,
			(unsigned long)ct_len);
		goto out;
	}

	/* Decrypt with OpenSSL */
	ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		ERROR("OpenSSL cipher context allocation failed\n");
		goto out;
	}

	if (EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, okm, NULL) != 1) {
		ERROR("OpenSSL EVP_DecryptInit_ex failed\n");
		goto out;
	}

	EVP_CIPHER_CTX_set_padding(ctx, 0);

	if (EVP_DecryptUpdate(ctx, pt_ossl, &outl1, ct_hse, sizeof(ct_hse)) != 1 ||
		EVP_DecryptFinal_ex(ctx, pt_ossl + outl1, &outl2) != 1) {

		ERROR("OpenSSL AES-ECB decrypt failed\n");
		goto out;
	}

	/* Compare decrypted result */
	if (memcmp(pt, pt_ossl, sizeof(pt)) != 0) {
		ERROR("HKDF verification FAILED: plaintext mismatch\n");
		goto out;
	}

	ret = 0;

out:
	EVP_CIPHER_CTX_free(ctx);
	EVP_PKEY_CTX_free(pctx);

	return ret;
}

static int generate_ec_keypair(CK_FUNCTION_LIST_PTR flist, CK_SESSION_HANDLE session,
                               CK_BYTE *key_id,
                               CK_OBJECT_HANDLE *phPubKey, CK_OBJECT_HANDLE *phPrivKey)
{
	CK_RV rv;
	CK_MECHANISM mech = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };
	CK_BBOOL boolean = CK_TRUE;
	CK_UTF8CHAR label[] = {"ECDH-EC-KEYPAIR"};
	CK_KEY_TYPE key_type = CKK_EC;

	CK_ATTRIBUTE pubKeyTemplate[] = {
		{ CKA_EC_PARAMS, ec_params_p256, sizeof(ec_params_p256) },
		{ CKA_VERIFY, &boolean, sizeof(boolean) },
	};

	CK_ATTRIBUTE privKeyTemplate[] = {
		{ CKA_KEY_TYPE, &key_type, sizeof(key_type) },
		{ CKA_LABEL, label, sizeof(label) - 1 },
		{ CKA_ID, key_id, 3 },
		{ CKA_SIGN, &boolean, sizeof(boolean) },
		{ CKA_DERIVE, &boolean, sizeof(boolean) },
		{ CKA_EXTRACTABLE, &boolean, sizeof(boolean) }
	};

	rv = flist->C_GenerateKeyPair(session, &mech,
								  pubKeyTemplate, ARRAY_SIZE(pubKeyTemplate),
								  privKeyTemplate, ARRAY_SIZE(privKeyTemplate),
								  phPubKey, phPrivKey);
	if (rv != CKR_OK) {
		ERROR("C_GenerateKeyPair failed: 0x%lX\n", (unsigned long)rv);
		return -1;
	}

	return 0;
}

static int get_ec_point(CK_FUNCTION_LIST_PTR flist, CK_SESSION_HANDLE session,
						CK_OBJECT_HANDLE hPubKey, CK_BYTE *ec_point, CK_ULONG *ec_point_len)
{
	CK_RV rv;
	CK_ATTRIBUTE attr = { CKA_EC_POINT, ec_point, *ec_point_len };

	rv = flist->C_GetAttributeValue(session, hPubKey, &attr, 1);
	if (rv != CKR_OK) {
		ERROR("C_GetAttributeValue (CKA_EC_POINT) failed: 0x%lX\n", (unsigned long)rv);
		return -1;
	}

	*ec_point_len = attr.ulValueLen;
	return 0;
}

static CK_OBJECT_HANDLE derive_ecdh_key(CK_FUNCTION_LIST_PTR flist, CK_SESSION_HANDLE session,
										CK_OBJECT_HANDLE hPrivKey, CK_BYTE *peer_ec_point,
										CK_ULONG peer_ec_point_len, CK_BYTE *derived_key_id,
										CK_EC_KDF_TYPE kdf)
{
	CK_RV rv;
	CK_OBJECT_HANDLE hDerivedKey;
	CK_ECDH1_DERIVE_PARAMS ecdh_params;
	CK_MECHANISM mech;
	CK_KEY_TYPE ktype = CKK_AES;
	CK_ULONG key_len = 32;
	CK_BBOOL boolean = CK_TRUE;
	CK_UTF8CHAR label[] = {"ECDH-DERIVED-KEY"};

	CK_BYTE *pub_data = peer_ec_point;
	CK_ULONG pub_data_len = peer_ec_point_len;

	/*
	 * CKA_EC_POINT returns DER-encoded OCTET STRING: Tag (04) | Length | Data
	 * The Data itself is the uncompressed point: 04 || X || Y
	 *
	 * Strip the DER OCTET STRING wrapper to get the raw point.
	 */
	if (peer_ec_point_len >= 3 && peer_ec_point[0] == 0x04) {
		if (peer_ec_point[1] < 0x80) {
			/* Short-form length: P-256 (65 bytes) and P-384 (97 bytes) */
			if (peer_ec_point[1] == peer_ec_point_len - 2) {
				pub_data = peer_ec_point + 2;
				pub_data_len = peer_ec_point[1];
			}
		} else if (peer_ec_point[1] == 0x81 && peer_ec_point_len >= 4) {
			/* Long-form length: P-521 (133 bytes) */
			if (peer_ec_point[2] == peer_ec_point_len - 3) {
				pub_data = peer_ec_point + 3;
				pub_data_len = peer_ec_point[2];
			}
		}
	}

	memset(&ecdh_params, 0, sizeof(ecdh_params));
	ecdh_params.kdf = kdf;
	ecdh_params.ulSharedDataLen = 0;
	ecdh_params.pSharedData = NULL;
	ecdh_params.ulPublicDataLen = pub_data_len;
	ecdh_params.pPublicData = pub_data;

	mech.mechanism = CKM_ECDH1_DERIVE;
	mech.pParameter = &ecdh_params;
	mech.ulParameterLen = sizeof(ecdh_params);

	CK_ATTRIBUTE keyTemplate[] = {
		{ CKA_KEY_TYPE, &ktype, sizeof(ktype) },
		{ CKA_LABEL, label, sizeof(label) - 1 },
		{ CKA_ID, derived_key_id, 3 },
		{ CKA_ENCRYPT, &boolean, sizeof(boolean) },
		{ CKA_DECRYPT, &boolean, sizeof(boolean) },
		{ CKA_VALUE_LEN, &key_len, sizeof(key_len) },
	};

	rv = flist->C_DeriveKey(session, &mech, hPrivKey,
							keyTemplate, ARRAY_SIZE(keyTemplate), &hDerivedKey);
	if (rv != CKR_OK) {
		ERROR("ECDH C_DeriveKey failed: 0x%lX\n", (unsigned long)rv);
		return CK_INVALID_HANDLE;
	}

	return hDerivedKey;
}

static int verify_ecdh_keys_match(CK_FUNCTION_LIST_PTR flist, CK_SESSION_HANDLE session,
								  CK_OBJECT_HANDLE hKey1, CK_OBJECT_HANDLE hKey2)
{
	CK_RV rv;
	CK_MECHANISM mech = { CKM_AES_ECB, NULL, 0 };
	CK_BYTE plaintext[16] = {
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
	};
	CK_BYTE ciphertext[16] = { 0 };
	CK_BYTE decrypted[16] = { 0 };
	CK_ULONG ct_len = sizeof(ciphertext);
	CK_ULONG pt_len = sizeof(decrypted);

	/* Encrypt with key1 */
	rv = flist->C_EncryptInit(session, &mech, hKey1);
	if (rv != CKR_OK) {
		ERROR("C_EncryptInit failed: 0x%lX\n", (unsigned long)rv);
		return -1;
	}

	rv = flist->C_Encrypt(session, plaintext, sizeof(plaintext), ciphertext, &ct_len);
	if (rv != CKR_OK) {
		ERROR("C_Encrypt failed: 0x%lX\n", (unsigned long)rv);
		return -1;
	}

	/* Decrypt with key2 */
	rv = flist->C_DecryptInit(session, &mech, hKey2);
	if (rv != CKR_OK) {
		ERROR("C_DecryptInit failed: 0x%lX\n", (unsigned long)rv);
		return -1;
	}

	rv = flist->C_Decrypt(session, ciphertext, ct_len, decrypted, &pt_len);
	if (rv != CKR_OK) {
		ERROR("C_Decrypt failed: 0x%lX\n", (unsigned long)rv);
		return -1;
	}

	/* Compare */
	if (memcmp(plaintext, decrypted, sizeof(plaintext)) != 0) {
		ERROR("ECDH verification FAILED: derived keys do not match\n");
		return -1;
	}

	INFO("ECDH verification PASSED\n");
	return 0;
}

/*
 * Test ECDH key derivation with a specific KDF
 * - Generate two EC key pairs
 * - First party derives shared secret using their private key + second party's public key
 * - Second party derives shared secret using their private key + first party's public key
 * - Verify both derived keys are identical
 */
static int test_ecdh_derive(CK_FUNCTION_LIST_PTR flist, CK_SESSION_HANDLE session, CK_EC_KDF_TYPE kdf)
{
	int ret = -1;
	CK_OBJECT_HANDLE hFirstPub = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hFirstPriv = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hSecondPub = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hSecondPriv = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hFirstDerived = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hSecondDerived = CK_INVALID_HANDLE;
	CK_BYTE first_ec_point[256];
	CK_BYTE second_ec_point[256];
	CK_ULONG first_ec_point_len = sizeof(first_ec_point);
	CK_ULONG second_ec_point_len = sizeof(second_ec_point);

	CK_BYTE first_key_id[] = { 0x00, 0x07, 0x01 };
	CK_BYTE second_key_id[] = { 0x01, 0x07, 0x01 };
	CK_BYTE first_derived_id[] = { 0x00, 0x02, 0x02 };
	CK_BYTE second_derived_id[] = { 0x01, 0x02, 0x02 };

	const char *kdf_name = get_kdf_name(kdf);

	INFO("ECDH - %s...\n", kdf_name);

	INFO("Generating first EC key pair...\n");
	if (generate_ec_keypair(flist, session, first_key_id,
							&hFirstPub, &hFirstPriv) != 0) {
		ERROR("Failed to generate first key pair\n");
		goto cleanup;
	}

	INFO("Generating second EC key pair...\n");
	if (generate_ec_keypair(flist, session, second_key_id,
							&hSecondPub, &hSecondPriv) != 0) {
		ERROR("Failed to generate second key pair\n");
		goto cleanup;
	}

	INFO("Retrieving first public key...\n");
	if (get_ec_point(flist, session, hFirstPub, first_ec_point, &first_ec_point_len) != 0) {
		ERROR("Failed to get first EC_POINT\n");
		goto cleanup;
	}

	INFO("Retrieving second public key...\n");
	if (get_ec_point(flist, session, hSecondPub, second_ec_point, &second_ec_point_len) != 0) {
		ERROR("Failed to get second EC_POINT\n");
		goto cleanup;
	}

	INFO("First party deriving shared secret...\n");
	hFirstDerived = derive_ecdh_key(flist, session, hFirstPriv,
									second_ec_point, second_ec_point_len,
									first_derived_id, kdf);
	if (hFirstDerived == CK_INVALID_HANDLE) {
		ERROR("First party failed to derive shared secret\n");
		goto cleanup;
	}

	INFO("Second party deriving shared secret...\n");
	hSecondDerived = derive_ecdh_key(flist, session, hSecondPriv,
									 first_ec_point, first_ec_point_len,
									 second_derived_id, kdf);
	if (hSecondDerived == CK_INVALID_HANDLE) {
		ERROR("Second party failed to derive shared secret\n");
		goto cleanup;
	}

	INFO("Verifying derived keys match...\n");
	ret = verify_ecdh_keys_match(flist, session, hFirstDerived, hSecondDerived);

cleanup:
	INFO("Cleaning up test keys...\n");
	if (hFirstPub != CK_INVALID_HANDLE)
		flist->C_DestroyObject(session, hFirstPub);
	if (hSecondPub != CK_INVALID_HANDLE)
		flist->C_DestroyObject(session, hSecondPub);
	if (hFirstPriv != CK_INVALID_HANDLE)
		flist->C_DestroyObject(session, hFirstPriv);
	if (hSecondPriv != CK_INVALID_HANDLE)
		flist->C_DestroyObject(session, hSecondPriv);
	if (hFirstDerived != CK_INVALID_HANDLE)
		flist->C_DestroyObject(session, hFirstDerived);
	if (hSecondDerived != CK_INVALID_HANDLE)
		flist->C_DestroyObject(session, hSecondDerived);

	return ret;
}

static int run_all_ecdh_tests(CK_FUNCTION_LIST_PTR flist, CK_SESSION_HANDLE session)
{
	int ret = 0;

	INFO("ECDH Key Derivation... \n");

	for (size_t i = 0; i < ARRAY_SIZE(supported_kdfs); i++) {
		CK_EC_KDF_TYPE kdf = supported_kdfs[i].kdf;

		if (test_ecdh_derive(flist, session, kdf) != 0)
			ret = -1;
	}

	return ret;
}

int main(int argc, char *argv[])
{
	void *lib_handle;
	char *libpath, *arg_help = "help";
	uint8_t key_id[3];
	int ret = 0;

	CK_FUNCTION_LIST_PTR flist;
	CK_SLOT_ID slot;
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE base_key, derived_key;
	CK_HKDF_PARAMS_PTR hkdf_param = NULL;
	CK_MECHANISM mechanism_hkdf;

	if (argc == 2 && !strncmp(argv[1], arg_help, sizeof(*arg_help))) {
		usage(argv[0]);
		return 0;
	}

	if (argc != 2) {
		ERROR("Incorrect number of arguments\n");
		usage(argv[0]);
		return -EINVAL;
	}

	hkdf_param = malloc(sizeof(*hkdf_param));
	if (!hkdf_param) {
		ERROR("Memory allocation failed for hkdf_param\n");
		return -ENOMEM;
	}

	memset(hkdf_param, 0, sizeof(*hkdf_param));
	hkdf_param->bExtract = CK_FALSE;
	hkdf_param->bExpand  = CK_FALSE;
	hkdf_param->prfHashMechanism = CKM_SHA256;
	hkdf_param->ulSaltType = CKF_HKDF_SALT_NULL;
	hkdf_param->pSalt = NULL;
	hkdf_param->ulSaltLen = 0;
	hkdf_param->hSaltKey = CK_INVALID_HANDLE;
	hkdf_param->pInfo = NULL;
	hkdf_param->ulInfoLen = 0;

	mechanism_hkdf.mechanism = CKM_HKDF_DERIVE;
	mechanism_hkdf.pParameter = hkdf_param;
	mechanism_hkdf.ulParameterLen = sizeof(*hkdf_param);

	libpath = argv[1];

	INFO("Loading %s shared library...\n", libpath);

	lib_handle = dlopen(libpath, RTLD_LAZY);
	if (!lib_handle) {
		ERROR("Could not find PKCS#11 shared library %s - %s\n", libpath, dlerror());
		return -ELIBACC;
	}

	INFO("Retrieving function list from %s...\n", libpath);

	flist = util_lib_get_function_list(lib_handle);
	if (!flist) {
		ERROR("Failed to find C_GetFunctionList in shared library - %s", dlerror());
		ret = -ENOSYS;
		goto err_close_lib;
	}

	INFO("Calling C_Initialize...\n");

	ret = util_lib_init(flist);
	if (ret) {
		ERROR("Failed call to C_Initialize\n");
		goto err_close_lib;
	}

	INFO("Getting Slot ID...\n");

	slot = util_lib_get_slot_list(flist);
	if (slot < 0) {
		ERROR("Failed to retrieve slot ID\n");
		ret = -1;
		goto err_lib_finalize;
	}

	INFO("Opening session on slot #%ld...\n", slot);

	session = util_lib_open_session(flist, slot);
	if (session < 0) {
		ERROR("Failed to open session\n");
		ret = -1;
		goto err_lib_finalize;
	}

	INFO("HKDF key derivation...\n");

	INFO("Install base key...\n");
	key_id[0] = 2;
	key_id[1] = 2;
	key_id[2] = 2;
	base_key = install_base_key(flist, session, CKK_AES, key_id, sizeof(key_value_AES_256), key_value_AES_256);
	if (base_key == CK_INVALID_HANDLE) {
		ERROR("Failed to create key object\n");
		ret = -EKEYREJECTED;
		goto err_close_session;
	}

	hkdf_param->bExtract = CK_TRUE;
	hkdf_param->bExpand = CK_TRUE;

	INFO("Calling C_DeriveKey with session ID #%ld...\n", session);
	derived_key = util_lib_derive_key_aes(flist, session, mechanism_hkdf, base_key);
	if (derived_key == CK_INVALID_HANDLE) {
		ERROR("Failed to derive key\n");
		ret = -EKEYREJECTED;
		goto err_close_session;
	}

	INFO("Verifying HKDF...\n");
	if (verify_hkdf_with_ecb(flist, session, derived_key, key_value_AES_256) != 0) {
		ERROR("HKDF verification FAILED\n");
		ret = -1;
		goto err_close_session;
	}
	INFO("HKDF verification PASSED\n");

	if (run_all_ecdh_tests(flist, session) != 0) {
		ERROR("Some ECDH tests failed\n");
		ret = -1;
	}

err_close_session:
	INFO("Cleaning up and calling C_Finalize...\n");
	util_lib_close_sessions(flist, slot);
err_lib_finalize:
	if (util_lib_finalize(flist))
		ERROR("Failed call to C_Finalize\n");
err_close_lib:
	if (dlclose(lib_handle))
		ERROR("Failed to close shared library %s - %s\n", libpath, dlerror());

	free(hkdf_param);

	return ret;
}
