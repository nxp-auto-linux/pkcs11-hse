// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <dlfcn.h>
#include <errno.h>
#include <openssl/sha.h>
#include "pkcs11.h"

/* add missing HMAC key type from pkcs11.h */
#ifndef CKK_SHA256_HMAC
#define CKK_SHA256_HMAC         0x0000002BUL
#endif

#ifndef CKK_SHA384_HMAC
#define CKK_SHA384_HMAC         0x0000002CUL
#endif

#ifndef CKK_SHA512_HMAC
#define CKK_SHA512_HMAC         0x0000002DUL
#endif

#ifndef CKK_SHA224_HMAC
#define CKK_SHA224_HMAC         0x0000002EUL
#endif


#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
#endif /* ARRAY_SIZE */

#ifndef ERROR
#define ERROR(fmt, ...) printf("[ERROR] " fmt, ##__VA_ARGS__)
#endif

#ifndef INFO
#define INFO(fmt, ...) printf("[INFO] " fmt, ##__VA_ARGS__)
#endif

static unsigned char key_value_AES_128[] = {
	0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF
};

/* key size should not bigger than the block size of SHA alg */
static unsigned char key_value_HMAC_1[] = {
	0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF,
	0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF
};

/* key size should not bigger than the block size of SHA alg */
static unsigned char key_value_HMAC_2[] = {
	0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF,
	0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF,
	0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF,
	0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF,
};

void usage(const char* progname)
{
	printf("\n%s - PKCS11 signature generate/verify example\n", progname);
	printf("\n");
	printf("\t%s /home/<user>/pkcs/libpkcs-hse.so\n", progname);
	printf("\n");
	printf("Usage:\n");
	printf("%s help\n", progname);
	printf("%s <lib>\n", progname);
	printf("\n");
	printf("\t<lib>         - full path to PKCS#11 shared library\n");
	printf("\n");
}

static CK_FUNCTION_LIST_PTR util_lib_get_function_list(void *handle)
{
	CK_RV(*C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR);
	CK_FUNCTION_LIST_PTR function_list;
	CK_RV rv;

	/* first get the function symbol */
	C_GetFunctionList = dlsym(handle, "C_GetFunctionList");
	if (!C_GetFunctionList) 
		return NULL;

	rv = C_GetFunctionList(&function_list);
	if (rv == CKR_OK)
		return function_list;

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

static CK_OBJECT_HANDLE install_aes_hmac_key(CK_FUNCTION_LIST_PTR flist, CK_SESSION_HANDLE session,
					       CK_KEY_TYPE key_type, uint8_t *key_id, int key_len, uint8_t *key_value)
{
	CK_OBJECT_HANDLE key;
	CK_RV rv;

	/* define key template */
	CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
	CK_KEY_TYPE type = key_type;
	CK_UTF8CHAR label[] = {"HSE-Sym-Key"};
	CK_ATTRIBUTE keyTemplate[] = {
		{ CKA_LABEL, label, sizeof(label)-1 },
		{ CKA_CLASS, &key_class, sizeof(key_class) },
		{ CKA_KEY_TYPE, &type, sizeof(type) },
		{ CKA_ID, key_id, 3 },
		{ CKA_VALUE, (CK_BYTE_PTR)key_value, key_len }
	};

	rv = flist->C_CreateObject(session, keyTemplate, ARRAY_SIZE(keyTemplate), &key);
	if (rv != CKR_OK)
		return -EKEYREJECTED;

	return key;
}

static CK_OBJECT_HANDLE install_ecc_private_key(CK_FUNCTION_LIST_PTR flist, CK_SESSION_HANDLE session)
{
	CK_OBJECT_HANDLE key = 0;
	CK_RV rv;

	/* define key template
	 * 
	 * key_id represent the HSE key slot in the key catalog
	 *     - key_id[0] - slot ID
	 *     - key_id[1] - group ID
	 *     - key_id[2] - catalog ID
	 */
	CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;
	CK_KEY_TYPE key_type = CKK_EC;
	CK_UTF8CHAR label[] = {"HSE-ECC-PRIV"};
	CK_BYTE key_id[] = { 0x00, 0x03, 0x01};
	CK_BYTE key_priv[] = {
		0x54, 0x4d, 0x90, 0xd1, 0xbf, 0x45, 0x32, 0x9c, 0xd2, 0x39, 0x47, 0x06, 0x29, 0x3b, 0x4f, 0xc8, 
		0x70, 0x28, 0xf7, 0xde, 0xac, 0x86, 0xb3, 0x91, 0xb6, 0x91, 0x93, 0xff, 0xe8, 0xe4, 0x2f, 0x68
	};
	/* DER-encoding of ANSI X9.62 ECPoint value */
	CK_BYTE key_pub[] = {
		0x42, 0x00, 0x04, 
		0x5e, 0x90, 0x7e, 0xa9, 0x80, 0xf2, 0x04, 0xfb, 0x46, 0xb6, 0x82, 0x93, 0x0d, 0x6b, 0xb1, 0x72, 
		0x9f, 0x31, 0x7a, 0x99, 0xc3, 0x4f, 0x39, 0xdc, 0x06, 0x74, 0xe4, 0x6c, 0x92, 0x54, 0x75, 0xf5, 
		0x81, 0x74, 0x1d, 0x7d, 0x5c, 0x46, 0x7c, 0x03, 0xbb, 0xec, 0x49, 0xf0, 0x7a, 0x51, 0x7b, 0x0b, 
		0x6b, 0xc1, 0x86, 0x86, 0x36, 0x3c, 0x89, 0x61, 0x29, 0xaa, 0x05, 0x8b, 0x4f, 0xea, 0x14, 0xdb
	};
	/* DER-encoding of an ANSI X9.62 Parameters value */
	char *ec_param_oid = "\x06\x09\x2B\x24\x03\x03\x02\x08\x01\x01\x07";
	CK_ATTRIBUTE keyTemplate[] = {
		{ CKA_LABEL, label, sizeof(label)-1 },
		{ CKA_CLASS, &key_class, sizeof(key_class) },
		{ CKA_KEY_TYPE, &key_type, sizeof(key_type) },
		{ CKA_ID, &key_id, sizeof(key_id) },
		{CKA_EC_POINT, key_pub, sizeof(key_pub)},
		{CKA_EC_PARAMS, (CK_BYTE_PTR)ec_param_oid, strlen(ec_param_oid)},
		{ CKA_VALUE, key_priv, sizeof(key_priv)}
	};

	rv = flist->C_CreateObject(session, keyTemplate, ARRAY_SIZE(keyTemplate), &key);
	if (rv != CKR_OK)
		return -EKEYREJECTED;

	return key;
}

static CK_OBJECT_HANDLE install_ecc_public_key(CK_FUNCTION_LIST_PTR flist, CK_SESSION_HANDLE session)
{
	CK_OBJECT_HANDLE key;
	CK_RV rv;

	/* define key template
	 * 
	 * key_id represent the HSE key slot in the key catalog
	 *     - key_id[0] - slot ID
	 *     - key_id[1] - group ID
	 *     - key_id[2] - catalog ID
	 */
	CK_OBJECT_CLASS key_class = CKO_PUBLIC_KEY;
	CK_KEY_TYPE key_type = CKK_EC;
	CK_UTF8CHAR label[] = {"HSE-ECC-PUB"};
	CK_BYTE key_id[] = { 0x00, 0x04, 0x01};
	/* DER-encoding of ANSI X9.62 ECPoint value */
	CK_BYTE key_pub[] = {
		0x42, 0x00, 0x04, 
		0x5e, 0x90, 0x7e, 0xa9, 0x80, 0xf2, 0x04, 0xfb, 0x46, 0xb6, 0x82, 0x93, 0x0d, 0x6b, 0xb1, 0x72, 
		0x9f, 0x31, 0x7a, 0x99, 0xc3, 0x4f, 0x39, 0xdc, 0x06, 0x74, 0xe4, 0x6c, 0x92, 0x54, 0x75, 0xf5, 
		0x81, 0x74, 0x1d, 0x7d, 0x5c, 0x46, 0x7c, 0x03, 0xbb, 0xec, 0x49, 0xf0, 0x7a, 0x51, 0x7b, 0x0b, 
		0x6b, 0xc1, 0x86, 0x86, 0x36, 0x3c, 0x89, 0x61, 0x29, 0xaa, 0x05, 0x8b, 0x4f, 0xea, 0x14, 0xdb
	};
	/* DER-encoding of an ANSI X9.62 Parameters value */
	char *ec_param_oid = "\x06\x09\x2B\x24\x03\x03\x02\x08\x01\x01\x07";
	CK_ATTRIBUTE keyTemplate[] = {
		{ CKA_LABEL, label, sizeof(label)-1 },
		{ CKA_CLASS, &key_class, sizeof(key_class) },
		{ CKA_KEY_TYPE, &key_type, sizeof(key_type) },
		{ CKA_ID, &key_id, sizeof(key_id) },
		{CKA_EC_POINT, key_pub, sizeof(key_pub)},
		{CKA_EC_PARAMS, (CK_BYTE_PTR)ec_param_oid, strlen(ec_param_oid)}
	};

	rv = flist->C_CreateObject(session, keyTemplate, ARRAY_SIZE(keyTemplate), &key);
	if (rv != CKR_OK)
		return -EKEYREJECTED;

	return key;
}

static CK_OBJECT_HANDLE util_lib_find_objects(CK_FUNCTION_LIST_PTR flist, CK_SESSION_HANDLE session, CK_OBJECT_CLASS class)
{
	CK_OBJECT_HANDLE aes_key = 0;
	CK_ULONG num_keys;
	CK_RV rv;
	CK_OBJECT_CLASS key_class = class;
	CK_ATTRIBUTE template[] = {
		{ CKA_CLASS, &key_class, sizeof(key_class) },
	};

	rv = flist->C_FindObjectsInit(session, template, ARRAY_SIZE(template));
	if (rv != CKR_OK)
		return 0;

	do {
		rv = flist->C_FindObjects(session, &aes_key, 1, &num_keys);
		/* no extra processing required, just return last key found */
	} while (rv == CKR_OK && num_keys != 0);

	rv = flist->C_FindObjectsFinal(session);
	if (rv != CKR_OK)
		return 0;

	return aes_key;
}

static int util_lib_destroy_object(CK_FUNCTION_LIST_PTR flist, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key)
{
	CK_RV rv;

	rv = flist->C_DestroyObject(session, key);
	if (rv != CKR_OK)
		return -1;

	return 0;
}

static int util_lib_finalize(CK_FUNCTION_LIST_PTR flist)
{
	CK_RV rv;

	rv = flist->C_Finalize(NULL);
	if (rv != CKR_OK)
		return -1;

	return 0;
}

static int util_lib_rsa_sig(CK_FUNCTION_LIST_PTR flist, CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE priv_key, CK_OBJECT_HANDLE pub_key)
{
	CK_RV rv;
	char *tobe_sign = "data to be sign";
	CK_BYTE sig[256] = {0};
	CK_ULONG sig_len = ARRAY_SIZE(sig);

	INFO("\tGenerate signature ...\n");
	rv = flist->C_SignInit(session, mechanism, priv_key);
	if (rv != CKR_OK) {
		ERROR("\tC_SignInit returns error 0x%lx\n", rv);
		return -1;
	}

	rv = flist->C_Sign(session, (uint8_t *)tobe_sign, strlen(tobe_sign), sig, &sig_len);
	if (rv != CKR_OK) {
		ERROR("\tC_Sign returns error 0x%lx\n", rv);
		return -1;
	}

	INFO("\tVerify signature ...\n");
	rv = flist->C_VerifyInit(session, mechanism, pub_key);
	if (rv != CKR_OK) {
		ERROR("\tC_VerifyInit returns error 0x%lx\n", rv);
		return -1;
	}

	rv = flist->C_Verify(session, (uint8_t *)tobe_sign, strlen(tobe_sign), sig, sig_len);
	if (rv != CKR_OK) {
		ERROR("\tC_Verify returns error 0x%lx\n", rv);
		return -1;
	}

	return 0;
}

static int util_lib_rsa_pre_hash_sig(CK_FUNCTION_LIST_PTR flist, CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE priv_key, CK_OBJECT_HANDLE pub_key)
{
	CK_RV rv;
	char *tobe_sign = "data to be sign";
	CK_BYTE sig[256] = {0};
	CK_ULONG sig_len = ARRAY_SIZE(sig);
	CK_BYTE digest_openssl[64];
	CK_ULONG digest_length = 0;

	/* calculate digest */
	if (mechanism->mechanism == CKM_RSA_PKCS) {
		SHA512((const uint8_t *)tobe_sign, strlen(tobe_sign), digest_openssl);
		digest_length = 512 >> 3;
	} else if (mechanism->mechanism == CKM_RSA_PKCS_PSS) {
		switch (((CK_RSA_PKCS_PSS_PARAMS *)mechanism->pParameter)->hashAlg) {
			case CKM_SHA_1:
				SHA1((const uint8_t *)tobe_sign, strlen(tobe_sign), digest_openssl);
				digest_length = 20;
				break;
			case CKM_SHA256:
				SHA256((const uint8_t *)tobe_sign, strlen(tobe_sign), digest_openssl);
				digest_length = 256 >> 3;
				break;
			case CKM_SHA384:
				SHA384((const uint8_t *)tobe_sign, strlen(tobe_sign), digest_openssl);
				digest_length = 384 >> 3;
				break;
			case CKM_SHA512:
				SHA512((const uint8_t *)tobe_sign, strlen(tobe_sign), digest_openssl);
				digest_length = 512 >> 3;
				break;
		}
	}

	INFO("\tGenerate signature ...\n");
	rv = flist->C_SignInit(session, mechanism, priv_key);
	if (rv != CKR_OK) {
		ERROR("\tC_SignInit returns error 0x%lx\n", rv);
		return -1;
	}

	rv = flist->C_Sign(session, digest_openssl, digest_length, sig, &sig_len);
	if (rv != CKR_OK) {
		ERROR("\tC_Sign returns error 0x%lx\n", rv);
		return -1;
	}

	INFO("\tVerify signature ...\n");
	rv = flist->C_VerifyInit(session, mechanism, pub_key);
	if (rv != CKR_OK) {
		ERROR("\tC_VerifyInit returns error 0x%lx\n", rv);
		return -1;
	}

	rv = flist->C_Verify(session, digest_openssl, digest_length, sig, sig_len);
	if (rv != CKR_OK) {
		ERROR("\tC_Verify returns error 0x%lx\n", rv);
		return -1;
	}

	return 0;
}

static int util_lib_ec_sig(CK_FUNCTION_LIST_PTR flist, CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE priv_key, CK_OBJECT_HANDLE pub_key)
{
	CK_RV rv;
	char *tobe_sign = "data to be sign";
	CK_BYTE sig[64] = {0};
	CK_ULONG sig_len = ARRAY_SIZE(sig);

	INFO("\tGenerate signature ...\n");
	rv = flist->C_SignInit(session, mechanism, priv_key);
	if (rv != CKR_OK) {
		ERROR("\tC_SignInit returns error 0x%lx\n", rv);
		return -1;
	}

	rv = flist->C_Sign(session, (uint8_t *)tobe_sign, strlen(tobe_sign), sig, &sig_len);
	if (rv != CKR_OK) {
		ERROR("\tC_Sign returns error 0x%lx\n", rv);
		return -1;
	}

	INFO("\tVerify signature ...\n");
	rv = flist->C_VerifyInit(session, mechanism, pub_key);
	if (rv != CKR_OK) {
		ERROR("\tC_VerifyInit returns error 0x%lx\n", rv);
		return -1;
	}

	rv = flist->C_Verify(session, (uint8_t *)tobe_sign, strlen(tobe_sign), sig, sig_len);
	if (rv != CKR_OK) {
		ERROR("\tC_Verify returns error 0x%lx\n", rv);
		return -1;
	}

	return 0;
}

static int util_lib_ec_pre_hash_sig(CK_FUNCTION_LIST_PTR flist, CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE priv_key, CK_OBJECT_HANDLE pub_key)
{
	CK_RV rv;
	char *tobe_sign = "data to be sign";
	CK_BYTE sig[256] = {0};
	CK_ULONG sig_len = ARRAY_SIZE(sig);
	CK_BYTE digest_openssl[64];
	CK_ULONG digest_length = 0;
	CK_MECHANISM_TYPE hash_alg[] = {CKM_SHA_1, CKM_SHA224, CKM_SHA384, CKM_SHA512};
	int i;

	for (i = 0; i < ARRAY_SIZE(hash_alg); i++) {

		switch (hash_alg[i]) {
			case CKM_SHA_1:
				SHA1((const uint8_t *)tobe_sign, strlen(tobe_sign), digest_openssl);
				digest_length = 20;
				break;
			case CKM_SHA224:
				SHA224((const uint8_t *)tobe_sign, strlen(tobe_sign), digest_openssl);
				digest_length = 224 >> 3;
				break;
			case CKM_SHA384:
				SHA384((const uint8_t *)tobe_sign, strlen(tobe_sign), digest_openssl);
				digest_length = 384 >> 3;
				break;
			case CKM_SHA512:
				SHA512((const uint8_t *)tobe_sign, strlen(tobe_sign), digest_openssl);
				digest_length = 512 >> 3;
				break;
		}

		rv = flist->C_SignInit(session, mechanism, priv_key);
		if (rv != CKR_OK) {
			ERROR("\tC_SignInit returns error 0x%lx\n", rv);
			return -1;
		}

		rv = flist->C_Sign(session, digest_openssl, digest_length, sig, &sig_len);
		if (rv != CKR_OK) {
			ERROR("\tC_Sign returns error 0x%lx\n", rv);
			return -1;
		}

		rv = flist->C_VerifyInit(session, mechanism, pub_key);
		if (rv != CKR_OK) {
			ERROR("\tC_VerifyInit returns error 0x%lx\n", rv);
			return -1;
		}

		rv = flist->C_Verify(session, digest_openssl, digest_length, sig, sig_len);
		if (rv != CKR_OK) {
			ERROR("\tC_Verify returns error 0x%lx\n", rv);
			return -1;
		}
	}

	return 0;
}

static int ec_sig(CK_FUNCTION_LIST_PTR flist, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE priv_key, CK_OBJECT_HANDLE pub_key)
{
	CK_MECHANISM mechanism;

	INFO("CKM_ECDSA_SHA1 ...\n");
	mechanism.mechanism = CKM_ECDSA_SHA1;
	util_lib_ec_sig(flist, session, &mechanism, priv_key, pub_key);

	INFO("CKM_ECDSA_SHA224 ...\n");
	mechanism.mechanism = CKM_ECDSA_SHA224;
	util_lib_ec_sig(flist, session, &mechanism, priv_key, pub_key);

	INFO("CKM_ECDSA_SHA256 ...\n");
	mechanism.mechanism = CKM_ECDSA_SHA256;
	util_lib_ec_sig(flist, session, &mechanism, priv_key, pub_key);

	INFO("CKM_ECDSA_SHA384 ...\n");
	mechanism.mechanism = CKM_ECDSA_SHA384;
	util_lib_ec_sig(flist, session, &mechanism, priv_key, pub_key);

	INFO("CKM_ECDSA_SHA512 ...\n");
	mechanism.mechanism = CKM_ECDSA_SHA512;
	util_lib_ec_sig(flist, session, &mechanism, priv_key, pub_key);

	INFO("CKM_ECDSA ...\n");
	mechanism.mechanism = CKM_ECDSA;
	util_lib_ec_pre_hash_sig(flist, session, &mechanism, priv_key, pub_key);

	return 0;
}

static int rsa_sig(CK_FUNCTION_LIST_PTR flist, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE priv_key, CK_OBJECT_HANDLE pub_key)
{
	CK_MECHANISM mechanism;
	CK_RSA_PKCS_PSS_PARAMS param;

	INFO("CKM_RSA_PKCS ...\n");
	mechanism.mechanism = CKM_RSA_PKCS;
	util_lib_rsa_pre_hash_sig(flist, session, &mechanism, priv_key, pub_key);

	INFO("CKM_SHA1_RSA_PKCS ...\n");
	mechanism.mechanism = CKM_SHA1_RSA_PKCS;
	util_lib_rsa_sig(flist, session, &mechanism, priv_key, pub_key);

	INFO("CKM_SHA256_RSA_PKCS ...\n");
	mechanism.mechanism = CKM_SHA256_RSA_PKCS;
	util_lib_rsa_sig(flist, session, &mechanism, priv_key, pub_key);

	INFO("CKM_SHA256_RSA_PKCS ...\n");
	mechanism.mechanism = CKM_SHA384_RSA_PKCS;
	util_lib_rsa_sig(flist, session, &mechanism, priv_key, pub_key);

	INFO("CKM_SHA512_RSA_PKCS ...\n");
	mechanism.mechanism = CKM_SHA512_RSA_PKCS;
	util_lib_rsa_sig(flist, session, &mechanism, priv_key, pub_key);

	INFO("CKM_RSA_PKCS_PSS ...\n");
	mechanism.mechanism = CKM_RSA_PKCS_PSS;
	mechanism.pParameter = &param;
	mechanism.ulParameterLen = sizeof(CK_RSA_PKCS_PSS_PARAMS);
	param.hashAlg = CKM_SHA512;
	param.sLen = 10;
	util_lib_rsa_pre_hash_sig(flist, session, &mechanism, priv_key, pub_key);

	INFO("CKM_SHA1_RSA_PKCS_PSS ...\n");
	mechanism.mechanism = CKM_SHA1_RSA_PKCS_PSS;
	mechanism.pParameter = &param;
	mechanism.ulParameterLen = sizeof(CK_RSA_PKCS_PSS_PARAMS);
	param.hashAlg = CKM_SHA_1;
	param.sLen = 10;
	util_lib_rsa_sig(flist, session, &mechanism, priv_key, pub_key);

	INFO("CKM_SHA256_RSA_PKCS_PSS ...\n");
	mechanism.mechanism = CKM_SHA256_RSA_PKCS_PSS;
	mechanism.pParameter = &param;
	mechanism.ulParameterLen = sizeof(CK_RSA_PKCS_PSS_PARAMS);
	param.hashAlg = CKM_SHA256;
	param.sLen = 10;
	util_lib_rsa_sig(flist, session, &mechanism, priv_key, pub_key);

	INFO("CKM_SHA384_RSA_PKCS_PSS ...\n");
	mechanism.mechanism = CKM_SHA384_RSA_PKCS_PSS;
	mechanism.pParameter = &param;
	mechanism.ulParameterLen = sizeof(CK_RSA_PKCS_PSS_PARAMS);
	param.hashAlg = CKM_SHA384;
	param.sLen = 10;
	util_lib_rsa_sig(flist, session, &mechanism, priv_key, pub_key);

	INFO("CKM_SHA512_RSA_PKCS_PSS ...\n");
	mechanism.mechanism = CKM_SHA512_RSA_PKCS_PSS;
	mechanism.pParameter = &param;
	mechanism.ulParameterLen = sizeof(CK_RSA_PKCS_PSS_PARAMS);
	param.hashAlg = CKM_SHA512;
	param.sLen = 10;
	util_lib_rsa_sig(flist, session, &mechanism, priv_key, pub_key);

	return 0;
}

static int util_lib_hmac_sig(CK_FUNCTION_LIST_PTR flist, CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key)
{
	CK_RV rv;
	char *tobe_sign = "data to be sign";
	CK_BYTE hmac[128] = {0};
	CK_ULONG hmac_len = ARRAY_SIZE(hmac);

	INFO("\tGenerate signature ...\n");
	rv = flist->C_SignInit(session, mechanism, key);
	if (rv != CKR_OK) {
		ERROR("\tC_SignInit returns error 0x%lx\n", rv);
		return -1;
	}

	rv = flist->C_Sign(session, (uint8_t *)tobe_sign, strlen(tobe_sign), hmac, &hmac_len);
	if (rv != CKR_OK) {
		ERROR("\tC_Sign returns error 0x%lx\n", rv);
		return -1;
	}

	INFO("\tVerify signature ...\n");
	rv = flist->C_VerifyInit(session, mechanism, key);
	if (rv != CKR_OK) {
		ERROR("\tC_VerifyInit returns error 0x%lx\n", rv);
		return -1;
	}

	rv = flist->C_Verify(session, (uint8_t *)tobe_sign, strlen(tobe_sign), hmac, hmac_len);
	if (rv != CKR_OK) {
		ERROR("\tC_Verify returns error 0x%lx\n", rv);
		return -1;
	}

	return 0;
}

static int hmac_sig(CK_FUNCTION_LIST_PTR flist, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key)
{
	CK_MECHANISM mechanism;

	INFO("CKM_SHA224_HMAC ...\n");
	mechanism.mechanism = CKM_SHA224_HMAC;
	util_lib_hmac_sig(flist, session, &mechanism, key);

	INFO("CKM_SHA256_HMAC ...\n");
	mechanism.mechanism = CKM_SHA256_HMAC;
	util_lib_hmac_sig(flist, session, &mechanism, key);

	INFO("CKM_SHA384_HMAC ...\n");
	mechanism.mechanism = CKM_SHA384_HMAC;
	util_lib_hmac_sig(flist, session, &mechanism, key);

	INFO("CKM_SHA512_HMAC ...\n");
	mechanism.mechanism = CKM_SHA512_HMAC;
	util_lib_hmac_sig(flist, session, &mechanism, key);

	return 0;
}

static int cmac_sig(CK_FUNCTION_LIST_PTR flist, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key)
{
	CK_RV rv;
	CK_MECHANISM mechanism;
	char *tobe_sign = "data to be sign";
	CK_BYTE cmac[16] = {0};
	CK_ULONG cmac_len = ARRAY_SIZE(cmac);

	INFO("CKM_AES_CMAC ...\n");
	mechanism.mechanism = CKM_AES_CMAC;

	INFO("\tGenerate signature ...\n");
	rv = flist->C_SignInit(session, &mechanism, key);
	if (rv != CKR_OK) {
		ERROR("\tC_SignInit returns error 0x%lx\n", rv);
		return -1;
	}

	rv = flist->C_Sign(session, (uint8_t *)tobe_sign, strlen(tobe_sign), cmac, &cmac_len);
	if (rv != CKR_OK) {
		ERROR("\tC_Sign returns error 0x%lx\n", rv);
		return -1;
	}

	INFO("\tVerify signature ...\n");
	rv = flist->C_VerifyInit(session, &mechanism, key);
	if (rv != CKR_OK) {
		ERROR("\tC_VerifyInit returns error 0x%lx\n", rv);
		return -1;
	}

	rv = flist->C_Verify(session, (uint8_t *)tobe_sign, strlen(tobe_sign), cmac, cmac_len);
	if (rv != CKR_OK) {
		ERROR("\tC_Verify returns error 0x%lx\n", rv);
		return -1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	void *lib_handle;
	char *libpath, *arg_help = "help";
	int ret = 0;

	CK_FUNCTION_LIST_PTR flist;
	
	CK_SLOT_ID slot;
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE rsa_pub_key, rsa_priv_key;
	CK_OBJECT_HANDLE ec_pub_key = -EKEYREJECTED;
	CK_OBJECT_HANDLE ec_priv_key = -EKEYREJECTED;
	CK_OBJECT_HANDLE aes128_key, hmac_key_1, hmac_key_2;
	uint8_t key_id[3];

	if (argc == 2 && !strncmp(argv[1], arg_help, sizeof(*arg_help))) {
		usage(argv[0]);
		return 0;
	}

	if (argc != 2) {
		ERROR("Incorrect number of arguments\n");
		usage(argv[0]);
		return -EINVAL;
	}

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

	INFO("RSA Signature operations...\n");
	/* Find RSA keys 
	 * We assume the RSA private & public keys are already installed.
	 * You can do that using pkcs11-tool from OpenSC */
	rsa_pub_key = util_lib_find_objects(flist, session, CKO_PUBLIC_KEY);
	if (!rsa_pub_key) {
		ERROR("Failed to find key object with Class CKO_PUBLIC_KEY\n");
		ret = -ENOKEY;
		goto err_lib_finalize;
	}

	INFO("Found Key Object with handle %06lx\n", rsa_pub_key);

	rsa_priv_key = util_lib_find_objects(flist, session, CKO_PRIVATE_KEY);
	if (!rsa_priv_key) {
		ERROR("Failed to find key object with Class CKO_PRIVATE_KEY\n");
		ret = -ENOKEY;
		goto err_lib_finalize;
	}

	INFO("Found Key Object with handle %06lx\n", rsa_priv_key);

	rsa_sig(flist, session, rsa_priv_key, rsa_pub_key);

	/* Install ECC Private/Public keys */
	INFO("Install ECC private key ...\n");
	ec_priv_key = install_ecc_private_key(flist, session);
	INFO("Created Key Object with handle %06lx\n", ec_priv_key);

	INFO("Install ECC public key ...\n");
	ec_pub_key = install_ecc_public_key(flist, session);
	INFO("Created Key Object with handle %06lx\n", ec_pub_key);

	/* ECC signature */
	ec_sig(flist, session, ec_priv_key, ec_pub_key);

	/* CMAC */
	INFO("Install AES key ...\n");
	 /* key_id represent the HSE key slot in the key catalog
	 *     - key_id[0] - slot ID
	 *     - key_id[1] - group ID
	 *     - key_id[2] - catalog ID
	 */
	key_id[0] = 0;
	key_id[1] = 0;
	key_id[2] = 1;	/* NVM key */
	aes128_key = install_aes_hmac_key(flist, session, CKK_AES, key_id, sizeof(key_value_AES_128), key_value_AES_128);
	if (!aes128_key) {
		ERROR("Failed to create key object\n");
		ret = -EKEYREJECTED;
		goto err_lib_finalize;
	}

	cmac_sig(flist, session, aes128_key);

	/* HMAC */
	INFO("Install HMAC key ...\n");

	key_id[0] = 0;
	key_id[1] = 2;
	key_id[2] = 1;	/* NVM key */
	hmac_key_1 = install_aes_hmac_key(flist, session, CKK_SHA256_HMAC, key_id, sizeof(key_value_HMAC_1), key_value_HMAC_1);
	if (!hmac_key_1) {
		ERROR("Failed to create key object\n");
		ret = -EKEYREJECTED;
		goto err_lib_finalize;
	}

	key_id[0] = 1;
	key_id[1] = 2;
	key_id[2] = 1;	/* NVM key */
	hmac_key_2 = install_aes_hmac_key(flist, session, CKK_SHA256_HMAC, key_id, sizeof(key_value_HMAC_2), key_value_HMAC_2);
	if (!hmac_key_2) {
		ERROR("Failed to create key object\n");
		ret = -EKEYREJECTED;
		goto err_lib_finalize;
	}

	hmac_sig(flist, session, hmac_key_1);
	hmac_sig(flist, session, hmac_key_2);
	
	INFO("Deleting Key Objects ...\n");

	if (ec_priv_key != (CK_OBJECT_HANDLE)(-EKEYREJECTED)) {
		ret = util_lib_destroy_object(flist, session, ec_priv_key);
		if (ret) {
			ERROR("Failed to destroy key object\n");
			goto err_lib_finalize;
		}
	}

	if (ec_pub_key != (CK_OBJECT_HANDLE)(-EKEYREJECTED)) {
		ret = util_lib_destroy_object(flist, session, ec_pub_key);
		if (ret) {
			ERROR("Failed to destroy key object\n");
			goto err_lib_finalize;
		}
	}

	util_lib_destroy_object(flist, session, aes128_key);
	util_lib_destroy_object(flist, session, hmac_key_1);
	util_lib_destroy_object(flist, session, hmac_key_2);

	INFO("Cleaning up and calling C_Finalize...\n");

err_lib_finalize:	
	if (util_lib_finalize(flist))
		ERROR("Failed call to C_Finalize\n");
err_close_lib:
	if (dlclose(lib_handle))
		ERROR("Failed to close shared library %s - %s\n", libpath, dlerror());

	return ret;
}
