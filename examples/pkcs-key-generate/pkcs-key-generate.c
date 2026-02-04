// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2026 NXP
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <dlfcn.h>
#include <errno.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#include "libhse.h"
#include "pkcs11-unix.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
#endif /* ARRAY_SIZE */

#define ERROR(fmt, ...) printf("[ERROR] " fmt, ##__VA_ARGS__)
#define INFO(fmt, ...) printf("[INFO] " fmt, ##__VA_ARGS__)

void usage(const char* progname)
{
	printf("\n%s - Generate a private key pair (RSA, ECC) or an AES key in HSE\n", progname);
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

static CK_OBJECT_HANDLE util_lib_generate_aes(CK_FUNCTION_LIST_PTR flist, CK_SESSION_HANDLE session,
					      CK_MECHANISM mechanism)
{
	CK_OBJECT_HANDLE key;
	CK_RV rv;

	/* 
	 * key_id represent the HSE key slot in the key catalog
	 *     - key_id[0] - slot ID
	 *     - key_id[1] - group ID
	 *     - key_id[2] - catalog ID
	 */
	CK_BYTE key_id[] = { 0x00, 0x00, 0x02 };
	CK_UTF8CHAR label[] = {"HSE-AES-256-GEN"};
	/* key length in bits required for AES keys */
	CK_ULONG key_bits = 256;
	CK_BBOOL boolean = CK_TRUE;

	CK_ATTRIBUTE keyTemplate[] = {
		{ CKA_LABEL, label, sizeof(label)-1 },
		{ CKA_ID, &key_id, sizeof(key_id) },
		{ CKA_ENCRYPT, &boolean, sizeof(boolean) },
		{ CKA_DECRYPT, &boolean, sizeof(boolean) },
		{ CKA_VALUE_LEN, &key_bits, sizeof(key_bits) }
	};

	rv = flist->C_GenerateKey(session, &mechanism, keyTemplate, ARRAY_SIZE(keyTemplate), &key);

	if (rv != CKR_OK){
		ERROR("AES Key generate failed!\n");
		return -1;
	}

	return 0;
}

static CK_OBJECT_HANDLE util_lib_generate_rsapair(CK_FUNCTION_LIST_PTR flist, CK_SESSION_HANDLE session,
						  CK_MECHANISM mechanism)
{
	CK_OBJECT_HANDLE pubkey, prikey;
	CK_RV rv;

	/* 
	 * key_id represent the HSE key slot in the key catalog
	 *     - key_id[0] - slot ID
	 *     - key_id[1] - group ID
	 *     - key_id[2] - catalog ID
	 */
	CK_BYTE key_id[] = { 0x00, 0x06, 0x01 };
	CK_UTF8CHAR label[] = {"HSE-RSA2048-PRIV-GEN"};
	CK_ULONG rsa_modulus_bits = 2048;
	CK_BYTE rsa_pub_exponent[] = { 0x01, 0x00, 0x01 };
	CK_BBOOL boolean = CK_TRUE;
	/*
	 * when generating a key pair, only the private key template
	 * contains the attributes necessary to generate the pair
	 *
	 * CKA_MODULUS_BITS and CKA_PUBLIC_EXPONENT are required
	 * to generate a rsa key pair
	 */
	CK_ATTRIBUTE privateKeyTemplate[] = {
		{ CKA_LABEL, label, sizeof(label)-1 },
		{ CKA_ID, &key_id, sizeof(key_id) },
		{ CKA_DECRYPT, &boolean, sizeof(boolean) },
		{ CKA_SIGN, &boolean, sizeof(boolean) }
	};

	CK_ATTRIBUTE publicKeyTemplate[] = {
		{ CKA_MODULUS_BITS, &rsa_modulus_bits, sizeof(rsa_modulus_bits) },
		{ CKA_PUBLIC_EXPONENT, rsa_pub_exponent, ARRAY_SIZE(rsa_pub_exponent) },
		{ CKA_ENCRYPT, &boolean, sizeof(boolean) },
		{ CKA_VERIFY, &boolean, sizeof(boolean) }
	};

	rv = flist->C_GenerateKeyPair(session, &mechanism, publicKeyTemplate, ARRAY_SIZE(publicKeyTemplate), privateKeyTemplate, ARRAY_SIZE(privateKeyTemplate), &pubkey, &prikey);

	if (rv != CKR_OK){
		ERROR("RSA Key Pair generate failed!\n");
		return -1;
		}

	return 0;
}

static CK_OBJECT_HANDLE util_lib_generate_eccpair(CK_FUNCTION_LIST_PTR flist, CK_SESSION_HANDLE session,
						  CK_MECHANISM mechanism)
{
	CK_OBJECT_HANDLE pubkey, prikey;
	CK_RV rv;

	/* 
	 * key_id represent the HSE key slot in the key catalog
	 *     - key_id[0] - slot ID
	 *     - key_id[1] - group ID
	 *     - key_id[2] - catalog ID
	 */
	CK_BYTE key_id[] = { 0x00, 0x03, 0x01 };
	CK_UTF8CHAR label[] = {"HSE-EC-PRIV-GEN"};
	CK_UTF8CHAR ecc_curve_oid[] = {"\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x07"};
	CK_BBOOL boolean = CK_TRUE;
	/*
	 * when generating a key pair, only the private key template
	 * contains the attributes necessary to generate the pair
	 *
	 * CKA_EC_PARAMS is required for generating an ecc key pair
	 * it shall specify the oid for the desired curve
	 */
	CK_ATTRIBUTE privateKeyTemplate[] = {
		{ CKA_LABEL, label, sizeof(label)-1 },
		{ CKA_ID, &key_id, sizeof(key_id) },
		{ CKA_DECRYPT, &boolean, sizeof(boolean) },
		{ CKA_SIGN, &boolean, sizeof(boolean) }
	};

	CK_ATTRIBUTE publicKeyTemplate[] = {
		{ CKA_EC_PARAMS, ecc_curve_oid, sizeof(ecc_curve_oid)-1 },
		{ CKA_ENCRYPT, &boolean, sizeof(boolean) },
		{ CKA_VERIFY, &boolean, sizeof(boolean) }
	};


	rv = flist->C_GenerateKeyPair(session, &mechanism, publicKeyTemplate, ARRAY_SIZE(publicKeyTemplate), 
	privateKeyTemplate, ARRAY_SIZE(privateKeyTemplate), &pubkey, &prikey
	);

	if (rv != CKR_OK){
		ERROR("ECC Key Pair generate failed!\n");
		return -1;
		}

	return 0;
}
static CK_OBJECT_HANDLE util_lib_find_objects(CK_FUNCTION_LIST_PTR flist, CK_SESSION_HANDLE session, char *label)
{
	CK_OBJECT_HANDLE match_key = 0;
	CK_ULONG num_keys;
	CK_RV rv;
	
	CK_ATTRIBUTE template[] = {
		{ CKA_LABEL, label, strlen(label)}
	};

	rv = flist->C_FindObjectsInit(session, template, ARRAY_SIZE(template));

	if (rv != CKR_OK)
		return 0;

	rv = flist->C_FindObjects(session, &match_key, 1, &num_keys);
	if (rv != CKR_OK)
		return 0;
		
	rv = flist->C_FindObjectsFinal(session);
	if (rv != CKR_OK)
		return 0;

	return match_key;
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

int main(int argc, char *argv[])
{
	void *lib_handle;
	char *libpath, *arg_help = "help";
	int ret = 0;
	int ret_aes = 0, ret_rsa=0, ret_ecc=0;

	CK_FUNCTION_LIST_PTR flist;
	CK_SLOT_ID slot;
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE aes_key, rsa_key, ecc_key;
	CK_MECHANISM mechanism_aes = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
	CK_MECHANISM mechanism_rsa = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };
	CK_MECHANISM mechanism_ecc = { CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0 };

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

	INFO("Calling C_GenerateKeyPair with session ID #%ld...\n", session);

	INFO("Generating an AES Key...\n");
	aes_key = util_lib_generate_aes(flist, session, mechanism_aes);
	if (aes_key) {
		ERROR("Failed to create key object\n");
		ret = -EKEYREJECTED;
		goto err_lib_finalize;
	}

	INFO("Generating a RSA Key Pair...\n");
	rsa_key = util_lib_generate_rsapair(flist, session, mechanism_rsa);
	if (rsa_key) {
		ERROR("Failed to create key object\n");
		ret = -EKEYREJECTED;
		goto err_lib_finalize;
	}

	INFO("Generating an ECC Key Pair...\n");
	ecc_key = util_lib_generate_eccpair(flist, session, mechanism_ecc);
	if (ecc_key) {
		ERROR("Failed to create key object\n");
		ret = -EKEYREJECTED;
		goto err_lib_finalize;
	}
	
	INFO("Calling C_FindObjects...\n");
	
	aes_key = util_lib_find_objects(flist, session, "HSE-AES-256-GEN");
	if (!aes_key) {
		ERROR("Failed to find aes key object\n");
		ret = -ENOKEY;
		goto err_lib_finalize;
	}
	INFO("Found AES Key Object with handle %06lx\n", aes_key);
	ret_aes = util_lib_destroy_object(flist, session, aes_key);
	if (ret_aes) {
		ERROR("Failed to destroy aes key object\n");
		goto err_lib_finalize;
	}
	INFO("Deleting AES Key Object with handle %06lx\n", aes_key);

	rsa_key = util_lib_find_objects(flist, session, "HSE-RSA2048-PRIV-GEN");
	if (!rsa_key) {
		ERROR("Failed to find rsa key object\n");
		ret = -ENOKEY;
		goto err_lib_finalize;
	}
	INFO("Found RSA Key Object with handle %06lx\n", rsa_key);
	ret_rsa = util_lib_destroy_object(flist, session, rsa_key);
	if (ret_rsa) {
		ERROR("Failed to destroy rsa key object\n");
		goto err_lib_finalize;
	}
	INFO("Deleting RSA Key Object with handle %06lx\n", rsa_key);

	ecc_key = util_lib_find_objects(flist, session, "HSE-EC-PRIV-GEN");
	if (!ecc_key) {
		ERROR("Failed to find ecc key object\n");
		ret = -ENOKEY;
		goto err_lib_finalize;
	}
	INFO("Found ECC Key Object with handle %06lx\n", ecc_key);
	ret_ecc = util_lib_destroy_object(flist, session, ecc_key);
	if (ret_ecc) {
		ERROR("Failed to destroy ecc key object\n");
		goto err_lib_finalize;
	}
	INFO("Deleting ECC Key Object with handle %06lx\n", ecc_key);

	INFO("Cleaning up and calling C_Finalize...\n");

err_lib_finalize:	
	if (util_lib_finalize(flist))
		ERROR("Failed call to C_Finalize\n");
err_close_lib:
	if (dlclose(lib_handle))
		ERROR("Failed to close shared library %s - %s\n", libpath, dlerror());

	return ret;
}

