// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022 NXP
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

#include "pkcs11.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
#endif /* ARRAY_SIZE */

#ifndef ERROR
#define ERROR(fmt, ...) printf("[ERROR] " fmt, ##__VA_ARGS__)
#endif

#ifndef INFO
#define INFO(fmt, ...) printf("[INFO] " fmt, ##__VA_ARGS__)
#endif

void usage(const char* progname)
{
	printf("\n%s - Store an OpenSSL-generated PEM format public key in HSE\n", progname);
	printf("\n");
	printf("\t%s /home/<user>/pkcs/libpkcs-hse.so /home/<user>/pkcs/rsa2048_public.pem\n", progname);
	printf("\n");
	printf("Usage:\n");
	printf("%s help\n", progname);
	printf("%s <lib> <rsa_key>.pem\n", progname);
	printf("\n");
	printf("\t<lib>         - full path to PKCS#11 shared library\n");
	printf("\t<rsa_key>.pem - full path to RSA Key file in PEM format\n");
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

static CK_OBJECT_HANDLE util_lib_create_object(CK_FUNCTION_LIST_PTR flist, CK_SESSION_HANDLE session,
					       int rsa_modulus_bytes, uint8_t *rsa_modulus,
					       int rsa_pub_exponent_bytes, uint8_t *rsa_pub_exponent)
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
	CK_KEY_TYPE key_type = CKK_RSA;
	CK_UTF8CHAR label[] = {"HSE-RSA2048-PUB"};
	CK_BYTE key_id[] = { 0x00, 0x07, 0x01 };
	CK_ATTRIBUTE keyTemplate[] = {
		{ CKA_LABEL, label, sizeof(label)-1 },
		{ CKA_CLASS, &key_class, sizeof(key_class) },
		{ CKA_KEY_TYPE, &key_type, sizeof(key_type) },
		{ CKA_ID, &key_id, sizeof(key_id) },
		{ CKA_MODULUS, (CK_BYTE_PTR)rsa_modulus, rsa_modulus_bytes },
		{ CKA_PUBLIC_EXPONENT, (CK_BYTE_PTR)rsa_pub_exponent, rsa_pub_exponent_bytes }
	};

	rv = flist->C_CreateObject(session, keyTemplate, ARRAY_SIZE(keyTemplate), &key);
	if (rv != CKR_OK)
		return -EKEYREJECTED;

	return key;
}

static CK_OBJECT_HANDLE util_lib_find_objects(CK_FUNCTION_LIST_PTR flist, CK_SESSION_HANDLE session)
{
	CK_OBJECT_HANDLE key_match = 0;
	CK_ULONG num_keys;
	CK_RV rv;

	rv = flist->C_FindObjectsInit(session, NULL, 0);
	if (rv != CKR_OK)
		return 0;

	do {
		rv = flist->C_FindObjects(session, &key_match, 1, &num_keys);
		/* no extra processing required, just return last key found */
	} while (rv == CKR_OK && num_keys != 0);

	rv = flist->C_FindObjectsFinal(session);
	if (rv != CKR_OK)
		return 0;

	return key_match;
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
	uint8_t *rsa_modulus, *rsa_pub_exponent;
	FILE *f;
	char *libpath, *keypath, *arg_help = "help";
	int bytes, ret = 0;

	const BIGNUM *rsa_bn_modulus, *rsa_bn_pub_exponent;
	RSA *rsa;

	CK_FUNCTION_LIST_PTR flist;
	
	CK_SLOT_ID slot;
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE key_match, key;

	if (argc == 2 && !strncmp(argv[1], arg_help, sizeof(*arg_help))) {
		usage(argv[0]);
		return 0;
	}

	if (argc != 3) {
		ERROR("Incorrect number of arguments\n");
		usage(argv[0]);
		return -EINVAL;
	}

	libpath = argv[1];
	keypath = argv[2];

	INFO("Loading %s shared library...\n", libpath);

	lib_handle = dlopen(libpath, RTLD_LAZY);
	if (!lib_handle) {
		ERROR("Could not find PKCS#11 shared library %s - %s\n", libpath, dlerror());
		return -ELIBACC;
	}

	INFO("Opening %s key file...\n", keypath);

	f = fopen(keypath, "rb");
	if (!f) {
		ERROR("Could not find RSA Key file %s\n", keypath);
		ret = -ENOENT;
		goto err_close_lib;
	}

	INFO("Retrieving function list from %s...\n", libpath);

	flist = util_lib_get_function_list(lib_handle);
	if (!flist) {
		ERROR("Failed to find C_GetFunctionList in shared library - %s", dlerror());
		ret = -ENOSYS;
		goto err_close_fd;
	}

	INFO("Calling C_Initialize...\n");

	ret = util_lib_init(flist);
	if (ret) {
		ERROR("Failed call to C_Initialize\n");
		goto err_close_fd;
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

	INFO("Reading and converting key...\n");

	/* try reading in SubjectPublicKeyInfo format */
	rsa = PEM_read_RSA_PUBKEY(f, NULL, NULL, NULL);
	if (!rsa) {
		/* try reading in PKCS#1 RSAPublicKey format */
		rsa = PEM_read_RSAPublicKey(f, NULL, NULL, NULL);
		if (!rsa) {
			ERROR("Failed to read RSA Public Key from file %s\n", keypath);
			ret = -ENOKEY;
			goto err_lib_finalize;
		}
	}

	rsa_bn_modulus = RSA_get0_n(rsa);
	if (!rsa_bn_modulus) {
		ERROR("Failed to read RSA Public Key Modulus from file %s\n", keypath);
		ret = -ENOKEY;
		goto err_lib_finalize;
	}

	rsa_bn_pub_exponent = RSA_get0_e(rsa);
	if (!rsa_bn_pub_exponent) {
		ERROR("Failed to read RSA Public Key Exponent from file %s\n", keypath);
		ret = -ENOKEY;
		goto err_lib_finalize;
	}

	rsa_modulus = malloc(BN_num_bytes(rsa_bn_modulus));
	if (!rsa_modulus) {
		ERROR("Failed to allocate space for RSA Public Key Modulus\n");
		ret = -ENOMEM;
		goto err_lib_finalize;
	}

	rsa_pub_exponent = malloc(BN_num_bytes(rsa_bn_pub_exponent));
	if (!rsa_pub_exponent) {
		ERROR("Failed to allocate space for RSA Public Key Exponent\n");
		ret = -ENOMEM;
		goto err_free_rsa_modulus;
	}

	bytes = BN_bn2bin(rsa_bn_modulus, rsa_modulus);
	if (bytes != BN_num_bytes(rsa_bn_modulus)) {
		ERROR("Failed to copy RSA Public Key Modulus\n");
		ret = -ENOKEY;
		goto err_free_rsa_pub_exponent;
	}

	bytes = BN_bn2bin(rsa_bn_pub_exponent, rsa_pub_exponent);
	if (bytes != BN_num_bytes(rsa_bn_pub_exponent)) {
		ERROR("Failed to copy RSA Public Exponent\n");
		ret = -ENOKEY;
		goto err_free_rsa_pub_exponent;
	}

	INFO("Calling C_CreateObject with session ID #%ld...\n", session);

	key = util_lib_create_object(flist, session,
				     BN_num_bytes(rsa_bn_modulus), rsa_modulus,
				     BN_num_bytes(rsa_bn_pub_exponent), rsa_pub_exponent);
	if (!key) {
		ERROR("Failed to create key object\n");
		ret = -EKEYREJECTED;
		goto err_free_rsa_pub_exponent;
	}

	INFO("Calling C_FindObjects...\n");

	key_match = util_lib_find_objects(flist, session);
	if (!key_match) {
		ERROR("Failed to find key object\n");
		ret = -ENOKEY;
		goto err_free_rsa_pub_exponent;
	}

	INFO("Found Key Object with handle %06lx\n", key_match);
	INFO("Deleting Key Object with handle %06lx\n", key_match);

	ret = util_lib_destroy_object(flist, session, key_match);
	if (ret) {
		ERROR("Failed to destroy key object\n");
		goto err_free_rsa_pub_exponent;
	}

	INFO("Cleaning up and calling C_Finalize...\n");

err_free_rsa_pub_exponent:
	free(rsa_pub_exponent);
err_free_rsa_modulus:
	free(rsa_modulus);
err_lib_finalize:	
	if (util_lib_finalize(flist))
		ERROR("Failed call to C_Finalize\n");
err_close_fd:
	if (fclose(f))
		ERROR("Failed to close key file %s\n", keypath);
err_close_lib:
	if (dlclose(lib_handle))
		ERROR("Failed to close shared library %s - %s\n", libpath, dlerror());

	return ret;
}
