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

static unsigned char key_value_AES_128[] = {
	0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF
};

static unsigned char iv[] = {
	0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12
};

void usage(const char* progname)
{
	printf("\n%s - PKCS11 block cipher example\n", progname);
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

static CK_OBJECT_HANDLE util_lib_create_object(CK_FUNCTION_LIST_PTR flist, CK_SESSION_HANDLE session,
					       int aes_key_len, uint8_t *key_value)
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
	CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
	CK_KEY_TYPE key_type = CKK_AES;
	CK_UTF8CHAR label[] = {"HSE-AES-128"};
	CK_BYTE key_id[] = { 0x03, 0x00, 0x02 };
	CK_ATTRIBUTE keyTemplate[] = {
		{ CKA_LABEL, label, sizeof(label)-1 },
		{ CKA_CLASS, &key_class, sizeof(key_class) },
		{ CKA_KEY_TYPE, &key_type, sizeof(key_type) },
		{ CKA_ID, &key_id, sizeof(key_id) },
		{ CKA_VALUE, (CK_BYTE_PTR)key_value, aes_key_len }
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

static int ciphering(CK_FUNCTION_LIST_PTR flist, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key, CK_MECHANISM_PTR p_mech)
{
	CK_RV rv;

	unsigned char plain_text[16] = {
		0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf
	};
	unsigned char cipher_text[16] = {0};
	unsigned char decrypted_text[16] = {0};

	CK_ULONG cipher_text_len = sizeof(cipher_text);
	CK_ULONG decrypt_text_len = sizeof(decrypted_text);

	/* encrypt:  plain_text -> cipher_text */
	rv = flist->C_EncryptInit(session, p_mech, key);
	if (rv != CKR_OK)
		return -1;

	rv = flist->C_Encrypt(session, plain_text, sizeof(plain_text), cipher_text, &cipher_text_len);
	if (rv != CKR_OK)
		return -1;

	/* decrypt:  cipher_text -> decrypted_text */
	rv = flist->C_DecryptInit(session, p_mech, key);
	if (rv != CKR_OK)
		return -1;

	rv = flist->C_Decrypt(session, cipher_text, cipher_text_len, decrypted_text, &decrypt_text_len);
	if (rv != CKR_OK)
		return -1;
	
	/* compare */
	return memcmp(decrypted_text, plain_text, decrypt_text_len);
}

static int util_lib_ciphering(CK_FUNCTION_LIST_PTR flist, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key)
{
	int ret;
	CK_MECHANISM mechanism;

	mechanism.mechanism = CKM_AES_ECB;
	mechanism.pParameter = NULL;
	ret = ciphering(flist, session, key, &mechanism);
	if (ret == 0)
		INFO("CKM_AES_ECB Done!\n");
	else 
		INFO("CKM_AES_ECB Fail!\n");

	mechanism.mechanism = CKM_AES_CBC;
	mechanism.ulParameterLen = 16;
	mechanism.pParameter = iv;
	ret = ciphering(flist, session, key, &mechanism);
	if (ret == 0)
		INFO("CKM_AES_CBC Done!\n");
	else 
		INFO("CKM_AES_CBC Fail!\n");

	mechanism.mechanism = CKM_AES_CTR;
	mechanism.ulParameterLen = 16;
	mechanism.pParameter = iv;
	ret = ciphering(flist, session, key, &mechanism);
	if (ret == 0)
		INFO("CKM_AES_CTR Done!\n");
	else 
		INFO("CKM_AES_CTR Fail!\n");

	mechanism.mechanism = CKM_AES_GCM;
	mechanism.ulParameterLen = 16;
	mechanism.pParameter = iv;
	ret = ciphering(flist, session, key, &mechanism);
	if (ret == 0)
		INFO("CKM_AES_GCM Done!\n");
	else 
		INFO("CKM_AES_GCM Fail!\n");

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
	CK_OBJECT_HANDLE key_match, key;

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

	INFO("Install an AES-128 RAM key ...\n");
	INFO("Calling C_CreateObject with session ID #%ld...\n", session);

	key = util_lib_create_object(flist, session, 16, key_value_AES_128);
	if (!key) {
		ERROR("Failed to create key object\n");
		ret = -EKEYREJECTED;
		goto err_lib_finalize;
	}

	INFO("Calling C_FindObjects...\n");

	key_match = util_lib_find_objects(flist, session);
	if (!key_match) {
		ERROR("Failed to find key object\n");
		ret = -ENOKEY;
		goto err_lib_finalize;
	}

	INFO("Found Key Object with handle %06lx\n", key_match);

	/* ciphering */
	util_lib_ciphering(flist, session, key);

	INFO("Deleting Key Object with handle %06lx\n", key_match);

	ret = util_lib_destroy_object(flist, session, key_match);
	if (ret) {
		ERROR("Failed to destroy key object\n");
		goto err_lib_finalize;
	}

	INFO("Cleaning up and calling C_Finalize...\n");

err_lib_finalize:	
	if (util_lib_finalize(flist))
		ERROR("Failed call to C_Finalize\n");
err_close_lib:
	if (dlclose(lib_handle))
		ERROR("Failed to close shared library %s - %s\n", libpath, dlerror());

	return ret;
}
