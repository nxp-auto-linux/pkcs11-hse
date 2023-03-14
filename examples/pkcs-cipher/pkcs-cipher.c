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

static CK_RV util_lib_close_sessions(CK_FUNCTION_LIST_PTR flist, CK_SLOT_ID slot)
{
	CK_RV rv;

	rv = flist->C_CloseAllSessions(slot);

	return rv;
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
	CK_BYTE key_id[] = { 0x05, 0x02, 0x02 };
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

	do {
		rv = flist->C_FindObjects(session, &match_key, 1, &num_keys);
		/* no extra processing required, just return last key found */
	} while (rv == CKR_OK && num_keys != 0);

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

static int block_ciphering(CK_FUNCTION_LIST_PTR flist, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key, CK_MECHANISM_PTR p_mech)
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

static int block_ciphering_parts(CK_FUNCTION_LIST_PTR flist, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key, CK_MECHANISM_PTR p_mech)
{
	CK_RV rv;
	int32_t i, test_loop;

	#define TEST_DATA_LEN		(128)
	#define TEST_PART_GROUPS	(10)

	unsigned char plain_text[TEST_DATA_LEN] = {0};

	/* testing length groups */
	CK_ULONG len1[TEST_PART_GROUPS] = {8,	16,	5,	40,	14,	1,	32, 80, 12,	10};
	CK_ULONG len2[TEST_PART_GROUPS] = {16,	16, 7,	20,	2,	1,	15, 10,	13,	2};
	CK_ULONG len3[TEST_PART_GROUPS] = {15,	32,	65,	10, 80,	2,	14, 10,	4, 	3};
	CK_ULONG len4[TEST_PART_GROUPS] = {25,	64,	19,	10, 16,	12,	3, 	12,	3,	1};

	CK_ULONG p1, p2, p3, p4;
	CK_ULONG in_pos, out_pos;

	unsigned char cipher_text[TEST_DATA_LEN] = {0};
	unsigned char cipher_text_ref[TEST_DATA_LEN] = {0};
	unsigned char decrypted_text[TEST_DATA_LEN] = {0};

	CK_ULONG cipher_text_len, decrypt_text_len;

	/* Init the plain text buffer */
	for (i = 0; i < TEST_DATA_LEN; i++)
		plain_text[i] = i;

	for (test_loop = 0; test_loop < TEST_PART_GROUPS; test_loop++) {
		p1 = len1[test_loop];
		p2 = len2[test_loop];
		p3 = len3[test_loop];
		p4 = len4[test_loop];

		INFO("Length: %ld + %ld + %ld + %ld (%ld)\n", p1, p2, p3, p4, p1+p2+p3+p4);

		in_pos = 0;
		out_pos = 0;

		cipher_text_len = sizeof(cipher_text);
		decrypt_text_len = sizeof(decrypted_text);

		/* encrypt:  plain_text -> cipher_text */
		rv = flist->C_EncryptInit(session, p_mech, key);
		if (rv != CKR_OK) {
			ERROR("Error at line [%d], rv=0x%lX\n", __LINE__, rv);
			continue;
		}

		rv = flist->C_EncryptUpdate(session, plain_text, p1, cipher_text, &cipher_text_len);
		if (rv != CKR_OK) {
			ERROR("Error at line [%d], rv=0x%lX\n", __LINE__, rv);
			continue;
		}
		
		in_pos += p1;
		out_pos += cipher_text_len;
		cipher_text_len = sizeof(cipher_text) - out_pos;
		rv = flist->C_EncryptUpdate(session, &plain_text[in_pos], p2, &cipher_text[out_pos], &cipher_text_len);
		if (rv != CKR_OK) {
			ERROR("Error at line [%d], rv=0x%lX\n", __LINE__, rv);
			continue;
		}

		/* CKR_BUFFER_TOO_SMALL test */
		in_pos += p2;
		out_pos += cipher_text_len;
		cipher_text_len = 0;
		rv = flist->C_EncryptUpdate(session, &plain_text[in_pos], p3, &cipher_text[out_pos], &cipher_text_len);
		if ((rv != CKR_BUFFER_TOO_SMALL) && (rv != CKR_OK)) {
			ERROR("Error at line [%d], rv=0x%lX\n", __LINE__, rv);
		}

		if (rv == CKR_BUFFER_TOO_SMALL) {
			cipher_text_len = sizeof(cipher_text) - out_pos;
			rv = flist->C_EncryptUpdate(session, &plain_text[in_pos], p3, &cipher_text[out_pos], &cipher_text_len);
			if (rv != CKR_OK) {
				ERROR("Error at line [%d], rv=0x%lX\n", __LINE__, rv);
				continue;
			}
		}

		in_pos += p3;
		out_pos += cipher_text_len;
		cipher_text_len = sizeof(cipher_text) - out_pos;
		rv = flist->C_EncryptUpdate(session, &plain_text[in_pos], p4, &cipher_text[out_pos], &cipher_text_len);
		if (rv != CKR_OK) {
			ERROR("Error at line [%d], rv=0x%lX\n", __LINE__, rv);
			continue;
		}

		in_pos += p4;
		out_pos += cipher_text_len;
		cipher_text_len = sizeof(cipher_text) - out_pos;
		rv = flist->C_EncryptFinal(session, &cipher_text[out_pos], &cipher_text_len);
		if (rv != CKR_OK) {
			ERROR("Error at line [%d], rv=0x%lX\n", __LINE__, rv);
			continue;
		}

		out_pos += cipher_text_len;

		if (out_pos != in_pos) {
			ERROR("Stream: encrypted data length was wrong\n");
			continue;
		}

		/* encrypt:  plain_text -> cipher_text_ref */
		rv = flist->C_EncryptInit(session, p_mech, key);
		if (rv != CKR_OK) {
			ERROR("Error at line [%d], rv=0x%lX\n", __LINE__, rv);
			continue;
		}

		cipher_text_len = sizeof(cipher_text_ref);
		rv = flist->C_Encrypt(session, plain_text, p1+p2+p3+p4, cipher_text_ref, &cipher_text_len);
		if (rv != CKR_OK) {
			ERROR("Error at line [%d], rv=0x%lX\n", __LINE__, rv);
			continue;
		}

		if ( (cipher_text_len != out_pos) ||
				(memcmp(cipher_text, cipher_text_ref, cipher_text_len) != 0)) {
			ERROR("Stream: Encryption data error\n");
			continue;
		}

		/* decrypt:  cipher_text -> decrypted_text */
		rv = flist->C_DecryptInit(session, p_mech, key);
		if (rv != CKR_OK) {
			ERROR("Error at line [%d], rv=0x%lX\n", __LINE__, rv);
			continue;
		}

		rv = flist->C_Decrypt(session, cipher_text, out_pos, decrypted_text, &decrypt_text_len);
		if (rv != CKR_OK) {
			ERROR("Error at line [%d], rv=0x%lX\n", __LINE__, rv);
			continue;
		}
		
		if (memcmp(decrypted_text, plain_text, decrypt_text_len) != 0) {
			ERROR("Stream: encryption data was wrong\n");
			continue;
		}


		/* stream decryption */
		memset(decrypted_text, 0x0, sizeof(decrypted_text));
		in_pos = 0;
		out_pos = 0;

		rv = flist->C_DecryptInit(session, p_mech, key);
		if (rv != CKR_OK) {
			ERROR("Error at line [%d], rv=0x%lX\n", __LINE__, rv);
			continue;
		}

		rv = flist->C_DecryptUpdate(session, cipher_text, p1, decrypted_text, &decrypt_text_len);
		if (rv != CKR_OK) {
			ERROR("Error at line [%d], rv=0x%lX\n", __LINE__, rv);
			continue;
		}

		in_pos += p1;
		out_pos += decrypt_text_len;
		decrypt_text_len = sizeof(cipher_text) - out_pos;
		rv = flist->C_DecryptUpdate(session, &cipher_text[in_pos], p2, &decrypted_text[out_pos], &decrypt_text_len);
		if (rv != CKR_OK) {
			ERROR("Error at line [%d], rv=0x%lX\n", __LINE__, rv);
			continue;
		}

		in_pos += p2;
		out_pos += decrypt_text_len;
		decrypt_text_len = sizeof(cipher_text) - out_pos;
		rv = flist->C_DecryptUpdate(session, &cipher_text[in_pos], p3, &decrypted_text[out_pos], &decrypt_text_len);
		if (rv != CKR_OK) {
			ERROR("Error at line [%d], rv=0x%lX\n", __LINE__, rv);
			continue;
		}

		/* CKR_BUFFER_TOO_SMALL test */
		in_pos += p3;
		out_pos += decrypt_text_len;
		decrypt_text_len = 0;
		rv = flist->C_DecryptUpdate(session, &cipher_text[in_pos], p4, &decrypted_text[out_pos], &decrypt_text_len);
		if ((rv != CKR_BUFFER_TOO_SMALL) && (rv != CKR_OK)) {
			ERROR("Error at line [%d], rv=0x%lX\n", __LINE__, rv);
		}

		if (rv == CKR_BUFFER_TOO_SMALL) {
			decrypt_text_len = sizeof(cipher_text) - out_pos;
			rv = flist->C_DecryptUpdate(session, &cipher_text[in_pos], p4, &decrypted_text[out_pos], &decrypt_text_len);
			if (rv != CKR_OK) {
				ERROR("Error at line [%d], rv=0x%lX\n", __LINE__, rv);
				continue;
			}
		}

		in_pos += p4;
		out_pos += decrypt_text_len;
		decrypt_text_len = sizeof(cipher_text) - out_pos;
		rv = flist->C_DecryptFinal(session, &decrypted_text[out_pos], &decrypt_text_len);
		if (rv != CKR_OK) {
			ERROR("Error at line [%d], rv=0x%lX\n", __LINE__, rv);
			continue;
		}

		out_pos += decrypt_text_len;

		if (out_pos != in_pos) {
			ERROR("Stream: Decrypted data length was wrong\n");
			continue;
		}

		/* compare */
		if (memcmp(decrypted_text, plain_text, out_pos) != 0) {
			ERROR("Stream: encryption data was wrong\n");
			continue;
		}
	}

	if (test_loop != TEST_PART_GROUPS)
		return -1;

	return 0;
}

static int util_lib_block_ciphering(CK_FUNCTION_LIST_PTR flist, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key)
{
	int ret;
	CK_MECHANISM mechanism;

	mechanism.mechanism = CKM_AES_ECB;
	mechanism.pParameter = NULL;
	ret = block_ciphering(flist, session, key, &mechanism);
	if (ret == 0)
		INFO("CKM_AES_ECB Done!\n");
	else 
		INFO("CKM_AES_ECB Fail!\n");

	ret = block_ciphering_parts(flist, session, key, &mechanism);
	if (ret == 0)
		INFO("Stream CKM_AES_ECB Done!\n");
	else 
		INFO("Stream CKM_AES_ECB Fail!\n");

	mechanism.mechanism = CKM_AES_CBC;
	mechanism.ulParameterLen = 16;
	mechanism.pParameter = iv;
	ret = block_ciphering(flist, session, key, &mechanism);
	if (ret == 0)
		INFO("CKM_AES_CBC Done!\n");
	else 
		INFO("CKM_AES_CBC Fail!\n");

	ret = block_ciphering_parts(flist, session, key, &mechanism);
	if (ret == 0)
		INFO("Stream CKM_AES_CBC Done!\n");
	else 
		INFO("Stream CKM_AES_CBC Fail!\n");

	mechanism.mechanism = CKM_AES_CTR;
	mechanism.ulParameterLen = 16;
	mechanism.pParameter = iv;
	ret = block_ciphering(flist, session, key, &mechanism);
	if (ret == 0)
		INFO("CKM_AES_CTR Done!\n");
	else 
		INFO("CKM_AES_CTR Fail!\n");

	ret = block_ciphering_parts(flist, session, key, &mechanism);
	if (ret == 0)
		INFO("Stream CKM_AES_CTR Done!\n");
	else 
		INFO("Stream CKM_AES_CTR Fail!\n");

	mechanism.mechanism = CKM_AES_GCM;
	mechanism.ulParameterLen = 16;
	mechanism.pParameter = iv;
	ret = block_ciphering(flist, session, key, &mechanism);
	if (ret == 0)
		INFO("CKM_AES_GCM Done!\n");
	else 
		INFO("CKM_AES_GCM Fail!\n");

	return 0;
}

static int util_lib_rsa_ciphering(CK_FUNCTION_LIST_PTR flist, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE pub_key, CK_OBJECT_HANDLE priv_key)
{
	CK_RV rv;
	CK_MECHANISM mechanism;
	char *plain_text = "rsa ciphering test; rsa ciphering test; rsa ciphering test";
	uint8_t cipher_text[256] = {0};
	CK_ULONG cipher_text_len = ARRAY_SIZE(cipher_text);
	uint8_t decrypted_text[64] = {0};
	CK_ULONG decrypted_text_length = 0;
	CK_RSA_PKCS_OAEP_PARAMS rsa_oaep_param;

	mechanism.mechanism = CKM_RSA_PKCS;
	mechanism.pParameter = NULL;
	mechanism.ulParameterLen = 0;

	INFO("CKM_RSA_PKCS encrypt/decrypt ...\n");
	/* encrypt:  plain_text -> cipher_text */
	rv = flist->C_EncryptInit(session, &mechanism, pub_key);
	if (rv != CKR_OK) {
		INFO("C_EncryptInit returns error 0x%lx\n", rv);
		return -1;
	}

	rv = flist->C_Encrypt(session, (uint8_t *)plain_text, strlen(plain_text), cipher_text, &cipher_text_len);
	if (rv != CKR_OK) {
		INFO("C_Encrypt returns error 0x%lx\n", rv);
		return -1;
	}

	/* decrypt: cipher_text -> decrypted_text */
	rv = flist->C_DecryptInit(session, &mechanism, priv_key);
	if (rv != CKR_OK) {
		INFO("C_DecryptInit returns error 0x%lx\n", rv);
		return -1;
	}

	decrypted_text_length = ARRAY_SIZE(decrypted_text);
	rv = flist->C_Decrypt(session, (uint8_t *)cipher_text, sizeof(cipher_text), decrypted_text, &decrypted_text_length);
	if (rv != CKR_OK) {
		INFO("C_Decrypt returns error 0x%lx\n", rv);
		return -1;
	}

	if (memcmp((void *)plain_text, (void *)decrypted_text, decrypted_text_length) == 0)
		INFO("CKM_RSA_PKCS Done!\n");
	else 
		INFO("CKM_RSA_PKCS Fail!\n");

	INFO("CKM_RSA_PKCS_OAEP encrypt/decrypt ...\n");
	mechanism.mechanism = CKM_RSA_PKCS_OAEP;
	mechanism.pParameter = (void *)&rsa_oaep_param;
	mechanism.ulParameterLen = sizeof(CK_RSA_PKCS_OAEP_PARAMS);
	rsa_oaep_param.hashAlg = CKM_SHA_1;

	/* encrypt:  plain_text -> cipher_text */
	rv = flist->C_EncryptInit(session, &mechanism, pub_key);
	if (rv != CKR_OK) {
		INFO("C_EncryptInit returns error 0x%lx\n", rv);
		return -1;
	}

	rv = flist->C_Encrypt(session, (uint8_t *)plain_text, strlen(plain_text), cipher_text, &cipher_text_len);
	if (rv != CKR_OK) {
		INFO("C_Encrypt returns error 0x%lx\n", rv);
		return -1;
	}

	/* decrypt: cipher_text -> decrypted_text */
	rv = flist->C_DecryptInit(session, &mechanism, priv_key);
	if (rv != CKR_OK) {
		INFO("C_DecryptInit returns error 0x%lx\n", rv);
		return -1;
	}

	decrypted_text_length = ARRAY_SIZE(decrypted_text);
	rv = flist->C_Decrypt(session, (uint8_t *)cipher_text, sizeof(cipher_text), decrypted_text, &decrypted_text_length);
	if (rv != CKR_OK) {
		INFO("C_Decrypt returns error 0x%lx\n", rv);
		return -1;
	}

	if (memcmp((void *)plain_text, (void *)decrypted_text, decrypted_text_length) == 0)
		INFO("CKM_RSA_PKCS_OAEP Done!\n");
	else 
		INFO("CKM_RSA_PKCS_OAEP Fail!\n");

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
	CK_OBJECT_HANDLE aes_key, key, rsa_pub_key, rsa_priv_key;

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
		goto err_close_session;
	}

	INFO("Calling C_FindObjects...\n");

	aes_key = util_lib_find_objects(flist, session, "HSE-AES-128");
	if (!aes_key) {
		ERROR("Failed to find key object with Class CKO_SECRET_KEY\n");
		ret = -ENOKEY;
		goto err_close_session;
	}

	INFO("Found Key Object with handle %06lx\n", aes_key);

	INFO("Block ciphering...\n");
	/* block ciphering */
	util_lib_block_ciphering(flist, session, aes_key);

	INFO("RSA ciphering...\n");
	/* RSA ciphering */
	rsa_pub_key = util_lib_find_objects(flist, session, "HSE-RSAPUB-KEY");
	if (!rsa_pub_key) {
		ERROR("Failed to find key object with Class CKO_PUBLIC_KEY\n");
		ret = -ENOKEY;
		goto err_close_session;
	}

	INFO("Found Key Object with handle %06lx\n", rsa_pub_key);

	rsa_priv_key = util_lib_find_objects(flist, session, "HSE-RSAPRIV-KEY");
	if (!rsa_priv_key) {
		ERROR("Failed to find key object with Class CKO_PRIVATE_KEY\n");
		ret = -ENOKEY;
		goto err_close_session;
	}

	INFO("Found Key Object with handle %06lx\n", rsa_priv_key);

	util_lib_rsa_ciphering(flist, session, rsa_pub_key, rsa_priv_key);

	INFO("Deleting Key Object with handle %06lx\n", aes_key);

	ret = util_lib_destroy_object(flist, session, aes_key);
	if (ret) {
		ERROR("Failed to destroy key object\n");
		goto err_close_session;
	}

	INFO("Cleaning up and calling C_Finalize...\n");

err_close_session:
	util_lib_close_sessions(flist, slot);
err_lib_finalize:	
	if (util_lib_finalize(flist))
		ERROR("Failed call to C_Finalize\n");
err_close_lib:
	if (dlclose(lib_handle))
		ERROR("Failed to close shared library %s - %s\n", libpath, dlerror());

	return ret;
}
