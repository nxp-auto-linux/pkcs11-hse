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
#include <unistd.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

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

#define HEX_DUMP_ON	(0)

#if (HEX_DUMP_ON == 1)
static void hex_dump(char *name, const unsigned char *hex, unsigned long len)
{
	int i;

	printf("\tHex Dump - %s:", name);
	
	for (i = 0; i < len; i++) {
		if ((i & 0xF) == 0)
			printf("\n\t\t%02X ", hex[i]);
		else 
			printf("%02X ", hex[i]);
	}
	printf("\n");
}
#endif

void usage(const char* progname)
{
	printf("\n%s - Message digesting example\n", progname);
	printf("\n");
	printf("\t%s -p /home/<user>/pkcs/libpkcs-hse.so -l 1024\n", progname);
	printf("\n");
	printf("Usage:\n");
	printf("%s -h\n", progname);
	printf("%s -p <lib> -l <input_length>\n", progname);
	printf("\n");
	printf("\t-p <lib>          - full path to PKCS#11 shared library\n");
	printf("\t-l <input_length> - length of message\n");
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

static int util_lib_msg_digest_onepass(CK_FUNCTION_LIST_PTR flist, CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism, 
						unsigned char *msg, CK_ULONG msg_length, unsigned char *digest, CK_ULONG *digest_length)
{
	CK_RV rv;

	rv = flist->C_DigestInit(session, mechanism);
	if (rv != CKR_OK) {
		ERROR("C_DigestInit error %ld\n", rv);
		return -1;
	}

	rv = flist->C_Digest(session, msg, msg_length, digest, digest_length);
	if (rv != CKR_OK) {
		ERROR("C_Digest error %ld\n", rv);
		return -1;
	}

	return 0;
}

static int util_lib_msg_digest_update(CK_FUNCTION_LIST_PTR flist, CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism, 
						unsigned char *msg, CK_ULONG msg_length, unsigned char *digest, CK_ULONG *digest_length)
{
	CK_RV rv;
	CK_ULONG part_len = 200;
	int part_num;

	rv = flist->C_DigestInit(session, mechanism);
	if (rv != CKR_OK) {
		ERROR("C_DigestInit error %ld\n", rv);
		return -1;
	}

	for (part_num = 0; part_num < (msg_length / part_len); part_num++) {
		rv = flist->C_DigestUpdate(session, msg + (part_num * part_len), part_len);
		if (rv != CKR_OK) {
			ERROR("C_DigestUpdate error %ld\n", rv);
			return -1;
		}
	}

	if ((msg_length % part_len) != 0) {
		rv = flist->C_DigestUpdate(session, msg + (part_num * part_len), msg_length % part_len);
		if (rv != CKR_OK) {
			ERROR("C_DigestUpdate error %ld\n", rv);
			return -1;
		}
	}

	rv = flist->C_DigestFinal(session, digest, digest_length);
	if (rv != CKR_OK) {
		ERROR("C_DigestFinal error %ld\n", rv);
		return -1;
	}

	return 0;
}

static int output_compare(const unsigned char *src, const unsigned char *ref, unsigned long len)
{
#if (HEX_DUMP_ON == 1)
	hex_dump("Digest(HSE)", src, len);
	hex_dump("Digest(OpenSSL)", ref, len);
#endif

	return memcmp(src, ref, len);
}

static int util_msg_digest_test(CK_FUNCTION_LIST_PTR flist, CK_SESSION_HANDLE session, 
				unsigned char *msg, CK_ULONG msg_length)
{
	int ret = 0;
	CK_MECHANISM mach_digest;
	unsigned char digest[64];
	unsigned char digest_openssl[64];
	CK_ULONG digest_length = 64;

	/* Prepare random input */
	RAND_seed("random.", strlen("random."));
	RAND_bytes(msg, msg_length);

#if (HEX_DUMP_ON == 1)
	hex_dump("Input (random)", msg, msg_length);
#endif

	/* SHA1 test */
	mach_digest.mechanism = CKM_SHA_1;
	ret = util_lib_msg_digest_onepass(flist, session, &mach_digest, msg, msg_length, digest, &digest_length);
	if (!ret) {
		/* compare with openssl result */
		SHA1(msg, msg_length, digest_openssl);
		if (!output_compare(digest, digest_openssl, digest_length))
			INFO("CKM_SHA_1 Pass\n");
		else
			INFO("CKM_SHA_1 Fail\n");
	}

	/* SHA224 test */
	digest_length = 64;
	mach_digest.mechanism = CKM_SHA224;
	ret = util_lib_msg_digest_onepass(flist, session, &mach_digest, msg, msg_length, digest, &digest_length);
	if (!ret) {
		/* compare with openssl result */
		SHA224(msg, msg_length, digest_openssl);
		if (!output_compare(digest, digest_openssl, digest_length))
			INFO("CKM_SHA224 Pass\n");
		else
			INFO("CKM_SHA224 Fail\n");
	}

	/* SHA256 test */
	digest_length = 64;
	mach_digest.mechanism = CKM_SHA256;
	ret = util_lib_msg_digest_onepass(flist, session, &mach_digest, msg, msg_length, digest, &digest_length);
	if (!ret) {
		/* compare with openssl result */
		SHA256(msg, msg_length, digest_openssl);
		if (!output_compare(digest, digest_openssl, digest_length))
			INFO("CKM_SHA256 Pass\n");
		else
			INFO("CKM_SHA256 Fail\n");
	}

	/* SHA512 test */
	digest_length = 64;
	mach_digest.mechanism = CKM_SHA512;
	ret = util_lib_msg_digest_onepass(flist, session, &mach_digest, msg, msg_length, digest, &digest_length);
	if (!ret) {
		/* compare with openssl result */
		SHA512(msg, msg_length, digest_openssl);
		if (!output_compare(digest, digest_openssl, digest_length))
			INFO("CKM_SHA512 Pass\n");
		else
			INFO("CKM_SHA512 Fail\n");
	}

	/* SHA1 test */
	mach_digest.mechanism = CKM_SHA_1;
	ret = util_lib_msg_digest_update(flist, session, &mach_digest, msg, msg_length, digest, &digest_length);
	if (!ret) {
		/* compare with openssl result */
		SHA1(msg, msg_length, digest_openssl);
		if (!output_compare(digest, digest_openssl, digest_length))
			INFO("CKM_SHA_1 Pass\n");
		else
			INFO("CKM_SHA_1 Fail\n");
	}

	/* SHA224 test */
	digest_length = 64;
	mach_digest.mechanism = CKM_SHA224;
	ret = util_lib_msg_digest_update(flist, session, &mach_digest, msg, msg_length, digest, &digest_length);
	if (!ret) {
		/* compare with openssl result */
		SHA224(msg, msg_length, digest_openssl);
		if (!output_compare(digest, digest_openssl, digest_length))
			INFO("CKM_SHA224 Pass\n");
		else
			INFO("CKM_SHA224 Fail\n");
	}

	/* SHA256 test */
	digest_length = 64;
	mach_digest.mechanism = CKM_SHA256;
	ret = util_lib_msg_digest_update(flist, session, &mach_digest, msg, msg_length, digest, &digest_length);
	if (!ret) {
		/* compare with openssl result */
		SHA256(msg, msg_length, digest_openssl);
		if (!output_compare(digest, digest_openssl, digest_length))
			INFO("CKM_SHA256 Pass\n");
		else
			INFO("CKM_SHA256 Fail\n");
	}

	/* SHA512 test */
	digest_length = 64;
	mach_digest.mechanism = CKM_SHA512;
	ret = util_lib_msg_digest_update(flist, session, &mach_digest, msg, msg_length, digest, &digest_length);
	if (!ret) {
		/* compare with openssl result */
		SHA512(msg, msg_length, digest_openssl);
		if (!output_compare(digest, digest_openssl, digest_length))
			INFO("CKM_SHA512 Pass\n");
		else
			INFO("CKM_SHA512 Fail\n");
	}

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
	int opt = 0;
	void *lib_handle;
	char *libpath = NULL;
	CK_ULONG msg_length = 0;
	int ret = 0;
	unsigned char *msg_rand = NULL;

	CK_FUNCTION_LIST_PTR flist;
	
	CK_SLOT_ID slot;
	CK_SESSION_HANDLE session;

	while((opt = getopt(argc, argv, "hl:p:")) != -1) {
		switch (opt) {
			case 'p':
				libpath = optarg;
			case 'l':
				msg_length = (CK_ULONG)atoi(optarg);
				break;
			case 'h':
				usage(argv[0]);
				return 0;
		}
	}

	if (libpath == NULL) {
		usage(argv[0]);
		return -EINVAL;
	}

	if (msg_length == 0) {
		INFO("Input length was missed, use the default length: 128 bytes\n");
		msg_length = 128;
	}

	INFO("Loading %s shared library...\n", libpath);

	lib_handle = dlopen(libpath, RTLD_LAZY);
	if (!lib_handle) {
		ERROR("Could not find PKCS#11 shared library %s - %s\n", libpath, dlerror());
		return -ELIBACC;
	}

	/* Prepare input */
	INFO("Input message length: %ld\n", msg_length);
	msg_rand = malloc(msg_length);
	if (NULL == msg_rand) {
		ret = -ENOMEM;
		goto err_close_lib;
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

	INFO("Start digest test...\n");
	util_msg_digest_test(flist, session, msg_rand, msg_length);

	INFO("Cleaning up and calling C_Finalize...\n");


err_lib_finalize:	
	if (util_lib_finalize(flist))
		ERROR("Failed call to C_Finalize\n");
err_close_lib:
	if (dlclose(lib_handle))
		ERROR("Failed to close shared library %s - %s\n", libpath, dlerror());

	return ret;
}
