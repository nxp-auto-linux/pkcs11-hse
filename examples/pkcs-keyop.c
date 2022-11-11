// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2022 NXP
 */

/*
 * pkcs-keyop
 *
 * short example file showing key operations
 */

#include <stdio.h>
#include <libp11.h>

int main(int argc, char *argv[])
{
	PKCS11_CTX *pkcs_ctx;
	PKCS11_SLOT *enum_slots;
	unsigned int slot_cnt;
	PKCS11_SLOT *slot;
	EVP_PKEY_CTX *openssl_ctx;
	EVP_PKEY *pkey1 = NULL, *pkey2 = NULL;
	unsigned char keyid1[3], keyid2[3];
	PKCS11_KEY *keyp;
	unsigned int keycount;

	if (argc != 2) {
		printf("usage: ./pkcs-keyop <path>/libpkcs-hse.so\n");
		return -EINVAL;
	}

	/* create a context for loading pkcs11 module */
	pkcs_ctx = PKCS11_CTX_new();

	/* load pkcs11-hse module */
	if (PKCS11_CTX_load(pkcs_ctx, argv[1])) {
		printf("ERROR: failed to load pkcs11 module\n");
		goto module_err;
	}

	/* find all slots */
	if (PKCS11_enumerate_slots(pkcs_ctx, &enum_slots, &slot_cnt)) {
		printf("ERROR: no slots available\n");
		goto enumslot_err;
	}
	printf("\n%d slots available\n\n", slot_cnt);

	/* get first slot with a token */
	slot = PKCS11_find_token(pkcs_ctx, enum_slots, slot_cnt);
	if (slot == NULL || slot->token == NULL) {
		printf("ERROR: no token available\n");
		goto token_err;
	}
	printf("Using token:\n");
	printf("Manufacturer......: %s\n", slot->manufacturer);
	printf("Description.......: %s\n", slot->description);
	printf("Token label.......: %s\n\n", slot->token->label);

	/* check how many keys are stored */
	if (PKCS11_enumerate_keys(slot->token, &keyp, &keycount)) {
		printf("ERROR: could not enumerate keys\n");
		goto token_err;
	}
	printf("Keys available: %d\n\n", keycount);

	/* create openssl context */
	openssl_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	if (!openssl_ctx) {
		printf("ERROR: openssl context creation failed\n");
		goto token_err;
	}

	/* init openssl context for keygen */
	if (EVP_PKEY_keygen_init(openssl_ctx) <= 0) {
		printf("ERROR: openssl keygen init failed\n");
		goto keygen_err;
	}

	/* set openssl keygen params */
	if (EVP_PKEY_CTX_set_rsa_keygen_bits(openssl_ctx, 2048) <= 0) {
		printf("ERROR: openssl keygen configuration failed\n");
		goto keygen_err;
	}

	/* generate 2 keys */
	if (EVP_PKEY_keygen(openssl_ctx, &pkey1) <= 0) {
		printf("ERROR: openssl keygen failed\n");
		goto keygen_err;
	}

	if (EVP_PKEY_keygen(openssl_ctx, &pkey2) <= 0) {
		printf("ERROR: openssl keygen failed\n");
		goto keygen_err;
	}

	/* 
	 * set an ID for the keys we want to import
	 * from MSB to LSB:
	 *     - keyid[2] - catalog ID
	 *     - keyid[1] - group ID
	 *     - keyid[0] - slot ID
	 * HSE key IDs can only be composed of 3 bytes
	 */
	keyid1[0] = 0x00;
	keyid1[1] = 0x06;
	keyid1[2] = 0x01;

	keyid2[0] = 0x01;
	keyid2[1] = 0x06;
	keyid2[2] = 0x01;

	/* 
	 * store the the key pairs
	 *
	 * PKCS11_store_private_key sends both the private and public key info
	 * to the module, so we can use it to store a key pair
	 */
	if (PKCS11_store_private_key(slot->token, pkey1, "HSE Key Pair", keyid1, sizeof(keyid1))) {
		printf("ERROR: could not store key pair #1\n");
	} else {
		printf("Key pair #1 stored\n");
	}

	if (PKCS11_store_private_key(slot->token, pkey2, "HSE Key Pair", keyid2, sizeof(keyid2))) {
		printf("ERROR: could not store key pair #2\n\n");
	} else {
		printf("Key pair #2 stored\n\n");
	}

	/* check how many keys are stored now */
	if (PKCS11_enumerate_keys(slot->token, &keyp, &keycount)) {
		printf("ERROR: could not enumerate keys\n");
		goto keygen_err;
	}
	printf("Keys available: %d\n\n", keycount);

	/* remove the first key */
	if(PKCS11_remove_key(&keyp[0])) {
		printf("ERROR: could not remove key #1\n");
		goto keygen_err;
	}
	printf("Key removed\n");

keygen_err:
	EVP_PKEY_CTX_free(openssl_ctx);
token_err:
	PKCS11_release_all_slots(pkcs_ctx, enum_slots, slot_cnt);
enumslot_err:
	PKCS11_CTX_unload(pkcs_ctx);
module_err:
	PKCS11_CTX_free(pkcs_ctx);
	return 0;
}
