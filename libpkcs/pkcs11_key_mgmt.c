// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "pkcs11_key_mgmt.h"
#include "pkcs11_context.h"
#include "hse_interface.h"

#define MAX_SLOTS_PER_RING 64 /* slot mask defined as uint64_t */

static CK_RV init_single_ring(struct key_ring *ring, uint32_t *handles)
{
	uint8_t i;

	if (ring->total_slots > MAX_SLOTS_PER_RING)
		return CKR_ARGUMENTS_BAD;

	/* Initialize mask with all slots available */
	if (ring->total_slots == MAX_SLOTS_PER_RING)
		ring->available_mask = UINT64_MAX;
	else
		ring->available_mask = BIT64(ring->total_slots) - 1;

	if (pthread_spin_init(&ring->ring_lock, PTHREAD_PROCESS_SHARED) != 0)
		return CKR_FUNCTION_FAILED;

	for (i = 0; i < ring->total_slots; i++)
		handles[i] = GET_KEY_HANDLE(ring->catalog, ring->group, i);

	return CKR_OK;
}

static struct key_ring *get_ring_by_type(struct rings *rings,
                                         hseKeyType_t hse_key_type,
                                         enum object_domain is_token)
{
	if (is_token == TOKEN_OBJ) {
		switch (hse_key_type) {
		case HSE_KEY_TYPE_AES:
			return &rings->aes_token;
		case HSE_KEY_TYPE_HMAC:
			return &rings->hmac_token;
		case HSE_KEY_TYPE_ECC_PAIR:
			return &rings->ecc_pair_token;
		case HSE_KEY_TYPE_ECC_PUB:
			return &rings->ecc_pub_token;
		case HSE_KEY_TYPE_RSA_PAIR:
			return &rings->rsa_pair_token;
		case HSE_KEY_TYPE_RSA_PUB:
			return &rings->rsa_pub_token;
		default:
			return NULL;
		}
	} else { /* SESSION_KEY */
		switch (hse_key_type) {
		case HSE_KEY_TYPE_AES:
			return &rings->aes_session;
		case HSE_KEY_TYPE_HMAC:
			return &rings->hmac_session;
		case HSE_KEY_TYPE_SHARED_SECRET:
			return &rings->shared_secret_session;
		case HSE_KEY_TYPE_ECC_PUB:
			return &rings->ecc_pub_session;
		case HSE_KEY_TYPE_RSA_PUB:
			return &rings->rsa_pub_session;
		case HSE_KEY_TYPE_ECC_PAIR:
			return &rings->ecc_pair_session;
		case HSE_KEY_TYPE_RSA_PAIR:
			return &rings->rsa_pair_session;
		default:
			return NULL;
		}
	}
}

static struct key_ring *find_ring_by_handle(struct rings *rings, uint32_t handle)
{
	uint8_t catalog = GET_CATALOG_ID(handle);
	uint8_t group = GET_GROUP_IDX(handle);
	struct key_ring *ring_list[] = {
		&rings->aes_token,
		&rings->hmac_token,
		&rings->ecc_pair_token,
		&rings->ecc_pub_token,
		&rings->rsa_pair_token,
		&rings->rsa_pub_token,
		&rings->aes_session,
		&rings->hmac_session,
		&rings->shared_secret_session,
		&rings->ecc_pub_session,
		&rings->rsa_pub_session,
		&rings->ecc_pair_session,
		&rings->rsa_pair_session,
	};
	size_t i;

	for (i = 0; i < sizeof(ring_list) / sizeof(ring_list[0]); i++) {
		if (ring_list[i]->catalog == catalog && ring_list[i]->group == group)
			return ring_list[i];
	}

	return NULL;
}

/**
 * key_rings_init() - Initialize key ring management (first time setup)
 *
 * Called during C_InitToken. Sets up all key rings with proper
 * configuration and initializes spinlocks.
 *
 * Return: CKR_OK on success, error code otherwise
 */
CK_RV key_rings_init(void)
{
	struct rings *r;
	CK_RV rv;
	struct tokenCtx *tCtx = getTokenCtx();
	size_t initialized_count = 0;

	if (!tCtx)
		return CKR_ARGUMENTS_BAD;

	r = &tCtx->rings;
	memset(r, 0, sizeof(struct rings));

	/* NVM (Token) Rings */

	/* NVM: AES token */
	r->aes_token.hse_key_type = HSE_KEY_TYPE_AES;
	r->aes_token.catalog = HSE_KEY_CATALOG_ID_NVM;
	r->aes_token.group = AES_TOKEN_GROUP_ID;
	r->aes_token.total_slots = AES_TOKEN_GROUP_SIZE;
	rv = init_single_ring(&r->aes_token, r->aes_token_handles);
	if (rv != CKR_OK)
		goto err_cleanup;
	initialized_count++;

	/* NVM: HMAC token */
	r->hmac_token.hse_key_type = HSE_KEY_TYPE_HMAC;
	r->hmac_token.catalog = HSE_KEY_CATALOG_ID_NVM;
	r->hmac_token.group = HMAC_TOKEN_GROUP_ID;
	r->hmac_token.total_slots = HMAC_TOKEN_GROUP_SIZE;
	rv = init_single_ring(&r->hmac_token, r->hmac_token_handles);
	if (rv != CKR_OK)
		goto err_cleanup;
	initialized_count++;

	/* NVM: ECC_PAIR token */
	r->ecc_pair_token.hse_key_type = HSE_KEY_TYPE_ECC_PAIR;
	r->ecc_pair_token.catalog = HSE_KEY_CATALOG_ID_NVM;
	r->ecc_pair_token.group = ECC_PAIR_TOKEN_GROUP_ID;
	r->ecc_pair_token.total_slots = ECC_PAIR_TOKEN_GROUP_SIZE;
	rv = init_single_ring(&r->ecc_pair_token, r->ecc_pair_token_handles);
	if (rv != CKR_OK)
		goto err_cleanup;
	initialized_count++;

	/* NVM: ECC_PUB token */
	r->ecc_pub_token.hse_key_type = HSE_KEY_TYPE_ECC_PUB;
	r->ecc_pub_token.catalog = HSE_KEY_CATALOG_ID_NVM;
	r->ecc_pub_token.group = ECC_PUB_TOKEN_GROUP_ID;
	r->ecc_pub_token.total_slots = ECC_PUB_TOKEN_GROUP_SIZE;
	rv = init_single_ring(&r->ecc_pub_token, r->ecc_pub_token_handles);
	if (rv != CKR_OK)
		goto err_cleanup;
	initialized_count++;

	/* NVM: RSA_PAIR token */
	r->rsa_pair_token.hse_key_type = HSE_KEY_TYPE_RSA_PAIR;
	r->rsa_pair_token.catalog = HSE_KEY_CATALOG_ID_NVM;
	r->rsa_pair_token.group = RSA_PAIR_TOKEN_GROUP_ID;
	r->rsa_pair_token.total_slots = RSA_PAIR_TOKEN_GROUP_SIZE;
	rv = init_single_ring(&r->rsa_pair_token, r->rsa_pair_token_handles);
	if (rv != CKR_OK)
		goto err_cleanup;
	initialized_count++;

	/* NVM: RSA_PUB token */
	r->rsa_pub_token.hse_key_type = HSE_KEY_TYPE_RSA_PUB;
	r->rsa_pub_token.catalog = HSE_KEY_CATALOG_ID_NVM;
	r->rsa_pub_token.group = RSA_PUB_TOKEN_GROUP_ID;
	r->rsa_pub_token.total_slots = RSA_PUB_TOKEN_GROUP_SIZE;
	rv = init_single_ring(&r->rsa_pub_token, r->rsa_pub_token_handles);
	if (rv != CKR_OK)
		goto err_cleanup;
	initialized_count++;

	/* RAM (Session) Rings */

	/* RAM: AES session */
	r->aes_session.hse_key_type = HSE_KEY_TYPE_AES;
	r->aes_session.catalog = AES_SESSION_CATALOG_ID;
	r->aes_session.group = AES_SESSION_GROUP_ID;
	r->aes_session.total_slots = AES_SESSION_GROUP_SIZE;
	rv = init_single_ring(&r->aes_session, r->aes_session_handles);
	if (rv != CKR_OK)
		goto err_cleanup;
	initialized_count++;

	/* RAM: HMAC session */
	r->hmac_session.hse_key_type = HSE_KEY_TYPE_HMAC;
	r->hmac_session.catalog = HMAC_SESSION_CATALOG_ID;
	r->hmac_session.group = HMAC_SESSION_GROUP_ID;
	r->hmac_session.total_slots = HMAC_SESSION_GROUP_SIZE;
	rv = init_single_ring(&r->hmac_session, r->hmac_session_handles);
	if (rv != CKR_OK)
		goto err_cleanup;
	initialized_count++;

	/* RAM: SHARED_SECRET session */
	r->shared_secret_session.hse_key_type = HSE_KEY_TYPE_SHARED_SECRET;
	r->shared_secret_session.catalog = SHARED_SECRET_SESSION_CATALOG_ID;
	r->shared_secret_session.group = SHARED_SECRET_SESSION_GROUP_ID;
	r->shared_secret_session.total_slots = SHARED_SECRET_SESSION_GROUP_SIZE;
	rv = init_single_ring(&r->shared_secret_session, r->shared_secret_session_handles);
	if (rv != CKR_OK)
		goto err_cleanup;
	initialized_count++;

	/* RAM: ECC_PUB session */
	r->ecc_pub_session.hse_key_type = HSE_KEY_TYPE_ECC_PUB;
	r->ecc_pub_session.catalog = ECC_PUB_SESSION_CATALOG_ID;
	r->ecc_pub_session.group = ECC_PUB_SESSION_GROUP_ID;
	r->ecc_pub_session.total_slots = ECC_PUB_SESSION_GROUP_SIZE;
	rv = init_single_ring(&r->ecc_pub_session, r->ecc_pub_session_handles);
	if (rv != CKR_OK)
		goto err_cleanup;
	initialized_count++;

	/* RAM: RSA_PUB session */
	r->rsa_pub_session.hse_key_type = HSE_KEY_TYPE_RSA_PUB;
	r->rsa_pub_session.catalog = RSA_PUB_SESSION_CATALOG_ID;
	r->rsa_pub_session.group = RSA_PUB_SESSION_GROUP_ID;
	r->rsa_pub_session.total_slots = RSA_PUB_SESSION_GROUP_SIZE;
	rv = init_single_ring(&r->rsa_pub_session, r->rsa_pub_session_handles);
	if (rv != CKR_OK)
		goto err_cleanup;
	initialized_count++;

	/* Session Key Pairs in NVM */

	/* NVM: ECC_PAIR session (HSE requires pairs in NVM) */
	r->ecc_pair_session.hse_key_type = HSE_KEY_TYPE_ECC_PAIR;
	r->ecc_pair_session.catalog = ECC_PAIR_SESSION_CATALOG_ID;
	r->ecc_pair_session.group = ECC_PAIR_SESSION_GROUP_ID;
	r->ecc_pair_session.total_slots = ECC_PAIR_SESSION_GROUP_SIZE;
	rv = init_single_ring(&r->ecc_pair_session, r->ecc_pair_session_handles);
	if (rv != CKR_OK)
		goto err_cleanup;
	initialized_count++;

	/* NVM: RSA_PAIR session (HSE requires pairs in NVM) */
	r->rsa_pair_session.hse_key_type = HSE_KEY_TYPE_RSA_PAIR;
	r->rsa_pair_session.catalog = RSA_PAIR_SESSION_CATALOG_ID;
	r->rsa_pair_session.group = RSA_PAIR_SESSION_GROUP_ID;
	r->rsa_pair_session.total_slots = RSA_PAIR_SESSION_GROUP_SIZE;
	rv = init_single_ring(&r->rsa_pair_session, r->rsa_pair_session_handles);
	if (rv != CKR_OK)
		goto err_cleanup;
	initialized_count++;

	return CKR_OK;

err_cleanup:
	switch (initialized_count) {
		case 13: pthread_spin_destroy(&r->rsa_pair_session.ring_lock);
		case 12: pthread_spin_destroy(&r->ecc_pair_session.ring_lock);
		case 11: pthread_spin_destroy(&r->rsa_pub_session.ring_lock);
		case 10: pthread_spin_destroy(&r->ecc_pub_session.ring_lock);
		case 9:  pthread_spin_destroy(&r->shared_secret_session.ring_lock);
		case 8:  pthread_spin_destroy(&r->hmac_session.ring_lock);
		case 7:  pthread_spin_destroy(&r->aes_session.ring_lock);
		case 6:  pthread_spin_destroy(&r->rsa_pub_token.ring_lock);
		case 5:  pthread_spin_destroy(&r->rsa_pair_token.ring_lock);
		case 4:  pthread_spin_destroy(&r->ecc_pub_token.ring_lock);
		case 3:  pthread_spin_destroy(&r->ecc_pair_token.ring_lock);
		case 2:  pthread_spin_destroy(&r->hmac_token.ring_lock);
		case 1:  pthread_spin_destroy(&r->aes_token.ring_lock);
		default: break;
	}

	return rv;
}

/**
 * key_rings_init_spinlocks() - Initialize spinlocks after loading from file
 *
 * Called during C_Initialize when rings were loaded from file.
 * Spinlocks cannot be persisted, so they must be reinitialized.
 *
 * Return: CKR_OK on success, error code otherwise
 */
CK_RV key_rings_init_spinlocks(void)
{
	struct tokenCtx *tCtx = getTokenCtx();
	struct key_ring *rings_array[] = {
		&tCtx->rings.aes_token,
		&tCtx->rings.hmac_token,
		&tCtx->rings.ecc_pair_token,
		&tCtx->rings.ecc_pub_token,
		&tCtx->rings.rsa_pair_token,
		&tCtx->rings.rsa_pub_token,
		&tCtx->rings.aes_session,
		&tCtx->rings.hmac_session,
		&tCtx->rings.shared_secret_session,
		&tCtx->rings.ecc_pub_session,
		&tCtx->rings.rsa_pub_session,
		&tCtx->rings.ecc_pair_session,
		&tCtx->rings.rsa_pair_session,
	};
	size_t num_rings = ARRAY_SIZE(rings_array);
	size_t i;
	int err;

	if (!tCtx)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	for (i = 0; i < num_rings; i++) {
		err = pthread_spin_init(&rings_array[i]->ring_lock, PTHREAD_PROCESS_SHARED);
		if (err != 0) {
			/* Destroy already initialized spinlocks */
			while (i-- > 0)
				pthread_spin_destroy(&rings_array[i]->ring_lock);

			return CKR_FUNCTION_FAILED;
		}
	}

	return CKR_OK;
}

/**
 * key_slot_acquire() - Acquire a key slot from the appropriate ring
 *
 * @hse_key_type: HSE key type
 * @is_token:     TOKEN_OBJ for persistent object, SESSION_OBJ otherwise
 * @handle:       pointer to store the acquired HSE key handle
 *
 * Return: CKR_OK on success, error code otherwise
 */
CK_RV key_slot_acquire(hseKeyType_t hse_key_type, enum object_domain is_token,
					   uint32_t *handle)
{
	struct tokenCtx *tCtx = getTokenCtx();
	struct key_ring *ring;
	int slot_idx;

	if (!handle)
		return CKR_ARGUMENTS_BAD;

	if (!tCtx)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	ring = get_ring_by_type(&tCtx->rings, hse_key_type, is_token);
	if (!ring) {
		printf("[key_slot_acquire] ERROR: No ring for type=0x%X, storage=%d\n",
			   hse_key_type, is_token);
		return CKR_KEY_TYPE_INCONSISTENT;
	}

	/* Lock only this ring - other rings can be accessed simultaneously */
	pthread_spin_lock(&ring->ring_lock);

	/* Check if any slots available */
	if (ring->available_mask == 0) {
		pthread_spin_unlock(&ring->ring_lock);
		printf("[key_slot_acquire] ERROR: No slots available for type=0x%X\n", hse_key_type);
		return CKR_DEVICE_MEMORY;
	}

	slot_idx = ffsll(ring->available_mask) - 1;

	/* Mark slot as acquired (clear the bit) */
	ring->available_mask &= ~BIT64(slot_idx);

	pthread_spin_unlock(&ring->ring_lock);

	/* Build the HSE handle */
	*handle = GET_KEY_HANDLE(ring->catalog, ring->group, slot_idx);

	printf("[key_slot_acquire] Acquired handle=0x%X (cat=%d, grp=%d, slot=%d)\n",
		   *handle, ring->catalog, ring->group, slot_idx);

	return CKR_OK;
}

/**
 * key_slot_release() - Release a key slot back to its ring
 *
 * @handle: HSE key handle to release
 *
 * Marks the slot corresponding to the given handle as available
 * in the appropriate key ring.
 *
 * Return: CKR_OK on success, error code otherwise
 */
CK_RV key_slot_release(uint32_t handle)
{
	struct tokenCtx *tCtx = getTokenCtx();
	struct key_ring *ring;
	uint8_t slot_idx;

	if (!tCtx)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	ring = find_ring_by_handle(&tCtx->rings, handle);
	if (!ring) {
		/* Handle not from a managed ring - not an error */
		return CKR_OK;
	}

	slot_idx = GET_SLOT_IDX(handle);

	if (slot_idx >= ring->total_slots)
		return CKR_ARGUMENTS_BAD;

	/* Lock only this ring */
	pthread_spin_lock(&ring->ring_lock);

	/* Mark slot as available (set the bit) */
	ring->available_mask |= BIT64(slot_idx);

	pthread_spin_unlock(&ring->ring_lock);

	printf("[key_slot_release] Released handle=0x%X (slot=%d)\n", handle, slot_idx);

	return CKR_OK;
}

/**
 * key_rings_lock_all() - Lock all key ring spinlocks
 *
 * Acquires locks on all key ring spinlocks in a consistent order
 * to prevent deadlocks. Used during finalization to ensure
 * safe persistence of ring state.
 *
 * Return: CKR_OK on success, error code otherwise
 */
CK_RV key_rings_lock_all(void)
{
	struct tokenCtx *tCtx = getTokenCtx();
	struct key_ring *rings_array[] = {
		&tCtx->rings.aes_token,
		&tCtx->rings.hmac_token,
		&tCtx->rings.ecc_pair_token,
		&tCtx->rings.ecc_pub_token,
		&tCtx->rings.rsa_pair_token,
		&tCtx->rings.rsa_pub_token,
		&tCtx->rings.aes_session,
		&tCtx->rings.hmac_session,
		&tCtx->rings.shared_secret_session,
		&tCtx->rings.ecc_pub_session,
		&tCtx->rings.rsa_pub_session,
		&tCtx->rings.ecc_pair_session,
		&tCtx->rings.rsa_pair_session,
	};
	size_t num_rings = ARRAY_SIZE(rings_array);
	size_t i;
	int err;

	if (!tCtx)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	for (i = 0; i < num_rings; i++) {
		err = pthread_spin_lock(&rings_array[i]->ring_lock);
		if (err != 0) {
			/* Unlock all previously locked spinlocks */
			while (i-- > 0)
				pthread_spin_unlock(&rings_array[i]->ring_lock);

			return CKR_CANT_LOCK;
		}
	}

	return CKR_OK;
}

/**
 * key_rings_unlock_all() - unlock all key ring spinlocks
 *
 * Releases locks on all key ring spinlocks in reverse order
 * of acquisition. Must be called after key_rings_lock_all().
 *
 * Return: CKR_OK on success, error code otherwise
 */
CK_RV key_rings_unlock_all(void)
{
	struct tokenCtx *tCtx = getTokenCtx();
	struct key_ring *rings_array[] = {
		&tCtx->rings.aes_token,
		&tCtx->rings.hmac_token,
		&tCtx->rings.ecc_pair_token,
		&tCtx->rings.ecc_pub_token,
		&tCtx->rings.rsa_pair_token,
		&tCtx->rings.rsa_pub_token,
		&tCtx->rings.aes_session,
		&tCtx->rings.hmac_session,
		&tCtx->rings.shared_secret_session,
		&tCtx->rings.ecc_pub_session,
		&tCtx->rings.rsa_pub_session,
		&tCtx->rings.ecc_pair_session,
		&tCtx->rings.rsa_pair_session,
	};
	size_t num_rings = ARRAY_SIZE(rings_array);
	size_t i;

	if (!tCtx)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	/* Unlock in reverse order */
	for (i = num_rings; i > 0; i--)
		pthread_spin_unlock(&rings_array[i - 1]->ring_lock);

	return CKR_OK;
}
