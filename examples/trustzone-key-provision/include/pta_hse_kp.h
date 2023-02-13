/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023 NXP
 */

#ifndef __PTA_HSE_KP_H
#define __PTA_HSE_KP_H

#define PTA_HSE_KP_UUID \
		{ 0xcbc3d171, 0x0e92, 0x436d, \
		{ 0x83, 0xbc, 0x33, 0xcb, 0x3a, 0x8f, 0xcc, 0x99} }

/*
 * PTA_CMD_SYM_KEY_PROVISION - Imports a ciphetext symmetric key into HSE's
 *			       RAM Key Catalog. The key is decrypted & authenticated
 *			       using HSE's KEK (Key Encryption Key) with AES-GCM algo
 *
 * [in]     memref[0]        Ciphertext key
 * [in]     value[1].a       Key group
 * [in]     value[2].b       Key slot
 *
 * Return codes:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_BAD_PARAMETERS - Incorrect input parameters
 * TEE_ERROR_OUT_OF_MEMORY - No memory left for allocations
 */
#define PTA_CMD_SYM_KEY_PROVISION	0x0

#endif /* __PTA_HSE_KP_H */
