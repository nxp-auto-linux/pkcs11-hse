// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pkcs11_context.h"

CK_DEFINE_FUNCTION(CK_RV, C_SeedRandom)(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pSeed,
		CK_ULONG ulSeedLen
)
{
	/* HSE does not support RNG seeding */
	return CKR_RANDOM_SEED_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_GenerateRandom)(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pRandomData,
		CK_ULONG ulRandomLen
)
{
	struct globalCtx *gCtx = getCtx();
	hseSrvDescriptor_t srv_desc;
	hseGetRandomNumSrv_t *rng_req;
	void *rng_output;
	int err;
	CK_RV rc = CKR_OK;

	if (gCtx->cryptokiInit == CK_FALSE) {
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto gen_err;
	}

	if (pRandomData == NULL || ulRandomLen < 32 ||
			ulRandomLen > 2048 || ulRandomLen % 4 != 0) {
		rc = CKR_ARGUMENTS_BAD;
		goto gen_err;
	}

	if (hSession != SESSION_ID) {
		rc = CKR_SESSION_HANDLE_INVALID;
		goto gen_err;
	}

	rng_output = hse_mem_alloc(ulRandomLen);
	if (rng_output == NULL) {
		rc = CKR_HOST_MEMORY;
		goto gen_err;
	}

	rng_req = &srv_desc.hseSrv.getRandomNumReq;
	
	srv_desc.srvId = HSE_SRV_ID_GET_RANDOM_NUM;
	rng_req->rngClass = HSE_RNG_CLASS_PTG3;
	rng_req->randomNumLength = ulRandomLen;
	rng_req->pRandomNum = hse_virt_to_dma(rng_output);

	err = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc);
	if (err) {
		rc = CKR_FUNCTION_FAILED;
		goto req_err;
	}

	memcpy(pRandomData, rng_output, ulRandomLen);

req_err:
	hse_mem_free(rng_output);
gen_err:
	return rc;
}
