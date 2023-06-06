// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2023 NXP
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
	struct sessionCtx *sCtx = getSessionCtx(hSession);
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	hseGetRandomNumSrv_t *rng_req;
	void *rng_output;
	int err;
	CK_RV rc = CKR_OK;
#if (HSE_PLATFORM == HSE_S32G3XX)
	CK_ULONG rng_max_len = 512;
#else
	CK_ULONG rng_max_len = 2048;
#endif

	if (gCtx->cryptokiInit == CK_FALSE)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!sCtx || sCtx->sessionInit == CK_FALSE)
		return CKR_SESSION_HANDLE_INVALID;

	if (pRandomData == NULL)
		return CKR_ARGUMENTS_BAD;

	rng_output = hse_mem_alloc((ulRandomLen > rng_max_len) ? rng_max_len : ulRandomLen);
	if (rng_output == NULL)
		return CKR_HOST_MEMORY;

	rng_req = &srv_desc.hseSrv.getRandomNumReq;
	srv_desc.srvId = HSE_SRV_ID_GET_RANDOM_NUM;
	rng_req->rngClass = HSE_RNG_CLASS_PTG3;
	rng_req->pRandomNum = hse_virt_to_dma(rng_output);

	while (ulRandomLen > rng_max_len) {
		rng_req->randomNumLength = rng_max_len;
		
		err = hse_srv_req_sync(sCtx->sID, &srv_desc, sizeof(srv_desc));
		if (err) {
			rc = CKR_FUNCTION_FAILED;
			goto err_free_output;
		}

		hse_memcpy(pRandomData, rng_output, rng_max_len);

		pRandomData += rng_max_len;
		ulRandomLen -= rng_max_len;
	}

	if (ulRandomLen > 0) {
		rng_req->randomNumLength = ulRandomLen;

		err = hse_srv_req_sync(sCtx->sID, &srv_desc, sizeof(srv_desc));
		if (err) {
			rc = CKR_FUNCTION_FAILED;
			goto err_free_output;
		}

		hse_memcpy(pRandomData, rng_output, ulRandomLen);
	}

err_free_output:
	hse_mem_free(rng_output);
	return rc;
}
