// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <tee_client_api.h>
#include <pta_hse_kp.h>

#define ERROR(fmt, ...) printf("[ERROR] " fmt, ##__VA_ARGS__)
#define INFO(fmt, ...) printf("[INFO] " fmt, ##__VA_ARGS__)

#define MAX_PAYLOAD_SIZE	128

/* TEE resources */
struct hse_ctx {
	TEEC_Context ctx;
	TEEC_Session sess;
};

void prepare_tee_session(struct hse_ctx *ctx)
{
	TEEC_UUID uuid = PTA_HSE_KP_UUID;
	uint32_t origin;
	TEEC_Result res;

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx->ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	/* Open a session with the TA */
	res = TEEC_OpenSession(&ctx->ctx, &ctx->sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, origin);
}

void terminate_tee_session(struct hse_ctx *ctx)
{
	TEEC_CloseSession(&ctx->sess);
	TEEC_FinalizeContext(&ctx->ctx);
}

int main(int argc, char *argv[])
{
	struct hse_ctx ctx;
	TEEC_Result res;
	TEEC_Operation op;
	uint32_t origin;
	FILE *file;
	size_t bytes_read;
	uint8_t key_payload[MAX_PAYLOAD_SIZE];
	int group, slot;

	switch (argc) {
	case 4:
		file = fopen(argv[1], "rb");
		if (!file) {
			ERROR("Cannot open file %s\n", argv[1]);
			return -EINVAL;
		}

		group = atoi(argv[2]);
		slot = atoi(argv[3]);

		break;
	default:
		INFO("Usage: %s <path/to/file> <key-group> <key-slot>\n", argv[0]);
		INFO("- imports the key from <file> in the specified key slot\n");

		ERROR("Wrong number of arguments\n");
		return -EINVAL;
	}

	bytes_read = fread(key_payload, sizeof(uint8_t), MAX_PAYLOAD_SIZE, file);
	if (bytes_read == 0) {
		ERROR("Could not read file\n");
		return -EIO;
	}

	prepare_tee_session(&ctx);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_VALUE_INPUT,
					 TEEC_NONE,
					 TEEC_NONE);

	op.params[0].tmpref.buffer = key_payload;
	op.params[0].tmpref.size = MAX_PAYLOAD_SIZE;

	op.params[1].value.a = group;
	op.params[1].value.b = slot;

	res = TEEC_InvokeCommand(&ctx.sess, PTA_CMD_SYM_KEY_PROVISION, &op, &origin);
	if (res != TEEC_SUCCESS)
		ERROR("TEEC_InvokeCommand failed with code 0x%x origin 0x%x\n",
		      res, origin);
	else
		INFO("TEEC_InvokeCommand successfully executed\n");

	terminate_tee_session(&ctx);

	return res;
}
