// SPDX-License-Identifier: BSD-3-Clause
/*
 * HSE advanced secure boot preparatory command demo
 *
 * Copyright 2022-2025 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <getopt.h>

#include <sys/ioctl.h>
#include <mtd/mtd-user.h>
#include "libhse.h"
#include "keys-config.h"
#include "hse_interface.h"

#define BIT(n) (0x1u << (n))
#define ERROR(fmt, ...) printf("[ERROR] " fmt, ##__VA_ARGS__)
#define INFO(fmt, ...) printf("[INFO] " fmt, ##__VA_ARGS__)
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))

#define APP_CODE_OFFSET 0x40u
#define IVT_OFFSET_QSPI 0x0
#define IVT_OFFSET_SD_MMC 0x1000u
#define HSE_SMR_ENTRY_1 BIT(1)
#define HSE_IVT_BOOTSEQ_BIT BIT(3)

#define BL2_SIGN_ARG_ID 0x100
#define BL2_BIN_ARG_ID 0x101
#define RPMB_DEFAULT_KEY_HANDLE 0x010200
#define BL2_DEFAULT_KEY_HANDLE 0x010700
#define BL31_DEFAULT_KEY_HANDLE 0x010700
#define BL32_DEFAULT_KEY_HANDLE 0x010700
#define BL33_DEFAULT_KEY_HANDLE 0x010700

#define HSE_MONOTONIC_CNT_TABLE_PATH "/etc/keys/secboot/hse_cnt_table.bin"

// Assuming 64KB QSPI block size
#define QSPI_BLOCK_SIZE 0x10000u
#define HSE_EXT_FLASH_PAGE_QSPI	0x1000u
#define HSE_EXT_FLASH_PAGE_SD_MMC 512u
#if (HSE_PLATFORM == HSE_S32G2XX) || (HSE_PLATFORM == HSE_S32R45X)
#define HSE_APP_CORE_A53_0 HSE_APP_CORE3
#elif (HSE_PLATFORM == HSE_S32G3XX)
#define HSE_APP_CORE_A53_0 HSE_APP_CORE4
#endif

enum boot_type {
	QSPI = 0,
	SD = 2,
	MMC = 3,
};

enum key_type {
	INVALID_KEY = -1,
	RPMB_KEY = 0,
	BL2_KEY,
	BL31_KEY,
	BL32_KEY,
	BL33_KEY,
};

struct ivt {
	uint32_t ivt_header;
	uint8_t reserved1[4];
	uint32_t dcd_self_test;
	uint32_t dcd_self_test_backup;
	uint32_t dcd;
	uint32_t dcd_backup;
	uint32_t hse_fw;
	uint32_t hse_fw_backup;
	uint32_t app_boot;
	uint32_t app_boot_backup;
	uint32_t boot_cfg;
	uint32_t lc_cfg;
	uint8_t reserved2[4];
	uint32_t sysimg;
	uint32_t sysimg_backup;
	uint32_t sysimg_ext_flash_type;
	uint32_t sysimg_flash_page_size;
	uint32_t app_bsb_ext_flash_type;
	uint8_t reserved3[168];
	uint32_t gmac[4];
} __attribute((packed));

struct app_boot_hdr {
	uint32_t header;
	uint32_t ram_load;
	uint32_t ram_entry;
	uint32_t code_len;
} __attribute((packed));

struct secboot_key {
	enum key_type type;
	bool req;
	uint32_t handle;
	char *name;
	char *input_arg;
	char *keypath;
};

struct secboot_key secboot_keys[] = {
	{ RPMB_KEY, false, RPMB_DEFAULT_KEY_HANDLE, "RPMB Symmetric key", NULL, NULL },
	{ BL2_KEY, true, BL2_DEFAULT_KEY_HANDLE, "BL2 Public key", NULL, NULL },
	{ BL31_KEY, true, BL31_DEFAULT_KEY_HANDLE, "BL31 Public key", NULL, NULL },
	{ BL32_KEY, false, BL32_DEFAULT_KEY_HANDLE, "BL32 Public key", NULL, NULL },
	{ BL33_KEY, true, BL33_DEFAULT_KEY_HANDLE, "BL33 Public key", NULL, NULL },
	{ INVALID_KEY, false, HSE_INVALID_KEY_HANDLE, NULL, NULL } /* end of key list - required */
};

const struct option secboot_options[] = {
	{ "bl2_sign", required_argument, NULL, BL2_SIGN_ARG_ID },
	{ "bl2_bin", required_argument, NULL, BL2_BIN_ARG_ID },
	{ "rpmb_key", required_argument, NULL, RPMB_KEY },
	{ "bl2_key",  required_argument, NULL, BL2_KEY },
	{ "bl31_key", required_argument, NULL, BL31_KEY },
	{ "bl32_key", required_argument, NULL, BL32_KEY },
	{ "bl33_key", required_argument, NULL, BL33_KEY },
	{ NULL, 0, NULL, 0}
};

/* the nvm container used to format the hse key catalogs */
const hseKeyGroupCfgEntry_t nvm_cat[] = {
	HSE_NVM_KEY_CATALOG_CFG
};

/* the ram container used to format the hse key catalogs */
const hseKeyGroupCfgEntry_t ram_cat[] = {
	HSE_RAM_KEY_CATALOG_CFG
};

static inline uint32_t get_app_boot_start(struct ivt *ivt)
{
	return ivt->app_boot + APP_CODE_OFFSET;
}

static int get_dev_offset(int fd, void *dest, off_t offset, size_t bytes)
{
	off_t seek_ret;
	int bytes_ret;

	seek_ret = lseek(fd, offset, SEEK_SET);
	if (seek_ret < 0 || seek_ret != offset)
		return -errno;

	bytes_ret = read(fd, (void *)dest, bytes);
	if (bytes_ret < 0 || bytes_ret != bytes)
		return -errno;

	return 0;
}

size_t get_file_size(const char *file)
{
	FILE *fd;
	size_t size = 0;

	fd = fopen(file, "r");
	if (!fd) {
		ERROR("Could not open %s to retrieve size\n", file);
		return -ENOENT;
	}

	fseek(fd, 0, SEEK_END);
	size = ftell(fd);
	fseek(fd, 0, SEEK_SET);

	fclose(fd);
	return size;
}

int hse_set_key_input(char *input, enum key_type type)
{
	for (int i = 0; secboot_keys[i].type != INVALID_KEY; i++) {
		if (secboot_keys[i].type != type)
			continue;

		secboot_keys[i].input_arg = input;
		return 0;
	}

	ERROR("Internal error: image key type unrecognized\n");
	return -EINVAL;
}

int hse_check_req_keys(void)
{
	for (int i = 0; secboot_keys[i].type != INVALID_KEY; i++) {
		if (secboot_keys[i].req && !secboot_keys[i].input_arg) {
			ERROR("The %s is required\n", secboot_keys[i].name);
			return -EINVAL;
		} else if (!secboot_keys[i].req && secboot_keys[i].input_arg) {
			INFO("The %s is not required, but will be imported\n", secboot_keys[i].name);
		}
	}
	return 0;
}

int hse_parse_keys(void)
{
	char *handle_string = NULL;

	for (int i = 0; secboot_keys[i].type != INVALID_KEY; i++) {
		if (!secboot_keys[i].input_arg)
			continue;

		if (!strchr(secboot_keys[i].input_arg, ':')) {
			secboot_keys[i].keypath = secboot_keys[i].input_arg;
			INFO("Successfully parsed %s input\n", secboot_keys[i].name);
			continue;
		}

		secboot_keys[i].keypath = strtok(strdup(secboot_keys[i].input_arg), ":");

		if (!secboot_keys[i].keypath)
			return -EINVAL;

		handle_string = strtok(NULL, ":");
		if (!handle_string || strlen(handle_string) != 8)
			return -EINVAL;

		secboot_keys[i].handle = (uint32_t)strtol(handle_string, NULL, 16);
		if (!secboot_keys[i].handle)
			return -EINVAL;
		INFO("Successfully parsed %s input\n", secboot_keys[i].name);
	}
	return 0;
}

int hse_check_prev_import(int key_idx)
{
	for (int i = 0; i < key_idx; i++) {
		if (secboot_keys[i].handle == secboot_keys[key_idx].handle) {
			INFO("Key slot already occupied, %s already imported for a previous BL.\n",
				 secboot_keys[key_idx].name);
			return 1;
		}
	}
	return 0;
}

int hse_mus_enable()
{
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	hseAttrMUConfig_t *mu_config;
	int i, ret = 0;

	mu_config = hse_mem_alloc(sizeof(*mu_config));
	if (!mu_config) {
		ERROR("Failed to allocate space for MU Configuration\n");
		return -ENOMEM;
	}
	hse_memset(mu_config, 0, sizeof(*mu_config));

	srv_desc.srvId = HSE_SRV_ID_SET_ATTR;

	for (i = 0; i < HSE_NUM_OF_MU_INSTANCES; i++) {
		mu_config->muInstances[i].muConfig = HSE_MU_ACTIVATED;
		mu_config->muInstances[i].xrdcDomainId = 0u;
		mu_config->muInstances[i].sharedMemChunkSize = 0u;
	}

	srv_desc.hseSrv.setAttrReq.attrId = HSE_MU_CONFIG_ATTR_ID;
	srv_desc.hseSrv.setAttrReq.attrLen = sizeof(*mu_config);
	srv_desc.hseSrv.setAttrReq.pAttr = hse_virt_to_dma(mu_config);

	ret = hse_srv_req_sync(HSE_CHANNEL_ADM, &srv_desc, sizeof(srv_desc));
	if (ret)
		ERROR("Failed to enable MUs\n");

	hse_mem_free(mu_config);
	return ret;
}

int hse_key_format()
{
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	hseKeyGroupCfgEntry_t *nvm_catalog, *ram_catalog;
	int ret = 0;

	nvm_catalog = hse_mem_alloc(sizeof(hseKeyGroupCfgEntry_t) * NUM_NVM_GROUPS);
	if (!nvm_catalog) {
		ERROR("Failed to allocate space for NVM Key Group\n");
		return -ENOMEM;
	}

	ram_catalog = hse_mem_alloc(sizeof(hseKeyGroupCfgEntry_t) * NUM_RAM_GROUPS);
	if (!ram_catalog) {
		ERROR("Failed to allocate space for RAM Key Group\n");
		ret = -ENOMEM;
		goto err_free_nvm;
	}

	hse_memcpy(nvm_catalog, &nvm_cat, sizeof(nvm_cat));
	hse_memcpy(ram_catalog, &ram_cat, sizeof(ram_cat));

	srv_desc.srvId = HSE_SRV_ID_FORMAT_KEY_CATALOGS;
	srv_desc.hseSrv.formatKeyCatalogsReq.pNvmKeyCatalogCfg = hse_virt_to_dma(nvm_catalog);
	srv_desc.hseSrv.formatKeyCatalogsReq.pRamKeyCatalogCfg = hse_virt_to_dma(ram_catalog);

	ret = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc, sizeof(srv_desc));
	if (ret)
		ERROR("Failed to format key catalogs!\n");

	hse_mem_free(ram_catalog);
err_free_nvm:
	hse_mem_free(nvm_catalog);
	return ret;
}

int hse_set_and_publish_cnt_table(void)
{
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	FILE *f;
	void *cnt_table;
	void *hse_cnt_table; 
	int ret = 0, err = 0;

	cnt_table = malloc(HSE_NVM_CONTAINER_CNT_TBL_SIZE);
	if (!cnt_table) {
		ERROR("Failed to alloc memory for monotonic counter table\n");
		return -ENOMEM;
	}

	hse_cnt_table = hse_mem_alloc(HSE_NVM_CONTAINER_CNT_TBL_SIZE);
	if (!hse_cnt_table) {
		ERROR("Failed to alloc reserved memory for counter table\n");
		ret = -ENOMEM;
		goto err_free_cnt_table;
	}

	srv_desc.srvId = HSE_SRV_ID_CONFIG_COUNTER;
	srv_desc.hseSrv.configSecCounter.counterIndex = 3;
	srv_desc.hseSrv.configSecCounter.RPBitSize = 32;

	ret = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc, sizeof(srv_desc));
	if (ret) {
		ERROR("Failed to configure monotonic counter table\n");
		goto err_free_hse_cnt_table;
	}

	memset(&srv_desc, 0, sizeof(srv_desc));

	srv_desc.srvId = HSE_SRV_ID_PUBLISH_LOAD_CNT_TBL;
	srv_desc.hseSrv.publishLoadCntTblReq.action = HSE_NVM_CNT_TBL_ACTION_PUBLISH;
	srv_desc.hseSrv.publishLoadCntTblReq.pNvmContainerCntTbl = hse_virt_to_dma(hse_cnt_table);

	ret = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc, sizeof(srv_desc));
	if (ret) {
		ERROR("Failed to publish monotonic counter table\n");
		goto err_free_hse_cnt_table;
	}
	hse_memcpy(cnt_table, hse_cnt_table, HSE_NVM_CONTAINER_CNT_TBL_SIZE);

	f = fopen(HSE_MONOTONIC_CNT_TABLE_PATH, "wb");
	if (!f) {
		ERROR("Could not create monotonic counter table binary file %s\n",
		      HSE_MONOTONIC_CNT_TABLE_PATH);
		ret = -ENOENT;
		goto err_free_hse_cnt_table;
	}

	err = fwrite(cnt_table, 1, HSE_NVM_CONTAINER_CNT_TBL_SIZE, f);
	if (err < 0 || err != HSE_NVM_CONTAINER_CNT_TBL_SIZE) {
		ERROR("Failed to write monotonic counter table to file %s\n",
		      HSE_MONOTONIC_CNT_TABLE_PATH);
		ret = -err;
	}
	
	fclose(f);
err_free_hse_cnt_table:
	hse_mem_free(hse_cnt_table);
err_free_cnt_table:
	free(cnt_table);

	return ret;
}

int hse_rsa_key_import(uint8_t *rsa_modulus, int rsa_modulus_size,
                   uint8_t *rsa_pub_exponent, int rsa_pub_exponent_size, uint32_t handle)
{
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	volatile hseKeyInfo_t *key_info;
	int ret = 0;

	key_info = hse_mem_alloc(sizeof(*key_info));
	if (!key_info) {
		ERROR("Failed to allocate space for key info\n");
		return -ENOMEM;
	}
	hse_memset((void *)key_info, 0, sizeof(*key_info));

	key_info->keyFlags = HSE_KF_USAGE_VERIFY;
	key_info->keyBitLen = HSE_BYTES_TO_BITS(rsa_modulus_size);
	key_info->keyCounter = 0ul;
	key_info->smrFlags = 0ul;
	key_info->keyType = HSE_KEY_TYPE_RSA_PUB;
	key_info->specific.pubExponentSize = rsa_pub_exponent_size;

	srv_desc.srvId = HSE_SRV_ID_IMPORT_KEY;
	srv_desc.hseSrv.importKeyReq.targetKeyHandle = handle;
	srv_desc.hseSrv.importKeyReq.pKeyInfo = hse_virt_to_dma((void *)key_info);
	srv_desc.hseSrv.importKeyReq.pKey[0] = hse_virt_to_dma(rsa_modulus);
	srv_desc.hseSrv.importKeyReq.pKey[1] = hse_virt_to_dma(rsa_pub_exponent);
	srv_desc.hseSrv.importKeyReq.pKey[2] = 0u;
	srv_desc.hseSrv.importKeyReq.keyLen[0] = rsa_modulus_size;
	srv_desc.hseSrv.importKeyReq.keyLen[1] = rsa_pub_exponent_size;
	srv_desc.hseSrv.importKeyReq.keyLen[2] = 0u;
	srv_desc.hseSrv.importKeyReq.cipher.cipherKeyHandle = HSE_INVALID_KEY_HANDLE;
	srv_desc.hseSrv.importKeyReq.keyContainer.authKeyHandle = HSE_INVALID_KEY_HANDLE;

	ret = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc, sizeof(srv_desc));
	if (ret)
		ERROR("Failed to import RSA Public Key\n");

	hse_mem_free((void *)key_info);
	return ret;
}

int hse_extract_and_import_sym_key(const char *keypath, uint32_t handle)
{
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	volatile hseKeyInfo_t *key_info;
	uint8_t key[32] = {0};
	int ret = 0, err = 0;
	uint32_t key_len;
	void *hse_key;
	FILE *f;

	key_len = get_file_size(keypath);
	if (!key_len || key_len != 32) {
		ERROR("Invalid  Key size. RPMB key must be 32 bytes long.\n");
		return -ENODATA;
	}

	f = fopen(keypath, "rb");
	if (!f) {
		ERROR("Could not find Symmetric Key file %s\n", keypath);
		return -ENOENT;
	}

	err = fread((void *)key, 1, key_len, f);
	if (err < 0 || err != key_len) {
		ERROR("Failed to read Symmetric Key from file\n");
		ret = -err;
		goto err_close_keyfile;
	}

	key_info = hse_mem_alloc(sizeof(*key_info));
	if (!key_info) {
		ERROR("Failed to allocate space for key info\n");
		ret = -ENOMEM;
		goto err_close_keyfile;
	}
	hse_memset((void *)key_info, 0, sizeof(*key_info));

	hse_key = hse_mem_alloc(key_len);
	if (!hse_key) {
		ERROR("Failed to allocate space for Symmetric Key\n");
		ret = -ENOMEM;
		goto err_free_key_info;
	}
	hse_memcpy(hse_key, key, key_len);

	key_info->keyFlags = HSE_KF_USAGE_SIGN;
	key_info->keyBitLen = HSE_BYTES_TO_BITS(key_len);
	key_info->keyCounter = 0ul;
	key_info->smrFlags = 0ul;
	key_info->keyType = HSE_KEY_TYPE_HMAC;

	srv_desc.srvId = HSE_SRV_ID_IMPORT_KEY;
	srv_desc.hseSrv.importKeyReq.targetKeyHandle = handle;
	srv_desc.hseSrv.importKeyReq.pKeyInfo = hse_virt_to_dma((void *)key_info);
	srv_desc.hseSrv.importKeyReq.pKey[0] = 0u;
	srv_desc.hseSrv.importKeyReq.pKey[1] = 0u;
	srv_desc.hseSrv.importKeyReq.pKey[2] = hse_virt_to_dma(hse_key);
	srv_desc.hseSrv.importKeyReq.keyLen[0] = 0u;
	srv_desc.hseSrv.importKeyReq.keyLen[1] = 0u;
	srv_desc.hseSrv.importKeyReq.keyLen[2] = key_len;
	srv_desc.hseSrv.importKeyReq.cipher.cipherKeyHandle = HSE_INVALID_KEY_HANDLE;
	srv_desc.hseSrv.importKeyReq.keyContainer.authKeyHandle = HSE_INVALID_KEY_HANDLE;

	ret = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc, sizeof(srv_desc));
	if (ret)
		ERROR("Failed to import Symmetric Key\n");

	hse_mem_free(hse_key);
err_free_key_info:
	hse_mem_free((void *)key_info);
err_close_keyfile:
	fclose(f);
	return ret;
}

int hse_extract_and_import_rsa_key(const char *keypath, uint32_t handle)
{
	FILE *f;
	int bytes, ret = 0;
	EVP_PKEY *pkey;
	uint8_t *rsa_modulus, *rsa_pub_exponent;
	BIGNUM *rsa_bn_modulus = NULL, *rsa_bn_pub_exponent = NULL;

	f = fopen(keypath, "rb");
	if (!f) {
		ERROR("Could not find RSA Key file %s\n", keypath);
		return -ENOENT;
	}

	pkey = PEM_read_PUBKEY(f, NULL, NULL, NULL);
	if (!pkey) {
		ERROR("Failed to read RSA Public Key from file %s\n", keypath);
		ret = -ENOKEY;
		goto err_close_keyfile;
	}

	ret = EVP_PKEY_get_bn_param(pkey, "n", &rsa_bn_modulus);
	if (!rsa_bn_modulus) {
		ERROR("Failed to read RSA Public Key Modulus from file %s\n", keypath);
		ret = -ENOKEY;
		goto err_close_keyfile;
	}

	ret = EVP_PKEY_get_bn_param(pkey, "e", &rsa_bn_pub_exponent);
	if (!rsa_bn_pub_exponent) {
		ERROR("Failed to read RSA Public Key Exponent from file %s\n", keypath);
		ret = -ENOKEY;
		goto err_close_keyfile;
	}

	rsa_modulus = hse_mem_alloc(BN_num_bytes(rsa_bn_modulus));
	if (!rsa_modulus) {
		ERROR("Failed to allocate space for RSA Public Key Modulus\n");
		ret = -ENOMEM;
		goto err_close_keyfile;
	}

	rsa_pub_exponent = hse_mem_alloc(BN_num_bytes(rsa_bn_pub_exponent));
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

	ret = hse_rsa_key_import(rsa_modulus, BN_num_bytes(rsa_bn_modulus), rsa_pub_exponent,
						 BN_num_bytes(rsa_bn_pub_exponent), handle);

err_free_rsa_pub_exponent:
	hse_mem_free(rsa_pub_exponent);
err_free_rsa_modulus:
	hse_mem_free(rsa_modulus);
err_close_keyfile:
	fclose(f);
	return ret;
}

int hse_extract_bin(const char *bin_file, uint8_t *bin, size_t bin_size)
{
	FILE *fd = NULL;
	int ret = 0, err = 0;
	uint8_t *bin_tmp = NULL;

	if (!bin)
		return -ENODATA;

	fd = fopen(bin_file, "rb");
	if (!fd) {
		ERROR("Could not find binary file %s\n", bin_file);
		return -errno;
	}

	bin_tmp = malloc(bin_size);
	if (!bin_tmp) {
		ERROR("Could not allocate space for temporary buffer\n");
		goto out_close_fd;
	}

	err = fread((void *)bin_tmp, 1, bin_size, fd);
	if (err < 0 || err != bin_size) {
		ret = -err;
		goto out_free_tmp_buf;
	}

	hse_memcpy(bin, bin_tmp, bin_size);

out_free_tmp_buf:
	free(bin_tmp);
out_close_fd:
	fclose(fd);
	return ret;
}

int hse_smr_install(int fd, struct ivt *ivt, struct app_boot_hdr *app_boot,
		    const char *bl2_sign_file, const char *bl2_bin_file,
		    uint32_t auth_handle, enum boot_type boot_medium)
{
	uint32_t bl2_bin_size;
	uint16_t bl2_sign_size;
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	hseSmrEntry_t smr_entry, *smr_entry_hse;
	uint8_t *bl2_sign = NULL, *bl2_bin = NULL;
	int ret = 0;

	bl2_bin_size = get_file_size(bl2_bin_file);
	if (!bl2_bin_size) {
		ERROR("Invalid BL2 size\n");
		return -ENODATA;
	}

	bl2_bin = hse_mem_alloc(bl2_bin_size);
	if (!bl2_bin) {
		ERROR("Failed to allocate space for BL2\n");
		return -ENOMEM;
	}

	ret = hse_extract_bin(bl2_bin_file, bl2_bin, bl2_bin_size);
	if (ret) {
		ERROR("Failed to read BL2 binary from file\n");
		goto err_free_bl2_bin;
	}

	bl2_sign_size = get_file_size(bl2_sign_file);
	if (bl2_sign_size <= 0) {
		ERROR("Failed to retrieve BL2 signature size\n");
		ret = -ENODATA;
		goto err_free_bl2_bin;
	}

	bl2_sign = hse_mem_alloc(bl2_sign_size);
	if (!bl2_sign) {
		ERROR("Failed to allocate space for BL2 signature\n");
		ret = -ENOMEM;
		goto err_free_bl2_bin;
	}

	ret = hse_extract_bin(bl2_sign_file, bl2_sign, bl2_sign_size);
	if (ret) {
		ERROR("Failed to read BL2 signature from file\n");
		goto err_free_bl2_sign;
	}

	smr_entry_hse = hse_mem_alloc(sizeof(*smr_entry_hse));
	if (!smr_entry_hse) {
		ERROR("Failed to allocate space for SMR Entry\n");
		ret = -ENOMEM;
		goto err_free_bl2_sign;
	}
	hse_memset(smr_entry_hse, 0, sizeof(*smr_entry_hse));

	smr_entry.pSmrSrc = get_app_boot_start(ivt);
	smr_entry.pSmrDest = app_boot->ram_load;
	smr_entry.smrSize = bl2_bin_size;

	if (boot_medium == QSPI)
		smr_entry.configFlags = (HSE_SMR_CFG_FLAG_QSPI_FLASH);
	else if (boot_medium == SD)
		smr_entry.configFlags = (HSE_SMR_CFG_FLAG_SD_FLASH);
	else if (boot_medium == MMC)
		smr_entry.configFlags = (HSE_SMR_CFG_FLAG_MMC_FLASH);

	smr_entry.checkPeriod = 0;
	smr_entry.authKeyHandle = auth_handle;
	smr_entry.authScheme.sigScheme.signSch = HSE_SIGN_RSASSA_PKCS1_V15;
	smr_entry.authScheme.sigScheme.sch.rsaPkcs1v15.hashAlgo = HSE_HASH_ALGO_SHA_1;
	smr_entry.smrDecrypt.decryptKeyHandle = HSE_SMR_DECRYPT_KEY_HANDLE_NOT_USED;
	smr_entry.versionOffset = 0;

	/* workaround for bus error on writing to hse rmem */
	memcpy(smr_entry_hse, &(smr_entry), sizeof(smr_entry));

	srv_desc.srvId = HSE_SRV_ID_SMR_ENTRY_INSTALL;
	srv_desc.hseSrv.smrEntryInstallReq.accessMode = HSE_ACCESS_MODE_ONE_PASS;
	srv_desc.hseSrv.smrEntryInstallReq.entryIndex = 1u;
	srv_desc.hseSrv.smrEntryInstallReq.pSmrEntry = hse_virt_to_dma(smr_entry_hse);
	srv_desc.hseSrv.smrEntryInstallReq.pSmrData = hse_virt_to_dma(bl2_bin);
	srv_desc.hseSrv.smrEntryInstallReq.smrDataLength = bl2_bin_size;
	srv_desc.hseSrv.smrEntryInstallReq.pAuthTag[0] = hse_virt_to_dma(bl2_sign);
	srv_desc.hseSrv.smrEntryInstallReq.pAuthTag[1] = 0u;
	srv_desc.hseSrv.smrEntryInstallReq.authTagLength[0] = bl2_sign_size;
	srv_desc.hseSrv.smrEntryInstallReq.authTagLength[1] = 0u;

	ret = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc, sizeof(srv_desc));
	if (ret)
		ERROR("Failed to install SMR Entry\n");

	hse_mem_free(smr_entry_hse);

err_free_bl2_sign:
	hse_mem_free(bl2_sign);
err_free_bl2_bin:
	hse_mem_free(bl2_bin);
	return ret;
}

int hse_cr_install(struct app_boot_hdr *app_boot)
{
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	volatile hseCrEntry_t *cr_entry;
	int ret = 0;

	cr_entry = hse_mem_alloc(sizeof(*cr_entry));
	if (!cr_entry) {
		ERROR("Failed to allocate space for core reset entry\n");
		return -ENOMEM;
	}
	hse_memset((void *)cr_entry, 0, sizeof(*cr_entry));

	cr_entry->coreId = HSE_APP_CORE_A53_0;
	cr_entry->crSanction = HSE_CR_SANCTION_KEEP_CORE_IN_RESET;
	cr_entry->preBootSmrMap = HSE_SMR_ENTRY_1;
	cr_entry->pPassReset = app_boot->ram_entry;
	cr_entry->altPreBootSmrMap = 0u;
	cr_entry->pAltReset = 0u;
	cr_entry->postBootSmrMap = 0u;
	cr_entry->startOption = HSE_CR_AUTO_START;

	srv_desc.srvId = HSE_SRV_ID_CORE_RESET_ENTRY_INSTALL;
	srv_desc.hseSrv.crEntryInstallReq.crEntryIndex = 1u;
	srv_desc.hseSrv.crEntryInstallReq.pCrEntry = hse_virt_to_dma((void *)cr_entry);

	ret = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc, sizeof(srv_desc));
	if (ret)
		ERROR("Failed to install Core Reset Entry\n");

	hse_mem_free((void *)cr_entry);
	return ret;
}

int hse_sysimg_getsize(uint32_t *sysimg_size)
{
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	int ret = 0;

	srv_desc.srvId = HSE_SRV_ID_GET_SYS_IMAGE_SIZE;
	srv_desc.hseSrv.getSysImageSizeReq.pSysImageSize = hse_virt_to_dma(sysimg_size);

	ret = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc, sizeof(srv_desc));
	if (ret)
		ERROR("Failed to get SYSIMG size\n");

	return ret;
}

int hse_sysimg_publish(void *sysimg, uint32_t *sysimg_size)
{
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	hsePublishSysImageSrv_t *publish_sysimg_req;
	uint32_t *publish_offset;
	int ret = 0;

	publish_sysimg_req = &srv_desc.hseSrv.publishSysImageReq;

	/* unused, but required by HSE */
	publish_offset = hse_mem_alloc(sizeof(*publish_offset));
	if (!publish_offset) {
		ERROR("Failed to allocate space for publish offset\n");
		return -ENOMEM;
	}

	srv_desc.srvId = HSE_SRV_ID_PUBLISH_SYS_IMAGE;
	publish_sysimg_req->publishOptions = HSE_PUBLISH_ALL_DATA_SETS;
	publish_sysimg_req->pPublishOffset = hse_virt_to_dma(publish_offset);
	publish_sysimg_req->pBuffLength = hse_virt_to_dma(sysimg_size);
	publish_sysimg_req->pBuff = hse_virt_to_dma(sysimg);

	ret = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc, sizeof(srv_desc));
	if (ret)
		ERROR("Failed to publish SYS_IMG\n");

	hse_mem_free(publish_offset);
	return ret;
}

int hse_sysimg_write_sd_mmc(int fd, struct ivt *ivt, void *sysimg, uint32_t *sysimg_size,
                            enum boot_type boot_medium, bool secure)
{
	off_t seek_off;
	int bytes;

	seek_off = lseek(fd, ivt->sysimg, SEEK_SET);
	if (seek_off < 0 || seek_off != ivt->sysimg) {
		ERROR("Failed to find SYSIMG location\n");
		return errno;
	}
	bytes = write(fd, sysimg, *sysimg_size);
	if (bytes < 0 || bytes != *sysimg_size) {
		ERROR("Failed to write SYSIMG\n");
		return errno;
	}
	ivt->sysimg_ext_flash_type = boot_medium;

	/* external flash type, flash page size */
	ivt->sysimg_flash_page_size = HSE_EXT_FLASH_PAGE_SD_MMC;

	/* set BOOT_SEQ bit, if using secure boot */
	if (secure)
		ivt->boot_cfg |= HSE_IVT_BOOTSEQ_BIT;

	seek_off = lseek(fd, IVT_OFFSET_SD_MMC, SEEK_SET);
	if (seek_off < 0 || seek_off != IVT_OFFSET_SD_MMC) {
		ERROR("Failed to find original IVT location\n");
		return errno;
	}

	bytes = write(fd, ivt, sizeof(*ivt));
	if (bytes < 0 || bytes != sizeof(*ivt)) {
		ERROR("Failed to write updated IVT\n");
		return errno;
	}

	return 0;
}

int hse_sysimg_write_qspi(int fd, struct ivt *ivt, void *sysimg, uint32_t *sysimg_size, bool secure)
{
	off_t seek_off;
	erase_info_t ei;
	uint8_t sysimage[2 * QSPI_BLOCK_SIZE];
	int bytes;

	uint32_t rem, div;

	// Assuming max 48KB SYSIMG size
	// Reading max 2 blocks, as SYSIMG Offset may be present at the end of QSPI block
	div = ivt->sysimg / QSPI_BLOCK_SIZE;
	rem = ivt->sysimg % QSPI_BLOCK_SIZE;
	get_dev_offset(fd, sysimage, (div * QSPI_BLOCK_SIZE), (2 * QSPI_BLOCK_SIZE));
	ei.length = (2 * QSPI_BLOCK_SIZE);
	ei.start = (div * QSPI_BLOCK_SIZE);
	ioctl(fd, MEMUNLOCK, &ei);
	ioctl(fd, MEMERASE, &ei);
	memcpy(sysimage+rem, sysimg, *sysimg_size);
	seek_off = lseek(fd, (div * QSPI_BLOCK_SIZE), SEEK_SET);
	if (seek_off < 0) {
		ERROR("Failed to find SYSIMG location\n");
		return errno;
	}
	bytes = write(fd, sysimage, (2 * QSPI_BLOCK_SIZE));
	if (bytes < 0 || bytes != (2 * QSPI_BLOCK_SIZE)) {
		ERROR("Failed to write SYSIMG\n");
		return errno;
	}
	ivt->sysimg_ext_flash_type = QSPI;

	/* external flash type, flash page size */
	ivt->sysimg_flash_page_size = HSE_EXT_FLASH_PAGE_QSPI;

	/* set BOOT_SEQ bit, if using secure boot */
	if (secure)
		ivt->boot_cfg |= HSE_IVT_BOOTSEQ_BIT;

	get_dev_offset(fd, sysimage, IVT_OFFSET_QSPI, QSPI_BLOCK_SIZE);
	ei.length = (QSPI_BLOCK_SIZE);
	ei.start = 0;
	ioctl(fd, MEMERASE, &ei);
	memcpy(sysimage, ivt, sizeof(*ivt));

	seek_off = lseek(fd, IVT_OFFSET_QSPI, SEEK_SET);
	if (seek_off < 0 || seek_off != IVT_OFFSET_QSPI) {
		ERROR("Failed to find original IVT location\n");
		return errno;
	}

	bytes = write(fd, sysimage, QSPI_BLOCK_SIZE);
	if (bytes < 0 || bytes != QSPI_BLOCK_SIZE) {
		ERROR("Failed to write updated IVT\n");
		return errno;
	}

	return 0;
}

int hse_secboot_enable(const char *device, const char *bl2_sign_file,
		       const char *bl2_bin_file, enum boot_type boot_medium)
{
	struct ivt ivt;
	bool gen_cnt_table = false;
	struct app_boot_hdr app_boot;
	uint16_t hse_status;
	uint32_t *sysimg_size;
	void *sysimg;
	int fd, ret = 0;

	ret = hse_dev_open();
	if (ret) {
		ERROR("Failed to open HSE device - error %d\n", ret);
		return ret;
	}

	/* check if hse has been initialised */
	hse_status = hse_check_status();
	if (!(hse_status & HSE_STATUS_INIT_OK)) {
		ERROR("HSE not initialised or missing firmware\n");
		ret = -ENODEV;
		goto err_close_hse;
	}

	INFO("Retrieving IVT from device %s\n", device);

	fd = open(device, O_SYNC | O_RDWR);
	if (fd < 0) {
		ERROR("Failed to open %s\n", device);
		ret = errno;
		goto err_close_hse;
	}

	if (boot_medium == QSPI)
		ret = get_dev_offset(fd, &ivt, IVT_OFFSET_QSPI, sizeof(ivt));
	else
		ret = get_dev_offset(fd, &ivt, IVT_OFFSET_SD_MMC, sizeof(ivt));

	if (ret)
		goto err_close_fd;

	ret = get_dev_offset(fd, &app_boot, ivt.app_boot, sizeof(app_boot));
	if (ret)
		goto err_close_fd;

	INFO("Enabling MUs\n");

	ret = hse_mus_enable();
	if (ret)
		goto err_close_fd;

	/* check if sysimg already exists */
	if (!(hse_status & HSE_STATUS_INSTALL_OK)) {
		INFO("HSE key catalogs not found, formatting NVM and RAM key catalogs\n");

		ret = hse_key_format();
		if (ret)
			goto err_close_fd;
	}

	for (int i = 0; secboot_keys[i].type != INVALID_KEY; i++) {
		if (!secboot_keys[i].keypath || hse_check_prev_import(i))
			continue;

		INFO("Importing %s\n", secboot_keys[i].name);
		if (secboot_keys[i].type == RPMB_KEY) {
			ret = hse_extract_and_import_sym_key(secboot_keys[i].keypath, secboot_keys[i].handle);
			INFO("DO NOT LOSE THE Symmetric KEY, IT IS NOT EXPORTABLE/RETRIEVABLE\n");
			gen_cnt_table = true;
		} else {
			ret = hse_extract_and_import_rsa_key(secboot_keys[i].keypath, secboot_keys[i].handle);
		} 
		if (ret) {
			ERROR("Failed to import %s\n", secboot_keys[i].name);
			goto err_close_fd;
		}
	}

	if (gen_cnt_table) {
		INFO("Publishing Monotonic Counter Table\n");
		ret = hse_set_and_publish_cnt_table();
		if (ret) {
			ERROR("Failed to setup monotonic counter table\n");
			goto err_close_fd;
		}
	}

	INFO("Generating Secure Memory Region entry\n");

	ret = hse_smr_install(fd, &ivt, &app_boot, bl2_sign_file,
			      bl2_bin_file, secboot_keys[BL2_KEY].handle,
			      boot_medium);
	if (ret)
		goto err_close_fd;

	INFO("Generating Core Reset Entry\n");

	ret = hse_cr_install(&app_boot);
	if (ret)
		goto err_close_fd;

	INFO("Retrieving SYSIMG size\n");

	sysimg_size = hse_mem_alloc(sizeof(*sysimg_size));
	if (!sysimg_size) {
		ERROR("Failed to allocate space for SYSIMG size\n");
		ret = -ENOMEM;
		goto err_close_fd;
	}

	ret = hse_sysimg_getsize(sysimg_size);
	if (ret)
		goto err_free_sysimg_size;

	INFO("Publishing SYSIMG\n");

	sysimg = hse_mem_alloc(*sysimg_size);
	if (!sysimg) {
		ERROR("Failed to allocate space for SYSIMG\n");
		ret = -ENOMEM;
		goto err_free_sysimg_size;
	}

	ret = hse_sysimg_publish(sysimg, sysimg_size);
	if (ret)
		goto err_free_sysimg;

	INFO("Writing SYSIMG to %s\n", device);

	if (boot_medium == QSPI)
		ret = hse_sysimg_write_qspi(fd, &ivt, sysimg, sysimg_size, 1);
	else
		ret = hse_sysimg_write_sd_mmc(fd, &ivt, sysimg, sysimg_size, boot_medium, 1);

err_free_sysimg:
	hse_mem_free(sysimg);
err_free_sysimg_size:
	hse_mem_free(sysimg_size);
err_close_fd:
	close(fd);
err_close_hse:
	hse_dev_close();
	return ret;
}

int hse_keycatalog_format(const char* device, bool overwrite, enum boot_type boot_medium)
{
	struct ivt ivt;
	void *sysimg;
	uint32_t *sysimg_size;
	uint16_t hse_status;
	int fd, ret = 0;

	ret = hse_dev_open();
	if (ret) {
		ERROR("Failed to open HSE device - error %d\n", ret);
		return ret;
	}

	/* check if hse has been initialised */
	hse_status = hse_check_status();
	if (!(hse_status & HSE_STATUS_INIT_OK)) {
		ERROR("HSE not initialised or missing firmware\n");
		ret = -ENODEV;
		goto err_close_hse;
	}

	if (hse_status & HSE_STATUS_INSTALL_OK && !overwrite) {
		ERROR("HSE key catalogs already formatted\n");
		ret = -ECANCELED;
		goto err_close_hse;
	}

	INFO("Retrieving IVT from device %s\n", device);

	fd = open(device, O_SYNC | O_RDWR);
	if (fd < 0) {
		ERROR("Failed to open %s\n", device);
		ret = errno;
		goto err_close_hse;
	}

	if (boot_medium == QSPI)
		ret = get_dev_offset(fd, &ivt, IVT_OFFSET_QSPI, sizeof(ivt));
	else
		ret = get_dev_offset(fd, &ivt, IVT_OFFSET_SD_MMC, sizeof(ivt));

	if (ret)
		goto err_close_fd;

	INFO("Enabling MUs\n");

	ret = hse_mus_enable();
	if (ret)
		goto err_close_fd;

	INFO("Formatting NVM and RAM key catalogs\n");

	ret = hse_key_format();
	if (ret)
		goto err_close_fd;

	INFO("Retrieving SYSIMG size\n");

	sysimg_size = hse_mem_alloc(sizeof(*sysimg_size));
	if (!sysimg_size) {
		ERROR("Failed to allocate space for SYSIMG size\n");
		ret = -ENOMEM;
		goto err_close_fd;
	}

	ret = hse_sysimg_getsize(sysimg_size);
	if (ret)
		goto err_free_sysimg_size;

	INFO("Publishing SYSIMG\n");

	sysimg = hse_mem_alloc(*sysimg_size);
	if (!sysimg) {
		ERROR("Failed to allocate space for SYSIMG\n");
		goto err_free_sysimg_size;
	}

	ret = hse_sysimg_publish(sysimg, sysimg_size);
	if (ret)
		goto err_free_sysimg;

	INFO("Writing SYSIMG to %s\n", device);

	if (boot_medium == QSPI)
		ret = hse_sysimg_write_qspi(fd, &ivt, sysimg, sysimg_size, 0);
	else
		ret = hse_sysimg_write_sd_mmc(fd, &ivt, sysimg, sysimg_size, boot_medium, 0);

err_free_sysimg:
	hse_mem_free(sysimg);
err_free_sysimg_size:
	hse_mem_free(sysimg_size);
err_close_fd:
	close(fd);
err_close_hse:
	hse_dev_close();
	return ret;
}

void usage(char *progname)
{
	printf("\nformat HSE key catalogs or set up HSE-based advanced secure boot\n\n");
	printf("Example: hse-secboot -s -d /dev/mmcblk0 --bl2_key /etc/keys/secboot/bl2_rsa2048_public.pem ");
	printf("--bl31_key -:0x010700 --bl33_key -:0x010700 ");
	printf("--bl2_sign /etc/keys/secboot/bl2-signature.bin-sdcard ");
	printf("--bl2_bin /etc/keys/secboot/bl2_w_dtb.bin-sdcard");
	printf("\n");
	printf("Usage:\n");
	printf("\n");
	printf("%s [-h] [-o] [-b bootmedium] [-f|s] [-d devpath]\n", progname);
	printf("%*c", (int)(strlen(progname) + 2), ' ');
	printf("[--bl2_key] [--bl31_key] [--bl32_key] [--bl33_key]\n");
	printf("\n");
	printf("\t-h:\tdisplay this help string\n");
	printf("\t-f:\tformat key catalogs\n");
	printf("\t\trequires -d\n");
	printf("\t\tmutually exclusive with -s\n");
	printf("\t-s:\tset up advanced secure boot\n");
	printf("\t\trequires -d and --bl2_key, --bl31_key, --bl33_key\n");
	printf("\t\tmutually exclusive with -f\n");
	printf("\t-o:\tforce overwrite of HSE key catalog\n");
	printf("\t-b:\tspecify boot medium type, possible values:\n");
	printf("\t\t\t    sd - SD card boot (default)\n");
	printf("\t\t\t  qspi - QSPI Flash boot\n");
	printf("\t\t\t   mmc - MMC or eMMC boot\n");
	printf("\t-d:\tspecify full path to SD/MMC/MTD device (e.g. /dev/sdb or /dev/mtd0)\n");
	printf("\t--rpmb_key: specify full path to symmetric key file for Rollback Protection and HSE key slot,\n");
	printf("\t            if this option is present, the HSE Monotonic Counter Table will be generated\n");
	printf("\t--bl2_sign: specify full path to the binary signature file of BL2 (required)\n");
	printf("\t--bl2_bin: specify full path to the BL2 binary file (required)\n");
	printf("\t--bl2_key: specify full path to PEM format key file for BL2 and HSE key slot (required)\n");
	printf("\t--bl31_key: specify full path to PEM format key file for BL31 and HSE key slot\n");
	printf("\t--bl32_key: specify full path to PEM format key file for BL32 and HSE key slot (should be used if OP-TEE is present)\n");
	printf("\t--bl33_key: specify full path to PEM format key file for BL33 and HSE key slot\n");
	printf("\t\tkey slot is optional, default values will be used if it is not set\n");
	printf("\n");
	printf("\t\tkey input for `--bl*_key` arguments: <key_file>:0x<key_slot>\n");
	printf("\t\t(key_file will be ignored if key_slot is equal to a previous key)\n");
}

int main(int argc, char *argv[])
{
	char *devpath = NULL, *bl2_sign_path = NULL, *bl2_bin_path = NULL;
	char *bootmedium = "sd";
	int c, fflag = 0, sflag = 0, oflag = 0, ret = 0;
	enum boot_type type = SD;

	while ((c = getopt_long(argc, argv, "hfosb:d:", secboot_options, NULL)) != -1) {
		switch (c) {
			case 'h':
				usage(argv[0]);
				return 0;
			case BL2_SIGN_ARG_ID:
				bl2_sign_path = optarg;
				break;
			case BL2_BIN_ARG_ID:
				bl2_bin_path = optarg;
				break;
			case RPMB_KEY:
			case BL2_KEY:
			case BL31_KEY:
			case BL32_KEY:
			case BL33_KEY:
				if (hse_set_key_input(optarg, c))
					return -1;
				break;
			case 'f':
				fflag = 1;
				break;
			case 'o':
				oflag = 1;
				break;
			case 's':
				sflag = 1;
				break;
			case 'd':
				devpath = optarg;
				break;
			case 'b':
				bootmedium = optarg;
				break;
			case '?':
				usage(argv[0]);
				return -1;
			default:
				ERROR("Unknown error\n");
				usage(argv[0]);
				return -1;
		}
	}

	if (!fflag && !sflag) {
		ERROR("-s or -f should be used\n");
		usage(argv[0]);
		return -1;
	}

	if (fflag && sflag) {
		ERROR("Options -s and -f are mutually exclusive\n");
		usage(argv[0]);
		return -1;
	}

	if (!devpath) {
		ERROR("Option -d is required\n");
		usage(argv[0]);
		return -1;
	}

	if (sflag && (hse_check_req_keys() || !bl2_sign_path ||
	    !bl2_bin_path)) {
		usage(argv[0]);
		return -1;
	}

	if (!strcmp(bootmedium, "qspi")) {
		type = QSPI;
	} else if (!strcmp(bootmedium, "mmc")) {
		type = MMC;
	} else if (strcmp(bootmedium, "sd")) {
		ERROR("Unrecognized boot medium type \"%s\"\n", bootmedium);
		usage(argv[0]);
		return -1;
	}
	INFO("Chosen boot medium: %s\n", bootmedium);

	if (fflag) {
		INFO("Formatting HSE key catalog\n");
		ret = hse_keycatalog_format(devpath, oflag, type);
		return ret;
	}
	
	if (sflag) {
		INFO("Setting up secure boot\n");
		ret = hse_parse_keys();
		if (ret)
			return ret; 
		
		ret = hse_secboot_enable(devpath, bl2_sign_path, bl2_bin_path,
					 type);
		return ret;
	}

	/* something very wrong has happened */
	ERROR("Unknown error\n");
	usage(argv[0]);
	return -1;
}
