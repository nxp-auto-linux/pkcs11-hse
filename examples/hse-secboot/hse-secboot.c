// SPDX-License-Identifier: BSD-3-Clause
/*
 * HSE advanced secure boot preparatory command demo
 *
 * Copyright 2022-2026 NXP
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
#include <openssl/ec.h>
#include <getopt.h>

#include <sys/ioctl.h>
#include <mtd/mtd-user.h>
#include "libhse.h"

#ifndef KS_CONFIG_OPTEE_EN
#include "default_ks_config.h"
#else
#include "optee_ks_config.h"
#endif /* KS_CONFIG_OPTEE_EN */

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
#define DDRFW_DEFAULT_KEY_HANDLE 0x010000
#define BL2_DEFAULT_KEY_HANDLE 0x010000
#define BL31_DEFAULT_KEY_HANDLE 0x010000
#define BL32_DEFAULT_KEY_HANDLE 0x010000
#define BL33_DEFAULT_KEY_HANDLE 0x010000

#define HSE_MONOTONIC_CNT_NUM 4
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

#define BL2_VERSION_OFFSET	0x4

enum boot_type {
	QSPI = 0,
	SD = 2,
	MMC = 3,
};

enum key_type {
	INVALID_KEY = -1,
	RPMB_KEY = 0,
	DDRFW_KEY,
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
	{ DDRFW_KEY, true, DDRFW_DEFAULT_KEY_HANDLE, "DDR FW Public key", NULL, NULL },
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
	{ "ddrfw_key", required_argument, NULL, DDRFW_KEY},
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

hseEccCurveId_t hse_get_ecc_curve_id(char *curve_name)
{
	if (!strncmp(curve_name, SN_X9_62_prime256v1, strlen(SN_X9_62_prime256v1))) {
		return HSE_EC_SEC_SECP256R1;
	} else if (!strncmp(curve_name, SN_secp384r1, strlen(SN_secp384r1))) {
		return HSE_EC_SEC_SECP384R1;
	}

	ERROR("Curve name invalid: %s\n", curve_name);
	return HSE_EC_CURVE_NONE;
}

uint16_t hse_get_ecc_curve_bitlen(hseEccCurveId_t hse_curve_id)
{
	switch (hse_curve_id)
	{
		case HSE_EC_SEC_SECP256R1:
			return 256u;
		case HSE_EC_SEC_SECP384R1:
			return 384u;
		case HSE_EC_BRAINPOOL_BRAINPOOLP256R1:
			return 256u;
		default:
			return 0;
	}
}

int hse_check_prev_import(int key_idx)
{
	for (int i = 0; i < key_idx; i++) {
		if (secboot_keys[i].handle == secboot_keys[key_idx].handle) {
			INFO("Slot already occupied, %s already imported for a previous image.\n",
				 secboot_keys[key_idx].name);
			return 1;
		}
	}
	return 0;
}

int hse_mus_enable()
{
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	DECLARE_SET_ZERO(hseAttrMUConfig_t, mu_config);
	int32_t mu_config_handle;
	int i, ret = 0;

	for (i = 0; i < HSE_NUM_OF_MU_INSTANCES; i++) {
		mu_config.muInstances[i].muConfig = HSE_MU_ACTIVATED;
	}

	mu_config_handle = hse_mem_alloc(sizeof(mu_config));
	if (mu_config_handle < 0) {
		ERROR("Failed to allocate space for MU Configuration in reserved memory\n");
		return -ENOMEM;
	}
	hse_memcpy_to_dev(mu_config_handle, &mu_config, sizeof(mu_config), 0);

	srv_desc.srvId = HSE_SRV_ID_SET_ATTR;
	srv_desc.hseSrv.setAttrReq.attrId = HSE_MU_CONFIG_ATTR_ID;
	srv_desc.hseSrv.setAttrReq.attrLen = sizeof(mu_config);
	srv_desc.hseSrv.setAttrReq.pAttr = hse_virt_to_dma(mu_config_handle, 0);

	ret = hse_srv_req_sync(HSE_CHANNEL_ADM, &srv_desc, sizeof(srv_desc), NULL);
	if (ret)
		ERROR("Failed to enable MUs\n");
	hse_mem_free(mu_config_handle);

	return ret;
}

int hse_get_fw_size(uint32_t *fw_size)
{
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	int hse_fw_size_handle;
	int ret = 0;

	hse_fw_size_handle = hse_mem_alloc(sizeof(hseAttrHseFwSize_t));
	if (hse_fw_size_handle < 0) {
		ERROR("Failed to allocate space for HSE Firmware Size Attribute\n");
		return -ENOMEM;
	}

	srv_desc.srvId = HSE_SRV_ID_GET_ATTR;
	srv_desc.hseSrv.getAttrReq.attrId = HSE_FW_SIZE_ATTR_ID;
	srv_desc.hseSrv.getAttrReq.attrLen = sizeof(hseAttrHseFwSize_t);
	srv_desc.hseSrv.getAttrReq.pAttr = hse_virt_to_dma(hse_fw_size_handle, 0);

	ret = hse_srv_req_sync(HSE_CHANNEL_ADM, &srv_desc, sizeof(srv_desc), NULL);
	if (ret) {
		ERROR("Failed to get HSE Firmware Size\n");
		goto err_free_fw_size;
	}
	hse_memcpy_from_dev(fw_size, hse_fw_size_handle, sizeof(hseAttrHseFwSize_t), 0);

err_free_fw_size:
	hse_mem_free(hse_fw_size_handle);

	return ret;
}

int hse_update_fw(void *new_fw, uint32_t size)
{
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	int hse_fw_size_handle, hse_new_fw_handle;
	uint32_t srv_rsp;
	int ret = 0;

	if (!new_fw)
		return -EINVAL;

	hse_fw_size_handle = hse_mem_alloc(sizeof(size));
	if (hse_fw_size_handle < 0) {
		ERROR("Failed to allocate space for HSE Firmware Size\n");
		return -ENOMEM;
	}
	hse_memcpy_to_dev(hse_fw_size_handle, &size, sizeof(size), 0);

	hse_new_fw_handle = hse_mem_alloc(size);
	if (hse_new_fw_handle < 0) {
		ERROR("Failed to allocate space for HSE Firmware\n");
		ret = -ENOMEM;
		goto err_free_hse_size;
	}

	srv_desc.srvId = HSE_SRV_ID_FIRMWARE_UPDATE;
	srv_desc.hseSrv.firmwareUpdateReq.pFwBufferLength = hse_virt_to_dma(hse_fw_size_handle, 0);
	srv_desc.hseSrv.firmwareUpdateReq.pOutFwBuffer = hse_virt_to_dma(hse_new_fw_handle, 0);

	ret = hse_srv_req_sync(HSE_CHANNEL_ADM, &srv_desc, sizeof(srv_desc), &srv_rsp);
	if (ret) {
		ERROR("Failed to update HSE Firmware, error 0x%08X\n", srv_rsp);
		goto err_free_hse_new_fw;
	}
	hse_memcpy_from_dev(new_fw, hse_new_fw_handle, size, 0);

err_free_hse_new_fw:
	hse_mem_free(hse_new_fw_handle);
err_free_hse_size:
	hse_mem_free(hse_fw_size_handle);

	return ret;
}

int hse_fw_write_sd_mmc(int fd, struct ivt *ivt, void *fw, uint32_t fw_size)
{
	off_t seek_off;
	int bytes;

	seek_off = lseek(fd, ivt->hse_fw, SEEK_SET);
	if (seek_off < 0 || seek_off != ivt->hse_fw) {
		ERROR("Failed to find HSE Firmware location\n");
		return errno;
	}
	bytes = write(fd, fw, fw_size);
	if (bytes < 0 || bytes != fw_size) {
		ERROR("Failed to write HSE Firmware\n");
		return errno;
	}

	return 0;
}

int hse_fw_write_qspi(int fd, struct ivt *ivt, void *fw, uint32_t fw_size)
{
	off_t seek_off;
	erase_info_t ei;
	uint8_t *hse_fw;
	uint32_t blk_cnt;
	uint32_t rem, div;
	int bytes, ret = 0;

	blk_cnt = fw_size / QSPI_BLOCK_SIZE + 1;

	hse_fw = malloc(blk_cnt * QSPI_BLOCK_SIZE);
	if (!hse_fw) {
		ERROR("Failed to allocate memory for HSE Firmware\n");
		return -ENOMEM;
	}

	div = ivt->hse_fw / QSPI_BLOCK_SIZE;
	rem = ivt->hse_fw % QSPI_BLOCK_SIZE;
	ret = get_dev_offset(fd, hse_fw, (div * QSPI_BLOCK_SIZE), (blk_cnt * QSPI_BLOCK_SIZE));
	if (ret) {
		ERROR("Failed to retrieve HSE Firmware from device\n");
		goto err_free_hse_fw;
	}
	memcpy(hse_fw + rem, fw, fw_size);

	ei.length = (blk_cnt * QSPI_BLOCK_SIZE);
	ei.start = (div * QSPI_BLOCK_SIZE);
	ioctl(fd, MEMUNLOCK, &ei);
	ioctl(fd, MEMERASE, &ei);

	seek_off = lseek(fd, (div * QSPI_BLOCK_SIZE), SEEK_SET);
	if (seek_off < 0) {
		ERROR("Failed to find SYSIMG location\n");
		ret = errno;
		goto err_free_hse_fw;
	}
	bytes = write(fd, hse_fw, (blk_cnt * QSPI_BLOCK_SIZE));
	if (bytes < 0 || bytes != (blk_cnt * QSPI_BLOCK_SIZE)) {
		ERROR("Failed to write SYSIMG\n");
		ret = errno;
		goto err_free_hse_fw;
	}

err_free_hse_fw:
	free(hse_fw);
	return ret;
}

int hse_fw_blue_image_convert(const char *device, enum boot_type boot_medium)
{
	struct ivt ivt;
	int fd, ret = 0;
	uint32_t fw_size;
	uint8_t *blue_fw;
	uint16_t hse_status;

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

	if (ret) {
		ERROR("Failed to get IVT from device\n");
		goto err_close_fd;
	}

	ret = hse_get_fw_size(&fw_size);
	if (ret)
		goto err_close_fd;

	blue_fw = malloc(fw_size);
	if (!blue_fw) {
		ERROR("Failed to allocate space for HSE Blue Firmware\n");
		ret = -ENOMEM;
		goto err_close_fd;
	}

	ret = hse_update_fw(blue_fw, fw_size);
	if (ret)
		goto err_free_blue_fw;

	if (boot_medium == QSPI)
		ret = hse_fw_write_qspi(fd, &ivt, blue_fw, fw_size);
	else
		ret = hse_fw_write_sd_mmc(fd, &ivt, blue_fw, fw_size);

	if (!ret)
		INFO("HSE Blue Firmware Image written successfully\n");

err_free_blue_fw:
	free(blue_fw);
err_close_fd:
	close(fd);
err_close_hse:
	hse_dev_close();

	return ret;
}

int hse_key_format()
{
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	int nvm_catalog_handle, ram_catalog_handle;
	int ret = 0;

	nvm_catalog_handle = hse_mem_alloc(sizeof(hseKeyGroupCfgEntry_t) * ARRAY_SIZE(nvm_cat));
	if (nvm_catalog_handle < 0) {
		ERROR("Failed to allocate space for NVM Key Group in reserved memory\n");
		return -ENOMEM;
	}

	ram_catalog_handle = hse_mem_alloc(sizeof(hseKeyGroupCfgEntry_t) * ARRAY_SIZE(ram_cat));
	if (ram_catalog_handle < 0) {
		ERROR("Failed to allocate space for RAM Key Group in reserved memory\n");
		ret = -ENOMEM;
		goto err_hse_free_nvm;
	}

	hse_memcpy_to_dev(nvm_catalog_handle, &nvm_cat, sizeof(nvm_cat), 0);
	hse_memcpy_to_dev(ram_catalog_handle, &ram_cat, sizeof(ram_cat), 0);

	srv_desc.srvId = HSE_SRV_ID_FORMAT_KEY_CATALOGS;
	srv_desc.hseSrv.formatKeyCatalogsReq.pNvmKeyCatalogCfg = hse_virt_to_dma(nvm_catalog_handle, 0);
	srv_desc.hseSrv.formatKeyCatalogsReq.pRamKeyCatalogCfg = hse_virt_to_dma(ram_catalog_handle, 0);

	ret = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc, sizeof(srv_desc), NULL);
	if (ret)
		ERROR("Failed to format key catalogs!\n");

	hse_mem_free(ram_catalog_handle);
err_hse_free_nvm:
	hse_mem_free(nvm_catalog_handle);
	return ret;
}

int hse_set_and_publish_cnt_table(void)
{
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	FILE *f;
	void *cnt_table;
	int hse_cnt_table_handle; 
	int ret = 0, err = 0;

	cnt_table = malloc(HSE_NVM_CONTAINER_CNT_TBL_SIZE);
	if (!cnt_table) {
		ERROR("Failed to alloc memory for monotonic counter table\n");
		return -ENOMEM;
	}

	hse_cnt_table_handle = hse_mem_alloc(HSE_NVM_CONTAINER_CNT_TBL_SIZE);
	if (hse_cnt_table_handle < 0) {
		ERROR("Failed to alloc reserved memory for counter table\n");
		ret = -ENOMEM;
		goto err_free_cnt_table;
	}

	srv_desc.srvId = HSE_SRV_ID_CONFIG_COUNTER;
	srv_desc.hseSrv.configSecCounter.counterIndex = HSE_MONOTONIC_CNT_NUM;
	srv_desc.hseSrv.configSecCounter.RPBitSize = 32;

	ret = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc, sizeof(srv_desc), NULL);
	if (ret) {
		ERROR("Failed to configure monotonic counter table\n");
		goto err_free_hse_cnt_table;
	}

	memset(&srv_desc, 0, sizeof(srv_desc));

	srv_desc.srvId = HSE_SRV_ID_PUBLISH_LOAD_CNT_TBL;
	srv_desc.hseSrv.publishLoadCntTblReq.action = HSE_NVM_CNT_TBL_ACTION_PUBLISH;
	srv_desc.hseSrv.publishLoadCntTblReq.pNvmContainerCntTbl = hse_virt_to_dma(hse_cnt_table_handle, 0);

	ret = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc, sizeof(srv_desc), NULL);
	if (ret) {
		ERROR("Failed to publish monotonic counter table\n");
		goto err_free_hse_cnt_table;
	}
	hse_memcpy_from_dev(cnt_table, hse_cnt_table_handle, HSE_NVM_CONTAINER_CNT_TBL_SIZE, 0);

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
	hse_mem_free(hse_cnt_table_handle);
err_free_cnt_table:
	free(cnt_table);

	return ret;
}

int hse_ecc_key_import(int xy_handle, int xy_size, char *curve_name, uint32_t handle)
{
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	DECLARE_SET_ZERO(hseKeyInfo_t, key_info);
	int key_info_handle;
	int ret = 0;

	key_info.keyFlags = HSE_KF_USAGE_VERIFY;
	key_info.specific.eccCurveId = hse_get_ecc_curve_id(curve_name);
	key_info.keyBitLen = hse_get_ecc_curve_bitlen(key_info.specific.eccCurveId);
	key_info.keyType = HSE_KEY_TYPE_ECC_PUB;

	key_info_handle = hse_mem_alloc(sizeof(key_info));
	if (key_info_handle < 0) {
		ERROR("Failed to allocate space for key info in reserved memory\n");
		return -ENOMEM;
	}
	hse_memcpy_to_dev(key_info_handle, &key_info, sizeof(key_info), 0);

	srv_desc.srvId = HSE_SRV_ID_IMPORT_KEY;
	srv_desc.hseSrv.importKeyReq.targetKeyHandle = handle;
	srv_desc.hseSrv.importKeyReq.pKeyInfo = hse_virt_to_dma(key_info_handle, 0);
	srv_desc.hseSrv.importKeyReq.pKey[0] = hse_virt_to_dma(xy_handle, 0);
	srv_desc.hseSrv.importKeyReq.keyLen[0] = xy_size;
	srv_desc.hseSrv.importKeyReq.cipher.cipherKeyHandle = HSE_INVALID_KEY_HANDLE;
	srv_desc.hseSrv.importKeyReq.keyContainer.authKeyHandle = HSE_INVALID_KEY_HANDLE;

	ret = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc, sizeof(srv_desc), NULL);
	if (ret)
		ERROR("Failed to import RSA Public Key\n");
	hse_mem_free(key_info_handle);

	return ret;
}

int hse_rsa_key_import(int rsa_modulus_handle, int rsa_modulus_size,
	                int rsa_pub_exponent_handle, int rsa_pub_exponent_size, uint32_t handle)
{
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	DECLARE_SET_ZERO(hseKeyInfo_t, key_info);
	int key_info_handle;
	int ret = 0;

	key_info.keyFlags = HSE_KF_USAGE_VERIFY;
	key_info.keyBitLen = HSE_BYTES_TO_BITS(rsa_modulus_size);
	key_info.keyType = HSE_KEY_TYPE_RSA_PUB;
	key_info.specific.pubExponentSize = rsa_pub_exponent_size;

	key_info_handle = hse_mem_alloc(sizeof(key_info));
	if (key_info_handle < 0) {
		ERROR("Failed to allocate space for key info in reserved memory\n");
		return -ENOMEM;
	}
	hse_memcpy_to_dev(key_info_handle, &key_info, sizeof(key_info), 0);

	srv_desc.srvId = HSE_SRV_ID_IMPORT_KEY;
	srv_desc.hseSrv.importKeyReq.targetKeyHandle = handle;
	srv_desc.hseSrv.importKeyReq.pKeyInfo = hse_virt_to_dma(key_info_handle, 0);
	srv_desc.hseSrv.importKeyReq.pKey[0] = hse_virt_to_dma(rsa_modulus_handle, 0);
	srv_desc.hseSrv.importKeyReq.pKey[1] = hse_virt_to_dma(rsa_pub_exponent_handle, 0);
	srv_desc.hseSrv.importKeyReq.keyLen[0] = rsa_modulus_size;
	srv_desc.hseSrv.importKeyReq.keyLen[1] = rsa_pub_exponent_size;
	srv_desc.hseSrv.importKeyReq.cipher.cipherKeyHandle = HSE_INVALID_KEY_HANDLE;
	srv_desc.hseSrv.importKeyReq.keyContainer.authKeyHandle = HSE_INVALID_KEY_HANDLE;

	ret = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc, sizeof(srv_desc), NULL);
	if (ret)
		ERROR("Failed to import RSA Public Key\n");
	hse_mem_free(key_info_handle);

	return ret;
}

int hse_extract_and_import_sym_key(const char *keypath, uint32_t handle)
{
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	DECLARE_SET_ZERO(hseKeyInfo_t, key_info);
	int hse_key_handle, hse_key_info_handle;
	uint8_t key[32] = {0};
	int ret = 0, err = 0;
	uint32_t key_len;
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

	hse_key_info_handle = hse_mem_alloc(sizeof(key_info));
	if (hse_key_info_handle < 0) {
		ERROR("Failed to allocate space for key info\n");
		ret = -ENOMEM;
		goto err_close_keyfile;
	}

	hse_key_handle = hse_mem_alloc(key_len);
	if (hse_key_handle < 0) {
		ERROR("Failed to allocate space for Symmetric Key\n");
		ret = -ENOMEM;
		goto err_free_key_info;
	}
	hse_memcpy_to_dev(hse_key_handle, key, key_len, 0);

	key_info.keyFlags = HSE_KF_USAGE_SIGN;
	key_info.keyBitLen = HSE_BYTES_TO_BITS(key_len);
	key_info.keyType = HSE_KEY_TYPE_HMAC;
	hse_memcpy_to_dev(hse_key_info_handle, &key_info, sizeof(key_info), 0);

	srv_desc.srvId = HSE_SRV_ID_IMPORT_KEY;
	srv_desc.hseSrv.importKeyReq.targetKeyHandle = handle;
	srv_desc.hseSrv.importKeyReq.pKeyInfo = hse_virt_to_dma(hse_key_info_handle, 0);
	srv_desc.hseSrv.importKeyReq.pKey[2] = hse_virt_to_dma(hse_key_handle, 0);
	srv_desc.hseSrv.importKeyReq.keyLen[2] = key_len;
	srv_desc.hseSrv.importKeyReq.cipher.cipherKeyHandle = HSE_INVALID_KEY_HANDLE;
	srv_desc.hseSrv.importKeyReq.keyContainer.authKeyHandle = HSE_INVALID_KEY_HANDLE;

	ret = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc, sizeof(srv_desc), NULL);
	if (ret)
		ERROR("Failed to import Symmetric Key\n");

	hse_mem_free(hse_key_handle);
err_free_key_info:
	hse_mem_free(hse_key_info_handle);
err_close_keyfile:
	fclose(f);
	return ret;
}

int hse_extract_and_import_ecc_key(const char *keypath, uint32_t handle)
{
	FILE *f;
	uint8_t *x, *y;
	EVP_PKEY *pkey;
	int bytes, ret = 0;
	char curve_name[64];
	int xy_handle, xy_size;
	uint64_t curve_name_len;
	BIGNUM *x_bn = NULL, *y_bn = NULL;

	f = fopen(keypath, "rb");
	if (!f) {
		ERROR("Could not find ECC Key file %s\n", keypath);
		return -ENOENT;
	}

	pkey = PEM_read_PUBKEY(f, NULL, NULL, NULL);
	if (!pkey) {
		ERROR("Failed to read ECC Public Key from file %s\n", keypath);
		ret = -ENOKEY;
		goto err_close_keyfile;
	}

	ret = EVP_PKEY_get_bn_param(pkey, "qx", &x_bn);
	if (!x_bn) {
		ERROR("Failed to read ECC x from file %s\n", keypath);
		ret = -ENOKEY;
		goto err_free_pkey;
	}

	ret = EVP_PKEY_get_bn_param(pkey, "qy", &y_bn);
	if (!y_bn) {
		ERROR("Failed to read ECC y from file %s\n", keypath);
		ret = -ENOKEY;
		goto err_free_x_bn;
	}
	xy_size = BN_num_bytes(x_bn) + BN_num_bytes(y_bn);

	ret = EVP_PKEY_get_utf8_string_param(pkey, "group", curve_name,
		                                 sizeof(curve_name), &curve_name_len);
	if (!ret) {
		ERROR("Failed to read ECC curve name from file %s\n", keypath);
		ret = -ENOKEY;
		goto err_free_y_bn;
	}

	xy_handle = hse_mem_alloc(xy_size);
	if (xy_handle < 0) {
		ERROR("Failed to allocate space for ECC public key in reserved memory\n");
		ret = -ENOMEM;
		goto err_close_keyfile;
	}

	x = malloc(BN_num_bytes(x_bn));
	if (!x) {
		ERROR("Failed to allocate space for ECC Public Key x component\n");
		ret = -ENOMEM;
		goto err_hse_free_xy;
	}

	bytes = BN_bn2bin(x_bn, x);
	if (bytes != BN_num_bytes(x_bn)) {
		ERROR("Failed to copy ECC Public Key x component\n");
		ret = -ENOKEY;
		goto err_free_x;
	}
	hse_memcpy_to_dev(xy_handle, x, bytes, 0);

	y = malloc(BN_num_bytes(y_bn));
	if (!y) {
		ERROR("Failed to allocate space for ECC Public Key y component\n");
		ret = -ENOMEM;
		goto err_free_x;
	}

	bytes = BN_bn2bin(y_bn, y);
	if (bytes != BN_num_bytes(y_bn)) {
		ERROR("Failed to copy ECC Public Key y component\n");
		ret = -ENOKEY;
		goto err_free_y;
	}
	hse_memcpy_to_dev(xy_handle, y, bytes, BN_num_bytes(x_bn));

	ret = hse_ecc_key_import(xy_handle, xy_size, curve_name, handle);

err_free_y:
	free(y);
err_free_x:
	free(x);
err_hse_free_xy:
	hse_mem_free(xy_handle);
err_free_y_bn:
	BN_free(y_bn);
err_free_x_bn:
	BN_free(x_bn);
err_free_pkey:
	EVP_PKEY_free(pkey);
err_close_keyfile:
	fclose(f);
	return ret;
}

int hse_extract_and_import_rsa_key(const char *keypath, uint32_t handle)
{
	FILE *f;
	int bytes, ret = 0;
	EVP_PKEY *pkey;
	int rsa_modulus_handle, rsa_pub_exponent_handle;
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
		goto err_free_pkey;
	}

	ret = EVP_PKEY_get_bn_param(pkey, "e", &rsa_bn_pub_exponent);
	if (!rsa_bn_pub_exponent) {
		ERROR("Failed to read RSA Public Key Exponent from file %s\n", keypath);
		ret = -ENOKEY;
		goto err_free_rsa_bn_modulus;
	}

	rsa_modulus_handle = hse_mem_alloc(BN_num_bytes(rsa_bn_modulus));
	if (rsa_modulus_handle < 0) {
		ERROR("Failed to allocate space for RSA Public Key Modulus in reserved memory\n");
		ret = -ENOMEM;
		goto err_free_rsa_bn_pub_exponent;
	}

	rsa_modulus = malloc(BN_num_bytes(rsa_bn_modulus));
	if (!rsa_modulus) {
		ERROR("Failed to allocate space for RSA Public Key Exponent\n");
		ret = -ENOMEM;
		goto err_hse_free_rsa_modulus;
	}

	bytes = BN_bn2bin(rsa_bn_modulus, rsa_modulus);
	if (bytes != BN_num_bytes(rsa_bn_modulus)) {
		ERROR("Failed to copy RSA Public Key Modulus\n");
		ret = -ENOKEY;
		goto err_free_rsa_modulus;
	}
	hse_memcpy_to_dev(rsa_modulus_handle, rsa_modulus, bytes, 0);

	rsa_pub_exponent_handle = hse_mem_alloc(BN_num_bytes(rsa_bn_pub_exponent));
	if (rsa_pub_exponent_handle < 0) {
		ERROR("Failed to allocate space for RSA Public Key Exponent in reserved memory\n");
		ret = -ENOMEM;
		goto err_free_rsa_modulus;
	}

	rsa_pub_exponent = malloc(BN_num_bytes(rsa_bn_pub_exponent));
	if (!rsa_pub_exponent) {
		ERROR("Failed to allocate space for RSA Public Key Exponent\n");
		ret = -ENOMEM;
		goto err_hse_free_rsa_pub_exponent;
	}

	bytes = BN_bn2bin(rsa_bn_pub_exponent, rsa_pub_exponent);
	if (bytes != BN_num_bytes(rsa_bn_pub_exponent)) {
		ERROR("Failed to copy RSA Public Exponent\n");
		ret = -ENOKEY;
		goto err_free_rsa_pub_exponent;
	}
	hse_memcpy_to_dev(rsa_pub_exponent_handle, rsa_pub_exponent, bytes, 0);

	ret = hse_rsa_key_import(rsa_modulus_handle, BN_num_bytes(rsa_bn_modulus), rsa_pub_exponent_handle,
				 BN_num_bytes(rsa_bn_pub_exponent), handle);

err_free_rsa_pub_exponent:
	free(rsa_pub_exponent);
err_hse_free_rsa_pub_exponent:
	hse_mem_free(rsa_pub_exponent_handle);
err_free_rsa_modulus:
	free(rsa_modulus);
err_hse_free_rsa_modulus:
	hse_mem_free(rsa_modulus_handle);
err_free_rsa_bn_pub_exponent:
	BN_free(rsa_bn_pub_exponent);
err_free_rsa_bn_modulus:
	BN_free(rsa_bn_modulus);
err_free_pkey:
	EVP_PKEY_free(pkey);
err_close_keyfile:
	fclose(f);
	return ret;
}

int hse_extract_bin(const char *bin_file, int bin_handle, size_t bin_size)
{
	FILE *fd = NULL;
	int ret = 0, err = 0;
	uint8_t *bin_tmp = NULL;

	if (bin_handle < 0)
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

	hse_memcpy_to_dev(bin_handle, bin_tmp, bin_size, 0);

out_free_tmp_buf:
	free(bin_tmp);
out_close_fd:
	fclose(fd);
	return ret;
}

int hse_get_bl2_bin(const char *bl2_bin_file, int *bl2_bin_handle, uint32_t *bl2_bin_size)
{
	int ret = 0;

	*bl2_bin_size = get_file_size(bl2_bin_file);
	if (!*bl2_bin_size) {
		ERROR("Invalid BL2 size\n");
		return -ENODATA;
	}

	*bl2_bin_handle = hse_mem_alloc(*bl2_bin_size);
	if (*bl2_bin_handle < 0) {
		ERROR("Failed to allocate space for BL2 in reserved memory\n");
		return -ENOMEM;
	}

	ret = hse_extract_bin(bl2_bin_file, *bl2_bin_handle, *bl2_bin_size);
	if (ret) {
		ERROR("Failed to read BL2 binary from file\n");
		hse_mem_free(*bl2_bin_handle);
	}
	return ret;
}

int hse_get_ecdsa_sig(const char *bl2_sign_file, int *bl2_sign_handle, uint16_t *bl2_sign_size)
{
	ECDSA_SIG *sig;
	uint8_t *r, *s;
	FILE *fd = NULL;
	int ret = 0, err = 0, bytes;
	uint16_t der_sign_size;
	unsigned char *der_sign, *der_sign_copy;
	BIGNUM *r_bn = NULL, *s_bn = NULL;

	der_sign_size = get_file_size(bl2_sign_file);
	if (der_sign_size <= 0) {
		ERROR("Failed to retrieve BL2 signature size\n");
		return -ENODATA;
	}

	der_sign = malloc(der_sign_size);
	if (!der_sign) {
		ERROR("Failed to allocate space for DER encoded ECDSA signature\n");
		return -ENOMEM;
	}
	der_sign_copy = der_sign;

	fd = fopen(bl2_sign_file, "rb");
	if (!fd) {
		ERROR("Could not find binary file %s\n", bl2_sign_file);
		ret = -errno;
		goto out_free_der_sign;
	}

	err = fread((void *)der_sign, 1, der_sign_size, fd);
	if (err < 0 || err != der_sign_size) {
		ret = -err;
		goto out_close_file;
	}

	sig = d2i_ECDSA_SIG(NULL, (const unsigned char**)&der_sign, der_sign_size);
	if (!sig) {
		ERROR("Could not decode DER encoded ECDSA signature\n");
		ret = -EINVAL;
		goto out_close_file;
	}

	ECDSA_SIG_get0(sig, (const BIGNUM**)&r_bn, (const BIGNUM**)&s_bn);
	if (!r_bn || !s_bn) {
		ERROR("Could not retrieve R/S from ECDSA signature\n");
		ret = -EINVAL;
		goto out_free_sig;
	}

	r = malloc(BN_num_bytes(r_bn));
	if (!r) {
		ERROR("Failed to allocate space for ECDSA R component\n");
		ret = -ENOMEM;
		goto out_free_sig;
	}
	
	bytes = BN_bn2bin(r_bn, r);
	if (bytes != BN_num_bytes(r_bn)) {
		ERROR("Failed to copy ECDSA R component\n");
		ret = -ENOKEY;
		goto out_free_r;
	}

	s = malloc(BN_num_bytes(s_bn));
	if (!s) {
		ERROR("Failed to allocate space for ECDSA S component\n");
		ret = -ENOMEM;
		goto out_free_r;
	}
	
	bytes = BN_bn2bin(s_bn, s);
	if (bytes != BN_num_bytes(s_bn)) {
		ERROR("Failed to copy ECDSA S component\n");
		ret = -ENOKEY;
		goto out_free_s;
	}

	*bl2_sign_handle = hse_mem_alloc(BN_num_bytes(r_bn) + BN_num_bytes(s_bn));
	if (*bl2_sign_handle < 0) {
		ERROR("Failed to allocated memory for BL2 signature\n");
		ret = -ENOMEM;
		goto out_free_s;
	}
	*bl2_sign_size = BN_num_bytes(r_bn) + BN_num_bytes(s_bn);

	hse_memcpy_to_dev(*bl2_sign_handle, r, BN_num_bytes(r_bn), 0);
	hse_memcpy_to_dev(*bl2_sign_handle, s, BN_num_bytes(s_bn), BN_num_bytes(r_bn));

out_free_s:
	free(s);
out_free_r:
	free(r);
out_free_sig:
	ECDSA_SIG_free(sig);
out_close_file:
	fclose(fd);
out_free_der_sign:
	free(der_sign_copy);

	return ret;
}

int hse_get_rsa_sig(const char *bl2_sign_file, int *bl2_sign_handle, uint16_t *bl2_sign_size)
{
	int ret = 0;

	*bl2_sign_size = get_file_size(bl2_sign_file);
	if (*bl2_sign_size <= 0) {
		ERROR("Failed to retrieve BL2 signature size\n");
		return -ENODATA;
	}

	*bl2_sign_handle = hse_mem_alloc(*bl2_sign_size);
	if (*bl2_sign_handle < 0) {
		ERROR("Failed to allocate space for BL2 signature in reserved memory\n");
		return -ENOMEM;
	}

	ret = hse_extract_bin(bl2_sign_file, *bl2_sign_handle, *bl2_sign_size);
	if (ret) {
		ERROR("Failed to read BL2 signature from file\n");
		hse_mem_free(*bl2_sign_handle);
	}
	return ret;
}

int hse_ecc_smr_install(int fd, struct ivt *ivt, struct app_boot_hdr *app_boot,
			 const char *bl2_sign_file, const char *bl2_bin_file,
			 uint32_t auth_handle, enum boot_type boot_medium)
{
	uint32_t bl2_bin_size;
	uint16_t bl2_sign_size;
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	DECLARE_SET_ZERO(hseSmrEntry_t, smr_entry);
	int bl2_bin_handle, bl2_sign_handle, smr_entry_handle;
	int ret = 0;

	ret = hse_get_bl2_bin(bl2_bin_file, &bl2_bin_handle, &bl2_bin_size);
	if (ret)
		return ret;

	ret = hse_get_ecdsa_sig(bl2_sign_file, &bl2_sign_handle, &bl2_sign_size);
	if (ret)
		goto err_hse_free_bl2_bin;

	smr_entry.pSmrSrc = get_app_boot_start(ivt);
	smr_entry.pSmrDest = app_boot->ram_load;
	smr_entry.smrSize = bl2_bin_size;

	if (boot_medium == QSPI)
		smr_entry.configFlags = (HSE_SMR_CFG_FLAG_QSPI_FLASH);
	else if (boot_medium == SD)
		smr_entry.configFlags = (HSE_SMR_CFG_FLAG_SD_FLASH);
	else if (boot_medium == MMC)
		smr_entry.configFlags = (HSE_SMR_CFG_FLAG_MMC_FLASH);

	smr_entry.authKeyHandle = auth_handle;
	smr_entry.authScheme.sigScheme.signSch = HSE_SIGN_ECDSA;
	smr_entry.authScheme.sigScheme.sch.ecdsa.hashAlgo = HSE_HASH_ALGO_SHA_1;
	smr_entry.smrDecrypt.decryptKeyHandle = HSE_SMR_DECRYPT_KEY_HANDLE_NOT_USED;
	smr_entry.versionOffset = BL2_VERSION_OFFSET;

	smr_entry_handle = hse_mem_alloc(sizeof(smr_entry));
	if (smr_entry_handle < 0) {
		ERROR("Failed to allocate space for SMR Entry in reserved memory\n");
		ret = -ENOMEM;
		goto err_hse_free_bl2_sign;
	}
	/* workaround for bus error on writing to hse rmem */
	hse_memcpy_to_dev(smr_entry_handle, &smr_entry, sizeof(smr_entry), 0);

	srv_desc.srvId = HSE_SRV_ID_SMR_ENTRY_INSTALL;
	srv_desc.hseSrv.smrEntryInstallReq.accessMode = HSE_ACCESS_MODE_ONE_PASS;
	srv_desc.hseSrv.smrEntryInstallReq.entryIndex = 1u;
	srv_desc.hseSrv.smrEntryInstallReq.pSmrEntry = hse_virt_to_dma(smr_entry_handle, 0);
	srv_desc.hseSrv.smrEntryInstallReq.pSmrData = hse_virt_to_dma(bl2_bin_handle, 0);
	srv_desc.hseSrv.smrEntryInstallReq.smrDataLength = bl2_bin_size;
	srv_desc.hseSrv.smrEntryInstallReq.pAuthTag[0] = hse_virt_to_dma(bl2_sign_handle, 0);
	srv_desc.hseSrv.smrEntryInstallReq.pAuthTag[1] = hse_virt_to_dma(bl2_sign_handle, bl2_sign_size / 2);
	srv_desc.hseSrv.smrEntryInstallReq.authTagLength[0] = bl2_sign_size / 2;
	srv_desc.hseSrv.smrEntryInstallReq.authTagLength[1] = bl2_sign_size / 2;

	ret = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc, sizeof(srv_desc), NULL);
	if (ret)
		ERROR("Failed to install SMR Entry\n");
	hse_mem_free(smr_entry_handle);

err_hse_free_bl2_sign:
	hse_mem_free(bl2_sign_handle);
err_hse_free_bl2_bin:
	hse_mem_free(bl2_bin_handle);
	return ret;
}

int hse_rsa_smr_install(int fd, struct ivt *ivt, struct app_boot_hdr *app_boot,
			 const char *bl2_sign_file, const char *bl2_bin_file,
			 uint32_t auth_handle, enum boot_type boot_medium)
{
	uint32_t bl2_bin_size;
	uint16_t bl2_sign_size;
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	DECLARE_SET_ZERO(hseSmrEntry_t, smr_entry);
	int bl2_bin_handle, bl2_sign_handle, smr_entry_handle;
	int ret = 0;

	ret = hse_get_bl2_bin(bl2_bin_file, &bl2_bin_handle, &bl2_bin_size);
	if (ret)
		return ret;

	ret = hse_get_rsa_sig(bl2_sign_file, &bl2_sign_handle, &bl2_sign_size);
	if (ret)
		goto err_hse_free_bl2_bin;

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
	smr_entry.versionOffset = BL2_VERSION_OFFSET;

	smr_entry_handle = hse_mem_alloc(sizeof(smr_entry));
	if (smr_entry_handle < 0) {
		ERROR("Failed to allocate space for SMR Entry in reserved memory\n");
		ret = -ENOMEM;
		goto err_hse_free_bl2_sign;
	}
	/* workaround for bus error on writing to hse rmem */
	hse_memcpy_to_dev(smr_entry_handle, &smr_entry, sizeof(smr_entry), 0);

	srv_desc.srvId = HSE_SRV_ID_SMR_ENTRY_INSTALL;
	srv_desc.hseSrv.smrEntryInstallReq.accessMode = HSE_ACCESS_MODE_ONE_PASS;
	srv_desc.hseSrv.smrEntryInstallReq.entryIndex = 1u;
	srv_desc.hseSrv.smrEntryInstallReq.pSmrEntry = hse_virt_to_dma(smr_entry_handle, 0);
	srv_desc.hseSrv.smrEntryInstallReq.pSmrData = hse_virt_to_dma(bl2_bin_handle, 0);
	srv_desc.hseSrv.smrEntryInstallReq.smrDataLength = bl2_bin_size;
	srv_desc.hseSrv.smrEntryInstallReq.pAuthTag[0] = hse_virt_to_dma(bl2_sign_handle, 0);
	srv_desc.hseSrv.smrEntryInstallReq.authTagLength[0] = bl2_sign_size;

	ret = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc, sizeof(srv_desc), NULL);
	if (ret)
		ERROR("Failed to install SMR Entry\n");
	hse_mem_free(smr_entry_handle);

err_hse_free_bl2_sign:
	hse_mem_free(bl2_sign_handle);
err_hse_free_bl2_bin:
	hse_mem_free(bl2_bin_handle);
	return ret;
}

int hse_cr_install(struct app_boot_hdr *app_boot)
{
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	DECLARE_SET_ZERO(hseCrEntry_t, cr_entry);
	int cr_entry_handle;
	int ret = 0;

	cr_entry.coreId = HSE_APP_CORE_A53_0;
	cr_entry.crSanction = HSE_CR_SANCTION_KEEP_CORE_IN_RESET;
	cr_entry.preBootSmrMap = HSE_SMR_ENTRY_1;
	cr_entry.pPassReset = app_boot->ram_entry;
	cr_entry.startOption = HSE_CR_AUTO_START;

	cr_entry_handle = hse_mem_alloc(sizeof(cr_entry));
	if (cr_entry_handle < 0) {
		ERROR("Failed to allocate space for core reset entry in reserved memory\n");
		return -ENOMEM;
	}
	hse_memcpy_to_dev(cr_entry_handle, &cr_entry, sizeof(cr_entry), 0);

	srv_desc.srvId = HSE_SRV_ID_CORE_RESET_ENTRY_INSTALL;
	srv_desc.hseSrv.crEntryInstallReq.crEntryIndex = 1u;
	srv_desc.hseSrv.crEntryInstallReq.pCrEntry = hse_virt_to_dma(cr_entry_handle, 0);

	ret = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc, sizeof(srv_desc), NULL);
	if (ret)
		ERROR("Failed to install Core Reset Entry\n");

	hse_mem_free(cr_entry_handle);
	return ret;
}

int hse_sysimg_getsize(int sysimg_size_handle)
{
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	int ret = 0;

	srv_desc.srvId = HSE_SRV_ID_GET_SYS_IMAGE_SIZE;
	srv_desc.hseSrv.getSysImageSizeReq.pSysImageSize = hse_virt_to_dma(sysimg_size_handle, 0);

	ret = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc, sizeof(srv_desc), NULL);
	if (ret)
		ERROR("Failed to get SYSIMG size\n");

	return ret;
}

int hse_sysimg_publish(int sysimg_handle, int sysimg_size_handle)
{
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	hsePublishSysImageSrv_t *publish_sysimg_req;
	int publish_offset_handle;
	int ret = 0;

	publish_sysimg_req = &srv_desc.hseSrv.publishSysImageReq;

	/* unused, but required by HSE */
	publish_offset_handle = hse_mem_alloc(sizeof(uint32_t));
	if (publish_offset_handle < 0) {
		ERROR("Failed to allocate space for publish offset in reserved memory\n");
		return -ENOMEM;
	}

	srv_desc.srvId = HSE_SRV_ID_PUBLISH_SYS_IMAGE;
	publish_sysimg_req->publishOptions = HSE_PUBLISH_ALL_DATA_SETS;
	publish_sysimg_req->pPublishOffset = hse_virt_to_dma(publish_offset_handle, 0);
	publish_sysimg_req->pBuffLength = hse_virt_to_dma(sysimg_size_handle, 0);
	publish_sysimg_req->pBuff = hse_virt_to_dma(sysimg_handle, 0);

	ret = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc, sizeof(srv_desc), NULL);
	if (ret)
		ERROR("Failed to publish SYS_IMG\n");

	hse_mem_free(publish_offset_handle);
	return ret;
}

int hse_sysimg_write_sd_mmc(int fd, struct ivt *ivt, void *sysimg, uint32_t sysimg_size,
                            enum boot_type boot_medium, bool secure)
{
	off_t seek_off;
	int bytes;

	seek_off = lseek(fd, ivt->sysimg, SEEK_SET);
	if (seek_off < 0 || seek_off != ivt->sysimg) {
		ERROR("Failed to find SYSIMG location\n");
		return errno;
	}
	bytes = write(fd, sysimg, sysimg_size);
	if (bytes < 0 || bytes != sysimg_size) {
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

int hse_sysimg_write_qspi(int fd, struct ivt *ivt, void *sysimg, uint32_t sysimg_size, bool secure)
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
	memcpy(sysimage + rem, sysimg, sysimg_size);
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
		       const char *bl2_bin_file, enum boot_type boot_medium, int eccflag)
{
	struct ivt ivt;
	bool gen_cnt_table = false;
	struct app_boot_hdr app_boot;
	uint16_t hse_status;
	int sysimg_size_handle, sysimg_handle;
	uint32_t sysimg_size;
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
			if (!eccflag)
				ret = hse_extract_and_import_rsa_key(secboot_keys[i].keypath, secboot_keys[i].handle);
			else
				ret = hse_extract_and_import_ecc_key(secboot_keys[i].keypath, secboot_keys[i].handle);
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

	if (!eccflag)
		ret = hse_rsa_smr_install(fd, &ivt, &app_boot, bl2_sign_file,
					  bl2_bin_file, secboot_keys[BL2_KEY].handle,
					  boot_medium);
	else
		ret = hse_ecc_smr_install(fd, &ivt, &app_boot, bl2_sign_file,
					  bl2_bin_file, secboot_keys[BL2_KEY].handle,
					  boot_medium);
	if (ret)
		goto err_close_fd;

	INFO("Generating Core Reset Entry\n");

	ret = hse_cr_install(&app_boot);
	if (ret)
		goto err_close_fd;

	INFO("Retrieving SYSIMG size\n");

	sysimg_size_handle = hse_mem_alloc(sizeof(sysimg_size));
	if (sysimg_size_handle < 0) {
		ERROR("Failed to allocate space for SYSIMG size\n");
		ret = -ENOMEM;
		goto err_close_fd;
	}

	ret = hse_sysimg_getsize(sysimg_size_handle);
	if (ret)
		goto err_hse_free_sysimg_size;
	hse_memcpy_from_dev(&sysimg_size, sysimg_size_handle, sizeof(sysimg_size), 0);

	INFO("Publishing SYSIMG\n");

	sysimg_handle = hse_mem_alloc(sysimg_size);
	if (sysimg_handle < 0) {
		ERROR("Failed to allocate space for SYSIMG\n");
		goto err_hse_free_sysimg_size;
	}

	ret = hse_sysimg_publish(sysimg_handle, sysimg_size_handle);
	if (ret)
		goto err_hse_free_sysimg_size;

	INFO("Writing SYSIMG to %s\n", device);

	sysimg = malloc(sysimg_size);
	if (!sysimg) {
		ERROR("Failed to allocate space for SYSIMG\n");
		ret = -ENOMEM;
		goto err_hse_free_sysimg;
	}
	hse_memcpy_from_dev(sysimg, sysimg_handle, sysimg_size, 0);

	if (boot_medium == QSPI)
		ret = hse_sysimg_write_qspi(fd, &ivt, sysimg, sysimg_size, 1);
	else
		ret = hse_sysimg_write_sd_mmc(fd, &ivt, sysimg, sysimg_size, boot_medium, 1);
	free(sysimg);

err_hse_free_sysimg:
	hse_mem_free(sysimg_handle);
err_hse_free_sysimg_size:
	hse_mem_free(sysimg_size_handle);
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
	uint32_t sysimg_size;
	int sysimg_handle, sysimg_size_handle;
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

	sysimg_size_handle = hse_mem_alloc(sizeof(sysimg_size));
	if (sysimg_size_handle < 0) {
		ERROR("Failed to allocate space for SYSIMG size\n");
		ret = -ENOMEM;
		goto err_close_fd;
	}

	ret = hse_sysimg_getsize(sysimg_size_handle);
	if (ret)
		goto err_hse_free_sysimg_size;
	hse_memcpy_from_dev(&sysimg_size, sysimg_size_handle, sizeof(sysimg_size), 0);

	INFO("Publishing SYSIMG\n");

	sysimg_handle = hse_mem_alloc(sysimg_size);
	if (sysimg_handle < 0) {
		ERROR("Failed to allocate space for SYSIMG\n");
		goto err_hse_free_sysimg_size;
	}

	ret = hse_sysimg_publish(sysimg_handle, sysimg_size_handle);
	if (ret)
		goto err_hse_free_sysimg_size;

	INFO("Writing SYSIMG to %s\n", device);

	sysimg = malloc(sysimg_size);
	if (!sysimg) {
		ERROR("Failed to allocate space for SYSIMG\n");
		ret = -ENOMEM;
		goto err_hse_free_sysimg;
	}
	hse_memcpy_from_dev(sysimg, sysimg_handle, sysimg_size, 0);

	if (boot_medium == QSPI)
		ret = hse_sysimg_write_qspi(fd, &ivt, sysimg, sysimg_size, 0);
	else
		ret = hse_sysimg_write_sd_mmc(fd, &ivt, sysimg, sysimg_size, boot_medium, 0);
	free(sysimg);

err_hse_free_sysimg:
	hse_mem_free(sysimg_handle);
err_hse_free_sysimg_size:
	hse_mem_free(sysimg_size_handle);
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
	printf("\t\tmutually exclusive with -s and -u\n");
	printf("\t-s:\tset up advanced secure boot\n");
	printf("\t\trequires -d and --bl2_key, --bl31_key, --bl33_key\n");
	printf("\t\tmutually exclusive with -f and -u\n");
	printf("\t-u:\tconvert currently running HSE FW image to blue image\n");
	printf("\t\tmutually exclusive with -f and -s\n");
	printf("\t-o:\tforce overwrite of HSE key catalog\n");
	printf("\t-b:\tspecify boot medium type, possible values:\n");
	printf("\t\t\t    sd - SD card boot (default)\n");
	printf("\t\t\t  qspi - QSPI Flash boot\n");
	printf("\t\t\t   mmc - MMC or eMMC boot\n");
	printf("\t-d:\tspecify full path to SD/MMC/MTD device (e.g. /dev/sdb or /dev/mtd0)\n");
	printf("\t-e:\tuse ECC keys and ECDSA signature for BL2 and BL3X images\n");
	printf("\t--rpmb_key: specify full path to symmetric key file for Rollback Protection and HSE key slot,\n");
	printf("\t            if this option is present, the HSE Monotonic Counter Table will be generated\n");
	printf("\t--ddrfw_key: specify full path to PEM format key file");
	printf("for DDR FW and HSE key slot\n");
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
	int c, fflag = 0, sflag = 0, oflag = 0, uflag = 0, eccflag = 0, ret = 0;
	enum boot_type type = SD;

	while ((c = getopt_long(argc, argv, "hfoseub:d:", secboot_options, NULL)) != -1) {
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
			case DDRFW_KEY:
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
			case 'e':
				eccflag = 1;
				break;
			case 'u':
				uflag = 1;
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

	if (!fflag && !sflag && !uflag) {
		ERROR("-s, -f or -u should be used\n");
		usage(argv[0]);
		return -1;
	}

	if ((fflag && sflag) || (fflag && uflag) || (sflag && uflag)) {
		ERROR("Options -s, -f and -u are mutually exclusive\n");
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

	if (uflag) {
		INFO("Converting HSE Pink Firmware Image to Blue Firmware Image\n");
		ret = hse_fw_blue_image_convert(devpath, type);
		return ret;
	}

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
					 type, eccflag);
		return ret;
	}

	/* something very wrong has happened */
	ERROR("Unknown error\n");
	usage(argv[0]);
	return -1;
}
