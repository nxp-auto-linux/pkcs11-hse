// SPDX-License-Identifier: BSD-3-Clause
/*
 * HSE advanced secure boot preparatory command demo
 *
 * Copyright 2022 NXP
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

#include "libhse.h"
#include "keys-config.h"
#include "hse_interface.h"

#define BIT(n) (0x1u << (n))
#define ERROR(fmt, ...) printf("[ERROR] " fmt, ##__VA_ARGS__)
#define INFO(fmt, ...) printf("[INFO] " fmt, ##__VA_ARGS__)
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))

#define APP_CODE_OFFSET 0x40u
#define IVT_OFFSET 0x1000u
#define HSE_BOOT_KEY_HANDLE 0x010700u
#define HSE_SMR_ENTRY_1 BIT(1)
#define HSE_IVT_BOOTSEQ_BIT BIT(3)
#define HSE_EXT_FLASH_SD 2u
#define HSE_EXT_FLASH_PAGE 512u

#if (HSE_PLATFORM == HSE_S32G2XX) || (HSE_PLATFORM == HSE_S32R45X)
#define HSE_APP_CORE_A53_0 HSE_APP_CORE3
#elif (HSE_PLATFORM == HSE_S32G3XX)
#define HSE_APP_CORE_A53_0 HSE_APP_CORE4
#endif

#define UUID_BL2_SIGN \
	{{0xd6, 0xe2, 0x69, 0xea}, {0x5d, 0x63}, {0xe4, 0x11}, 0x8d, 0x8c, {0x9f, 0xba, 0xbe, 0x99, 0x56, 0xa5} }

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

struct uuid {
	uint8_t time_low[4];
	uint8_t time_mid[2];
	uint8_t time_hi_and_version[2];
	uint8_t clock_seq_hi_and_reserved;
	uint8_t clock_seq_low;
	uint8_t node[6];
} __attribute((packed));

struct fip_toc_header {
	uint32_t name;
	uint32_t serial_number;
	uint64_t flags;
} __attribute((packed));

struct fip_toc_entry {
	struct uuid uuid;
	uint64_t offset;
	uint64_t size;
	uint64_t flags;
} __attribute((packed));

/* the nvm container used to format the hse key catalogs */
const hseKeyGroupCfgEntry_t nvm_cat[] = {
	HSE_NVM_KEY_CATALOG_CFG
};

/* the ram container used to format the hse key catalogs */
const hseKeyGroupCfgEntry_t ram_cat[] = {
	HSE_RAM_KEY_CATALOG_CFG
};

/* return 0 for equal uuids */
static inline int compare_uuids(const struct uuid *uuid1, const struct uuid *uuid2)
{
	return memcmp(uuid1, uuid2, sizeof(struct uuid));
}

static inline uint32_t get_fip_start(struct ivt *ivt)
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

static uint64_t get_fip_header_size(int fd, struct ivt *ivt)
{
	struct fip_toc_entry toc_entry;
	off_t seek;

	seek = get_fip_start(ivt) + sizeof(struct fip_toc_header);

	if (get_dev_offset(fd, &toc_entry, seek, sizeof(toc_entry)))
		return 0;

	/* the offset of the first entry in the FIP is equal to the size of the FIP header */
	return toc_entry.offset;
}

static struct fip_toc_entry *get_fip_toc_entry(uint8_t *fip_header, struct uuid *search)
{
	struct fip_toc_header *toc_header;
	struct fip_toc_entry *toc_entry;
	uintptr_t fip_hdr_end;

	toc_header = (struct fip_toc_header *)fip_header;
	toc_entry = (struct fip_toc_entry *)(toc_header + 1);

	/* fip_hdr_end is at the start of the first entry */
	fip_hdr_end = (uintptr_t)fip_header + (uintptr_t)toc_entry->offset;

	while ((uintptr_t)toc_entry < fip_hdr_end) {
		if (!compare_uuids(&toc_entry->uuid, search))
			return toc_entry;
		toc_entry++;
	}

	return NULL;
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

int hse_key_import(uint8_t *rsa_modulus, int rsa_modulus_size, uint8_t *rsa_pub_exponent, int rsa_pub_exponent_size)
{
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	hseKeyInfo_t *key_info;
	int ret = 0;

	key_info = hse_mem_alloc(sizeof(*key_info));
	if (!key_info) {
		ERROR("Failed to allocate space for key info\n");
		return -ENOMEM;
	}
	hse_memset(key_info, 0, sizeof(*key_info));

	key_info->keyFlags = HSE_KF_USAGE_VERIFY;
	key_info->keyBitLen = HSE_BYTES_TO_BITS(rsa_modulus_size);
	key_info->keyCounter = 0ul;
	key_info->smrFlags = 0ul;
	key_info->keyType = HSE_KEY_TYPE_RSA_PUB;
	key_info->specific.pubExponentSize = rsa_pub_exponent_size;

	srv_desc.srvId = HSE_SRV_ID_IMPORT_KEY;
	srv_desc.hseSrv.importKeyReq.targetKeyHandle = HSE_BOOT_KEY_HANDLE;
	srv_desc.hseSrv.importKeyReq.pKeyInfo = hse_virt_to_dma(key_info);
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

	hse_mem_free(key_info);
	return ret;
}

int hse_smr_install(int fd, struct ivt *ivt, struct app_boot_hdr *app_boot)
{
	struct uuid uuid_bl2_sign = UUID_BL2_SIGN;
	struct fip_toc_entry *toc_bl2_sign;
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	hseSmrEntry_t smr_entry, *smr_entry_hse;
	uint8_t *fip_header, *bl2_sign, *fip_bin;
	int ret = 0;

	fip_header = malloc(get_fip_header_size(fd, ivt));
	if (!fip_header) {
		ERROR("Failed to allocate space for FIP header\n");
		return -ENOMEM;
	}

	ret = get_dev_offset(fd, fip_header, get_fip_start(ivt), get_fip_header_size(fd, ivt));
	if (ret) {
		ERROR("Failed to retrieve FIP header\n");
		goto err_free_fip_header;
	}

	toc_bl2_sign = get_fip_toc_entry(fip_header, &uuid_bl2_sign);
	if (!toc_bl2_sign) {
		ERROR("Failed to retrieve BL2 Certificate TOC entry\n");
		ret = -ENODATA;
		goto err_free_fip_header;
	}

	bl2_sign = hse_mem_alloc(toc_bl2_sign->size);
	if (!bl2_sign) {
		ERROR("Failed to allocate space for BL2 signature\n");
		ret = -ENOMEM;
		goto err_free_fip_header;
	}

	ret = get_dev_offset(fd, bl2_sign, get_fip_start(ivt) + toc_bl2_sign->offset, toc_bl2_sign->size);
	if (ret) {
		ERROR("Failed to retrieve BL2 signature\n");
		goto err_free_bl2_sign;
	}

	fip_bin = hse_mem_alloc(toc_bl2_sign->offset);
	if (!fip_bin) {
		ERROR("Failed to allocate space for FIP binary\n");
		ret = -ENOMEM;
		goto err_free_bl2_sign;
	}

	/* entire fip with header, except for signature */
	ret = get_dev_offset(fd, fip_bin, get_fip_start(ivt), toc_bl2_sign->offset);
	if (ret) {
		ERROR("Failed to retrieve BL2\n");
		goto err_free_fip_bin;
	}

	smr_entry_hse = hse_mem_alloc(sizeof(*smr_entry_hse));
	if (!smr_entry_hse) {
		ERROR("Failed to allocate space for SMR Entry\n");
		ret = -ENOMEM;
		goto err_free_fip_bin;
	}
	hse_memset(smr_entry_hse, 0, sizeof(*smr_entry_hse));

	smr_entry.pSmrSrc = get_fip_start(ivt);
	smr_entry.pSmrDest = app_boot->ram_load;
	smr_entry.smrSize = toc_bl2_sign->offset;
	smr_entry.configFlags = (HSE_SMR_CFG_FLAG_SD_FLASH | HSE_SMR_CFG_FLAG_INSTALL_AUTH);
	smr_entry.checkPeriod = 0;
	smr_entry.authKeyHandle = HSE_BOOT_KEY_HANDLE;
	smr_entry.authScheme.sigScheme.signSch = HSE_SIGN_RSASSA_PKCS1_V15;
	smr_entry.authScheme.sigScheme.sch.rsaPkcs1v15.hashAlgo = HSE_HASH_ALGO_SHA_1;
	smr_entry.pInstAuthTag[0] = get_fip_start(ivt) + toc_bl2_sign->offset;
	smr_entry.pInstAuthTag[1] = 0u;
	smr_entry.smrDecrypt.decryptKeyHandle = HSE_SMR_DECRYPT_KEY_HANDLE_NOT_USED;
	smr_entry.versionOffset = 0;

	/* workaround for bus error on writing to hse rmem */
	memcpy(smr_entry_hse, &(smr_entry), sizeof(smr_entry));

	srv_desc.srvId = HSE_SRV_ID_SMR_ENTRY_INSTALL;
	srv_desc.hseSrv.smrEntryInstallReq.accessMode = HSE_ACCESS_MODE_ONE_PASS;
	srv_desc.hseSrv.smrEntryInstallReq.entryIndex = 1u;
	srv_desc.hseSrv.smrEntryInstallReq.pSmrEntry = hse_virt_to_dma(smr_entry_hse);
	srv_desc.hseSrv.smrEntryInstallReq.pSmrData = hse_virt_to_dma(fip_bin);
	srv_desc.hseSrv.smrEntryInstallReq.smrDataLength = toc_bl2_sign->offset;
	srv_desc.hseSrv.smrEntryInstallReq.pAuthTag[0] = hse_virt_to_dma(bl2_sign);
	srv_desc.hseSrv.smrEntryInstallReq.pAuthTag[1] = 0u;
	srv_desc.hseSrv.smrEntryInstallReq.authTagLength[0] = toc_bl2_sign->size;
	srv_desc.hseSrv.smrEntryInstallReq.authTagLength[1] = 0u;

	ret = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc, sizeof(srv_desc));
	if (ret)
		ERROR("Failed to install SMR Entry\n");

	hse_mem_free(smr_entry_hse);
err_free_bl2_sign:
	hse_mem_free(bl2_sign);
err_free_fip_bin:
	hse_mem_free(fip_bin);
err_free_fip_header:
	free(fip_header);
	return ret;
}

int hse_cr_install(struct app_boot_hdr *app_boot)
{
	DECLARE_SET_ZERO(hseSrvDescriptor_t, srv_desc);
	hseCrEntry_t *cr_entry;
	int ret = 0;

	cr_entry = hse_mem_alloc(sizeof(*cr_entry));
	if (!cr_entry) {
		ERROR("Failed to allocate space for core reset entry\n");
		return -ENOMEM;
	}
	hse_memset(cr_entry, 0, sizeof(*cr_entry));

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
	srv_desc.hseSrv.crEntryInstallReq.pCrEntry = hse_virt_to_dma(cr_entry);

	ret = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc, sizeof(srv_desc));
	if (ret)
		ERROR("Failed to install Core Reset Entry\n");

	hse_mem_free(cr_entry);
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

int hse_sysimg_write(int fd, struct ivt *ivt, void *sysimg, uint32_t *sysimg_size, bool secure)
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

	/* external flash type, flash page size */
	ivt->sysimg_ext_flash_type = HSE_EXT_FLASH_SD;
	ivt->sysimg_flash_page_size = HSE_EXT_FLASH_PAGE;

	/* set BOOT_SEQ bit, if using secure boot */
	if (secure)
		ivt->boot_cfg |= HSE_IVT_BOOTSEQ_BIT;

	/* write updated ivt */
	seek_off = lseek(fd, IVT_OFFSET, SEEK_SET);
	if (seek_off < 0 || seek_off != IVT_OFFSET) {
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

int hse_secboot_enable(const char *device, const char *keypath)
{
	struct ivt ivt;
	struct app_boot_hdr app_boot;
	uint32_t *sysimg_size;
	uint8_t *rsa_modulus, *rsa_pub_exponent;
	void *sysimg;
	uint16_t hse_status;
	int fd, bytes, ret = 0;
	FILE *f;
	const BIGNUM *rsa_bn_modulus, *rsa_bn_pub_exponent;
	RSA *rsa;

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

	ret = get_dev_offset(fd, &ivt, IVT_OFFSET, sizeof(ivt));
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
	if (!(hse_status & HSE_STATUS_PRIMARY_SYS_IMAGE)) {
		INFO("Did not find previous SYSIMG, formatting NVM and RAM key catalogs\n");

		ret = hse_key_format();
		if (ret)
			goto err_close_fd;
	}

	f = fopen(keypath, "rb");
	if (!f) {
		ERROR("Could not find RSA Key file %s\n", keypath);
		ret = -ENOENT;
		goto err_close_fd;
	}

	/* try reading in SubjectPublicKeyInfo format */
	rsa = PEM_read_RSA_PUBKEY(f, NULL, NULL, NULL);
	if (!rsa) {
		/* try reading in PKCS#1 RSAPublicKey format */
		rsa = PEM_read_RSAPublicKey(f, NULL, NULL, NULL);
		if (!rsa) {
			ERROR("Failed to read RSA Public Key from file %s\n", keypath);
			ret = -ENOKEY;
			goto err_close_keyfile;
		}
	}

	rsa_bn_modulus = RSA_get0_n(rsa);
	if (!rsa_bn_modulus) {
		ERROR("Failed to read RSA Public Key Modulus from file %s\n", keypath);
		ret = -ENOKEY;
		goto err_close_keyfile;
	}

	rsa_bn_pub_exponent = RSA_get0_e(rsa);
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

	INFO("Importing RSA public key into NVM key catalog\n");

	ret = hse_key_import(rsa_modulus, BN_num_bytes(rsa_bn_modulus), rsa_pub_exponent, BN_num_bytes(rsa_bn_pub_exponent));
	if (ret)
		goto err_free_rsa_pub_exponent;

	INFO("Generating Secure Memory Region entry\n");

	ret = hse_smr_install(fd, &ivt, &app_boot);
	if (ret)
		goto err_free_rsa_pub_exponent;

	INFO("Generating Core Reset Entry\n");

	ret = hse_cr_install(&app_boot);
	if (ret)
		goto err_free_rsa_pub_exponent;

	INFO("Retrieving SYSIMG size\n");

	sysimg_size = hse_mem_alloc(sizeof(*sysimg_size));
	if (!sysimg_size) {
		ERROR("Failed to allocate space for SYSIMG size\n");
		ret = -ENOMEM;
		goto err_free_rsa_pub_exponent;
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

	ret = hse_sysimg_write(fd, &ivt, sysimg, sysimg_size, 1);

err_free_sysimg:
	hse_mem_free(sysimg);
err_free_sysimg_size:
	hse_mem_free(sysimg_size);
err_free_rsa_pub_exponent:
	hse_mem_free(rsa_pub_exponent);
err_free_rsa_modulus:
	hse_mem_free(rsa_modulus);
err_close_keyfile:
	fclose(f);
err_close_fd:
	close(fd);
err_close_hse:
	hse_dev_close();
	return ret;
}

int hse_keycatalog_format(const char* device, bool overwrite)
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

	if (hse_status & HSE_STATUS_PRIMARY_SYS_IMAGE && !overwrite) {
		ERROR("SYS_IMG already loaded\n");
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

	ret = get_dev_offset(fd, &ivt, IVT_OFFSET, sizeof(ivt));
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

	ret = hse_sysimg_write(fd, &ivt, sysimg, sysimg_size, 0);

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
	printf("\nformat HSE key catalogs or set up HSE-based advanced secure boot\n");
	printf("\n");
	printf("Usage:\n");
	printf("\n");
	printf("%s [-h] [-f|s] [-k keypath] [-d devpath]\n", progname);
	printf("\n");
	printf("\t-h:\tdisplay this help string\n");
	printf("\t-f:\tformat key catalogs\n");
	printf("\t\trequires -d\n");
	printf("\t\tmutually exclusive with -s\n");
	printf("\t-o:\tforce overwrite of HSE key catalog\n");
	printf("\t-s:\tset up advanced secure boot\n");
	printf("\t\trequires -d and -k\n");
	printf("\t\tmutually exclusive with -f\n");
	printf("\t-k:\tspecify full path to PEM format key file\n");
	printf("\t-d:\tspecify full path to SD device (e.g. /dev/sdb)\n");
}

int main(int argc, char *argv[])
{
	char *keypath = NULL, *devpath = NULL;
	int c, fflag = 0, sflag = 0, oflag = 0, ret = 0;

	while ((c = getopt(argc, argv, "hfosk:d:")) != -1) {
		switch (c) {
			case 'h':
				usage(argv[0]);
				return 0;
			case 'f':
				fflag = 1;
				break;
			case 'o':
				oflag = 1;
				break;
			case 's':
				sflag = 1;
				break;
			case 'k':
				keypath = optarg;
				break;
			case 'd':
				devpath = optarg;
				break;
			case '?':
				if (optopt == 'k' || optopt == 'd')
					ERROR("Option -%c requires an argument\n", optopt);
				else
					ERROR("Unrecognized option: -%c\n", optopt);
				usage(argv[0]);
				return -1;
			default:
				ERROR("Unknown error\n");
				usage(argv[0]);
				return -1;
		}
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

	if (sflag && !keypath) {
		ERROR("Option -s requires -k\n");
		usage(argv[0]);
		return -1;
	}

	if (fflag && devpath) {
		INFO("Formatting HSE key catalog\n");
		ret = hse_keycatalog_format(devpath, oflag);
		return ret;
	}

	if (sflag && devpath && keypath) {
		INFO("Setting up secure boot\n");
		ret = hse_secboot_enable(devpath, keypath);
		return ret;
	}

	/* something very wrong has happened */
	ERROR("Unknown error\n");
	usage(argv[0]);
	return -1;
}
