/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * NXP HSE Driver - User-space driver support
 *
 * Copyright 2019-2021 NXP
 */

#ifndef HSE_USR_H
#define HSE_USR_H

#define HSE_NUM_CHANNELS    16u /* number of available service channels */

#define HSE_CHANNEL_ANY    0xACu /* use any channel, no request ordering */
#define HSE_CHANNEL_ADM    0u /* channel reserved for administrative services */

int hse_usr_initialize(void);
void hse_usr_finalize(void);

int hse_srv_req_sync(uint8_t channel, uint32_t srv_desc);

void *hse_get_shared_mem_addr(uint64_t offset);

uint64_t hse_virt_to_phys(const void *virt_addr);

#endif /* HSE_USR_H */
