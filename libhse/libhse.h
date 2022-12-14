/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * NXP HSE User Space Driver - Low-level Interface
 *
 * Copyright 2019-2022 NXP
 */

#ifndef LIBHSE_H
#define LIBHSE_H

#define HSE_NUM_CHANNELS    16u /* number of available service channels */

#define HSE_CHANNEL_ANY    0xACu /* use any channel, no request ordering */
#define HSE_CHANNEL_ADM    0u /* channel reserved for administrative services */

int hse_dev_open(void);
void hse_dev_close(void);

uint16_t hse_check_status(void);

int hse_srv_req_sync(uint8_t channel, const void *srv_desc);

void *hse_mem_alloc(size_t size);
void hse_mem_free(void *addr);

uint64_t hse_virt_to_dma(const void *addr);

#endif /* LIBHSE_H */
