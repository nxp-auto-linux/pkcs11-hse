/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * NXP HSE User Space Driver - Internal
 *
 * Copyright 2019-2023 NXP
 */

#ifndef HSE_INTERNAL_H
#define HSE_INTERNAL_H

#define HSE_SRV_DESC_MAX_SIZE    256u /* maximum service descriptor size */

int hse_mem_setup(const void *base_addr, const uint64_t mem_size, bool intl);
int hse_mem_init(const void *intl_base_addr, const void *rmem_base_addr);

pthread_spinlock_t *get_mem_lock(void);

void *hse_intl_mem_alloc(size_t size);
void hse_intl_mem_free(void *addr);

void hse_intl_iterstart();
bool hse_intl_hasnext();
uint8_t *hse_intl_next();
void hse_intl_iterstop();

#endif /* HSE_INTERNAL_H */
