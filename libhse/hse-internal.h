/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * NXP HSE User Space Driver - Internal
 *
 * Copyright 2019-2025 NXP
 */

#ifndef HSE_INTERNAL_H
#define HSE_INTERNAL_H

#define HSE_SRV_DESC_MAX_SIZE    256u /* maximum service descriptor size */

int hse_mem_setup(void *base_addr, uint64_t mem_size, bool intl);
int hse_mem_init(void *intl_base_addr, void *rmem_base_addr);

pthread_spinlock_t *get_mem_lock(void);

int hse_intl_mem_alloc(size_t size, uint8_t type);
void hse_intl_mem_free(int node_handle);
uint8_t hse_intl_get_node_type(int node_handle);
void hse_intl_set_node_type(int node_handle, uint8_t type);
uint64_t hse_get_node_mem_addr(int node_handle, bool intl);

void *_raw_hse_memcpy(void *dest, const void *src, size_t size);
void *_raw_hse_memset(void *dest, int fill, size_t size);

void hse_intl_iterstart(void);
bool hse_intl_hasnext(void);
int hse_intl_next(void);
void hse_intl_iterstop(void);

#endif /* HSE_INTERNAL_H */
