/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * NXP HSE User Space Driver - Internal
 *
 * Copyright 2019-2021 NXP
 */

#ifndef HSE_INTERNAL_H
#define HSE_INTERNAL_H

#define HSE_SRV_DESC_MAX_SIZE    256u /* maximum service descriptor size */

int hse_mem_init(void *rmem_base_addr, uint64_t rmem_size);

#endif /* HSE_INTERNAL_H */
