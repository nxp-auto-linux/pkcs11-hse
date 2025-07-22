/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * NXP HSE User Space Driver - Low-level Interface
 *
 * Copyright 2019-2025 NXP
 */

#ifndef LIBHSE_H
#define LIBHSE_H

#include <stdbool.h>

#define HSE_NUM_CHANNELS    16u /* number of available service channels */

#define HSE_CHANNEL_ANY    0xACu /* use any channel, no request ordering */
#define HSE_CHANNEL_ADM    0u /* channel reserved for administrative services */

#define DECLARE_SET_ZERO(stype, sname) \
	typeof(stype) ((sname)) = {0}

int hse_dev_open(void);
void hse_dev_close(void);

uint16_t hse_check_status(void);

int hse_srv_req_sync(uint8_t channel, const void *srv_desc, const size_t size,
		     uint32_t *srv_rsp);

int hse_channel_acquire(uint8_t *channel);
void hse_channel_free(uint8_t channel);

int hse_stream_acquire(uint8_t *stream);
void hse_stream_free(uint8_t stream);

int hse_mem_alloc(size_t size);
void hse_mem_free(int node_handle);

/* mapped hse-accesible memory has certain restrictions that makes the use of
 * standard string routines impossible; these should be used instead of their
 * libc counterparts */
void hse_memcpy_to_dev(int dest_handle, const void *src, size_t size, size_t offset);
void hse_memcpy_from_dev(void *dest, int src_handle, size_t size, size_t offset);
void hse_memset(int node_handle, int fill, size_t size, size_t offset);

void hse_print_node_list(void);

uint64_t hse_virt_to_dma(int node_handle, uint32_t offset);

#endif /* LIBHSE_H */
