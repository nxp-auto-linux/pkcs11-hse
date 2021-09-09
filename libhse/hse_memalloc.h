/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * NXP HSE Driver - Userspace memory allocation
 *
 * Copyright 2021 NXP
 */

#ifndef HSE_MEMALLOC_H
#define HSE_MEMALLOC_H

#define ALIGNMENT 16
#define HSE_NODE_SIZE sizeof(struct node_data)
#define PLACEHOLDER_MEM_SIZE 4096

struct node_data {
	uint32_t size;
	struct node_data *next;
};

void hse_mem_init();

void *hse_mem_malloc(size_t size);
void hse_mem_free(void *p);

#endif /* HSE_MEMALLOC_H */
