/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * NXP HSE Userspace Driver - Memory Management
 *
 * Copyright 2021-2023 NXP
 */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <pthread.h>
#include <errno.h>

#include "libhse.h"
#include "hse-internal.h"

#define HSE_NODE_SIZE    sizeof(struct node_data) /* memory block metadata */

struct node_data {
	uint32_t size;
	uint8_t used;
	uint8_t intl;
	uint8_t reserved[2];
	uint64_t next_offset;
} __attribute__((packed));

/**
 * struct hse_mem_priv - component private data
 * @mem_start: shared memory starting node
 * @intl_mem_start: internal memory starting node
 * @iter: node list iterator for internal memory
 * @mem_lock: used for shared memory allocation
 */
static struct hse_mem_priv {
	volatile struct node_data *mem_start;
	volatile struct node_data *intl_mem_start;
	volatile struct node_data *iter;
	volatile pthread_spinlock_t *mem_lock;
} priv;

static volatile struct node_data *next_node(volatile struct node_data *block)
{
	if (!block || !block->next_offset)
		return NULL;

	if (block->intl)
		return (struct node_data *)((uint8_t *)priv.intl_mem_start + block->next_offset);

	return (struct node_data *)((uint8_t *)priv.mem_start + block->next_offset);
}

void hse_intl_iterstart()
{
	priv.iter = priv.intl_mem_start;
}

bool hse_intl_hasnext()
{
	pthread_spin_lock(priv.mem_lock);
	while ((next_node(priv.iter) != NULL) && (!next_node(priv.iter)->used))
		priv.iter = next_node(priv.iter);
	pthread_spin_unlock(priv.mem_lock);

	return (next_node(priv.iter) != NULL) ? true : false;
}

uint8_t *hse_intl_next()
{
	volatile struct node_data *to_ret;

	pthread_spin_lock(priv.mem_lock);
	to_ret = next_node(priv.iter);
	priv.iter = next_node(priv.iter);
	pthread_spin_unlock(priv.mem_lock);

	return (uint8_t *)to_ret + HSE_NODE_SIZE;
}

void hse_intl_iterstop()
{
	priv.iter = NULL;
}

int hse_mem_init(const void *intl_base_addr, const void *rmem_base_addr)
{
	if (!intl_base_addr || !rmem_base_addr)
		return EINVAL;

	priv.intl_mem_start = (struct node_data *)intl_base_addr;
	priv.mem_start = (struct node_data *)rmem_base_addr;

	priv.mem_lock = get_mem_lock();

	return 0;
}

int hse_mem_setup(const void *base_addr, const uint64_t mem_size, bool intl)
{
	if (!base_addr)
		return EINVAL;

	if (intl) {
		priv.intl_mem_start = (struct node_data *)base_addr;
		priv.intl_mem_start->size = mem_size - HSE_NODE_SIZE;
		priv.intl_mem_start->intl = 1;
		priv.intl_mem_start->next_offset = 0;
	} else {
		priv.mem_start = (struct node_data *)base_addr;
		priv.mem_start->size = mem_size - HSE_NODE_SIZE;
		priv.mem_start->next_offset = 0;
	}

	priv.mem_lock = get_mem_lock();

	return 0;
}

static void *_hse_mem_alloc(size_t size, bool intl)
{
	volatile struct node_data *crt_block;
	volatile struct node_data *best_block;
	volatile struct node_data *alloc_block;
	size_t best_block_size;
	uint64_t mem_start;

	/* align size to HSE_NODE_SIZE */
	size = (size + (HSE_NODE_SIZE - 1)) & ~(HSE_NODE_SIZE - 1);
	if (!size)
		return NULL;

	pthread_spin_lock(priv.mem_lock);

	if (intl) {

		crt_block = priv.intl_mem_start;
		best_block = NULL;
		best_block_size = priv.intl_mem_start->size;
	} else {

		crt_block = priv.mem_start;
		best_block = NULL;
		best_block_size = priv.mem_start->size;
	}

	while (crt_block) {
		/* check if current block fits */
		if ((!crt_block->used) &&
		    (crt_block->size >= (size + HSE_NODE_SIZE)) &&
		    (crt_block->size <= best_block_size)) {
			best_block = crt_block;
			best_block_size = crt_block->size;
		}

		crt_block = next_node(crt_block);
	}

	if (!best_block) {
		/* no matching block found */
		pthread_spin_unlock(priv.mem_lock);
		return NULL;
	}

	/* found a match, split a chunk of requested size and return it */
	best_block->size = best_block->size - size - HSE_NODE_SIZE;
	alloc_block = (struct node_data *)((uint8_t *)best_block +
					   HSE_NODE_SIZE + best_block->size);
	alloc_block->size = size;
	alloc_block->used = true;
	alloc_block->intl = best_block->intl;

	if (intl)
		mem_start = (uint64_t)priv.intl_mem_start;
	else
		mem_start = (uint64_t)priv.mem_start;


	alloc_block->next_offset = best_block->next_offset;
	best_block->next_offset = (uint64_t)alloc_block - mem_start;

	pthread_spin_unlock(priv.mem_lock);

	return (void *)((uint8_t *)alloc_block + HSE_NODE_SIZE);
}

void *hse_mem_alloc(size_t size)
{
	return _hse_mem_alloc(size, false);
}

void *hse_intl_mem_alloc(size_t size)
{
	return _hse_mem_alloc(size, true);
}

static void _hse_mem_free(void *addr, bool intl)
{
	volatile struct node_data *prev_block;
	volatile struct node_data *next_block;
	volatile struct node_data *free_block;

	if (addr == NULL)
		return;

	/* get the node_data for the block to be freed */
	free_block = (struct node_data *)((uint8_t *)addr - HSE_NODE_SIZE);
	if (free_block == NULL)
		return;

	pthread_spin_lock(priv.mem_lock);

	/* find left neighbour of free_block */
	if (intl) {
		next_block = priv.intl_mem_start;
	} else {
		next_block = priv.mem_start;
	}

	free_block->used = false;

	prev_block = NULL;
	while ((next_block != NULL) && (next_block < free_block)) {
		prev_block = next_block;
		next_block = next_node(next_block);
	}

	if (next_node(free_block) != NULL) {
		if (!next_node(free_block)->used) {
			free_block->size += next_node(free_block)->size;
			free_block->size += HSE_NODE_SIZE;

			/* remove next_block from list */
			free_block->next_offset = next_node(free_block)->next_offset;
		}
	}

	if (prev_block != NULL) {
		if (!prev_block->used) {
			prev_block->size += free_block->size + HSE_NODE_SIZE;

			/* remove free_block from list */
			prev_block->next_offset = free_block->next_offset;
		}
	}

	pthread_spin_unlock(priv.mem_lock);
}

void hse_mem_free(void *addr)
{
	_hse_mem_free(addr, false);
}

void hse_intl_mem_free(void *addr)
{
	_hse_mem_free(addr, true);
}

void *hse_memcpy(void *dest, const void *src, size_t size)
{
	const uint8_t *s = src;
	uint8_t *d = dest;
	const uint64_t *s64;
	uint64_t *d64;

	if (!size)
		return dest;

	/* write bytes if source OR destination are not 64bit-aligned */
	while (((uintptr_t)d & 7) || ((uintptr_t)s & 7)) {
		*d++ = *s++;
		if (!(--size))
			return dest;
	}

	/* write 64bit if both source and destionation are aligned */
	d64 = (uint64_t *)d;
	s64 = (uint64_t *)s;
	for (; size >= 8; size -= 8)
		*d64++ = *s64++;

	/* write bytes for the rest of the buffer */
	d = (uint8_t *)d64;
	s = (uint8_t *)s64;
	while (size-- > 0)
		*d++ = *s++;

	return dest;
}

void *hse_memset(void *dest, int fill, size_t size)
{
	uint8_t *d = dest;
	uint64_t *d64;
	uint64_t fill64 = (uint8_t)fill;

	if (!size)
		return dest;

	/* write bytes if not 64bit-aligned */
	while (((uintptr_t)d & 7)) {
		*d = (uint8_t)fill;
		d++;
		if (!(--size))
			return dest;
	}

	/* fill each byte with fill value */
	fill64 |= fill64 << 8;
	fill64 |= fill64 << 16;
	fill64 |= fill64 << 32;

	/* write 64bit */
	d64 = (uint64_t *)d;
	for (; size >= 8; size -= 8) {
		*d64 = fill64;
		d64++;
	}

	/* write bytes for the rest of the buffer */
	d = (uint8_t *)d64;
	while (size-- > 0)  {
		*d = (uint8_t)fill;
		d++;
	}

	return dest;
}
