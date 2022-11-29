/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * NXP HSE Userspace Driver - Memory Management
 *
 * Copyright 2021-2022 NXP
 */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include "libhse.h"
#include "hse-internal.h"

#define ALIGNMENT 16
#define HSE_NODE_SIZE sizeof(struct node_data)

struct node_data {
	uint32_t size;
	uint8_t used;
	uint8_t reserved[3];
	struct node_data *next;
} __attribute__((packed));

static struct node_data *mem_start;
static struct node_data *intl_mem_start;
static struct node_data *iter;

void hse_intl_iterstart()
{
	iter = intl_mem_start;
}

bool hse_intl_hasnext()
{
	while ((iter->next != NULL) && (!iter->next->used))
		iter = iter->next;

	return (iter->next != NULL) ? true : false;
}

uint8_t *hse_intl_next()
{
	struct node_data *to_ret;

	to_ret = iter->next;
	iter = iter->next;

	return (uint8_t *)to_ret + HSE_NODE_SIZE;
}

void hse_intl_iterstop()
{
	iter = NULL;
}

int hse_mem_init(void *base_addr, uint64_t mem_size, bool intl)
{
	if (!base_addr)
		return 1;

	if (intl) {
		intl_mem_start = (struct node_data *)base_addr;
		intl_mem_start->size = mem_size - HSE_NODE_SIZE;
		intl_mem_start->next = NULL;
	} else {
		mem_start = (struct node_data *)base_addr;
		mem_start->size = mem_size - HSE_NODE_SIZE;
		mem_start->next = NULL;
	}

	return 0;
}

void *_hse_mem_alloc(size_t size, bool intl)
{
	struct node_data *curr_block;
	struct node_data *best_block;
	struct node_data *alloc_block;
	size_t best_block_size;

	/* align size to 16 */
	size = (size + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1);
	if (!size)
		return NULL;

	if (intl) {
		curr_block = intl_mem_start;
		best_block = NULL;
		best_block_size = intl_mem_start->size;
	} else {
		curr_block = mem_start;
		best_block = NULL;
		best_block_size = mem_start->size;
	}

	while (curr_block) {
		/* check if curr_block fits */
		if ((!curr_block->used) &&
		    (curr_block->size >= (size + HSE_NODE_SIZE)) &&
		    (curr_block->size <= best_block_size)) {
			best_block = curr_block;
			best_block_size = curr_block->size;
		}

		curr_block = curr_block->next;
	}

	/* found a match, split a chunk of requested size and return it */
	if (best_block != NULL) {
		best_block->size = best_block->size - size - HSE_NODE_SIZE;
		alloc_block = (struct node_data *)((uint8_t *)best_block + HSE_NODE_SIZE + best_block->size);
		alloc_block->size = size;
		alloc_block->used = true;
		alloc_block->next = best_block->next;
		best_block->next = alloc_block;

		return (void *)((uint8_t *)alloc_block + HSE_NODE_SIZE);
	}

	return NULL;
}

void *hse_mem_alloc(size_t size)
{
	return _hse_mem_alloc(size, false);
}

void *hse_intl_mem_alloc(size_t size)
{
	return _hse_mem_alloc(size, true);
}

void _hse_mem_free(void *addr, bool intl)
{
	struct node_data *prev_block;
	struct node_data *next_block;
	struct node_data *free_block;

	if (addr == NULL)
		return;

	/* get the node_data for the block to be freed */
	free_block = (struct node_data *)((uint8_t *)addr - HSE_NODE_SIZE);
	if (free_block == NULL)
		return;

	free_block->used = false;

	/* find left neighbour of free_block */
	if (intl)
		next_block = intl_mem_start;
	else
		next_block = mem_start;
	prev_block = NULL;
	while ((next_block != NULL) && (next_block < free_block)) {
		prev_block = next_block;
		next_block = next_block->next;
	}

	if (free_block->next != NULL) {
		if (!free_block->next->used) {
			free_block->size += free_block->next->size + HSE_NODE_SIZE;

			/* remove next_block from list */
			free_block->next = free_block->next->next;
		}
	}

	if (prev_block != NULL) {
		if (!prev_block->used) {
			prev_block->size += free_block->size + HSE_NODE_SIZE;

			/* remove free_block from list */
			prev_block->next = free_block->next;
		}
	}
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

	/* write bytes if not 64bit-aligned */
	while (((uintptr_t)d & 7)) {
		*d++ = *s++;
		if (!(--size))
			return dest;
	}

	/* write 64bit if aligned */
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
