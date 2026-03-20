/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * NXP HSE Userspace Driver - Memory Management
 *
 * Copyright 2021-2026 NXP
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

/**
 * enum hse_node_status
 * HSE_NODE_UNUSED: the node is not used in the linked list
 * HSE_NODE_OWNING_MEM: the node is used in the linked list and owns
 *                      memory, but does not contain a valid buffer
 * HSE_NODE_USING_MEM: the node is used in the linked list and uses
 *                     its allocated memory to hold a valid buffer
 */
enum hse_node_status {
	HSE_NODE_UNUSED = 0x0,
	HSE_NODE_OWNING_MEM = 0x10,
	HSE_NODE_USING_MEM = 0x20
};

struct node_data {
	uint32_t size;
	uint32_t mem_offset;
	uint32_t next_offset;
	uint8_t use_status;
	uint8_t type;
	uint8_t reserved[2]; /* necessary for alignment to 8 */
};

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

static volatile struct node_data *next_node(volatile struct node_data *block, bool intl)
{
	if (!block || !block->next_offset)
		return NULL;

	if (intl)
		return (struct node_data *)((uint8_t *)priv.intl_mem_start + block->next_offset);

	return (struct node_data *)((uint8_t *)priv.mem_start + block->next_offset);
}

static volatile struct node_data *next_unused_node(bool intl)
{
	volatile struct node_data *mem = intl ? priv.intl_mem_start : priv.mem_start;
	uint64_t mem_start = (uint64_t)(intl ? priv.intl_mem_start : priv.mem_start);

	while (((uint64_t)mem <= (mem_start + HSE_MEM_OFF - HSE_NODE_SIZE)) &&
		   (mem->use_status != HSE_NODE_UNUSED))
		mem += 1;

	if ((uint64_t)mem >= mem_start + HSE_MEM_OFF)
		return NULL;
	return mem;
}

static int get_node_handle(uint64_t addr, bool intl)
{
	uint64_t mem_start = (uint64_t)(intl ? priv.intl_mem_start : priv.mem_start);

	if (addr - mem_start > HSE_MEM_OFF - HSE_NODE_SIZE)
		return -EINVAL;

	return (addr - mem_start) / HSE_NODE_SIZE;
}

static struct node_data *get_node_ptr(int node_handle, bool intl)
{
	uint64_t mem_start = (uint64_t)(intl ? priv.intl_mem_start : priv.mem_start);
	uint64_t mem_addr = mem_start + (node_handle * HSE_NODE_SIZE);

	if (mem_addr >= mem_start + HSE_MEM_OFF)
		return NULL;

	return (struct node_data *)mem_addr;
}

uint64_t hse_get_node_mem_addr(int node_handle, bool intl)
{
	uint64_t mem_start = (uint64_t)(intl ? priv.intl_mem_start : priv.mem_start);

	if (node_handle < 0) 
		return 0;

	if (!get_node_ptr(node_handle, intl) ||
		!(get_node_ptr(node_handle, intl)->use_status == HSE_NODE_USING_MEM))
		return 0;

	return mem_start + get_node_ptr(node_handle, intl)->mem_offset;
}

void hse_intl_iterstart()
{
	priv.iter = priv.intl_mem_start;
}

bool hse_intl_hasnext()
{
	pthread_spin_lock(priv.mem_lock);
	while ((next_node(priv.iter, true) != NULL) &&
		   (!(next_node(priv.iter, true)->use_status == HSE_NODE_USING_MEM)))
		priv.iter = next_node(priv.iter, true);
	pthread_spin_unlock(priv.mem_lock);

	return (next_node(priv.iter, true) != NULL) ? true : false;
}

int hse_intl_next()
{
	volatile struct node_data *to_ret;

	pthread_spin_lock(priv.mem_lock);
	to_ret = next_node(priv.iter, true);
	priv.iter = next_node(priv.iter, true);
	pthread_spin_unlock(priv.mem_lock);

	return get_node_handle((uint64_t)to_ret, true);
}

void hse_intl_iterstop()
{
	priv.iter = NULL;
}

int hse_mem_init(void *intl_base_addr, void *rmem_base_addr)
{
	if (!rmem_base_addr)
		return EINVAL;

	priv.intl_mem_start = (struct node_data *)intl_base_addr;
	priv.mem_start = (struct node_data *)rmem_base_addr;

	priv.mem_lock = get_mem_lock();

	return 0;
}

int hse_mem_setup(void *base_addr, uint64_t mem_size, bool intl)
{
	volatile struct node_data **mem = intl ? &priv.intl_mem_start : &priv.mem_start;

	if (!base_addr || mem_size < HSE_MEM_OFF)
		return EINVAL;

	_raw_hse_memset((void *)base_addr, 0, HSE_MEM_OFF);
	*mem = (struct node_data *)base_addr;
	(*mem)->size = mem_size - HSE_MEM_OFF;
	(*mem)->next_offset = 0;
	(*mem)->mem_offset = HSE_MEM_OFF;
	(*mem)->use_status = HSE_NODE_OWNING_MEM;

	priv.mem_lock = get_mem_lock();

	return 0;
}

static int _hse_mem_alloc(size_t size, bool intl)
{
	volatile struct node_data *crt_block;
	volatile struct node_data *best_block;
	volatile struct node_data *alloc_block;
	size_t best_block_size;
	uint64_t mem_start;

	if (!size)
		return -EINVAL;

	/* Check if internal memory pool is available */
	if (intl && !priv.intl_mem_start)
		return -ENOSPC;

	/* align size to 8 bytes */
	size = (size + (8 - 1)) & ~(8 - 1);

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
		if (!(crt_block->use_status == HSE_NODE_USING_MEM) && (crt_block->size >= size) &&
		    (crt_block->size <= best_block_size)) {
			best_block = crt_block;
			best_block_size = crt_block->size;
		}
		crt_block = next_node(crt_block, intl);
	}

	if (!best_block) {
		/* no matching block found */
		pthread_spin_unlock(priv.mem_lock);
		return -ENOMEM;
	}

	alloc_block = next_unused_node(intl);
	/* no unused node found, return best_block */
	if (!alloc_block) {
		best_block->type = 0;
		best_block->use_status = HSE_NODE_USING_MEM;
		pthread_spin_unlock(priv.mem_lock);
		return get_node_handle((uint64_t)best_block, intl);
	}

	best_block->size = best_block->size - size;
	alloc_block->size = size;
	alloc_block->type = 0;
	alloc_block->mem_offset = best_block->mem_offset + best_block->size;
	alloc_block->use_status = HSE_NODE_USING_MEM;

	mem_start = (uint64_t)(intl ? priv.intl_mem_start : priv.mem_start);

	alloc_block->next_offset = best_block->next_offset;
	best_block->next_offset = (uint64_t)alloc_block - mem_start;

	pthread_spin_unlock(priv.mem_lock);

	return get_node_handle((uint64_t)alloc_block, intl);
}

static void _hse_mem_free(int node_handle, bool intl)
{
	volatile struct node_data *prev_block;
	volatile struct node_data *next_block;
	volatile struct node_data *free_block;

	if (node_handle < 0)
		return;

	/* Check if internal memory pool is available */
	if (intl && !priv.intl_mem_start)
		return;

	/* get the node_data for the block to be freed */
	free_block = get_node_ptr(node_handle, intl);
	if (!free_block || !(free_block->use_status == HSE_NODE_USING_MEM))
		return;

	pthread_spin_lock(priv.mem_lock);

	/* find left neighbour of free_block */
	next_block = intl ? priv.intl_mem_start : priv.mem_start;
	_raw_hse_memset((void *)hse_get_node_mem_addr(node_handle, intl), 0, free_block->size);
	free_block->use_status = HSE_NODE_OWNING_MEM;

	prev_block = NULL;
	while ((next_block != NULL) && (next_block != free_block)) {
		prev_block = next_block;
		next_block = next_node(next_block, intl);
	}

	next_block = next_node(free_block, intl);
	if (next_block != NULL) {
		if (!(next_block->use_status == HSE_NODE_USING_MEM)) {
			free_block->size += next_block->size;
			/* remove next_block from list */
			free_block->next_offset = next_block->next_offset;

			_raw_hse_memset((void *)next_block, 0, HSE_NODE_SIZE);
		}
	}

	if (prev_block != NULL) {
		if (!(prev_block->use_status == HSE_NODE_USING_MEM)) {
			prev_block->size += free_block->size;
			/* remove free_block from list */
			prev_block->next_offset = free_block->next_offset;

			_raw_hse_memset((void *)free_block, 0, HSE_NODE_SIZE);
		}
	}

	pthread_spin_unlock(priv.mem_lock);
}

uint8_t hse_intl_get_node_type(int node_handle)
{
	struct node_data *node;

	if (!priv.intl_mem_start)
		return 0;

	node = get_node_ptr(node_handle, true);
	if (!node)
		return 0;
	return node->type;
}

void hse_intl_set_node_type(int node_handle, uint8_t type)
{
	struct node_data *node;

	if (!priv.intl_mem_start)
		return;

	node = get_node_ptr(node_handle, true);
	if (!node)
		return;
	node->type = type;
}

int hse_mem_alloc(size_t size)
{
	return _hse_mem_alloc(size, false);
}

int hse_intl_mem_alloc(size_t size, uint8_t type)
{
	int node_handle;

	/* Early check for pool availability */
	if (!priv.intl_mem_start)
		return -ENOSPC;

	node_handle = _hse_mem_alloc(size, true);

	if (node_handle < 0)
		goto err_node_idx;
	hse_intl_set_node_type(node_handle, type);

err_node_idx:
	return node_handle;
}

void hse_mem_free(int node_handle)
{
	_hse_mem_free(node_handle, false);
}

void hse_intl_mem_free(int node_handle)
{
	_hse_mem_free(node_handle, true);
}

void *_raw_hse_memcpy(void *dest, const void *src, size_t size)
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

void *_raw_hse_memset(void *dest, int fill, size_t size)
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

void hse_memcpy_to_dev(int dest_handle, const void *src, size_t size, size_t offset)
{
	uint8_t *d;
	struct node_data *dest_node;

	dest_node = get_node_ptr(dest_handle, false);

	if (!size || !dest_node ||
		!(dest_node->use_status == HSE_NODE_USING_MEM) ||
		size > (dest_node->size - offset))
		return;

	d = (uint8_t *)((uint64_t)priv.mem_start + dest_node->mem_offset + offset);

	_raw_hse_memcpy(d, src, size);
}

void hse_memcpy_from_dev(void *dest, int src_handle, size_t size, size_t offset)
{
	uint8_t *s;
	struct node_data *src_node;

	src_node = get_node_ptr(src_handle, false);

	if (!size || !src_node ||
		!(src_node->use_status == HSE_NODE_USING_MEM) ||
		size > (src_node->size - offset))
		return;

	s = (uint8_t *)((uint64_t)priv.mem_start + src_node->mem_offset + offset);

	_raw_hse_memcpy(dest, s, size);
}

void hse_memset(int node_handle, int fill, size_t size, size_t offset)
{
	uint8_t *d;
	struct node_data *dest_node;

	dest_node = get_node_ptr(node_handle, false);

	if (!size || !dest_node ||
		!(dest_node->use_status == HSE_NODE_USING_MEM) ||
		size > (dest_node->size - offset))
		return;

	d = (uint8_t *)((uint64_t)priv.mem_start + dest_node->mem_offset + offset);

	_raw_hse_memset(d, fill, size);
}
