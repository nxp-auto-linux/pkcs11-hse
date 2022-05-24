/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * NXP HSE Userspace Driver - Memory Management
 *
 * Copyright 2021 NXP
 */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include "libhse.h"
#include "hse-internal.h"

#define ALIGNMENT 16

static struct node_data *mem_start;
static struct node_data *intl_mem_start;

struct node_data *hse_get_intl_mem_node()
{
	return intl_mem_start;
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
		if ((curr_block->size >= (size + HSE_NODE_SIZE)) &&
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

	/* add the free_block to the node list */
	free_block->next = next_block;
	if (prev_block != NULL)
		prev_block->next = free_block;

	/* check if free_block can be merged with next_block */
	if ((next_block != NULL) &&
	    ((uint8_t *)free_block + free_block->size + HSE_NODE_SIZE == (uint8_t *)next_block)) {
		free_block->size += next_block->size + HSE_NODE_SIZE;
		free_block->next = next_block->next;
		}

	/* check if free_block can be merged with prev_block */
	if ((prev_block != NULL) &&
	    ((uint8_t *)prev_block + prev_block->size + HSE_NODE_SIZE == (uint8_t *)free_block)) {
		prev_block->size += free_block->size + HSE_NODE_SIZE;
		prev_block->next = free_block->next;
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
