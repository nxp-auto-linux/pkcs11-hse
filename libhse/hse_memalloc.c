/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * NXP HSE Driver - Userspace memory allocation
 *
 * Copyright 2021 NXP
 */

#include <stdio.h>
#include <stdint.h>
#include "libhse.h"
#include "hse_memalloc.h"

static unsigned char PLACEHOLDER[PLACEHOLDER_MEM_SIZE];

static struct node_data *mem_start = (struct node_data *)PLACEHOLDER;

void hse_mem_init()
{
	mem_start = (struct node_data *)PLACEHOLDER;
	mem_start->size = PLACEHOLDER_MEM_SIZE;
	mem_start->next = NULL;
}

void *hse_mem_malloc(size_t size)
{
	struct node_data *curr_block;
	struct node_data *best_block;
	struct node_data *alloc_block;
	uint32_t best_block_size;

	/* align size to 16 */
	size = (size + (ALIGNMENT - 1)) & ~ALIGNMENT;

	curr_block = mem_start;
	best_block = NULL;
	best_block_size = PLACEHOLDER_MEM_SIZE;
	while (curr_block) {
		/* check if curr_block fits */
		if ((curr_block->size >= size + HSE_NODE_SIZE) &&
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

void hse_mem_free(void *p)
{
	struct node_data *prev_block;
	struct node_data *next_block;
	struct node_data *free_block;

	if (p == NULL)
		return;

	/* get the node_data for the block to be freed */
	free_block = (struct node_data *)((uint8_t *)p - HSE_NODE_SIZE);
	if (free_block == NULL)
		return;

	/* find left neighbour of free_block */
	prev_block = NULL;
	next_block = mem_start;
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
