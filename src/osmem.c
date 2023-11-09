// SPDX-License-Identifier: BSD-3-Clause

#include "osmem.h"
#include "block_meta.h"
#define MMAP_THRESHOLD (128*1024)
#define META_SIZE sizeof(struct block_meta)

void *global_base;

int Heap_alocation;

int min(int a, int b)
{
	return (a < b) ? a : b;
}

int align_offset(int offset)
{
	int padding = (8 - (offset % 8)) % 8;
	int aligned = offset + padding;
	return aligned;
}

void *align_memory(void *ptr)
{
	int padding = (8 - (sizeof(ptr) % 8)) % 8;

	return (char *)ptr + padding;
}

struct block_meta *find_last_block(struct block_meta *block)
{
	while (block->next)
		block = block->next;

	return block;
}

struct block_meta *split_block(struct block_meta *block, size_t new_size)
{
	struct block_meta *new_block = (struct block_meta *)((char *)block + block->size - new_size);

	new_block->size = new_size;
	new_block->status = STATUS_FREE;
	new_block->prev = block;
	new_block->next = block->next;

	if (block->next)
		block->next->prev = new_block;

	block->next = new_block;
	// Update the current block's size
	block->size = block->size - new_size;
	return block;
}

struct block_meta *coalesce_realloc_blocks(struct block_meta *block)
{
	struct block_meta *next_block = block->next;

	// Check if the next block is free and can be merged
	if (next_block && !next_block->status) {
		// Merge the next block into the current block
		block->size += next_block->size;

		// Update the linked list
		block->next = next_block->next;

		next_block = next_block->next;

		if (block->next)
			block->next->prev = block;
	}
	return block;
}

struct block_meta *coalesce_blocks(struct block_meta *block)
{
	struct block_meta *next_block = block->next;

	// Check if the next block is free and can be merged
	while (next_block && !next_block->status) {
		// Merge the next block into the current block
		block->size += next_block->size;

		// Update the linked list
		block->next = next_block->next;

		next_block = next_block->next;

		if (block->next)
			block->next->prev = block;
	}
	return block;
}

struct block_meta *expand_block(struct block_meta *block, size_t new_size)
{
	size_t size_diff = new_size - block->size;

	if (size_diff < MMAP_THRESHOLD) {
		// Expand using sbrk
		void *request = sbrk(size_diff);

		block->size = new_size;
	} else {
		// Expand using mmap
		void *request = mmap(0, size_diff, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);

		block->size = new_size;
	}

	return block;
}

struct block_meta *find_free_block(struct block_meta **last, size_t size)
{
	struct block_meta *current_col = global_base;

	while (current_col) {
		if (!current_col->status && current_col->next && !current_col->next->status)
			current_col = coalesce_blocks(current_col);
		current_col = current_col->next;
	}

	struct block_meta *current1 = global_base;

	size_t min_dif = 9999999;

	while (current1) {
		if (!current1->status && current1->size - size >= 0 && current1->size - size < min_dif)
			min_dif = current1->size - size;
		current1 = current1->next;
	}

	current1 = global_base;

	while (current1 && (current1->status || (current1->size - size) != min_dif)) {
		*last = current1;
		current1 = current1->next;
	}

	if (current1) {
		if (current1 && current1->size - size > META_SIZE)
			current1 = split_block(current1, current1->size - size);

		return current1;
	}

	struct block_meta *current = global_base;

	while (current && current->status) {
		*last = current;
		current = current->next;
	}

	if (current && current->size < size) {
		while (current->next) {
			if (current->next->status == 2)
				break;
			current = current->next;
			*last = current;
		}

		if ((!current->next && !current->status) || (!current->status && current->next && current->next->status == 2))
			return expand_block(current, size);

		while (current->next) {
			current = current->next;
			*last = current;
		}

		return NULL;
	}

	if (current && current->size - size > META_SIZE)
		return split_block(current, current->size - size);


	return current;
}

struct block_meta *request_space(struct block_meta *last, size_t size, char call_type)
{
	struct block_meta *block;

	size_t allocation_limmit = 0;

	if (call_type == 'm')
		allocation_limmit = MMAP_THRESHOLD;
	else
		allocation_limmit = 4096;

	if (size < allocation_limmit) {
		if (Heap_alocation == 0) {
			void *request = sbrk(MMAP_THRESHOLD);

			if (request == (void *) -1)
				return NULL; // sbrk failed.

			block = request;
			block->status = STATUS_ALLOC;
			Heap_alocation++;
			block->size = MMAP_THRESHOLD;
			if (block && block->size - size > META_SIZE)
				block = split_block(block, block->size - size);

		} else {
			void *request = sbrk(size);

			if (request == (void *) -1)
				return NULL; // sbrk failed.

			block = request;
			block->status = STATUS_ALLOC;
		}
	} else {
		void *request = mmap(0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);

		if (request == MAP_FAILED)
			return NULL; // Allocation failed

		block = request;
		block->status = STATUS_MAPPED;
	}

	if (last) {
		last->next = block;
		block->prev = last;
	} else {
		block->prev = NULL;
	}

	block->size = size;
	if (!block->next)
		block->next = NULL;

	return block;
}

void *os_malloc(size_t size)
{
	struct block_meta *block;

	size_t aligned_size = align_offset(size + META_SIZE);

	if (size <= 0)
		return NULL;

	if (!global_base) {
		block = request_space(NULL, aligned_size, 'm');
		global_base = block;
	} else {
		struct block_meta *last = global_base;

		block = find_free_block(&last, aligned_size);

		if (!block)
			block = request_space(last, aligned_size, 'm');
		else
			if (aligned_size < MMAP_THRESHOLD)
				block->status = STATUS_ALLOC;
			else
				block->status = STATUS_MAPPED;
	}

	return (void *)(block + 1);
}

void os_free(void *ptr)
{
	if (!ptr)
		return;

	struct block_meta *block_ptr = (struct block_meta *)((char *)ptr - META_SIZE);

	if (block_ptr->status == STATUS_MAPPED) {
		struct block_meta *block_prev = block_ptr->prev;

		struct block_meta *block_next = block_ptr->next;

		block_ptr->status = STATUS_FREE;

		if (!block_next && !block_prev)
			global_base = NULL;

		if (block_prev)
			block_prev->next = block_next;

		if (block_next)
			block_next->prev = block_prev;

		munmap(block_ptr, block_ptr->size);
		block_ptr = NULL;
	} else {
		block_ptr->status = STATUS_FREE;
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	struct block_meta *block;

	size_t aligned_size = align_offset(size * nmemb + META_SIZE);

	if (size <= 0 || nmemb <= 0)
		return NULL;

	if (!global_base) {
		block = request_space(NULL, aligned_size, 'c');
		global_base = block;
	} else {
		struct block_meta *last = global_base;

		block = find_free_block(&last, aligned_size);

		if (!block)
			block = request_space(last, aligned_size, 'c');
		else
			if (block->size > 4096)
				block = request_space(find_last_block(block), aligned_size, 'c');
			else
				if (aligned_size < MMAP_THRESHOLD)
					block->status = STATUS_ALLOC;
				else
					block->status = STATUS_MAPPED;
	}
	memset((void *)(block + 1), 0, size * nmemb);
	return (void *)(block + 1);
}

struct block_meta *find_free_block_realloc(size_t size)
{
	struct block_meta *current = global_base;

	while (current && (current->status || current->size < size))
		current = current->next;

	return current;
}

void *os_realloc(void *ptr, size_t size)
{
	struct block_meta *block = (struct block_meta *)((char *)ptr - META_SIZE);

	if (size <= 0) {
		os_free(ptr);
		return NULL;
	}

	if (!ptr)
		return os_malloc(size);

	if (!block->status)
		return NULL;

	size_t aligned_size = align_offset(size + META_SIZE);

	if (block->status == STATUS_ALLOC && !block->next && block->size < aligned_size)
		return (void *)(expand_block(block, aligned_size) + 1);

	if (block->status == STATUS_ALLOC && block->size >= aligned_size)
		if (block->size - aligned_size > META_SIZE)
			return (void *)(split_block(block, block->size - aligned_size) + 1);
		else
			return (void *)(block + 1);

	size_t old_block_size = block->size;

	while (block->next && !block->next->status) {
		coalesce_realloc_blocks(block);
		if (block->status == STATUS_ALLOC && block->size >= aligned_size)
			if (block->size - aligned_size > META_SIZE)
				return (void *)(split_block(block, block->size - aligned_size) + 1);
			else
				return (void *)(block + 1);
	}

	if (size > MMAP_THRESHOLD) {
		struct block_meta *last = find_last_block(global_base);

		block = request_space(last, aligned_size, 'm');

		if (old_block_size < block->size)
			memmove((void *)((char *)block + META_SIZE), ptr, old_block_size);

		os_free(ptr);
		return (void *)(block + 1);
	}

	if (block->status == STATUS_ALLOC) {
		void *ptr_new = os_malloc(size);

		struct block_meta *block_new = (struct block_meta *)((char *)ptr_new - META_SIZE);

		memmove(ptr_new, ptr, min(old_block_size, size));
		os_free(ptr);
		return ptr_new;
	}

	if (block->status == STATUS_MAPPED || aligned_size > MMAP_THRESHOLD) {
		void *ptr_new = os_malloc(size);

		struct block_meta *block_new = (struct block_meta *)((char *)ptr_new - META_SIZE);

		if (old_block_size < block_new->size)
			memmove(ptr_new, ptr, old_block_size);

		os_free(ptr);
		return ptr_new;
	}

	return (void *)(block + 1);
}
