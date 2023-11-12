// SPDX-License-Identifier: BSD-3-Clause

// Include necessary header files
#include "osmem.h"
#include "block_meta.h"

// Define a threshold for using mmap to allocate memory
#define MMAP_THRESHOLD (128 * 1024)

// Define the size of the metadata structure for each block
#define META_SIZE sizeof(struct block_meta)

// Global variable to store the base of the memory allocation
void *global_base;

// Global variable to track the number of heap allocations
size_t Heap_alocation;

// Function to find the minimum of two integers
size_t min(size_t a, size_t b)
{
	return (a < b) ? a : b;
}

// Function to calculate the padding needed for alignment
size_t align_offset(size_t offset)
{
	size_t padding = (8 - (offset % 8)) % 8;
	size_t aligned = offset + padding;
	return aligned;
}

// Function to find the last block in the linked list
struct block_meta *find_last_block(struct block_meta *block)
{
	while (block->next)
		block = block->next;

	return block;
}

// Function to split a block into two blocks
struct block_meta *split_block(struct block_meta *block, size_t new_size)
{
	// Create a new block at the end of the current block
	struct block_meta *new_block = (struct block_meta *)((char *)block + block->size - new_size);

	// Initialize the new block
	new_block->size = new_size;
	new_block->status = STATUS_FREE;
	new_block->prev = block;
	new_block->next = block->next;

	// Update the linked list
	if (block->next)
		block->next->prev = new_block;

	block->next = new_block;

	// Update the current block's size
	block->size = block->size - new_size;

	return block;
}

// Function to coalesce adjacent blocks during realloc
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

// Function to coalesce adjacent free blocks
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

// Function to expand a block using sbrk or mmap
struct block_meta *expand_block(struct block_meta *block, size_t new_size)
{
	size_t size_diff = new_size - block->size;

	if (size_diff < MMAP_THRESHOLD) {
		// Expand using sbrk
		void *request = sbrk(size_diff);

		// Check if sbrk failed
		DIE(request == NULL, "Sbrk Failed\n");

		// Update the current block's size
		block->size = new_size;
	} else {
		// Expand using mmap
		void *request = mmap(0, size_diff, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);

		// Check if mmap failed
		DIE(request == MAP_FAILED, "Mmap Failed\n");

		// Update the current block's size
		block->size = new_size;
	}

	return block;
}

// Function to find a free block for allocation
struct block_meta *find_free_block(struct block_meta **last, size_t size)
{
	// Iterate through the linked list to find and coalesce free blocks
	struct block_meta *current_col = global_base;

	while (current_col) {
		if (!current_col->status && current_col->next && !current_col->next->status)
			current_col = coalesce_blocks(current_col);
		current_col = current_col->next;
	}

	// Find the block with the smallest size greater than or equal to the requested size
	struct block_meta *current1 = global_base;

	size_t min_dif = 9999999;

	while (current1) {
		if (!current1->status && current1->size - size < min_dif)
			min_dif = current1->size - size;
		current1 = current1->next;
	}

	// Iterate to the block with the smallest size
	current1 = global_base;

	while (current1 && (current1->status || (current1->size - size) != min_dif)) {
		*last = current1;
		current1 = current1->next;
	}

	// Split the block if it is larger than the requested size and has enough space for metadata
	if (current1) {
		if (current1 && current1->size - size > META_SIZE)
			current1 = split_block(current1, current1->size - size);

		return current1;
	}

	// If no suitable block is found, expand the last block or allocate a new one
	struct block_meta *current = global_base;

	while (current && current->status) {
		*last = current;
		current = current->next;
	}

	if (current && current->size < size) {
		// Iterate to the last allocated block before expanding
		while (current->next) {
			if (current->next->status == 2)
				break;
			current = current->next;
			*last = current;
		}

		// Check if the current or next block is free or the last block in the list
		if ((!current->next && !current->status) || (!current->status && current->next && current->next->status == 2))
			return expand_block(current, size);

		// Iterate to the last block in the list
		while (current->next) {
			current = current->next;
			*last = current;
		}

		return NULL;
	}

	// Split the block if it is larger than the requested size and has enough space for metadata
	if (current && current->size - size > META_SIZE)
		return split_block(current, current->size - size);

	return current;
}

// Function to request memory space for allocation
struct block_meta *request_space(struct block_meta *last, size_t size, char call_type)
{
	struct block_meta *block;

	size_t allocation_limit = 0;

	// Set allocation limit based on the type of allocation
	if (call_type == 'm')
		allocation_limit = MMAP_THRESHOLD;
	else
		allocation_limit = 4096;

    // Determine whether to use sbrk or mmap based on the size
	if (size < allocation_limit) {
		if (Heap_alocation == 0) {
			// Allocate memory using sbrk
			void *request = sbrk(MMAP_THRESHOLD);

			// Check if sbrk failed
			DIE(request == NULL, "Sbrk Failed\n");

			block = request;
			block->status = STATUS_ALLOC;
			Heap_alocation++;
			block->size = MMAP_THRESHOLD;

			// Split the block if it is larger than the requested size and has enough space for metadata
			if (block && block->size - size > META_SIZE)
				block = split_block(block, block->size - size);
		} else {
			// Allocate memory using sbrk
			void *request = sbrk(size);

			// Check if sbrk failed
			DIE(request == NULL, "Sbrk Failed\n");

			block = request;
			block->status = STATUS_ALLOC;
		}
	} else {
		// Allocate memory using mmap
		void *request = mmap(0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);

		// Check if mmap failed
		DIE(request == MAP_FAILED, "Mmap Failed\n");

		block = request;
		block->status = STATUS_MAPPED;
	}

    // Update the linked list
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

// Function to allocate memory
void *os_malloc(size_t size)
{
	struct block_meta *block;

	// Calculate the aligned size with metadata
	size_t aligned_size = align_offset(size + META_SIZE);

	// Check for invalid size
	if (size <= 0)
		return NULL;

	// Check if the memory space is uninitialized
	if (!global_base) {
		// Request space for the initial block
		block = request_space(NULL, aligned_size, 'm');
		global_base = block;
	} else {
		// Find a free block in the existing memory space
		struct block_meta *last = global_base;

		block = find_free_block(&last, aligned_size);

		// If no free block is found, request space for a new block
		if (!block)
			block = request_space(last, aligned_size, 'm');
		else
			// Update the status based on the size and type of allocation
			if (aligned_size < MMAP_THRESHOLD)
				block->status = STATUS_ALLOC;
			else
				block->status = STATUS_MAPPED;
	}

	// Return a pointer to the user data within the block
	return (void *)(block + 1);
}

// Function to free allocated memory
void os_free(void *ptr)
{
	// Check if the pointer is NULL
	if (!ptr)
		return;

	// Calculate the block pointer from the user data pointer
	struct block_meta *block_ptr = (struct block_meta *)((char *)ptr - META_SIZE);

	// Check if the block is mapped (allocated using mmap)
	if (block_ptr->status == STATUS_MAPPED) {
		struct block_meta *block_prev = block_ptr->prev;

		struct block_meta *block_next = block_ptr->next;

		// Update the block status to free
		block_ptr->status = STATUS_FREE;

		// Check if the block is the only block in the list
		if (!block_next && !block_prev)
			global_base = NULL;

		// Update the linked list
		if (block_prev)
			block_prev->next = block_next;

		if (block_next)
			block_next->prev = block_prev;

		// Unmap the memory
		munmap(block_ptr, block_ptr->size);

		block_ptr = NULL;
	} else {
		// Update the block status to free
		block_ptr->status = STATUS_FREE;
	}
}

// Function to allocate zero-initialized memory
void *os_calloc(size_t nmemb, size_t size)
{
	struct block_meta *block;

	// Calculate the aligned size with metadata
	size_t aligned_size = align_offset(size * nmemb + META_SIZE);

	// Check for invalid size
	if (size <= 0 || nmemb <= 0)
		return NULL;

	// Check if the memory space is uninitialized
	if (!global_base) {
		// Request space for the initial block
		block = request_space(NULL, aligned_size, 'c');
		global_base = block;
	} else {
		// Find a free block in the existing memory space
		struct block_meta *last = global_base;

		block = find_free_block(&last, aligned_size);

		// If no free block is found, request space for a new block
		if (!block)
			block = request_space(last, aligned_size, 'c');
		else
			// Update the status based on the size and type of allocation
			if (block->size > 4096)
				block = request_space(find_last_block(block), aligned_size, 'c');
			else
				if (aligned_size < MMAP_THRESHOLD)
					block->status = STATUS_ALLOC;
				else
					block->status = STATUS_MAPPED;
	}

	// Set the allocated memory to zero
	memset((void *)(block + 1), 0, size * nmemb);

	// Return a pointer to the user data within the block
	return (void *)(block + 1);
}

// Function to find a free block for realloc
struct block_meta *find_free_block_realloc(size_t size)
{
	struct block_meta *current = global_base;

	// Iterate through the linked list to find a block with enough space
	while (current && (current->status || current->size < size))
		current = current->next;

	return current;
}

// Function to reallocate memory
void *os_realloc(void *ptr, size_t size)
{
	struct block_meta *block = (struct block_meta *)((char *)ptr - META_SIZE);

	// Check for invalid size
	if (size <= 0) {
		// Free the memory if size is zero
		os_free(ptr);
		return NULL;
	}

	// If the pointer is NULL, allocate new memory
	if (!ptr)
		return os_malloc(size);

	// If the block is not marked as allocated, return NULL
	if (!block->status)
		return NULL;

	// Calculate the aligned size with metadata
	size_t aligned_size = align_offset(size + META_SIZE);

    // Check if the block is allocated and does not have a next block than expand it
	if (block->status == STATUS_ALLOC && !block->next && block->size < aligned_size)
		return (void *)(expand_block(block, aligned_size) + 1);

	// If the given size it's enough than reuse the block and split it if necessary
	if (block->status == STATUS_ALLOC && block->size >= aligned_size) {
		if (block->size - aligned_size > META_SIZE)
			return (void *)(split_block(block, block->size - aligned_size) + 1);
		else
			return (void *)(block + 1);
	}

	// Remeber the size before coalesces
	size_t old_block_size = block->size;

	// Coalesce block by block and check if the size is big enough
	// After finding a block big enough split it if possible
	while (block->next && !block->next->status) {
		coalesce_realloc_blocks(block);
		if (block->status == STATUS_ALLOC && block->size >= aligned_size) {
			if (block->size - aligned_size > META_SIZE)
				return (void *)(split_block(block, block->size - aligned_size) + 1);
			else
				return (void *)(block + 1);
		}
	}

	// If size is greater than a threshold, allocate a new block using mmap
	if (size > MMAP_THRESHOLD) {
		struct block_meta *last = find_last_block(global_base);

		block = request_space(last, aligned_size, 'm');

		if (old_block_size < block->size)
			memmove((void *)((char *)block + META_SIZE), ptr, old_block_size);

		os_free(ptr);
		return (void *)(block + 1);
	}

	// Handle realloc for allocated blocks
	if (block->status == STATUS_ALLOC) {
		void *ptr_new = os_malloc(size);

		memmove(ptr_new, ptr, min(old_block_size, size));
		os_free(ptr);
		return ptr_new;
	}

	// Handle realloc for mapped blocks or when size exceeds the threshold
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
