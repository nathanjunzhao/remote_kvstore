// Nathan Zhao - njz1

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "kvstore.h"

// Helper Functions:

static void *compute_ht_size(const char key[KEYSIZE], void *value,
void *cookie);
static void *copy_entry(const char key[KEYSIZE], void *value, void *cookie);
static int   switch_active_side(void);
static int   sync_helper(void *addr, size_t length, int flags);
static struct file_entry *write_next_entry(op_type op, const char key[KEYSIZE],
    uint8_t *value, uint32_t len, uint32_t padded_len);

// Global Variables:

struct file_header *header;

struct hash_table *active_table;
char		  *active_space_start;
char		  *active_space_end;
char		  *next_entry;

struct hash_table *inactive_table;
char		  *inactive_space_start;
uint64_t	   inactive_space_used;

long page_size;

int
init(const char *filename)
{
	struct file_header temp_header;
	int		   fd;

	page_size = sysconf(_SC_PAGE_SIZE);

	/*
	 * Open the file, read and validate the header, and mmap() the file.
	 */
	if ((fd = open(filename, O_RDWR)) == -1) {
		perror("open");
		return (-1);
	}
	if (read(fd, &temp_header, sizeof(temp_header)) <
	    (ssize_t)sizeof(temp_header)) {
		fprintf(stderr, "short read on header\n");
		return (-1);
	}
	if (temp_header.magic != MAGIC_NUM) {
		fprintf(stderr, "header has an invalid magic number\n");
		return (-1);
	}
	if (temp_header.active_half != FIRST &&
	    temp_header.active_half != SECOND) {
		fprintf(stderr, "header has an invalid active_half\n");
		return (-1);
	}
	if (temp_header.storage_size == 0) {
		fprintf(stderr, "header has an invalid storage_size\n");
		return (-1);
	}
	if ((header = mmap(NULL,
		 sizeof(temp_header) + 2 * temp_header.storage_size,
		 PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)) == MAP_FAILED) {
		perror("mmap");
		return (-1);
	}

	/*
	 * Restore the active and inactive spaces based upon the active half
	 * field from the header.
	 */
	if (header->active_half == FIRST) {
		active_space_start = (char *)header + sizeof(*header);
		active_space_end = active_space_start + header->storage_size;
		inactive_space_start = active_space_end;
	} else {
		inactive_space_start = (char *)header + sizeof(*header);
		active_space_start = inactive_space_start +
		    header->storage_size;
		active_space_end = active_space_start + header->storage_size;
	}

	if ((inactive_table = hash_table_create(1.5)) == NULL) {
		fprintf(stderr, "hash table create failed\n");
		return (-1);
	}
	if ((active_table = hash_table_create(1.5)) == NULL) {
		fprintf(stderr, "hash table create failed\n");
		return (-1);
	}

	inactive_space_used = 0;

	/*
	 * Reload the inactive space hash table, and compute
	 * inactive_space_used.
	 */
	for (char *inactive_cursor = inactive_space_start;;) {
		struct file_entry *entry = (struct file_entry *)inactive_cursor;

		printf("Old entry, op: %d, key: %s, val: %s\n", entry->op,
		    entry->key, entry->value);

		if (entry->op == OP_SET) {
			if (hash_table_insert(inactive_table, entry->key,
				entry) != 0) {
				fprintf(stderr, "failed to insert to table\n");
				return (-1);
			}
			inactive_space_used += file_entry_size(entry);
		} else if (entry->op == OP_DELETE) {
			/*
			 * On reload, there may be nothing to delete, because
			 * the deleted OP_SET was originally in the other
			 * space, which has been destroyed.
			 */
			struct file_entry *deleted_entry =
			    hash_table_lookup(inactive_table, entry->key);
			if (deleted_entry != NULL) {
				hash_table_remove(inactive_table, entry->key,
				    NULL, NULL);
				inactive_space_used -= file_entry_size(
				    deleted_entry);
			}
		} else if (entry->op == OP_EOS)
			break;
		else {
			fprintf(stderr, "invalid op value: %d\n", entry->op);
			return (-1);
		}

		inactive_cursor += file_entry_size(entry);
	}

	next_entry = active_space_start;

	/*
	 * Reload the active space hash table.
	 */
	for (;;) {
		struct file_entry *entry = (struct file_entry *)next_entry;

		printf("New entry, op: %d, key: %s, val: %s\n", entry->op,
		    entry->key, entry->value);

		if (entry->op == OP_SET) {
			struct file_entry *inactive_entry =
			    hash_table_lookup(inactive_table, entry->key);
			if (inactive_entry != NULL) {
				hash_table_remove(inactive_table, entry->key,
				    NULL, NULL);
				inactive_space_used -= file_entry_size(
				    inactive_entry);
			}
			if (hash_table_insert(active_table, entry->key,
				entry) != 0) {
				fprintf(stderr, "failed to insert to table\n");
				return (-1);
			}
		} else if (entry->op == OP_DELETE) {
			struct file_entry *inactive_entry =
			    hash_table_lookup(inactive_table, entry->key);
			if (inactive_entry != NULL) {
				hash_table_remove(inactive_table, entry->key,
				    NULL, NULL);
				inactive_space_used -= file_entry_size(
				    inactive_entry);
			} else
				hash_table_remove(active_table, entry->key,
				    NULL, NULL);
		} else if (entry->op == OP_EOS)
			break;
		else {
			fprintf(stderr, "invalid op value: %d\n", entry->op);
			return (-1);
		}

		next_entry += file_entry_size(entry);
	}

	return (0);
}

enum resp
get_entry(const char key[KEYSIZE], uint32_t *len, uint8_t **value)
{
	(void)key;
	(void)len;
	(void)value;
	/*
	 * If the key does not exist in the active table, then consult the
	 * inactive table.  If it does not exist in the inactive table either,
	 * then return NOT_FOUND.  Otherwise, return the len and value by
	 * reference.
	 */

	struct file_entry *record_p = hash_table_lookup(active_table, key);

	if (record_p == NULL) {
		record_p = hash_table_lookup(inactive_table, key);
	}

	if (record_p == NULL) {

		return (NOT_FOUND);
	}

	*len = record_p->len;
	*value = record_p->value;

	return (SUCCESS);
}

enum resp
set_entry(const char key[KEYSIZE], uint32_t len, uint8_t *value)
{
	/*
	 * Compute the padded length by rounding len up to the next multiple
	 * of 8.
	 */
	uint32_t align_len = (len + 7) & ~7;

	/*
	 * Lookup the key in the inactive table.
	 */
	struct file_entry *exist_rec = hash_table_lookup(inactive_table,
	    key);

	/*
	 * If there is not enough space in the active space to write the new
	 * entry, given the inactive space used, the size of the new entry,
	 * and the size of the existing entry in the inactive table (if one
	 * exists), then switch the active and inactive spaces, look up the
	 * key in the new inactive table, and check the space again.  If there
	 * is still not enough space, then return NOT_ENOUGH_SPACE.
	 */

	uint64_t free_space = active_space_end - next_entry;
	uint64_t req_space = inactive_space_used +
	    sizeof(struct file_entry) + sizeof(op_type) -
	    (exist_rec ? file_entry_size(exist_rec) : 0);

	if (free_space < req_space) {
		if (switch_active_side() != 0)
			return (SERVER_ERROR);

		exist_rec = hash_table_lookup(inactive_table, key);

		free_space = active_space_end - next_entry;
		req_space = inactive_space_used + sizeof(struct file_entry) +
		    sizeof(op_type) -
		    (exist_rec ? file_entry_size(exist_rec) : 0);

		if (free_space < req_space) {
			return (NOT_ENOUGH_SPACE);
		}
	}

	/*
	 * Write the new entry into the active space, and insert it into the
	 * active table.
	 */

	struct file_entry *new_rec = write_next_entry(OP_SET, key, value,
	    len, align_len);

	if (new_rec == NULL)
		return (SERVER_ERROR);

	if (hash_table_insert(active_table, new_rec->key, new_rec) != 0) {
		return (SERVER_ERROR);
	}

	/*
	 * If the key was previously found in the inactive table, remove it
	 * from the inactive table and update the size of the inactive space.
	 */

	if (exist_rec != NULL) {
		assert(exist_rec->op == OP_SET);

		uint32_t old_rec_size = file_entry_size(exist_rec);
		hash_table_remove(inactive_table, key, NULL, NULL);
		inactive_space_used -= old_rec_size;
	}

	return (SUCCESS);
	
}

enum resp
delete_entry(const char key[KEYSIZE])
{
	struct file_entry *inactive_entry = hash_table_lookup(inactive_table,
	    key);
	struct file_entry *active_entry = hash_table_lookup(active_table, key);
	if (inactive_entry == NULL && active_entry == NULL)
		return (NOT_FOUND);
	assert(inactive_entry == NULL || active_entry == NULL);

	uint64_t active_space_unused = active_space_end - next_entry;
	if (active_space_unused <
	    inactive_space_used + sizeof(struct file_entry) + sizeof(op_type)) {
		if (switch_active_side() != 0)
			return (SERVER_ERROR);
		inactive_entry = hash_table_lookup(inactive_table, key);
		active_entry = NULL;
	}

	struct file_entry *entry = write_next_entry(OP_DELETE, key, NULL, 0, 0);
	if (entry == NULL)
		return (SERVER_ERROR);

	if (active_entry != NULL)
		hash_table_remove(active_table, key, NULL, NULL);
	else {
		assert(inactive_entry != NULL);
		assert(inactive_entry->op == OP_SET);
		uint32_t inactive_entry_size = file_entry_size(inactive_entry);
		hash_table_remove(inactive_table, key, NULL, NULL);
		inactive_space_used -= inactive_entry_size;
	}

	return (SUCCESS);
}

/**
 * @brief inserts the next entry into the KVStore
 *
 * Fills the next entry in the file with the provided arguments.
 *
 * @param op the opcode of the entry
 * @param key the key of the entry
 * @param value the value of the entry
 * @param len the length of the entry
 * @param padded_len the length padded to the next 8-byte increment
 */
static struct file_entry *
write_next_entry(op_type op, const char key[KEYSIZE], uint8_t *value,
    uint32_t len, uint32_t padded_len)
{
	assert((uintptr_t)next_entry % 8 == 0);
	assert(*(op_type *)next_entry == OP_EOS);

	/*
	 * Write the next entry into the active space, except for the op
	 * field, which must remain OP_EOS until the new OP_EOS is msync()ed.
	 */

	struct file_entry *rec = (struct file_entry *)next_entry;
	rec->len = len;
	rec->padded_len = padded_len;

	memcpy(rec->key, key, KEYSIZE);

	if (value != NULL && len > 0) {
		memcpy(rec->value, value, len);
		if (padded_len > len) {
			memset(rec->value + len, 0, padded_len - len);
		}
	}

	/*
	 * Write the new OP_EOS at the end of the active space and synchronize
	 * everything after the new entry's op, including the new OP_EOS.
	 */

	char *end_mark = next_entry + sizeof(struct file_entry) +
	    padded_len;
	*(op_type *)end_mark = OP_EOS;

	/*
	 * Ensure that we have not yet overwritten the old OP_EOS.
	 */

	assert(*(op_type *)next_entry == OP_EOS);

	/*
	 * Now that the new OP_EOS is stable, overwrite the old OP_EOS with
	 * the new op value and synchronize.
	 */

	if (sync_helper(end_mark, sizeof(op_type), MS_SYNC) != 0) {
		return NULL;
	}

	/*
	 * Now that the new entry is stable, update next_entry to point to the
	 * location where a future new entry will be placed.
	 */

	rec->op = op;
	if (sync_helper(&rec->op, sizeof(op_type), MS_SYNC) != 0) {
		return NULL;
	}

	next_entry = end_mark;

	return (rec);
}

struct copy_data {
	int		   err;
	struct hash_table *table;
};

/**
 * @brief Switches the active and inactive storage spaces in the key-value
 * store.
 *
 * This function moves all live entries from the inactive storage space to the
 * active storage space, swaps the active and inactive storage spaces, and
 * updates the metadata to reflect the change. It also creates a new hash table
 * for the active space and recalculates the size of the inactive space.
 *
 * @return 0 on success, or a negative value on failure.
 */
static int
switch_active_side(void)
{
	printf("switching sides\n");

	/*
	 * First, move the file entries that are still live in the inactive
	 * space to the active space, using hash_table_iterate() and
	 * copy_entry().  Then, destroy the inactive table.
	 */
	struct copy_data data = { .err = 0, .table = active_table };

	hash_table_iterate(inactive_table, copy_entry, &data);

	if (data.err != 0) {
		return -1;
	}

	hash_table_destroy(inactive_table, NULL, NULL);

	/*
	 * Swap active and inactive spaces.
	 */

	char *tmp_p = inactive_space_start;
	inactive_space_start = active_space_start;

	active_space_start = tmp_p;
	active_space_end = active_space_start + header->storage_size;

	/*
	 * Write and synchronize an OP_EOS to the start of the new half.
	 */

	*(op_type *)active_space_start = OP_EOS;
	if (sync_helper(active_space_start, sizeof(op_type), MS_SYNC) != 0) {
		return (-1);
	}

	next_entry = active_space_start;

	/*
	 * Switch which half of the file we're writing into, and synchronize
	 * this change.
	 */
	header->active_half = (header->active_half == FIRST) ? SECOND : FIRST;

	if (sync_helper(&header->active_half, sizeof(header->active_half),
		MS_SYNC) != 0) {
		return (-1);
	}

	/*
	 * Make the old active table the new inactive table, and compute the
	 * amount of live data that it holds using hash_table_iterate() and
	 * compute_ht_size().
	 */
	inactive_table = active_table;
	inactive_space_used = 0;

	hash_table_iterate(inactive_table, compute_ht_size,
	    &inactive_space_used);

	/*
	 * Create the new active table.
	 */

	active_table = hash_table_create(1.5);
	if (active_table == NULL) {
		return (-1);
	}

	return (0);
}

/**
 * @brief Copies a file_entry to a specified memory location.
 *
 * This function copies the key-value entry to the provided memory location.
 *
 * @param key The key of the entry to copy.
 * @param value A pointer to the entry to be copied.
 * @param data The new table we will be using, and the current pointer being
 * used.
 * @return A struct with the new hash table and pointer to where next memory
 * will go.
 */
static void *
copy_entry(const char key[KEYSIZE], void *value, void *cookie)
{
	struct copy_data *data = cookie; // Pass error along
	if (data->err != 0)
		return (data);

	// Copy this entry into the file.
	struct file_entry *entry = value;
	struct file_entry *copied_entry = write_next_entry(entry->op, key,
	    entry->value, entry->len, entry->padded_len);
	if (copied_entry == NULL) {
		data->err = -1;
		return (data);
	}

	// Include the entry in the active table.
	if (hash_table_insert(data->table, copied_entry->key, copied_entry) !=
	    0)
		data->err = -1;

	return (data);
}

/**
 * @brief Iterator function to computes the total size of all entries in a hash
 * table.
 *
 * This accumulates the file entry size into the provided cookie.
 *
 * @param key The key of the current entry (unused in this function).
 * @param value A pointer to the current entry in the hash table.
 * @param cookie A pointer to an integer where the total size will be
 * accumulated.
 * @return A pointer to the cookie containing the accumulated size.
 */
static void *
compute_ht_size(const char key[KEYSIZE], void *value, void *cookie)
{
	(void)key;
	struct file_entry *entry = value;
	int		  *size = cookie;
	*size += file_entry_size(entry);
	return (size);
}

/**
 * @brief Synchronizes a memory region with the underlying storage.
 *
 * This function ensures that changes made to a memory-mapped region are
 * written to the underlying storage. It calculates the page-aligned start
 * address and the total length to synchronize, including the offset within
 * the page.
 *
 * @param addr The starting address of the memory region to synchronize.
 * @param length The length of the memory region to synchronize.
 * @param flags Flags to control the synchronization behavior (e.g., MS_SYNC).
 * @return 0 on success, or -1 on failure with `errno` set appropriately.
 */
static int
sync_helper(void *addr, size_t length, int flags)
{
	uintptr_t page_mask = page_size - 1;
	uintptr_t page_offset = ((uintptr_t)addr & page_mask);
	void	 *page_start = (void *)((uintptr_t)addr & ~page_mask);
	return (msync(page_start, page_offset + length, flags));
}

// Prevent "unused function" and "unused variable" warnings.
static const void *dummy_ref[] = { copy_entry, compute_ht_size, sync_helper,
	dummy_ref };