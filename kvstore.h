#include <stdint.h>

#include "hash_table.h"

#define MAGIC_NUM 0xabcddcba // 32 bit number files must have in header

typedef uint32_t half_type;

#define FIRST  0
#define SECOND 1

struct file_header {
	uint32_t  magic;	// Magic number to check if file is valid
	half_type active_half;  // Which half of the file we are currently using
	uint64_t  storage_size; // How much storage space in each half
};

_Static_assert(sizeof(struct file_header) % 8 == 0,
    "sizeof(struct file_header) is not a multiple of 8");

#define OP_SET    0  // Set operation
#define OP_DELETE 1  // Delete operation
#define OP_EOS    2  // End of storage marker

typedef uint32_t op_type;

struct file_entry {
	op_type	 op;	       // Type of operation
	uint32_t padding;      // To make this 80 bytes, unused
	char	 key[KEYSIZE]; // Key of the entry
	uint32_t len;	       // Length of the value
	uint32_t padded_len;   // length for 8-byte padding
	uint8_t	 value[];      // Value of the entry
};

_Static_assert(sizeof(struct file_entry) % 8 == 0,
    "sizeof(struct file_entry) is not a multiple of 8");

static inline size_t
file_entry_size(struct file_entry *entry)
{
	return (sizeof(*entry) + entry->padded_len);
}

enum resp { SUCCESS, SERVER_ERROR, NOT_FOUND, NOT_ENOUGH_SPACE };

/**
 * @brief Initializes the key-value store.
 *
 * This function opens the specified file, truncates it to the maximum file
 * size, and memory-maps it for read and write operations. It also initializes
 * the hash table used for storing the key-value entries.
 *
 * @param filename The name of the file to be used for the key-value store.
 * @param num_table_entries The number of entries in the hash table.
 * @return 0 on success, the errno value if it fails on a system call, or -1 if
 * it fails for any other reason.
 */
int init(const char *filename);

/**
 * @brief Retrieves an entry from the key-value store.
 *
 * This function looks up the specified key in the hash table and stores the
 * associated value and its length in the provided pointers if the key is found.
 *
 * @param key The key to look up in the key-value store.
 * @param len A pointer to a variable where the length of the value will be
 * stored.
 * @param value A pointer to a variable where the address of the value will be
 * stored.
 * @return SUCCESS if the key is found, NOT_FOUND if the key does not exist.
 */
enum resp get_entry(const char key[KEYSIZE], uint32_t *len, uint8_t **value);

/**
 * @brief Sets an entry in the key-value store.
 *
 * This function adds or updates the specified key with the given value and
 * length in the key-value store. If there is not enough space to store the
 * entry, it returns an error.
 *
 * @param key The key to set in the key-value store.
 * @param len The length of the value to be stored.
 * @param value A pointer to a byte array of length len.
 * @return SUCCESS if the entry is successfully set, the appropriate error
 * response otherwise.
 */
enum resp set_entry(const char key[KEYSIZE], uint32_t len, uint8_t *value);

/**
 * @brief Deletes an entry from the key-value store.
 *
 * This function removes the specified key from the key-value store. It removes
 * the entry from the hash table and updates the memory-mapped file accordingly.
 *
 * @param key The key to delete from the key-value store.
 * @return SUCCESS if the entry is successfully deleted, the appropriate error
 * response otherwise.
 */
enum resp delete_entry(const char key[KEYSIZE]);
