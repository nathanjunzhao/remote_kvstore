#include <stdint.h>

/**
 * @brief initializes a file with the proper header info.
 *
 * Empties out the file, then writes the correct MAGIC_NUM into it, sets the
 * half to be the first half, and writes an EOFF marker.
 *
 * @param file_name the name of the file to initialize
 * @return 0 on success, -1 on failure
 */
int initialize_file(char *file_name, uint64_t storage_size);