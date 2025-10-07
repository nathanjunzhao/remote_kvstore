#include <sys/mman.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "file_initializer.h"
#include "kvstore.h"

int
initialize_file(char *file_name, uint64_t storage_size)
{
	int	 file;
	uint64_t aligned_storage_size = storage_size - storage_size % 8;
	char	*in_mem_file, *second_half_start;

	if ((file = open(file_name, O_RDWR | O_CREAT | O_TRUNC, 0777)) == -1) {
		fprintf(stderr, "open failed: %s\n", strerror(errno));
		return (-1);
	}

	if (ftruncate(file, sizeof(struct file_header) + 2 * aligned_storage_size) !=
	    0) {
		fprintf(stderr, "ftruncate failed: %s\n", strerror(errno));
		return (-1);
	}

	if ((in_mem_file = mmap(NULL,
		 sizeof(struct file_header) + 2 * aligned_storage_size,
		 PROT_READ | PROT_WRITE, MAP_SHARED, file, 0)) == (void *)-1) {
		fprintf(stderr, "mmap failed: %s\n", strerror(errno));
		return (-1);
	}

	struct file_header *header = (struct file_header *)in_mem_file;
	header->magic = MAGIC_NUM;
	header->active_half = FIRST;
	header->storage_size = aligned_storage_size;
	in_mem_file += sizeof(struct file_header);

	// Write first half OP_EOS
	op_type eos_marker = OP_EOS;
	memcpy(in_mem_file, &eos_marker, sizeof(eos_marker));

	second_half_start = in_mem_file + aligned_storage_size;

	// Write second half OP_EOS
	memcpy(second_half_start, &eos_marker, sizeof(eos_marker));

	if (munmap(in_mem_file - sizeof(struct file_header),
		sizeof(struct file_header) + 2 * aligned_storage_size) == -1) {
		fprintf(stderr, "munmap failed: %s\n", strerror(errno));
		return (-1);
	}

	close(file);
	return (0);
}
