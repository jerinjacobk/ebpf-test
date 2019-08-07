/*
 * build:
 * gcc -Wall bin_to_ebpf_instn_arrray.c
 * 
 * assemble ebpf opcode to file
 * ./bin/ubpf-assembler tests/ja.data /home/jerin/bpf/code
 *
 * To dump the opcode in array format
 * $ ./a.out /home/jerin/bpf/code
 */

#include <stdio.h> 
#include <stdlib.h> 
#include <string.h> 
#include <stdint.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <assert.h>
#include <byteswap.h>
#include <inttypes.h>

size_t getfilesize(const char* filename)
{
	struct stat st;
	stat(filename, &st);
	return st.st_size;
}

 
/* First arg is file name */
int main (int argc, char** argv) 
{ 
	int fd, count;
	uint64_t *ptr;

	const char *header = "static const u64 test_prog[] = {\n";
	const char *footer = "};\n";

	size_t filesize = getfilesize(argv[1]);
	fd = open(argv[1], O_RDONLY, 0);
	if (fd == -1) 
	{ 
		fprintf(stderr, "\nError in opening file=%s\n", argv[1]); 
		exit (1); 
	} 

	ptr = mmap(NULL, filesize,
			 PROT_READ, MAP_PRIVATE | MAP_POPULATE, fd, 0);
	assert(ptr != MAP_FAILED);

	printf(header);
	for (count = 0; count < (filesize/sizeof(uint64_t)); count++) {
		uint64_t x = *(uint64_t *)ptr++;
		printf("\t0x%" PRIx64 ",\n", x);
	}
	printf(footer);

	munmap(ptr, filesize);
	close(fd);

	return 0;
}
