/*
 * build:
 * gcc -Wall ebpf_instn_to_file.c
 * 
 * dump the test to file:
 * ./a.out /home/jerin/bpf/code1
 *
 * disassemble blob to file
 * ./bin/ubpf-disassembler /home/jerin/bpf/code1 /home/jerin/bpf/jerin.asm
 *
 * cat /home/jerin/bpf/jerin.asm to see the ebpf asm code
 *
 *
 */

#include <stdio.h> 
#include <stdlib.h> 
#include <string.h> 
#include <stdint.h>
 
#include "bpf_def.h"

#ifndef offsetof
#define offsetof(t, m) ((size_t) &((t *)0)->m)
#endif

struct dummy_offset {
	uint64_t u64;
	uint32_t u32;
	uint16_t u16;
	uint8_t  u8;
};

#define	TEST_FILL_1	0xDEADBEEF


/* store immediate test-cases */
static const struct ebpf_insn test_prog[] = {
	{
		.code = (BPF_ST | BPF_MEM | BPF_B),
		.dst_reg = EBPF_REG_1,
		.off = offsetof(struct dummy_offset, u8),
		.imm = TEST_FILL_1,
	},
	{
		.code = (BPF_ST | BPF_MEM | BPF_H),
		.dst_reg = EBPF_REG_1,
		.off = offsetof(struct dummy_offset, u16),
		.imm = TEST_FILL_1,
	},
	{
		.code = (BPF_ST | BPF_MEM | BPF_W),
		.dst_reg = EBPF_REG_1,
		.off = offsetof(struct dummy_offset, u32),
		.imm = TEST_FILL_1,
	},
	{
		.code = (BPF_ST | BPF_MEM | EBPF_DW),
		.dst_reg = EBPF_REG_1,
		.off = offsetof(struct dummy_offset, u64),
		.imm = TEST_FILL_1,
	},
	/* return 1 */
	{
		.code = (BPF_ALU | EBPF_MOV | BPF_K),
		.dst_reg = EBPF_REG_0,
		.imm = 1,
	},
	{
		.code = (BPF_JMP | EBPF_EXIT),
	},
};

 
/* First arg is file name */
int main (int argc, char** argv) 
{ 
	FILE *outfile; 
	int rc;

	outfile = fopen (argv[1], "w"); 
	if (outfile == NULL) 
	{ 
		fprintf(stderr, "\nError in opening file=%s\n", argv[1]); 
		exit (1); 
	} 

	rc = fwrite(test_prog, sizeof(struct ebpf_insn),
		sizeof(test_prog) / sizeof(struct ebpf_insn), outfile); 
	if(rc != 0)  
		printf("contents to file written successfully !\n"); 
	else 
		printf("error writing file !\n"); 

	fclose (outfile); 

	return 0;
}
