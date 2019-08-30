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

struct dummy_vect8 {
	struct dummy_offset in[8];
	struct dummy_offset out[8];
};

#define	TEST_FILL_1	0xDEADBEEF
#define	TEST_MUL_1	21
#define TEST_MUL_2	-100

#define TEST_SHIFT_1	15
#define TEST_SHIFT_2	33

#define TEST_JCC_1	0
#define TEST_JCC_2	-123
#define TEST_JCC_3	5678
#define TEST_JCC_4	TEST_FILL_1

#define TEST_IMM_1	UINT64_MAX
#define TEST_IMM_2	((uint64_t)INT64_MIN)
#define TEST_IMM_3	((uint64_t)INT64_MAX + INT32_MAX)
#define TEST_IMM_4	((uint64_t)UINT32_MAX)
#define TEST_IMM_5	((uint64_t)UINT32_MAX + 1)

static const struct ebpf_insn test_prog[] = {
	[0] = {
		.code = (BPF_ALU | EBPF_MOV | BPF_K),
		.dst_reg = EBPF_REG_0,
		.imm = 0,
	},
	[1] = {
		.code = (BPF_LDX | BPF_MEM | BPF_W),
		.dst_reg = EBPF_REG_2,
		.src_reg = EBPF_REG_1,
		.off = offsetof(struct dummy_vect8, in[0].u32),
	},
	[2] = {
		.code = (BPF_LDX | BPF_MEM | EBPF_DW),
		.dst_reg = EBPF_REG_3,
		.src_reg = EBPF_REG_1,
		.off = offsetof(struct dummy_vect8, in[0].u64),
	},
	[3] = {
		.code = (BPF_LDX | BPF_MEM | BPF_W),
		.dst_reg = EBPF_REG_4,
		.src_reg = EBPF_REG_1,
		.off = offsetof(struct dummy_vect8, in[1].u32),
	},
	[4] = {
		.code = (BPF_LDX | BPF_MEM | EBPF_DW),
		.dst_reg = EBPF_REG_5,
		.src_reg = EBPF_REG_1,
		.off = offsetof(struct dummy_vect8, in[1].u64),
	},
	[5] = {
		.code = (BPF_JMP | BPF_JEQ | BPF_K),
		.dst_reg = EBPF_REG_2,
		.imm = TEST_JCC_1,
		.off = 8,
	},
	[6] = {
		.code = (BPF_JMP | EBPF_JSLE | BPF_K),
		.dst_reg = EBPF_REG_3,
		.imm = TEST_JCC_2,
		.off = 9,
	},
	[7] = {
		.code = (BPF_JMP | BPF_JGT | BPF_K),
		.dst_reg = EBPF_REG_4,
		.imm = TEST_JCC_3,
		.off = 10,
	},
	[8] = {
		.code = (BPF_JMP | BPF_JSET | BPF_K),
		.dst_reg = EBPF_REG_5,
		.imm = TEST_JCC_4,
		.off = 11,
	},
	[9] = {
		.code = (BPF_JMP | EBPF_JNE | BPF_X),
		.dst_reg = EBPF_REG_2,
		.src_reg = EBPF_REG_3,
		.off = 12,
	},
	[10] = {
		.code = (BPF_JMP | EBPF_JSGT | BPF_X),
		.dst_reg = EBPF_REG_2,
		.src_reg = EBPF_REG_4,
		.off = 13,
	},
	[11] = {
		.code = (BPF_JMP | EBPF_JLE | BPF_X),
		.dst_reg = EBPF_REG_2,
		.src_reg = EBPF_REG_5,
		.off = 14,
	},
	[12] = {
		.code = (BPF_JMP | BPF_JSET | BPF_X),
		.dst_reg = EBPF_REG_3,
		.src_reg = EBPF_REG_5,
		.off = 15,
	},
	[13] = {
		.code = (BPF_JMP | EBPF_EXIT),
	},
	[14] = {
		.code = (EBPF_ALU64 | BPF_OR | BPF_K),
		.dst_reg = EBPF_REG_0,
		.imm = 0x1,
	},
	[15] = {
		.code = (BPF_JMP | BPF_JA),
		.off = -10,
	},
	[16] = {
		.code = (EBPF_ALU64 | BPF_OR | BPF_K),
		.dst_reg = EBPF_REG_0,
		.imm = 0x2,
	},
	[17] = {
		.code = (BPF_JMP | BPF_JA),
		.off = -11,
	},
	[18] = {
		.code = (EBPF_ALU64 | BPF_OR | BPF_K),
		.dst_reg = EBPF_REG_0,
		.imm = 0x4,
	},
	[19] = {
		.code = (BPF_JMP | BPF_JA),
		.off = -12,
	},
	[20] = {
		.code = (EBPF_ALU64 | BPF_OR | BPF_K),
		.dst_reg = EBPF_REG_0,
		.imm = 0x8,
	},
	[21] = {
		.code = (BPF_JMP | BPF_JA),
		.off = -13,
	},
	[22] = {
		.code = (EBPF_ALU64 | BPF_OR | BPF_K),
		.dst_reg = EBPF_REG_0,
		.imm = 0x10,
	},
	[23] = {
		.code = (BPF_JMP | BPF_JA),
		.off = -14,
	},
	[24] = {
		.code = (EBPF_ALU64 | BPF_OR | BPF_K),
		.dst_reg = EBPF_REG_0,
		.imm = 0x20,
	},
	[25] = {
		.code = (BPF_JMP | BPF_JA),
		.off = -15,
	},
	[26] = {
		.code = (EBPF_ALU64 | BPF_OR | BPF_K),
		.dst_reg = EBPF_REG_0,
		.imm = 0x40,
	},
	[27] = {
		.code = (BPF_JMP | BPF_JA),
		.off = -16,
	},
	[28] = {
		.code = (EBPF_ALU64 | BPF_OR | BPF_K),
		.dst_reg = EBPF_REG_0,
		.imm = 0x80,
	},
	[29] = {
		.code = (BPF_JMP | BPF_JA),
		.off = -17,
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
