/*
 * echo 2 > /proc/sys/net/core/bpf_jit_enable
 * bpf_jit_disasm or bpf_jit_disasm -o
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/init.h>
#include <linux/module.h>
#include <linux/filter.h>
#include <linux/bpf.h>

#include "bpf_def.h"

/* Tests */
struct dummy_offset {
	u64 u64;
	u32 u32;
	u16 u16;
	u8  u8;
};

#define	TEST_FILL_1	0xDEADBEEF

#if 0
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

#else

static const u64 test_prog[] = {
        0x1000000b7,
        0x10005,
        0x2000000b7,
        0x95,
};

#endif

int run_ebpf_test(const struct ebpf_insn *fptr, u32 len,
			       u32 stack_depth, const void *ctx,
			       unsigned int *ret)
{
	struct bpf_prog *fp;
	int err = 0;
	int rc = -1;

	fp = bpf_prog_alloc(len, 0);
	if (fp == NULL) {
		pr_cont("UNEXPECTED_FAIL no memory left\n");
		goto fail1;
	}

	fp->len = len;
	/* Type doesn't really matter here as long as it's not unspec. */
	fp->type = BPF_PROG_TYPE_SOCKET_FILTER;
	memcpy(fp->insnsi, fptr, fp->len * sizeof(struct bpf_insn));
	fp->aux->stack_depth = stack_depth ;

	/* We cannot error here as we don't need type compatibility
	 * checks.
	 */
	fp = bpf_prog_select_runtime(fp, &err);
	if (err) {
		pr_cont("FAIL to select_runtime err=%d\n", err);
		goto fail2;
	}
	rc = 0;

	*ret = BPF_PROG_RUN(fp, ctx);
fail2:
	bpf_prog_free(fp);
fail1:
	return rc;
}

static int __init test_ebpf_init(void)
{
	struct dummy_offset ctx;
	int ret;
	int rc;
	u32 insns_cnt = sizeof(test_prog) / sizeof(struct ebpf_insn);


	rc = run_ebpf_test((struct ebpf_insn*)test_prog, insns_cnt,
			   512, &ctx, &ret);
	if (!rc)
		pr_cont("ret=%d\n", ret);

	return rc;

}

static void __exit test_ebpf_exit(void)
{
}

module_init(test_ebpf_init);
module_exit(test_ebpf_exit);

MODULE_LICENSE("GPL");
