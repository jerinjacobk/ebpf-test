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
        0xb4,
        0x81261,
        0x1379,
        0x181461,
        0x101579,
        0x80215,
        0xffffff85000903d5,
        0x162e000a0425,
        0xdeadbeef000b0545,
        0xc325d,
        0xd426d,
        0xe52bd,
        0xf534d,
        0x95,
        0x100000047,
        0xfff60005,
        0x200000047,
        0xfff50005,
        0x400000047,
        0xfff40005,
        0x800000047,
        0xfff30005,
        0x1000000047,
        0xfff20005,
        0x2000000047,
        0xfff10005,
        0x4000000047,
        0xfff00005,
        0x8000000047,
        0xffef0005,
};


struct dummy_vect8 {
	struct dummy_offset in[8];
	struct dummy_offset out[8];
};

static void
test_jump1_prepare(void *arg)
{
	struct dummy_vect8 *dv;
	uint64_t v1, v2;

	dv = arg;

	v1 = 0xffff000011112222;
	v2 = 0x1111222233334444;

	memset(dv, 0, sizeof(*dv));
	dv->in[0].u64 = v1;
	dv->in[1].u64 = v2;
	dv->in[0].u32 = (v1 << 12) + (v2 >> 6);
	dv->in[1].u32 = (v2 << 12) - (v1 >> 6);
}

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

struct dummy_offset ctx;

static int __init test_ebpf_init(void)
{
	int ret;
	int rc;
	u32 insns_cnt = sizeof(test_prog) / sizeof(struct ebpf_insn);

	memset(&ctx, 0, sizeof(ctx));
	test_jump1_prepare(&ctx);
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
