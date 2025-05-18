// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char _license[] SEC("license") = "GPL";

#define ARG(n) ({				\
	__u64 __val = 0;			\
	bpf_get_func_arg(ctx, n, &__val);	\
	__val;					\
})

__u64 test1_result = 0;
SEC("fentry.multi/bpf_fentry_test1")
int BPF_PROG(test1)
{
	test1_result = (int)ARG(0) == 1;
	return 0;
}

__u64 test2_result = 0;
SEC("fentry.multi/bpf_fentry_test2")
int BPF_PROG(test2)
{
	test2_result = (int)ARG(0) == 2 && ARG(1) == 3;
	return 0;
}

__u64 test3_result = 0;
SEC("fentry.multi/bpf_fentry_test3")
int BPF_PROG(test3)
{
	test3_result = (char)ARG(0) == 4 && (int)ARG(1) == 5 && ARG(2) == 6;
	return 0;
}

__u64 test4_result = 0;
SEC("fentry.multi/bpf_fentry_test4")
int BPF_PROG(test4)
{
	test4_result = (void *)ARG(0) == (void *)7 && (char)ARG(1) == 8 &&
		(int)ARG(2) == 9 && ARG(3) == 10;
	return 0;
}

__u64 test5_result = 0;
SEC("fentry.multi/bpf_fentry_test5")
int BPF_PROG(test5, __u64 a, void *b, short c, int d, __u64 e)
{
	test5_result = ARG(0) == 11 && (void *)ARG(1) == (void *)12 && (short)ARG(2) == 13 &&
		(int)ARG(3) == 14 && ARG(4) == 15;
	return 0;
}

__u64 test6_result = 0;
SEC("fentry.multi/bpf_fentry_test6")
int BPF_PROG(test6, __u64 a, void *b, short c, int d, void *e, __u64 f)
{
	test6_result = ARG(0) == 16 && (void *)ARG(1) == (void *)17 && (short)ARG(2) == 18 &&
		(int)ARG(3) == 19 && (void *)ARG(4) == (void *)20 && ARG(5) == 21;
	return 0;
}

struct bpf_fentry_test_t {
	struct bpf_fentry_test_t *a;
};

__u64 test7_result = 0;
SEC("fentry.multi/bpf_fentry_test7")
int BPF_PROG(test7, struct bpf_fentry_test_t *arg)
{
	if (!(void *)ARG(0))
		test7_result = 1;
	return 0;
}

__u64 test8_result = 0;
SEC("fentry.multi/bpf_fentry_test8")
int BPF_PROG(test8)
{
	struct bpf_fentry_test_t *arg;

	arg = bpf_core_cast((void *)ARG(0), struct bpf_fentry_test_t);
	if (arg->a == 0)
		test8_result = 1;
	return 0;
}
