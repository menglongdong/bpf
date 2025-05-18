// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

#define ARG(n) ({				\
	__u64 __val = 0;			\
	bpf_get_func_arg(ctx, n, &__val);	\
	__val;					\
})

#define RET() ({ __u64 __ret = 0; bpf_get_func_ret(ctx, &__ret); __ret; })

__u64 test1_result = 0;
SEC("fexit/bpf_fentry_test1")
int BPF_PROG(test1, int a, int ret)
{
	test1_result = (int)ARG(0) == 1 && (int)RET() == 2;
	return 0;
}

__u64 test2_result = 0;
SEC("fexit/bpf_fentry_test2")
int BPF_PROG(test2, int a, __u64 b, int ret)
{
	test2_result = (int)ARG(0) == 2 && ARG(1) == 3 && (int)RET() == 5;
	return 0;
}

__u64 test3_result = 0;
SEC("fexit/bpf_fentry_test3")
int BPF_PROG(test3, char a, int b, __u64 c, int ret)
{
	test3_result = (char)ARG(0) == 4 && (int)ARG(1) == 5 && ARG(2) == 6 && (int)RET() == 15;
	return 0;
}

__u64 test4_result = 0;
SEC("fexit/bpf_fentry_test4")
int BPF_PROG(test4, void *a, char b, int c, __u64 d, int ret)
{
	test4_result = (void *)ARG(0) == (void *)7 && (char)ARG(1) == 8 &&
		(int)ARG(2) == 9 && ARG(3) == 10 && (int)RET() == 34;
	return 0;
}

__u64 test5_result = 0;
SEC("fexit/bpf_fentry_test5")
int BPF_PROG(test5, __u64 a, void *b, short c, int d, __u64 e, int ret)
{
	test5_result = ARG(0) == 11 && (void *)ARG(1) == (void *)12 && (short)ARG(2) == 13 &&
		(int)ARG(3) == 14 && ARG(4) == 15 && (int)RET() == 65;
	return 0;
}

__u64 test6_result = 0;
SEC("fexit/bpf_fentry_test6")
int BPF_PROG(test6, __u64 a, void *b, short c, int d, void *e, __u64 f, int ret)
{
	test6_result = ARG(0) == 16 && (void *)ARG(1) == (void *)17 && (short)ARG(2) == 18 &&
		(int)ARG(3) == 19 && (void *)ARG(4) == (void *)20 && ARG(5) == 21 &&
		(int)RET() == 111;
	return 0;
}
