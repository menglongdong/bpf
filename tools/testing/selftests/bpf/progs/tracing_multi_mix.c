// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 ChinaTelecom */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

__u64 test_result;

#define ARG(n) ({				\
	__u64 __val = 0;			\
	bpf_get_func_arg(ctx, n, &__val);	\
	__val;					\
})

SEC("?fentry.multi/bpf_fentry_test1")
int BPF_PROG(fentry_multi_mix_test1)
{
	test_result = ARG(0) == 1;
	return 0;
}

SEC("?fentry/bpf_fentry_test1")
int BPF_PROG(fentry_mix_test1)
{
	test_result = ARG(0) == 1;
	return 0;
}
