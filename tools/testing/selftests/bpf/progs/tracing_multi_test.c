// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 ChinaTelecom */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

int pid = 0;
int test_cookie = 0;

__u64 fentry_test1_result = 0;
__u64 fentry_test2_result = 0;
__u64 fentry_test3_result = 0;
__u64 fentry_test4_result = 0;
__u64 fentry_test5_result = 0;
__u64 fentry_test6_result = 0;
__u64 fentry_test7_result = 0;
__u64 fentry_test8_result = 0;

extern const void bpf_fentry_test1 __ksym;
extern const void bpf_fentry_test2 __ksym;
extern const void bpf_fentry_test3 __ksym;
extern const void bpf_fentry_test4 __ksym;
extern const void bpf_fentry_test5 __ksym;
extern const void bpf_fentry_test6 __ksym;
extern const void bpf_fentry_test7 __ksym;
extern const void bpf_fentry_test8 __ksym;

static void tracing_multi_check_cookie(unsigned long long *ctx)
{
	if (bpf_get_current_pid_tgid() >> 32 != pid)
		return;

	__u64 cookie = test_cookie ? bpf_get_attach_cookie(ctx) : 0;
	__u64 addr = bpf_get_func_ip(ctx);

#define SET(__var, __addr, __cookie) ({			\
	if (((const void *) addr == __addr) &&		\
	     (!test_cookie || (cookie == __cookie)))	\
		__var = 1;				\
})
	SET(fentry_test1_result, &bpf_fentry_test1, 1);
	SET(fentry_test2_result, &bpf_fentry_test2, 7);
	SET(fentry_test3_result, &bpf_fentry_test3, 2);
	SET(fentry_test4_result, &bpf_fentry_test4, 3);
	SET(fentry_test5_result, &bpf_fentry_test5, 4);
	SET(fentry_test6_result, &bpf_fentry_test6, 5);
	SET(fentry_test7_result, &bpf_fentry_test7, 6);
	SET(fentry_test8_result, &bpf_fentry_test8, 8);
}

SEC("fentry.multi/bpf_fentry_test*")
int BPF_PROG(fentry_cookie_test1)
{
	tracing_multi_check_cookie(ctx);
	return 0;
}
