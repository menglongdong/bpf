// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 ChinaTelecom */

#include <bpf/btf.h>
#include <test_progs.h>

#include "tracing_multi_test.skel.h"
#include "tracing_multi_mix.skel.h"
#include "fentry_multi_empty.skel.h"

static void test_run(struct tracing_multi_test *skel)
{
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	int err, prog_fd;

	skel->bss->pid = getpid();
	prog_fd = bpf_program__fd(skel->progs.fentry_cookie_test1);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_run");
	ASSERT_EQ(topts.retval, 0, "test_run");

	ASSERT_EQ(skel->bss->fentry_test1_result, 1, "fentry_test1_result");
	ASSERT_EQ(skel->bss->fentry_test2_result, 1, "fentry_test2_result");
	ASSERT_EQ(skel->bss->fentry_test3_result, 1, "fentry_test3_result");
	ASSERT_EQ(skel->bss->fentry_test4_result, 1, "fentry_test4_result");
	ASSERT_EQ(skel->bss->fentry_test5_result, 1, "fentry_test5_result");
	ASSERT_EQ(skel->bss->fentry_test6_result, 1, "fentry_test6_result");
	ASSERT_EQ(skel->bss->fentry_test7_result, 1, "fentry_test7_result");
	ASSERT_EQ(skel->bss->fentry_test8_result, 1, "fentry_test8_result");
}

static void test_skel_auto_api(void)
{
	struct tracing_multi_test *skel;
	int err;

	skel = tracing_multi_test__open_and_load();
	if (!ASSERT_OK_PTR(skel, "tracing_multi_test__open_and_load"))
		return;

	err = tracing_multi_test__attach(skel);
	if (!ASSERT_OK(err, "tracing_multi_test__attach"))
		goto cleanup;

	test_run(skel);

cleanup:
	tracing_multi_test__destroy(skel);
}

static int attach_bpf(struct bpf_program *prog, struct bpf_link **link_ptr,
		      bool success)
{
	struct bpf_link *link;
	int err;

	link = bpf_program__attach(prog);
	err = libbpf_get_error(link);
	if (!ASSERT_OK(success ? err : !err, "attach_bpf"))
		return err;
	*link_ptr = link;

	return 0;
}

#define ATTACH(skel, name, success)	\
	attach_bpf(skel->progs.name, &skel->links.name, success)

static void test_skel_manual_api(void)
{
	struct tracing_multi_test *skel;

	skel = tracing_multi_test__open_and_load();
	if (!ASSERT_OK_PTR(skel, "tracing_multi_test__open_and_load"))
		return;

	ATTACH(skel, fentry_cookie_test1, true);

	test_run(skel);
	tracing_multi_test__destroy(skel);
}

static void test_attach_api(void)
{
	LIBBPF_OPTS(bpf_trace_multi_opts, opts);
	struct tracing_multi_test *skel;
	struct bpf_link *link;
	const char *syms[8] = {
		"bpf_fentry_test1",
		"bpf_fentry_test2",
		"bpf_fentry_test3",
		"bpf_fentry_test4",
		"bpf_fentry_test5",
		"bpf_fentry_test6",
		"bpf_fentry_test7",
		"bpf_fentry_test8",
	};
	__u64 cookies[] = {1, 7, 2, 3, 4, 5, 6, 8};

	skel = tracing_multi_test__open_and_load();
	if (!ASSERT_OK_PTR(skel, "tracing_multi_test__open_and_load"))
		return;

	opts.syms = syms;
	opts.cookies = cookies;
	opts.cnt = ARRAY_SIZE(syms);
	link = bpf_program__attach_trace_multi_opts(skel->progs.fentry_cookie_test1,
						    NULL, &opts);
	if (!ASSERT_OK_PTR(link, "bpf_program__attach_trace_multi_opts"))
		goto cleanup;
	skel->links.fentry_cookie_test1 = link;

	skel->bss->test_cookie = true;
	test_run(skel);
cleanup:
	tracing_multi_test__destroy(skel);
}

static void test_attach_mix(bool fentry_over_multi)
{
	struct tracing_multi_mix *skel = NULL, *skel_multi;
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	int err, prog_fd;

	skel_multi = tracing_multi_mix__open();
	if (!ASSERT_OK_PTR(skel_multi, "tracing_multi_mix__open"))
		goto cleanup;
	skel = tracing_multi_mix__open();
	if (!ASSERT_OK_PTR(skel, "tracing_multi_mix__open"))
		goto cleanup;

	bpf_program__set_autoload(skel_multi->progs.fentry_multi_mix_test1, true);
	bpf_program__set_autoload(skel->progs.fentry_mix_test1, true);

	if (fentry_over_multi) {
		/* attach fentry-multi first, then fentry */
		ASSERT_OK(tracing_multi_mix__load(skel_multi), "load");
		ASSERT_OK(tracing_multi_mix__attach(skel_multi), "attach");
		ASSERT_OK(tracing_multi_mix__load(skel), "load");
		ASSERT_OK(tracing_multi_mix__attach(skel), "attach");
	} else {
		/* attach fentry first, then fentry-multi */
		ASSERT_OK(tracing_multi_mix__load(skel), "load");
		ASSERT_OK(tracing_multi_mix__attach(skel), "attach");
		ASSERT_OK(tracing_multi_mix__load(skel_multi), "load");
		ASSERT_OK(tracing_multi_mix__attach(skel_multi), "attach");
	}

	prog_fd = bpf_program__fd(skel->progs.fentry_mix_test1);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_run");
	ASSERT_EQ(topts.retval, 0, "test_run");

	ASSERT_EQ(skel_multi->bss->test_result, 1, "test_result");
	ASSERT_EQ(skel->bss->test_result, 1, "test_result");
cleanup:
	tracing_multi_mix__destroy(skel_multi);
	tracing_multi_mix__destroy(skel);
}

static void test_attach_bench(void)
{
	LIBBPF_OPTS(bpf_trace_multi_opts, opts);
	struct fentry_multi_empty *skel;
	long attach_start_ns, attach_end_ns;
	long detach_start_ns, detach_end_ns;
	double attach_delta, detach_delta;
	struct bpf_link *link = NULL;
	__u32 *btf_ids = NULL;
	struct btf *btf;
	size_t cnt = 0;

	skel = fentry_multi_empty__open_and_load();
	if (!ASSERT_OK_PTR(skel, "fentry_multi_empty__open_and_load"))
		goto cleanup;

	btf = btf__load_vmlinux_btf();
	if (!ASSERT_OK_PTR(btf, "load_vmlinux_btf"))
		goto cleanup;

	if (!ASSERT_OK(bpf_get_btf_type_ids(btf, &btf_ids, &cnt), "get_syms"))
		goto cleanup;

	opts.btf_type_ids = btf_ids;
	opts.cnt = cnt;
	attach_start_ns = get_time_ns();
	link = bpf_program__attach_trace_multi_opts(skel->progs.fentry_multi_empty,
						    NULL, &opts);
	attach_end_ns = get_time_ns();

	if (!ASSERT_OK_PTR(link, "bpf_program__attach_trace_multi_opts"))
		goto cleanup;

	detach_start_ns = get_time_ns();
	bpf_link__destroy(link);
	detach_end_ns = get_time_ns();

	attach_delta = (attach_end_ns - attach_start_ns) / 1000000000.0;
	detach_delta = (detach_end_ns - detach_start_ns) / 1000000000.0;

	printf("%s: found %lu functions\n", __func__, opts.cnt);
	printf("%s: attached in %7.3lfs\n", __func__, attach_delta);
	printf("%s: detached in %7.3lfs\n", __func__, detach_delta);

cleanup:
	fentry_multi_empty__destroy(skel);
	free(btf_ids);
}

void serial_test_tracing_multi_attach_bench(void)
{
	test_attach_bench();
}

void test_tracing_multi_test(void)
{
	if (test__start_subtest("skel_auto_api"))
		test_skel_auto_api();
	if (test__start_subtest("skel_manual_api"))
		test_skel_manual_api();
	if (test__start_subtest("attach_api"))
		test_attach_api();
	if (test__start_subtest("attach_over_multi"))
		test_attach_mix(true);
	if (test__start_subtest("attach_over_fentry"))
		test_attach_mix(false);
}
