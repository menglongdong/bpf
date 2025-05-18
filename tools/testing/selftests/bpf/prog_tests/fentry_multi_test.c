// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2019 Facebook */
#include <test_progs.h>
#include "fentry_multi_test.skel.h"

static int fentry_multi_test_common(struct fentry_multi_test *fentry_skel)
{
	struct bpf_link *link;
	int err, prog_fd, i;
	__u64 *result;
	LIBBPF_OPTS(bpf_test_run_opts, topts);

	err = fentry_multi_test__attach(fentry_skel);
	if (!ASSERT_OK(err, "fentry_multi_attach"))
		return err;

	link = bpf_program__attach(fentry_skel->progs.test1);
	if (!ASSERT_ERR_PTR(link, "fentry_attach_link"))
		return -1;

	prog_fd = bpf_program__fd(fentry_skel->progs.test2);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_run");
	ASSERT_EQ(topts.retval, 0, "test_run");

	result = (__u64 *)fentry_skel->bss;
	for (i = 0; i < sizeof(*fentry_skel->bss) / sizeof(__u64); i++) {
		if (!ASSERT_EQ(result[i], 1, "fentry_multi_result"))
			return -1;
	}

	fentry_multi_test__detach(fentry_skel);

	/* zero results for re-attach test */
	memset(fentry_skel->bss, 0, sizeof(*fentry_skel->bss));
	return 0;
}

static void fentry_multi_test(void)
{
	struct fentry_multi_test *fentry_skel = NULL;
	int err;

	fentry_skel = fentry_multi_test__open_and_load();
	if (!ASSERT_OK_PTR(fentry_skel, "fentry_skel_load"))
		goto cleanup;

	err = fentry_multi_test_common(fentry_skel);
	if (!ASSERT_OK(err, "fentry_first_attach"))
		goto cleanup;

cleanup:
	fentry_multi_test__destroy(fentry_skel);
}

void test_fentry_multi_test(void)
{
	if (test__start_subtest("fentry"))
		fentry_multi_test();
}
