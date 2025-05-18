// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2019 Facebook */
#include <test_progs.h>
#include "fexit_multi_test.skel.h"

static int fexit_test_common(struct fexit_multi_test *fexit_skel)
{
	struct bpf_link *link;
	int err, prog_fd, i;
	__u64 *result;
	LIBBPF_OPTS(bpf_test_run_opts, topts);

	err = fexit_multi_test__attach(fexit_skel);
	if (!ASSERT_OK(err, "fexit_attach"))
		return err;

	/* Check that already linked program can't be attached again. */
	link = bpf_program__attach(fexit_skel->progs.test1);
	if (!ASSERT_ERR_PTR(link, "fexit_attach_link"))
		return -1;

	prog_fd = bpf_program__fd(fexit_skel->progs.test1);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_run");
	ASSERT_EQ(topts.retval, 0, "test_run");

	result = (__u64 *)fexit_skel->bss;
	for (i = 0; i < sizeof(*fexit_skel->bss) / sizeof(__u64); i++) {
		if (!ASSERT_EQ(result[i], 1, "fexit_result"))
			return -1;
	}

	fexit_multi_test__detach(fexit_skel);

	/* zero results for re-attach test */
	memset(fexit_skel->bss, 0, sizeof(*fexit_skel->bss));
	return 0;
}

static void fexit_multi_test(void)
{
	struct fexit_multi_test *fexit_skel = NULL;
	int err;

	fexit_skel = fexit_multi_test__open_and_load();
	if (!ASSERT_OK_PTR(fexit_skel, "fexit_skel_load"))
		goto cleanup;

	err = fexit_test_common(fexit_skel);
	if (!ASSERT_OK(err, "fexit_first_attach"))
		goto cleanup;

	err = fexit_test_common(fexit_skel);
	ASSERT_OK(err, "fexit_second_attach");

cleanup:
	fexit_multi_test__destroy(fexit_skel);
}

void test_fexit_multi_test(void)
{
	if (test__start_subtest("fexit"))
		fexit_multi_test();
}
