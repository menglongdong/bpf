// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

#define RET() ({ __u64 __ret = 0; bpf_get_func_ret(ctx, &__ret); __ret; })

static int sequence;
__s32 input_retval = 0;

__u64 fentry_result = 0;
SEC("fentry.multi/bpf_modify_return_test")
int BPF_PROG(fentry_test)
{
	sequence++;
	fentry_result = (sequence == 1);
	return 0;
}

__u64 fmod_ret_result = 0;
SEC("fmod_ret.multi/bpf_modify_return_test")
int BPF_PROG(fmod_ret_test)
{
	sequence++;
	/* This is the first fmod_ret program, the ret passed should be 0 */
	fmod_ret_result = (sequence == 2 && (int)RET() == 0);
	return input_retval;
}

__u64 fexit_result = 0;
SEC("fexit.multi/bpf_modify_return_test")
int BPF_PROG(fexit_test)
{
	sequence++;
	/* If the input_reval is non-zero a successful modification should have
	 * occurred.
	 */
	if (input_retval)
		fexit_result = (sequence == 3 && (int)RET() == input_retval);
	else
		fexit_result = (sequence == 3 && (int)RET() == 4);

	return 0;
}
