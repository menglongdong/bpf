/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_KFUNC_MD_H
#define _LINUX_KFUNC_MD_H

#include <linux/kernel.h>
#include <linux/bpf.h>
#include <linux/rhashtable.h>

struct kfunc_md_tramp_prog {
	struct hlist_node list;
	struct bpf_prog *prog;
	u64 cookie;
	struct rcu_head rcu;
};

struct kfunc_md {
	struct rhash_head hlist;
	struct rcu_head rcu;
	unsigned long func;
	struct hlist_head __rcu bpf_progs[BPF_TRAMP_MAX];
	struct percpu_ref pcref;
	u16 users;
	bool bpf_origin_call;
	u8 bpf_prog_cnt;
	u8 nr_args;
};

extern struct rhashtable kfunc_md_rht;

struct kfunc_md *kfunc_md_create(unsigned long ip, int nr_args);
void kfunc_md_put(struct kfunc_md *meta);

int kfunc_md_bpf_ips(void ***ips);
int kfunc_md_bpf_unlink(struct kfunc_md *md, struct bpf_prog *prog, int type);
int kfunc_md_bpf_link(struct kfunc_md *md, struct bpf_prog *prog, int type,
		      u64 cookie);

static inline u32 kfunc_md_hashfn(const void *data, u32 len, u32 seed)
{
	return hash_ptr(*(unsigned long **)data, 32);
}

static inline int kfunc_md_cmp(struct rhashtable_compare_arg *arg,
			       const void *ptr)
{
	unsigned long key = *(unsigned long *)arg->key;
	const struct kfunc_md *n = ptr;

	return n->func != key;
}

static inline u32 kfunc_md_obj_hashfn(const void *data, u32 len, u32 seed)
{
	const struct kfunc_md *n = data;

	return hash_ptr((void *)n->func, 32);
}

static const struct rhashtable_params kfunc_md_rht_params = {
	.head_offset		= offsetof(struct kfunc_md, hlist),
	.key_offset		= offsetof(struct kfunc_md, func),
	.key_len		= sizeof_field(struct kfunc_md, func),
	.hashfn			= kfunc_md_hashfn,
	.obj_hashfn		= kfunc_md_obj_hashfn,
	.obj_cmpfn		= kfunc_md_cmp,
	.automatic_shrinking	= true,
};

static __always_inline notrace struct kfunc_md *
__kfunc_md_get(unsigned long ip)
{
	return rhashtable_lookup(&kfunc_md_rht, &ip, kfunc_md_rht_params);
}

static inline struct kfunc_md *kfunc_md_get(unsigned long ip)
{
	struct kfunc_md *md;

	rcu_read_lock();
	md = __kfunc_md_get(ip);
	rcu_read_unlock();

	return md;
}

#endif
