// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 ChinaTelecom */

#include <linux/slab.h>
#include <linux/memory.h>
#include <linux/rcupdate.h>
#include <linux/ftrace.h>
#include <linux/rhashtable.h>
#include <linux/kfunc_md.h>

#include <uapi/linux/bpf.h>

static DEFINE_MUTEX(kfunc_md_mutex);
struct rhashtable kfunc_md_rht;

static void kfunc_md_release_pcref(struct percpu_ref *pcref)
{
	struct kfunc_md *md;

	md = container_of(pcref, struct kfunc_md, pcref);
	percpu_ref_exit(&md->pcref);
	kfree(md);
}

static struct kfunc_md *__kfunc_md_create(unsigned long ip, int nr_args)
{
	struct kfunc_md *md = kfunc_md_get(ip);
	int err;

	if (md) {
		md->users++;
		return md;
	}

	md = kzalloc(sizeof(*md), GFP_KERNEL);
	if (!md)
		return NULL;

	md->users = 1;
	md->func = ip;
	md->nr_args = nr_args;
	err = percpu_ref_init(&md->pcref, kfunc_md_release_pcref, 0, GFP_KERNEL);
	if (err)
		goto free_out;

	err = rhashtable_insert_fast(&kfunc_md_rht, &md->hlist,
				     kfunc_md_rht_params);
	if (err) {
		percpu_ref_exit(&md->pcref);
		goto free_out;
	}

	return md;
free_out:
	kfree(md);
	return NULL;
}

struct kfunc_md *kfunc_md_create(unsigned long ip, int nr_args)
{
	struct kfunc_md *md = NULL;

	mutex_lock(&kfunc_md_mutex);
	md = __kfunc_md_create(ip, nr_args);
	mutex_unlock(&kfunc_md_mutex);

	return md;
}
EXPORT_SYMBOL_GPL(kfunc_md_create);

static void kfunc_md_release_rcu(struct rcu_head *rcu)
{
	struct kfunc_md *md;

	md = container_of(rcu, struct kfunc_md, rcu);
	/* kfunc_md_release_pcref() will be called. */
	percpu_ref_kill(&md->pcref);
}

void kfunc_md_put(struct kfunc_md *md)
{
	if (!md || WARN_ON_ONCE(md->users <= 0))
		return;

	mutex_lock(&kfunc_md_mutex);
	md->users--;
	if (md->users > 0)
		goto out_unlock;

	rhashtable_remove_fast(&kfunc_md_rht, &md->hlist, kfunc_md_rht_params);

	/* For no origin call case, we can free the md with kfree_rcu()
	 * directly. For the origin call case, we need to make sure the
	 * per-cpu ref is held with the rcu, and free the md with
	 * percpu_ref_kill(). To make thing simpler, make the two case
	 * together.
	 */
	call_rcu(&md->rcu, kfunc_md_release_rcu);
out_unlock:
	mutex_unlock(&kfunc_md_mutex);
}
EXPORT_SYMBOL_GPL(kfunc_md_put);

static bool kfunc_md_bpf_check(struct kfunc_md *md)
{
	return md->bpf_prog_cnt;
}

int kfunc_md_bpf_ips(void ***ips_ptr)
{
	struct rhashtable_iter iter;
	struct kfunc_md *md;
	int count, res = 0;
	void **ips;

	mutex_lock(&kfunc_md_mutex);
	count = atomic_read(&kfunc_md_rht.nelems);
	if (count <= 0)
		goto out_unlock;

	ips = kmalloc_array(count, sizeof(*ips), GFP_KERNEL);
	if (!ips) {
		res = -ENOMEM;
		goto out_unlock;
	}

	rhashtable_walk_enter(&kfunc_md_rht, &iter);
	do {
		rhashtable_walk_start(&iter);
		while ((md = rhashtable_walk_next(&iter)) && !IS_ERR(md)) {
			if (kfunc_md_bpf_check(md))
				ips[res++] = (void *)md->func;
		}
		rhashtable_walk_stop(&iter);
	} while (md == ERR_PTR(-EAGAIN));
	rhashtable_walk_exit(&iter);

	*ips_ptr = ips;
out_unlock:
	mutex_unlock(&kfunc_md_mutex);

	return res;
}

int kfunc_md_bpf_link(struct kfunc_md *md, struct bpf_prog *prog, int type,
		      u64 cookie)
{
	struct kfunc_md_tramp_prog *tramp;
	struct hlist_head *head;
	int err = 0;

	mutex_lock(&kfunc_md_mutex);
	head = &md->bpf_progs[type];
	/* check if the prog is already linked */
	hlist_for_each_entry_rcu(tramp, head, list) {
		if (tramp->prog == prog) {
			err = -EEXIST;
			goto out_unlock;
		}
	}

	tramp = kmalloc(sizeof(*tramp), GFP_KERNEL);
	if (!tramp) {
		err = -ENOMEM;
		goto out_unlock;
	}

	WRITE_ONCE(tramp->prog, prog);
	WRITE_ONCE(tramp->cookie, cookie);

	/* add the new prog to the list tail */
	hlist_add_tail_rcu(&tramp->list, head);

	md->bpf_prog_cnt++;
	if (type == BPF_TRAMP_FEXIT || type == BPF_TRAMP_MODIFY_RETURN)
		md->bpf_origin_call = true;

out_unlock:
	mutex_unlock(&kfunc_md_mutex);
	return err;
}

int kfunc_md_bpf_unlink(struct kfunc_md *md, struct bpf_prog *prog, int type)
{
	struct kfunc_md_tramp_prog *tramp;
	bool origin_call;

	mutex_lock(&kfunc_md_mutex);
	hlist_for_each_entry_rcu(tramp, &md->bpf_progs[type], list) {
		if (tramp->prog == prog)
			goto found;
	}
	mutex_unlock(&kfunc_md_mutex);

	return -EINVAL;
found:
	hlist_del_rcu(&tramp->list);
	origin_call = !hlist_empty(&md->bpf_progs[BPF_TRAMP_FEXIT]) ||
		!hlist_empty(&md->bpf_progs[BPF_TRAMP_MODIFY_RETURN]);
	WRITE_ONCE(md->bpf_origin_call, origin_call);

	md->bpf_prog_cnt--;

	kfree_rcu(tramp, rcu);
	mutex_unlock(&kfunc_md_mutex);

	return 0;
}

static int __init init_kfunc_md(void)
{
	return rhashtable_init(&kfunc_md_rht, &kfunc_md_rht_params);
}
late_initcall(init_kfunc_md);
