// SPDX-License-Identifier: GPL-2.0
/*
 * BPF struct_ops backend for MGLRU eviction: owns the struct_ops
 * registration and the RCU-protected pointer to the attached program.
 * The isolation logic is in mm/vmscan.c:lru_gen_isolate_hint(); struct
 * upager_ctx (include/linux/upager.h) is the whole kernel/BPF contract.
 */
#include <linux/upager.h>

#include "internal.h"

#ifdef CONFIG_BPF_SYSCALL

#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/capability.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>

static struct upager_ops __rcu *bpf_upager;
static DEFINE_MUTEX(bpf_upager_lock);

static struct bpf_struct_ops bpf_upager_ops;

static void bpf_upager_isolate_stub(struct upager_ctx *ctx)
{
}

static struct upager_ops __bpf_upager_ops = {
	.isolate = bpf_upager_isolate_stub,
};

static int bpf_upager_init(struct btf *btf)
{
	return 0;
}

static int bpf_upager_init_member(const struct btf_type *t,
				   const struct btf_member *member,
				   void *kdata, const void *udata)
{
	const struct upager_ops *uops = udata;
	struct upager_ops *ops = kdata;
	u32 moff = __btf_member_bit_offset(t, member) / 8;

	switch (moff) {
	case offsetof(struct upager_ops, flags):
		if (uops->flags & ~UPAGER_F_ALL)
			return -EINVAL;
		ops->flags = uops->flags;
		return 1;
	case offsetof(struct upager_ops, name):
		if (bpf_obj_name_cpy(ops->name, uops->name, sizeof(ops->name)) <= 0)
			return -EINVAL;
		return 1;
	}
	return 0;
}

static int bpf_upager_reg(void *kdata, struct bpf_link *link)
{
	int err = 0;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	mutex_lock(&bpf_upager_lock);
	if (rcu_dereference_protected(bpf_upager, lockdep_is_held(&bpf_upager_lock)))
		err = -EEXIST;
	else
		rcu_assign_pointer(bpf_upager, kdata);
	mutex_unlock(&bpf_upager_lock);

	return err;
}

static void bpf_upager_unreg(void *kdata, struct bpf_link *link)
{
	mutex_lock(&bpf_upager_lock);
	RCU_INIT_POINTER(bpf_upager, NULL);
	mutex_unlock(&bpf_upager_lock);

	synchronize_rcu(); /* let in-flight upager_isolate() callers finish */
}

static bool bpf_upager_is_valid_access(int off, int size,
				       enum bpf_access_type type,
				       const struct bpf_prog *prog,
				       struct bpf_insn_access_aux *info)
{
	return bpf_tracing_btf_ctx_access(off, size, type, prog, info);
}

static const struct bpf_verifier_ops bpf_upager_verifier_ops = {
	.get_func_proto = bpf_base_func_proto,
	.is_valid_access = bpf_upager_is_valid_access,
};

static struct bpf_struct_ops bpf_upager_ops = {
	.verifier_ops = &bpf_upager_verifier_ops,
	.init = bpf_upager_init,
	.init_member = bpf_upager_init_member,
	.reg = bpf_upager_reg,
	.unreg = bpf_upager_unreg,
	.cfi_stubs = &__bpf_upager_ops,
	.owner = THIS_MODULE,
	.name = "upager_ops",
};

void upager_isolate(struct upager_ctx *ctx)
{
	struct upager_ops *ops;

	rcu_read_lock();
	ops = rcu_dereference(bpf_upager);
	if (ops) {
		ctx->flags = ops->flags;
		ops->isolate(ctx);
	}
	rcu_read_unlock();
}

__bpf_kfunc_start_defs();

__bpf_kfunc int bpf_upager_isolate_pfn(struct upager_ctx *ctx, u64 pfn)
{
	return lru_gen_isolate_hint(ctx, pfn);
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(bpf_upager_kfunc_ids)
BTF_ID_FLAGS(func, bpf_upager_isolate_pfn)
BTF_KFUNCS_END(bpf_upager_kfunc_ids)

/* Shared per struct_ops kfunc call; do_check_main() re-runs this once
 * prog->aux->st_ops is known, so anything outside our set stays a no-op.
 */
static int bpf_upager_kfunc_filter(const struct bpf_prog *prog, u32 kfunc_id)
{
	if (!btf_id_set8_contains(&bpf_upager_kfunc_ids, kfunc_id))
		return 0;
	if (!prog->aux->st_ops)
		return 0;
	if (prog->aux->st_ops != &bpf_upager_ops)
		return -EACCES;
	return 0;
}

static const struct btf_kfunc_id_set bpf_upager_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &bpf_upager_kfunc_ids,
	.filter = bpf_upager_kfunc_filter,
};

static int __init bpf_upager_init_late(void)
{
	int err;

	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS, &bpf_upager_kfunc_set);
	if (err)
		return err;

	return register_bpf_struct_ops(&bpf_upager_ops, upager_ops);
}
late_initcall(bpf_upager_init_late);

#else /* !CONFIG_BPF_SYSCALL */

void upager_isolate(struct upager_ctx *ctx)
{
}

#endif /* CONFIG_BPF_SYSCALL */
