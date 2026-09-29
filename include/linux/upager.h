/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_UPAGER_H
#define _LINUX_UPAGER_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/gfp_types.h>

struct lruvec;

/*
 * BTF-visible to BPF struct_ops programs; read-only from their side.
 * mm/bpf_upager.c fills it in, mm/vmscan.c owns lruvec and list.
 */
struct upager_ctx {
	struct lruvec *lruvec;
	struct list_head *list;	/* hint list, owned by evict_folios */
	gfp_t gfp_mask;			/* copied from scan_control */
	u32 reclaim_idx;		/* copied from scan_control */
	u32 nr_to_scan;
	u32 nr_isolated;
};

struct upager_ops {
	void (*isolate)(struct upager_ctx *ctx);
	char name[16];
};

#endif /* _LINUX_UPAGER_H */
