// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Wenbo Zhang
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define TASK_RUNNING	0

const volatile bool filter_cg = false;
const volatile bool targ_per_process = false;
const volatile bool targ_per_thread = false;
const volatile bool targ_offcpu = false;
const volatile bool targ_ms = false;
const volatile pid_t targ_tgid = -1;

struct {
	__uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 1);
} cgroup_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u64);
} start SEC(".maps");

static struct hist initial_hist;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, struct hist);
} hists SEC(".maps");

static __always_inline void store_start(u32 tgid, u32 pid, u64 ts)
{
	if (targ_tgid != -1 && targ_tgid != tgid)
		return;
	bpf_map_update_elem(&start, &pid, &ts, 0);
}

static __always_inline void update_hist(struct task_struct *task,
					u32 tgid, u32 pid, u64 ts)
{
	u64 delta, *tsp, slot;
	struct hist *histp;
	u32 id;

	if (targ_tgid != -1 && targ_tgid != tgid)
		return;

	tsp = bpf_map_lookup_elem(&start, &pid);
	if (!tsp || ts < *tsp)
		return;

	if (targ_per_process)
		id = tgid;
	else if (targ_per_thread)
		id = pid;
	else
		id = -1;
	histp = bpf_map_lookup_elem(&hists, &id);
	if (!histp) {
		bpf_map_update_elem(&hists, &id, &initial_hist, 0);
		histp = bpf_map_lookup_elem(&hists, &id);
		if (!histp)
			return;
		BPF_CORE_READ_STR_INTO(&histp->comm, task, comm);
	}
	delta = ts - *tsp;
	if (targ_ms)
		delta /= 1000000;
	else
		delta /= 1000;
	slot = log2l(delta);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;
	__sync_fetch_and_add(&histp->slots[slot], 1);
}
SEC("kprobe/nfs_file_read")
int BPF_PROG(sched_switch_btf, bool preempt, struct task_struct *prev,
	     struct task_struct *next)
{
	return time(prev, next);
}

SEC("kprobe/nfs_file_write")
int BPF_PROG(sched_switch_tp, bool preempt, struct task_struct *prev,
	     struct task_struct *next)
{
	return time(prev, next);
}
SEC("kretprobe/nfs_file_read")
int BPF_PROG(sched_switch_btf, bool preempt, struct task_struct *prev,
	     struct task_struct *next)
{
	return time(prev, next);
}
SEC("kretprobe/nfs_file_write")
int BPF_PROG(sched_switch_tp, bool preempt, struct task_struct *prev,
	     struct task_struct *next)
{
	return time(prev, next);
}
char LICENSE[] SEC("license") = "GPL";