// SPDX-License-Identifier: MIT
//
// Benchmark eBPF programs.
// Copyright (c) 2021  William Findlay
//
// May 20, 2021  William Findlay  Created this.

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "bpfbench.h"

volatile bool trace_children = false;

// Dummy instances to generate BTF info
struct overhead __overhead = {};
struct syscall_key __syscall_key = {};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, bool);
} children SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, u64);
} syscall_start_times SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct syscall_key);
    __type(value, struct overhead);
} syscall_overheads SEC(".maps");

SEC("tp_btf/sys_enter")
int BPF_PROG(do_sys_enter, struct pt_regs *regs, long id)
{
    u32 pid = bpf_get_current_pid_tgid();
    u32 tgid = bpf_get_current_pid_tgid() >> 32;

    if (!bpfbench__should_trace(&children, pid, tgid))
        return 0;

    u64 start_time = bpf_ktime_get_ns();

    bpf_map_update_elem(&syscall_start_times, &pid, &start_time, BPF_ANY);

    return 0;
}

SEC("tp_btf/sys_exit")
int BPF_PROG(do_sys_exit, struct pt_regs *regs, long ret)
{
    u64 end_time = bpf_ktime_get_ns();
    // @FIXME: This is x86-only for now
    long id = regs->orig_ax;
    u32 pid = bpf_get_current_pid_tgid();
    u32 tgid = bpf_get_current_pid_tgid() >> 32;

    if (!bpfbench__should_trace(&children, pid, tgid))
        return 0;

    // Ignore restart_syscall
    if (id == bpfbench__restart_syscall_nr()) {
        bpf_map_delete_elem(&syscall_start_times, &pid);
        return 0;
    }

    // Ignore errors
    if (id < 0)
        return 0;

    struct syscall_key key = {};
    key.pid = pid;
    key.num = id;

    u64 *start_time_p = bpf_map_lookup_elem(&syscall_start_times, &pid);
    if (!start_time_p || end_time < *start_time_p)
        return 0;

    u64 delta_us = (end_time - *start_time_p);

    struct overhead *overhead =
        bpf_map_lookup_or_try_init(&syscall_overheads, &key, &__overhead);
    if (!overhead)
        return 0;

    __sync_fetch_and_add(&overhead->event_count, 1);
    __sync_fetch_and_add(&overhead->total_ns, delta_us);

    return 0;
}

/* Trace children */
SEC("tp_btf/sched_process_fork")
int sched_process_fork(struct bpf_raw_tracepoint_args *args)
{
    if (!trace_children)
        return 0;
    if (!trace_pid && !trace_tgid)
        return 0;

    struct task_struct *parent = (struct task_struct *)args->args[0];
    struct task_struct *child = (struct task_struct *)args->args[1];

    u32 ppid = parent->pid;
    u32 ptgid = parent->tgid;

    if (!bpfbench__should_trace(&children, ppid, ptgid)) {
        return 0;
    }

    bool t = true;
    u32 cpid = parent->pid;

    bpf_map_update_elem(&children, &cpid, &t, BPF_ANY);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
