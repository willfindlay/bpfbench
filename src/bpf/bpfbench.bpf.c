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

// Dummy instances to generate BTF info
struct overhead __overhead = {};
struct event_key __event_key = {};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct event_key);
    __type(value, u64);
} start_times SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct event_key);
    __type(value, struct overhead);
} overheads SEC(".maps");

SEC("tp_btf/sys_enter")
int BPF_PROG(do_sys_enter, struct pt_regs *regs, long id)
{
    u32 pid = bpf_get_current_pid_tgid();
    u32 tgid = bpf_get_current_pid_tgid() >> 32;

    if (!bpfbench__should_trace(pid, tgid))
        return 0;

    struct event_key key = {};
    key.type_ = ET_SYSCALL;
    key.pid = pid;
    key.event_number = id;

    u64 start_time = bpfbench__get_time_ns();

    bpf_map_update_elem(&start_times, &key, &start_time, 0);

    return 0;
}

SEC("tp_btf/sys_exit")
int BPF_PROG(do_sys_exit, struct pt_regs *regs, long ret)
{
    long id = regs->r8;
    u32 pid = bpf_get_current_pid_tgid();
    u32 tgid = bpf_get_current_pid_tgid() >> 32;

    if (!bpfbench__should_trace(pid, tgid))
        return 0;

    // Ignore restart_syscall
    if (id == bpfbench__restart_syscall_nr())
        return 0;

    struct event_key key = {};
    key.type_ = ET_SYSCALL;
    key.pid = pid;
    key.event_number = id;

    u64 *start_time_p = bpf_map_lookup_elem(&start_times, &key);
    if (!start_time_p)
        return 0;

    u64 end_time = bpfbench__get_time_ns();
    if (end_time < *start_time_p)
        return 0;

    u64 delta_us = (end_time - *start_time_p);

    struct overhead *overhead =
        bpf_map_lookup_or_try_init(&overheads, &key, &__overhead);
    if (!overhead)
        return 0;

    __sync_fetch_and_add(&overhead->event_count, 1);
    __sync_fetch_and_add(&overhead->total_ns, delta_us);

    return 0;
}
