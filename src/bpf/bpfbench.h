// SPDX-License-Identifier: MIT
//
// Benchmark eBPF programs.
// Copyright (c) 2021  William Findlay
//
// May 20, 2021  William Findlay  Created this.

#ifndef BPFBENCH_H
#define BPFBENCH_H

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

volatile u32 trace_pid = 0;
volatile u32 trace_tgid = 0;
volatile u32 bpfbench_pid = 0;

extern bool CONFIG_X86_64 __kconfig;
extern bool CONFIG_X86 __kconfig;
extern bool CONFIG_PPC __kconfig;

struct syscall_key {
    u32 pid;
    long num;
};

struct overhead {
    u64 event_count;
    u64 total_ns;
};

static __always_inline bool bpfbench__should_trace(void *children_map, u32 pid,
                                                   u32 tgid)
{
    if (!pid || !tgid)
        return false;
    if (bpfbench_pid == pid)
        return false;
    if (bpf_map_lookup_elem(children_map, &pid))
        return true;
    if (trace_pid && trace_pid != pid)
        return false;
    if (trace_tgid && trace_tgid != tgid)
        return false;
    return true;
}

static __always_inline void *
bpf_map_lookup_or_try_init(void *map, const void *key, const void *val)
{
    void *res = bpf_map_lookup_elem(map, key);
    if (!res) {
        bpf_map_update_elem(map, key, val, BPF_NOEXIST);
    }
    return bpf_map_lookup_elem(map, key);
}

static __always_inline long bpfbench__restart_syscall_nr()
{
    if (CONFIG_X86_64)
        return 219;
    return 0;
}

#endif /* ifndef BPFBENCH_H */
