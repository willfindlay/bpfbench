// SPDX-License-Identifier: MIT
//
// Benchmark eBPF programs.
// Copyright (c) 2021  William Findlay
//
// May 20, 2021  William Findlay  Created this.

use plain::Plain;

use crate::bpf::bpfbench_bss_types::*;

pub type Overhead = overhead;
unsafe impl Plain for overhead {}

pub type SyscallKey = syscall_key;
unsafe impl Plain for syscall_key {}
