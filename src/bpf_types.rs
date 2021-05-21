// SPDX-License-Identifier: MIT
//
// Benchmark eBPF programs.
// Copyright (c) 2021  William Findlay
//
// May 20, 2021  William Findlay  Created this.

use plain::Plain;

pub use crate::bpf::bpfbench_bss_types::*;

unsafe impl Plain for event_key {}
unsafe impl Plain for overhead {}
