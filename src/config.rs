// SPDX-License-Identifier: MIT
//
// Benchmark eBPF programs.
// Copyright (c) 2021  William Findlay
//
// May 20, 2021  William Findlay  Created this.

#[derive(Default)]
pub struct Config {
    pub trace_pid: Option<u32>,
    pub trace_tgid: Option<u32>,
    pub coarse_ns: bool,
    pub debug: bool,
}
