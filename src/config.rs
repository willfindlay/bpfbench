// SPDX-License-Identifier: MIT
//
// Benchmark eBPF programs.
// Copyright (c) 2021  William Findlay
//
// May 20, 2021  William Findlay  Created this.

use std::time::Duration;

#[derive(Default)]
pub struct Config {
    pub trace_pid: Option<u32>,
    pub trace_tgid: Option<u32>,
    pub debug: bool,
    pub trace_children: bool,
    pub duration: Option<Duration>,
    pub interval: Option<Duration>,
}
