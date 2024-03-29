// SPDX-License-Identifier: MIT
//
// Benchmark eBPF programs.
// Copyright (c) 2021  William Findlay
//
// May 20, 2021  William Findlay  Created this.

use std::path::Path;

use anyhow::{Context as _, Result};

use crate::bpf::{BpfbenchSkel, BpfbenchSkelBuilder, OpenBpfbenchSkel};
use crate::config::Config;
use crate::results::{Results, ResultsOrder};
use crate::util::bump_memlock_rlimit;

pub struct BpfBenchContext<'a> {
    skel: BpfbenchSkel<'a>,
}

impl<'a> BpfBenchContext<'a> {
    pub fn new(config: &Config) -> Result<Self> {
        let skel = load_bpf(config)?;

        Ok(Self { skel })
    }

    pub fn dump_results<P: AsRef<Path>>(&self, output: Option<P>) -> Result<()> {
        Results::new(&self.skel).summarize(&ResultsOrder::AverageTimeDecreasing, output)?;
        Ok(())
    }
}

fn load_bpf<'a>(config: &Config) -> Result<BpfbenchSkel<'a>> {
    let mut builder = BpfbenchSkelBuilder::default();
    builder.obj_builder.debug(config.debug);
    bump_memlock_rlimit().context("Failed to bump memlock rlimit")?;

    let mut open_skel = builder.open().context("Failed to open BPF objects")?;
    set_globals(&mut open_skel, config);

    let mut skel = open_skel.load().context("Failed to load BPF objects")?;
    skel.attach().context("Failed to attach BPF programs")?;

    Ok(skel)
}

fn set_globals(open_skel: &mut OpenBpfbenchSkel, config: &Config) {
    open_skel.bss().trace_pid = config.trace_pid.unwrap_or(0);
    open_skel.bss().trace_tgid = config.trace_tgid.unwrap_or(0);
    open_skel.bss().trace_children = config.trace_children as u8;
    open_skel.bss().filter_errors = config.filter_errors as u8;

    // Set own pid
    open_skel.bss().bpfbench_pid = std::process::id();
}
