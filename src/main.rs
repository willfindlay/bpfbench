// SPDX-License-Identifier: MIT
//
// Benchmark eBPF programs.
// Copyright (c) 2021  William Findlay
//
// May 20, 2021  William Findlay  Created this.

use anyhow::{Context as _, Result};
use clap::{App, AppSettings, Arg, ArgGroup};

fn main() -> Result<()> {
    let app = App::new("bpfbench")
        .version("1.0")
        .author("William Findlay <william@williamfindlay.com>")
        .about("Macro benchmarking in eBPF")
        .global_setting(AppSettings::ArgRequiredElseHelp)
        .global_setting(AppSettings::ColoredHelp)
        .arg(
            Arg::with_name("duration")
                .long("duration")
                .takes_value(true)
                .help("Duration to run tests (conflicts with --driver)"),
        )
        .arg(
            Arg::with_name("driver")
                .long("driver")
                .takes_value(true)
                .conflicts_with("duration")
                .help("Path to driver program to run during tests (conflicts with --duration)"),
        );

    let matches = app.get_matches();

    Ok(())
}
