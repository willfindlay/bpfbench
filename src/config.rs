// SPDX-License-Identifier: MIT
//
// Benchmark eBPF programs.
// Copyright (c) 2021  William Findlay
//
// May 20, 2021  William Findlay  Created this.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, Result};
use clap::ArgMatches;

#[derive(Default)]
pub struct Config {
    pub trace_pid: Option<u32>,
    pub trace_tgid: Option<u32>,
    pub debug: bool,
    pub trace_children: bool,
    pub filter_errors: bool,
    pub duration: Option<Duration>,
    pub interval: Option<Duration>,
    pub output_path: Option<PathBuf>,
    pub driver_path: Option<PathBuf>,
}

impl Config {
    pub fn from_arg_matches(matches: &ArgMatches) -> Result<Self> {
        let mut config = Self::default();

        config.duration = matches
            .value_of("duration")
            .map(|duration| {
                duration
                    .parse::<u64>()
                    .expect("Failed to parse duration time")
            })
            .map(|duration| Duration::from_secs(duration));

        config.interval = matches
            .value_of("interval")
            .map(|interval| {
                interval
                    .parse::<u64>()
                    .expect("Failed to parse interval time")
            })
            .map(|interval| Duration::from_secs(interval));

        if let Some(pid) = matches.value_of("pid") {
            config.trace_tgid = Some(pid.parse().context("Failed to parse PID")?);
        }

        if let Some(tid) = matches.value_of("tid") {
            config.trace_pid = Some(tid.parse().context("Failed to parse TID")?);
        }

        if matches.is_present("trace children") {
            config.trace_children = true;
        }

        if matches.is_present("filter errors") {
            config.trace_children = true;
        }

        if matches.is_present("debug") {
            config.debug = true;
        }

        if let Some(driver_path) = matches.value_of("driver") {
            config.driver_path = Some(Path::new(driver_path).to_path_buf());
        }

        if let Some(output_path) = matches.value_of("output") {
            config.output_path = Some(Path::new(output_path).to_path_buf());
        }

        Ok(config)
    }
}
