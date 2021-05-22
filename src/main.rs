// SPDX-License-Identifier: MIT
//
// Benchmark eBPF programs.
// Copyright (c) 2021  William Findlay
//
// May 20, 2021  William Findlay  Created this.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::sleep;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result};
use clap::{App, AppSettings, Arg, ArgMatches};
use scopeguard::defer;

use bpfbench::BpfBenchContext;
use bpfbench::Config;

fn main() -> Result<()> {
    let app = App::new("bpfbench")
        .version("1.0")
        .author("William Findlay <william@williamfindlay.com>")
        .about("Macro benchmarking in eBPF")
        //.global_setting(AppSettings::ArgRequiredElseHelp)
        .global_setting(AppSettings::ColoredHelp)
        .arg(
            Arg::with_name("duration")
                .long("duration")
                .short("d")
                .takes_value(true)
                .help("Duration to run (in seconds). Defaults to infinite."),
        )
        .arg(
            Arg::with_name("interval")
                .long("interval")
                .short("i")
                .default_value("300")
                .takes_value(true)
                .help("How often should resulted be printed (in seconds). Defaults to 300."),
        )
        .arg(
            Arg::with_name("pid")
                .long("pid")
                .short("p")
                .takes_value(true)
                .conflicts_with("tid")
                .help("Only trace process with this pid"),
        )
        .arg(
            Arg::with_name("tid")
                .long("tid")
                .short("t")
                .takes_value(true)
                .conflicts_with("pid")
                .help("Only trace thread with this tid"),
        )
        .arg(
            Arg::with_name("coarse")
                .long("coarse")
                .help("Use coarse-grained time measurements. This is more performant but may impact result accuracy. Requires Linux >=5.11"),
        )
        .arg(
            Arg::with_name("debug")
                .long("debug")
                .hidden(true),
        );
    //.arg(
    //    Arg::with_name("driver")
    //        .long("driver")
    //        .takes_value(true)
    //        .conflicts_with("duration")
    //        .conflicts_with("tid")
    //        .conflicts_with("pid")
    //        .help("Path to driver program to run during tests"),
    //);

    let matches = app.get_matches();

    // Set the run duration
    let duration = matches
        .value_of("duration")
        .map(|duration| {
            duration
                .parse::<u64>()
                .expect("Failed to parse duration time")
        })
        .map(|duration| Duration::from_secs(duration));

    // Set the print interval
    let interval = matches
        .value_of("interval")
        .map(|interval| {
            interval
                .parse::<u64>()
                .expect("Failed to parse interval time")
        })
        .map(|interval| Duration::from_secs(interval))
        .unwrap();

    // Create and set configuration
    let mut config = Config::default();
    update_config(&matches, &mut config)?;

    // Flag to determine whether the process should exit
    let should_exit = Arc::new(AtomicBool::new(false));
    let should_exit_clone = should_exit.clone();

    // Register a signal handler on SIGINT, SIGTERM, and SA_SIGINFO to set should_exit to
    // true
    ctrlc::set_handler(move || should_exit_clone.store(true, Ordering::SeqCst))
        .expect("Failed to register signal handler");

    // Get start time and initial interval_time
    let start_time = Instant::now();
    let mut interval_time = Instant::now();
    let ctx = BpfBenchContext::new(&config).context("Failed to create BpfBenchContext")?;

    defer! {
        ctx.dump_results();
    }

    // @TODO spawn driver program here when we support this

    loop {
        sleep(Duration::from_secs(1));

        // Exit when we have reached the target duration
        if let Some(duration) = duration {
            if start_time.elapsed() >= duration {
                break;
            }
        }

        // Dump results and reset interval on every interval
        if interval_time.elapsed() >= interval {
            ctx.dump_results();
            interval_time = Instant::now();
        }

        // Exit when should_exit has been set to true
        if should_exit.load(Ordering::SeqCst) {
            break;
        }
    }

    Ok(())
}

/// Update configuration struct according to parsed arguments
fn update_config(matches: &ArgMatches, config: &mut Config) -> Result<()> {
    if let Some(pid) = matches.value_of("pid") {
        config.trace_tgid = Some(pid.parse().context("Failed to parse PID")?);
    }

    if let Some(tid) = matches.value_of("tid") {
        config.trace_pid = Some(tid.parse().context("Failed to parse TID")?);
    }

    if matches.is_present("coarse") {
        config.coarse_ns = true;
    }

    if matches.is_present("debug") {
        config.debug = true;
    }

    Ok(())
}
