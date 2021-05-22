// SPDX-License-Identifier: MIT
//
// Benchmark eBPF programs.
// Copyright (c) 2021  William Findlay
//
// May 20, 2021  William Findlay  Created this.

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
                .takes_value(true)
                .help("Duration to run tests (in seconds)"),
        )
        .arg(
            Arg::with_name("checkpoint")
                .long("checkpoint")
                .short("c")
                .default_value("300")
                .takes_value(true)
                .help("How often should resulted be checkpointed (in seconds)"),
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

    let duration = matches
        .value_of("duration")
        .map(|duration| {
            duration
                .parse::<u64>()
                .expect("Failed to parse duration time")
        })
        .map(|duration| Duration::from_secs(duration));

    let checkpoint = matches
        .value_of("checkpoint")
        .map(|checkpoint| {
            checkpoint
                .parse::<u64>()
                .expect("Failed to parse checkpoint time")
        })
        .map(|checkpoint| Duration::from_secs(checkpoint))
        .unwrap();

    let mut config = Config::default();

    update_config(&matches, &mut config)?;

    let start_time = Instant::now();
    let mut cp_time = Instant::now();
    let ctx = BpfBenchContext::new(&config).context("Failed to create BpfBenchContext")?;

    defer! {
        ctx.dump_results();
    }

    loop {
        sleep(Duration::from_secs(1));

        if let Some(duration) = duration {
            if start_time.elapsed() >= duration {
                break;
            }
        }

        if cp_time.elapsed() >= checkpoint {
            ctx.dump_results();
            cp_time = Instant::now();
        }
    }

    Ok(())
}

fn update_config(matches: &ArgMatches, config: &mut Config) -> Result<()> {
    if let Some(pid) = matches.value_of("pid") {
        config.trace_tgid = Some(pid.parse().context("Failed to parse PID")?);
    }

    if let Some(tid) = matches.value_of("tid") {
        config.trace_pid = Some(tid.parse().context("Failed to parse TID")?);
    }

    if matches.is_present("coarse") {
        config.coarse_ns = Some(true);
    }

    Ok(())
}
