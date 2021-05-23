// SPDX-License-Identifier: MIT
//
// Benchmark eBPF programs.
// Copyright (c) 2021  William Findlay
//
// May 20, 2021  William Findlay  Created this.

use std::env;
use std::ffi::CString;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::sleep;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result};
use clap::{App, AppSettings, Arg, ArgMatches, Values};
use nix::sys::signal::{kill, SIGPOLL, SIGUSR1};
use nix::unistd::{execvp, fork, setgid, setuid, ForkResult, Gid, Pid, Uid};
use scopeguard::defer;
use signal_hook::iterator::Signals;

use bpfbench::BpfBenchContext;
use bpfbench::Config;

fn main() -> Result<()> {
    let app = App::new("bpfbench")
        .version("1.0")
        .author("William Findlay <william@williamfindlay.com>")
        .about("Macro benchmarking in eBPF")
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
            Arg::with_name("debug")
                .long("debug")
                .hidden(true),
        )
        .arg(
            Arg::with_name("driver")
                .multiple(true)
                .last(true)
                .conflicts_with("duration")
                .conflicts_with("tid")
                .conflicts_with("pid")
                .help("Driver program to test and corresponding args. Not compatible with duration, tid, or pid"),
        );

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

    // Spawn driver program if one is supplied
    let mut child_pid: Option<Pid> = None;
    if let Some(mut driver) = matches.values_of("driver") {
        child_pid = spawn_driver(&mut driver);
        config.trace_pid = Some(child_pid.expect("No child pid").as_raw() as u32);
    }

    // Get start time and initial interval_time
    let start_time = Instant::now();
    let mut interval_time = Instant::now();
    let ctx = BpfBenchContext::new(&config).expect("Failed to create BpfBenchContext");

    // Wake the child
    if let Some(child_pid) = child_pid {
        kill(child_pid, SIGUSR1).unwrap();
    }

    defer! {
        ctx.dump_results();
    }

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

        if let Some(child_pid) = child_pid {
            if kill(child_pid, SIGPOLL).is_err() {
                break;
            }
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

/// Spawn driver program, waiting for SIGUSR1 before the execvp
fn spawn_driver(driver: &mut Values) -> Option<Pid> {
    let mut signals = Signals::new(&[libc::SIGUSR1]).unwrap();

    match unsafe { fork() } {
        Ok(ForkResult::Parent { child, .. }) => {
            return Some(child);
        }
        Ok(ForkResult::Child) => {
            for _ in signals.forever() {
                break;
            }

            setgid(Gid::from_raw(
                env::var("SUDO_GID")
                    .expect("No value for SUDO_GID")
                    .parse::<u32>()
                    .expect("Failed to parse SUDO_GID"),
            ))
            .expect("Failed to call setgid");

            setuid(Uid::from_raw(
                env::var("SUDO_UID")
                    .expect("No value for SUDO_UID")
                    .parse::<u32>()
                    .expect("Failed to parse SUDO_UID"),
            ))
            .expect("Failed to call setuid");

            let cmd = CString::new(driver.clone().nth(0).expect("No driver command provided"))
                .expect("Failed to create CString");
            let args = driver
                .map(|s| CString::new(s).expect("Failed to create CString"))
                .collect::<Vec<_>>();

            assert!(args.len() >= 1);

            execvp(&cmd, &args).expect("Failed to execute driver");
        }
        Err(e) => {
            panic!("Failed to fork with: {}", e)
        }
    };

    None
}
