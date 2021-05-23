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
use std::thread;
use std::thread::sleep;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result};
use clap::{App, AppSettings, Arg, ArgMatches, Values};
use nix::errno::Errno;
use nix::sys::signal::{kill, SIGUSR1};
use nix::sys::wait::{waitpid, WaitPidFlag};
use nix::unistd::{execvp, fork, setgid, setuid, ForkResult, Gid, Pid, Uid};
use nix::Error;
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
                .help("Duration to run (in seconds). If this is not specified, tracing runs infinitely"),
        )
        .arg(
            Arg::with_name("interval")
                .long("interval")
                .short("i")
                .takes_value(true)
                .help("How often should resulted be printed (in seconds)"),
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
            Arg::with_name("trace children")
                .long("children")
                .short("c")
                .help("Trace children of tracees. Only makes sense when combined with --driver, --pid, or --tid"),
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
    let mut child: Option<Pid> = None;
    if let Some(mut driver) = matches.values_of("driver") {
        child = spawn_driver(&mut driver);
        config.trace_tgid = Some(child.expect("No child pid").as_raw() as u32);
    }

    // Get start time and initial interval_time
    let start_time = Instant::now();
    let mut interval_time = Instant::now();
    let ctx = BpfBenchContext::new(&config).expect("Failed to create BpfBenchContext");

    // Wake the child
    if let Some(child) = child {
        kill(child, SIGUSR1).unwrap();
    }

    defer! {
        ctx.dump_results();
    }

    print_initial_info(&config);

    loop {
        sleep(Duration::from_secs(1));

        // Exit when we have reached the target duration
        if let Some(duration) = config.duration {
            if start_time.elapsed() >= duration {
                break;
            }
        }

        // Dump results and reset interval on every interval
        if config.interval.is_some() && interval_time.elapsed() >= config.interval.unwrap() {
            ctx.dump_results();
            interval_time = Instant::now();
        }

        // Poll and reap child process
        if let Some(child) = child {
            match waitpid(Some(child), Some(WaitPidFlag::WNOHANG)) {
                Err(Error::Sys(errno)) if errno == Errno::ECHILD => {
                    break;
                }
                _ => {}
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

    if matches.is_present("debug") {
        config.debug = true;
    }

    Ok(())
}

fn print_initial_info(config: &Config) {
    let pid_str = if let Some(pid) = config.trace_tgid {
        format!(" pid {}", pid)
    } else {
        "".into()
    };

    let tid_str = if let Some(tid) = config.trace_pid {
        format!(" tid {}", tid)
    } else {
        "".into()
    };

    let dur_str = if let Some(duration) = config.duration {
        format!(" for {:?}", duration)
    } else {
        " until exit".into()
    };

    eprintln!(
        "Tracing{}{}{}. Press Ctrl-C to exit.",
        pid_str, tid_str, dur_str
    );
}

/// Spawn driver program, waiting for SIGUSR1 before the execvp
fn spawn_driver(driver: &mut Values) -> Option<Pid> {
    let mut signals = Signals::new(&[libc::SIGUSR1]).unwrap();

    match unsafe { fork() } {
        Ok(ForkResult::Parent { child, .. }) => {
            thread::spawn(move || {
                waitpid(Some(child), None).expect("Failed to call waitpid");
            });
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
