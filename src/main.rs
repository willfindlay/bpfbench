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

use anyhow::Result;
use clap::{App, AppSettings, Arg, Values};
use nix::errno::Errno;
use nix::sys::signal::{kill, SIGUSR1};
use nix::sys::wait::{waitpid, WaitPidFlag};
use nix::unistd::{execvp, fork, setgid, setuid, ForkResult, Gid, Pid, Uid};
use nix::Error;
use scopeguard::defer;
use signal_hook::iterator::Signals;

use bpfbench::validators::{is_positive_integer, is_valid_path};
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
                .validator(is_positive_integer)
                .help("Duration to run (in seconds). If this is not specified, tracing runs infinitely"),
        )
        .arg(
            Arg::with_name("interval")
                .long("interval")
                .short("i")
                .takes_value(true)
                .validator(is_positive_integer)
                .help("How often should resulted be printed (in seconds)"),
        )
        .arg(
            Arg::with_name("pid")
                .long("pid")
                .short("p")
                .takes_value(true)
                .validator(is_positive_integer)
                .conflicts_with("tid")
                .help("Only trace process with this pid"),
        )
        .arg(
            Arg::with_name("tid")
                .long("tid")
                .short("t")
                .takes_value(true)
                .validator(is_positive_integer)
                .conflicts_with("pid")
                .help("Only trace thread with this tid"),
        )
        .arg(
            Arg::with_name("driver")
                .multiple(true)
                .last(true)
                .conflicts_with("duration")
                .conflicts_with("tid")
                .conflicts_with("pid")
                .help("Driver program to test and corresponding args. Not compatible with duration, tid, or pid"),
        )
        .arg(
            Arg::with_name("trace children")
                .long("children")
                .short("c")
                .help("Trace children of tracees. Only makes sense when combined with --driver, --pid, or --tid"),
        )
        .arg(
            Arg::with_name("filter errors")
                .long("filter-errors")
                .short("e")
                .help("Filter out system calls with error results"),
        )
        .arg(
            Arg::with_name("output")
                .long("output")
                .short("o")
                .takes_value(true)
                .validator(is_valid_path)
                .help("Output to a file instead of stdout")
        )
        .arg(
            Arg::with_name("debug")
                .long("debug")
                .hidden(true),
        );

    let matches = app.get_matches();

    // Create and set configuration
    let mut config = Config::from_arg_matches(&matches)?;

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
        ctx.dump_results(config.output_path.as_ref()).expect("Failed to dump results");
    }

    print_initial_info(&config);

    loop {
        sleep(Duration::from_millis(100));

        // Exit when we have reached the target duration
        if let Some(duration) = config.duration {
            if start_time.elapsed() >= duration {
                break;
            }
        }

        // Dump results and reset interval on every interval
        if config.interval.is_some() && interval_time.elapsed() >= config.interval.unwrap() {
            ctx.dump_results(config.output_path.as_ref())
                .expect("Failed to dump results");
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

/// Print initial information to the user when starting a trace.
fn print_initial_info(config: &Config) {
    // What PID are we tracing?
    let pid_str = if let Some(pid) = config.trace_tgid {
        format!(" PID {}", pid)
    } else {
        "".into()
    };

    // What TID are we tracing?
    let tid_str = if let Some(tid) = config.trace_pid {
        format!(" TID {}", tid)
    } else {
        "".into()
    };

    // How long are we tracing for?
    let dur_str = if let Some(duration) = config.duration {
        format!(" for {:?}", duration)
    } else {
        " until exit".into()
    };

    // Where are we printing results?
    let out_str = if let Some(output) = config.output_path.clone() {
        format!(" to {}", output.display())
    } else {
        " to stdout".into()
    };

    // How often are we printing results
    let int_str = if let Some(interval) = config.interval {
        format!(" every {:?}", interval)
    } else {
        " when finished".into()
    };

    eprintln!(
        "Tracing{}{}{} and outputting results{}{}... Press Ctrl-C to exit.",
        pid_str, tid_str, dur_str, out_str, int_str
    );
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
