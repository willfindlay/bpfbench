// SPDX-License-Identifier: MIT
//
// Benchmark eBPF programs.
// Copyright (c) 2021  William Findlay
//
// May 20, 2021  William Findlay  Created this.

use std::fs::{remove_file, File};
use std::io::{BufWriter, Write};
use std::os::unix::fs::symlink;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use glob::glob;
use libbpf_cargo::SkeletonBuilder;
use uname::uname;

pub fn main() {
    // Re-run build if src/bpf/*.[ch] has changed
    for path in glob("src/bpf/include/*.[ch]")
        .expect("Failed to glob")
        .filter_map(Result::ok)
    {
        println!("cargo:rerun-if-changed={}", path.display());
    }

    // Generate vmlinux.h
    generate_vmlinux();

    // Generate skeleton
    match SkeletonBuilder::new("src/bpf/bpfbench.bpf.c").generate("src/bpf/mod.rs") {
        Ok(_) => {}
        Err(e) => panic!("Failed to generate skeleton: {}", e),
    }
}

fn generate_vmlinux() {
    // Determine pathname for vmlinux header
    let kernel_release = uname().expect("Failed to fetch system information").release;
    let vmlinux_path = PathBuf::from(format!("src/bpf/vmlinux_{}.h", kernel_release));
    let vmlinux_link_path = PathBuf::from("src/bpf/vmlinux.h");

    // Populate vmlinux_{kernel_release}.h with BTF info
    if !vmlinux_path.exists() {
        let mut vmlinux_writer = BufWriter::new(
            File::create(vmlinux_path.clone())
                .expect("Failed to open vmlinux destination for writing"),
        );

        let output = Command::new("bpftool")
            .arg("btf")
            .arg("dump")
            .arg("file")
            .arg("/sys/kernel/btf/vmlinux")
            .arg("format")
            .arg("c")
            .stdout(Stdio::piped())
            .output()
            .expect("Failed to run bpftool. You can install bpftool from linux/tools/bpf/bpftool");

        assert!(output.status.success());

        vmlinux_writer
            .write_all(&output.stdout)
            .expect("Failed to write to vmlinux.h");
    }

    // Remove existing link if it exists
    if vmlinux_link_path.exists() {
        remove_file(vmlinux_link_path.clone()).expect("Failed to unlink vmlinux.h");
    }

    // Create a new symlink
    symlink(vmlinux_path.file_name().unwrap(), vmlinux_link_path)
        .expect("Failed to symlink vmlinux.h");
}
