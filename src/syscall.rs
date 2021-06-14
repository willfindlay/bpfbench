// SPDX-License-Identifier: MIT
//
// Benchmark eBPF programs.
// Copyright (c) 2021  William Findlay
//
// May 20, 2021  William Findlay  Created this.

use anyhow::Result;
use conv::ValueFrom;
use sysnames::Syscalls;

#[derive(Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct SystemCall(pub i64);

impl SystemCall {
    /// Get the name of this system call
    pub fn name(&self) -> Result<String> {
        let number = u64::value_from(self.0)?;
        Ok(Syscalls::name(number)
            .and_then(|name| Some(name.to_string()))
            .unwrap_or(format!("[UNKNOWN {}]", number)))
    }
}
