// SPDX-License-Identifier: MIT
//
// Benchmark eBPF programs.
// Copyright (c) 2021  William Findlay
//
// May 20, 2021  William Findlay  Created this.

use crate::syscall_names::SYSTEM_CALL_NAMES_X86_64;
use conv::ValueFrom;

#[derive(Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct SystemCall(pub i64);

impl SystemCall {
    pub fn name(&self) -> &str {
        let number = usize::value_from(self.0).ok();
        if number.is_none() {
            return "[UNKNOWN]";
        }
        let number = number.unwrap();

        // @TODO: Handle other archs
        *SYSTEM_CALL_NAMES_X86_64.get(number).unwrap_or(&"[UNKNOWN]")
    }
}
