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
    pub fn name(&self) -> String {
        let number = usize::value_from(self.0).ok();
        if number.is_none() {
            return format!("[unknown {}]", self.0);
        }

        let mut number = number.unwrap();
        // There is a gap in x86_64 syscall numbers
        if number > 334 {
            number -= 89;
        }

        // @TODO: Handle other archs
        SYSTEM_CALL_NAMES_X86_64
            .get(number)
            .map(|s| s.to_string())
            .unwrap_or(format!("[unknown {}]", self.0))
            .to_string()
    }
}
