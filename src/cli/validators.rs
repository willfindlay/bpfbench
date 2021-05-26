// SPDX-License-Identifier: MIT
//
// Benchmark eBPF programs.
// Copyright (c) 2021  William Findlay
//
// May 20, 2021  William Findlay  Created this.

use std::path::Path;

/// Is the argument a positive integer?
pub fn is_positive_integer(s: String) -> Result<(), String> {
    if let Err(e) = s.parse::<u64>() {
        return Err(format!("Failed to parse integer: {}", e));
    }

    Ok(())
}

/// Is the argument a valid path?
pub fn is_valid_path(s: String) -> Result<(), String> {
    let path = Path::new(&s);

    if let Some(parent) = path.parent() {
        if !parent.exists() {
            return Err(format!("Parent directory does not exist"));
        }
    }

    Ok(())
}
