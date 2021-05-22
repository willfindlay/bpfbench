// SPDX-License-Identifier: MIT
//
// Benchmark eBPF programs.
// Copyright (c) 2021  William Findlay
//
// May 20, 2021  William Findlay  Created this.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use libbpf_rs::{Map, MapFlags};
use plain::from_bytes;

use crate::bpf::BpfbenchSkel;
use crate::bpf_types::{Overhead, SyscallKey};

fn get_raw_result(map: &Map, key: &[u8]) -> (SystemCall, Overhead) {
    let val = map.lookup(&key, MapFlags::ANY).unwrap().unwrap();
    let val: &Overhead = from_bytes(&val).unwrap();
    let key: &SyscallKey = from_bytes(&key).unwrap();

    (SystemCall(key.num), val.clone())
}

pub enum ResultsOrdering {
    CountDecreasing,
    AverageTimeDecreasing,
    TotalTimeDecreasing,
    CallNumberIncreasing,
}

impl ResultsOrdering {
    pub fn ordering(
        &'static self,
    ) -> impl FnMut(&(&SystemCall, &BenchResult), &(&SystemCall, &BenchResult)) -> Ordering {
        move |a, b| match self {
            Self::CountDecreasing => a.1.count.cmp(&b.1.count).reverse(),
            Self::AverageTimeDecreasing => a.1.average_ns().cmp(&b.1.average_ns()).reverse(),
            Self::TotalTimeDecreasing => a.1.total_ns.cmp(&b.1.total_ns).reverse(),
            Self::CallNumberIncreasing => a.0 .0.cmp(&b.0 .0),
        }
    }
}

//mod sort {
//    pub fn by_count_decreasing(
//        a: &(&SystemCall, &BenchResult),
//        b: &(&SystemCall, &BenchResult),
//    ) -> Ordering {
//        a.1.count.cmp(&b.1.count).reverse()
//    }
//
//    pub fn by_average_time_decreasing(
//        a: &(&SystemCall, &BenchResult),
//        b: &(&SystemCall, &BenchResult),
//    ) -> Ordering {
//        a.1.average_ns().cmp(&b.1.average_ns()).reverse()
//    }
//
//    pub fn by_total_time_decreasing(
//        a: &(&SystemCall, &BenchResult),
//        b: &(&SystemCall, &BenchResult),
//    ) -> Ordering {
//        a.1.total_ns.cmp(&b.1.total_ns).reverse()
//    }
//}

#[derive(Debug)]
pub struct Results {
    inner: BTreeMap<SystemCall, BenchResult>,
}

impl Results {
    pub fn new(skel: &BpfbenchSkel) -> Self {
        let mut hash = BTreeMap::new();

        let syscalls_map = skel.obj.map("syscall_overheads").unwrap();

        for key in syscalls_map.keys() {
            let (k, v) = get_raw_result(syscalls_map, &key);

            let entry = hash.entry(k).or_insert(BenchResult::default());
            entry.count += v.event_count;
            entry.total_ns += v.total_ns;
        }

        Self { inner: hash }
    }

    pub fn summarize(&self, ordering: &'static ResultsOrdering) {
        let mut data = self.inner.iter().collect::<Vec<_>>();
        data.sort_by(ordering.ordering());

        println!(
            "{:>12} {:>8} {:>20} {:>20}",
            "Syscall", "Count", "Total Time (ns)", "Avg. Time (ns)"
        );
        for (syscall, result) in data {
            println!(
                "{:>12} {:>8} {:>20} {:>20}",
                syscall.0,
                result.count,
                result.total_ns,
                result.average_ns()
            );
        }
        println!()
    }
}

#[derive(Debug, Default)]
pub struct BenchResult {
    pub count: u64,
    pub total_ns: u64,
}

impl BenchResult {
    fn average_ns(&self) -> u64 {
        self.total_ns / self.count
    }
}

#[derive(Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct SystemCall(pub i64);
