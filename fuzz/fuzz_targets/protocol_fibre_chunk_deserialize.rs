#![no_main]
//! Plan completion harness (generated batch 2).

use blvm_protocol::fibre::FecChunk;
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| { let _ = FecChunk::deserialize(data); });
