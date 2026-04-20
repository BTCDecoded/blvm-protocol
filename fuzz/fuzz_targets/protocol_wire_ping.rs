#![no_main]
//! Plan harness (generated).

use blvm_protocol::wire::deserialize_ping;
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| { let _ = deserialize_ping(data); });
