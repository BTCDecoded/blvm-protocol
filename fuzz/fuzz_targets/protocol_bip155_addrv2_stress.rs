#![no_main]
//! Plan completion harness (generated batch 2).

use blvm_protocol::wire::deserialize_addrv2;
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| { let _ = deserialize_addrv2(data); });
