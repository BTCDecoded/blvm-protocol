#![no_main]
//! Plan harness (generated).

use blvm_protocol::wire::{deserialize_addrv2, serialize_addrv2};
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if let Ok(v) = deserialize_addrv2(data) {
        if let Ok(b) = serialize_addrv2(&v) { let _ = deserialize_addrv2(&b); }
    }
});
