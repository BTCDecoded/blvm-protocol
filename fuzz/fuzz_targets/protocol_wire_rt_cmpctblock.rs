#![no_main]
//! Plan harness (generated).

use blvm_protocol::wire::{deserialize_cmpctblock, serialize_cmpctblock};
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if let Ok(v) = deserialize_cmpctblock(data) {
        if let Ok(b) = serialize_cmpctblock(&v) { let _ = deserialize_cmpctblock(&b); }
    }
});
