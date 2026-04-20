#![no_main]
//! Plan harness (generated).

use blvm_protocol::wire::{deserialize_inv, serialize_inv};
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if let Ok(v) = deserialize_inv(data) {
        if let Ok(b) = serialize_inv(&v) { let _ = deserialize_inv(&b); }
    }
});
