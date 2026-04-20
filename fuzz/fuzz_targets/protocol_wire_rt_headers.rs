#![no_main]
//! Plan harness (generated).

use blvm_protocol::wire::{deserialize_headers, serialize_headers};
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if let Ok(v) = deserialize_headers(data) {
        if let Ok(b) = serialize_headers(&v) { let _ = deserialize_headers(&b); }
    }
});
