#![no_main]
//! Plan harness (generated).

use blvm_protocol::wire::{deserialize_version, serialize_version};
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if let Ok(v) = deserialize_version(data) {
        if let Ok(b) = serialize_version(&v) { let _ = deserialize_version(&b); }
    }
});
