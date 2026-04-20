#![no_main]
//! Plan completion harness (generated batch 2).

use blvm_protocol::varint::{write_varint, varint_size};
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let v = u64::from_le_bytes(data.get(0..8).unwrap_or(&[0u8;8]).try_into().unwrap_or([0u8;8]));
    let mut b = Vec::new();
    let _ = write_varint(&mut b, v);
    let _ = varint_size(v);
});
