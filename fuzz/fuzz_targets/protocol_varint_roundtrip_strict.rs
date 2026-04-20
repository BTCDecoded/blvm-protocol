#![no_main]
//! Plan completion harness (generated batch 2).

use std::io::Cursor;
use blvm_protocol::varint::{read_varint, write_varint};
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let mut c = Cursor::new(data);
    if let Ok(v) = read_varint(&mut c) {
        let mut out = Vec::new();
        let _ = write_varint(&mut out, v);
        let _ = read_varint(&mut Cursor::new(&out));
    }
});
