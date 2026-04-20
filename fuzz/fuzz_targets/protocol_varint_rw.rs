#![no_main]
//! Bitcoin varint read/write (same encoding as transaction and many wire payloads).
use std::io::Cursor;

use blvm_protocol::varint::{read_varint, write_varint, varint_size};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut c = Cursor::new(data);
    if let Ok(v) = read_varint(&mut c) {
        let mut buf = Vec::new();
        let _ = write_varint(&mut buf, v);
        let _ = varint_size(v);
        let mut c2 = Cursor::new(&buf);
        let _ = read_varint(&mut c2);
    }

    for skip in [0usize, 1, data.len().saturating_sub(1)] {
        if skip < data.len() {
            let mut c3 = Cursor::new(&data[skip..]);
            let _ = read_varint(&mut c3);
        }
    }
});
