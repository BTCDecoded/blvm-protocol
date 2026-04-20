#![no_main]
//! Plan completion harness (generated batch 2).

use std::io::Cursor;
use blvm_protocol::varint::read_varint;
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| { let _ = read_varint(&mut Cursor::new(data)); });
