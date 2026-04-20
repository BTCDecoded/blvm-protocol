#![no_main]
//! Plan completion harness (generated batch 2).

use std::io::Cursor;
use blvm_protocol::p2p_framing::BITCOIN_MAGIC_MAINNET;
use blvm_protocol::wire::{calculate_checksum, deserialize_message, MAX_MESSAGE_PAYLOAD};
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let p = if data.len() > MAX_MESSAGE_PAYLOAD { &data[..MAX_MESSAGE_PAYLOAD] } else { data };
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0xf9, 0xbe, 0xd4, 0xf9]);
    frame.extend_from_slice(b"inv\0\0\0\0\0\0\0\0\0\0");
    frame.extend_from_slice(&(p.len() as u32).to_le_bytes());
    let mut c = calculate_checksum(p);
    c[1] ^= 0x55;
    frame.extend_from_slice(&c);
    frame.extend_from_slice(p);
    let _ = deserialize_message(&mut Cursor::new(&frame), BITCOIN_MAGIC_MAINNET);
});
