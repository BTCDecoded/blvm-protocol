#![no_main]
//! Plan completion harness (generated batch 2).

use std::io::Cursor;
use blvm_protocol::p2p_framing::BITCOIN_MAGIC_MAINNET;
use blvm_protocol::wire::{deserialize_message, MAX_MESSAGE_PAYLOAD};
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0xf9, 0xbe, 0xd4, 0xf9]);
    frame.extend_from_slice(b"tx\0\0\0\0\0\0\0\0\0\0");
    let bad = MAX_MESSAGE_PAYLOAD.saturating_add(1 + (data.first().copied().unwrap_or(0) as usize));
    frame.extend_from_slice(&(bad as u32).to_le_bytes());
    frame.extend_from_slice(&[0,0,0,0]);
    let _ = deserialize_message(&mut Cursor::new(&frame), BITCOIN_MAGIC_MAINNET);
});
