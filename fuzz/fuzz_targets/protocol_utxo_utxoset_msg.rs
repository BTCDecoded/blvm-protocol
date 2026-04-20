#![no_main]
//! Plan completion harness (generated batch 2).

use std::io::Cursor;
use blvm_protocol::p2p_framing::BITCOIN_MAGIC_MAINNET;
use blvm_protocol::wire::deserialize_message;
use blvm_protocol_fuzz::build_mainnet_frame;
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let frame = build_mainnet_frame("utxoset", data);
    let _ = deserialize_message(&mut Cursor::new(&frame), BITCOIN_MAGIC_MAINNET);
});
