#![no_main]
//! Sequential framed P2P messages in one byte buffer (`deserialize_message` until EOF or error).
use std::io::Cursor;

use blvm_protocol::p2p_framing::BITCOIN_MAGIC_MAINNET;
use blvm_protocol::wire::deserialize_message;
use libfuzzer_sys::fuzz_target;

const MAX_MSGS: usize = 64;

fuzz_target!(|data: &[u8]| {
    let mut cur = Cursor::new(data);
    for _ in 0..MAX_MSGS {
        let pos = cur.position() as usize;
        if pos >= data.len() {
            break;
        }
        match deserialize_message(&mut cur, BITCOIN_MAGIC_MAINNET) {
            Ok(_) => {}
            Err(_) => break,
        }
        if cur.position() as usize == pos {
            break;
        }
    }
});
