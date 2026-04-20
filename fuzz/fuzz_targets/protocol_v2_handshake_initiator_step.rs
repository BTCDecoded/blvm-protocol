#![no_main]
//! Plan completion harness (generated batch 2).

use blvm_protocol::v2_transport::V2Handshake;
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if data.len() < 64 { return; }
    let (_o, i) = V2Handshake::new_initiator();
    let _ = i.complete_handshake(&data[..64]);
});
