#![no_main]
//! Plan completion harness (generated batch 2).

use blvm_protocol::v2_transport::V2Handshake;
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if data.len() < 64 { return; }
    let mut r = V2Handshake::new_responder();
    let _ = r.process_initiator_message(&data[..64]);
});
