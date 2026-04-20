#![no_main]
//! BIP324 `V2Handshake` responder and initiator completion (`bip324` feature).
//! Cross-party messages are taken from the fuzz input; local keys use the library RNG.
use blvm_protocol::v2_transport::V2Handshake;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() >= 64 {
        let mut responder = V2Handshake::new_responder();
        let _ = responder.process_initiator_message(&data[..64]);
    }
    if data.len() >= 128 {
        let (_initiator_out, initiator) = V2Handshake::new_initiator();
        let _ = initiator.complete_handshake(&data[64..128]);
    }
});
