#![no_main]
//! Double-SHA256 payload checksum used in P2P headers.
use blvm_protocol::wire::calculate_checksum;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = calculate_checksum(data);
    if data.len() > 8 {
        let mid = data.len() / 2;
        let _ = calculate_checksum(&data[..mid]);
        let _ = calculate_checksum(&data[mid..]);
    }
});
