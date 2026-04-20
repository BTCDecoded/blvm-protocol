#![no_main]
//! BIP324 `V2Transport` encrypt/decrypt (`bip324` feature). Keys derived from fuzz bytes.
use blvm_protocol::v2_transport::V2Transport;
use libfuzzer_sys::fuzz_target;

fn key32(data: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 32];
    for i in 0..32 {
        k[i] = data.get(i).copied().unwrap_or(0);
    }
    k
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }
    let k = key32(data);
    let mut t = V2Transport::new(k, k);
    let plaintext = &data[32..];
    if plaintext.len() > 1_000_000 {
        return;
    }
    if let Ok(packet) = t.encrypt(plaintext) {
        let _ = t.decrypt(&packet);
    }
});
