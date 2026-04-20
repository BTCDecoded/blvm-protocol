#![no_main]
//! Plan completion harness (generated batch 2).

use blvm_protocol::v2_transport::V2Transport;
use libfuzzer_sys::fuzz_target;
fn k(d: &[u8]) -> [u8;32] { let mut x=[0u8;32]; for i in 0..32 { x[i]=d.get(i).copied().unwrap_or(0); } x }
fuzz_target!(|data: &[u8]| {
    if data.len() < 32 { return; }
    let mut t = V2Transport::new(k(data), k(data));
    let pkt = &data[32..];
    let _ = t.decrypt(pkt);
});
