#![no_main]
//! Plan completion harness (generated batch 2).

use blvm_protocol::utxo_commitments::data_structures::UtxoCommitment;
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if data.len() >= 88 {
        let _ = UtxoCommitment::from_bytes(&data[..88]);
    }
    let mut v = data.to_vec();
    while v.len() < 88 { v.push(0); }
    v.truncate(88);
    if let Ok(c) = UtxoCommitment::from_bytes(&v) {
        let _ = c.to_bytes();
    }
});
