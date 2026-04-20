#![no_main]
//! Plan completion harness (generated batch 2).

use blvm_protocol::utxo_commitments::data_structures::UtxoCommitment;
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let mut v = data.to_vec();
    while v.len() < 84 { v.push(0); }
    v.truncate(84);
    if let Ok(c) = UtxoCommitment::from_bytes(&v) {
        let b = c.to_bytes();
        let _ = UtxoCommitment::from_bytes(&b);
    }
});
