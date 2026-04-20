#![no_main]
//! Plan completion harness (generated batch 2).

use blvm_protocol::utxo_commitments::data_structures::UtxoCommitment;
use blvm_protocol::utxo_commitments::verification::verify_supply;
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let mut v = data.to_vec();
    while v.len() < 88 { v.push(0); }
    v.truncate(88);
    if let Ok(c) = UtxoCommitment::from_bytes(&v) {
        let _ = verify_supply(&c);
    }
});
