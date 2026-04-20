#![no_main]
//! Plan completion harness (generated batch 2).

use blvm_protocol::utxo_commitments::data_structures::UtxoCommitment;
use blvm_protocol::utxo_commitments::verification::verify_forward_consistency;
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if data.len() < 168 { return; }
    let mut a = data[..84].to_vec();
    let mut b = data[84..168].to_vec();
    while a.len() < 84 { a.push(0); }
    while b.len() < 84 { b.push(0); }
    a.truncate(84); b.truncate(84);
    let Ok(x) = UtxoCommitment::from_bytes(&a) else { return; };
    let Ok(y) = UtxoCommitment::from_bytes(&b) else { return; };
    let _ = verify_forward_consistency(&x, &y, y.block_height.saturating_sub(x.block_height));
});
