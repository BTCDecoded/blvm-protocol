#![no_main]
//! Plan completion harness (generated batch 2).

use blvm_protocol::utxo_commitments::merkle_tree::UtxoMerkleTree;
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let _ = UtxoMerkleTree::deserialize_proof_from_wire(data);
});
