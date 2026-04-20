#![no_main]
//! Deserialize a block from raw bytes, then run consensus `check_transaction` on each tx (cross-layer).
use blvm_protocol::serialization::block::deserialize_block_with_witnesses;
use blvm_protocol::transaction::check_transaction;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok((block, _witnesses)) = deserialize_block_with_witnesses(data) else {
        return;
    };
    for tx in block.transactions.iter() {
        let _ = check_transaction(tx);
    }
});
