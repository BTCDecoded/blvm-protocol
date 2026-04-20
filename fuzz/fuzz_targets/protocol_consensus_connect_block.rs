#![no_main]
//! Deserialize a block via protocol serialization, then run consensus `connect_block` (empty UTXO).
use blvm_consensus::block::connect_block;
use blvm_consensus::block::BlockValidationContext;
use blvm_consensus::serialization::block::deserialize_block_with_witnesses;
use blvm_consensus::types::Network;
use blvm_consensus::UtxoSet;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok((block, witnesses)) = deserialize_block_with_witnesses(data) else {
        return;
    };
    let ctx = BlockValidationContext::for_network(Network::Mainnet);
    let _ = connect_block(&block, &witnesses, UtxoSet::default(), 0, &ctx);
});
