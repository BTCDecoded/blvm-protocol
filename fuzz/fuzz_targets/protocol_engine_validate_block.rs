#![no_main]
//! Plan completion harness (generated batch 2).

use blvm_protocol::serialization::block::deserialize_block_with_witnesses;
use blvm_protocol::validation::ProtocolValidationContext;
use blvm_protocol::{BitcoinProtocolEngine, ProtocolVersion};
use blvm_consensus::types::UtxoSet;
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let Ok(engine) = BitcoinProtocolEngine::new(ProtocolVersion::BitcoinV1) else { return; };
    let Ok(ctx) = ProtocolValidationContext::new(ProtocolVersion::BitcoinV1, 0) else { return; };
    if let Ok((block, _w)) = deserialize_block_with_witnesses(data) {
        let _ = engine.validate_block_with_protocol(&block, &UtxoSet::default(), 0, &ctx);
    }
});
