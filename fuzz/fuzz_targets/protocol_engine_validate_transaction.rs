#![no_main]
//! Plan completion harness (generated batch 2).

use blvm_protocol::serialization::transaction::deserialize_transaction;
use blvm_protocol::validation::ProtocolValidationContext;
use blvm_protocol::{BitcoinProtocolEngine, ProtocolVersion};
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let Ok(engine) = BitcoinProtocolEngine::new(ProtocolVersion::BitcoinV1) else { return; };
    let Ok(ctx) = ProtocolValidationContext::new(ProtocolVersion::BitcoinV1, 0) else { return; };
    if let Ok(tx) = deserialize_transaction(data) {
        let _ = engine.validate_transaction_with_protocol(&tx, &ctx);
    }
});
