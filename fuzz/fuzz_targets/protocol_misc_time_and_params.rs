#![no_main]
//! Plan completion harness (generated batch 2).

use blvm_protocol::genesis::{mainnet_genesis, regtest_genesis, testnet_genesis};
use blvm_protocol::time;
use blvm_protocol::features::FeatureRegistry;
use blvm_protocol::{NetworkParameters, ProtocolVersion};
use blvm_protocol::variants::ProtocolVariant;
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let _ = time::current_timestamp();
    let _ = NetworkParameters::for_version(ProtocolVersion::BitcoinV1);
    let _ = mainnet_genesis();
    let _ = testnet_genesis();
    let _ = regtest_genesis();
    let _ = FeatureRegistry::for_protocol(ProtocolVersion::BitcoinV1);
    let _ = ProtocolVariant::for_version(ProtocolVersion::BitcoinV1);
    let _ = data.first();
});
