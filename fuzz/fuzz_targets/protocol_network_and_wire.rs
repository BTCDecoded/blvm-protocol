#![no_main]
//! Address / varint / genesis params / spam filter — bounded, panic-free paths.
use std::io::Cursor;

use blvm_protocol::address::BitcoinAddress;
use blvm_protocol::economic::EconomicParameters;
use blvm_protocol::genesis::{mainnet_genesis, regtest_genesis, testnet_genesis};
use blvm_protocol::serialization::transaction::deserialize_transaction;
use blvm_protocol::spam_filter::{SpamFilter, SpamFilterPreset};
use blvm_protocol::time;
use blvm_protocol::validation::ProtocolValidationContext;
use blvm_protocol::variants::ProtocolVariant;
use blvm_protocol::{NetworkParameters, ProtocolVersion};
use blvm_protocol::varint::read_varint;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut cur = Cursor::new(data);
    let _ = read_varint(&mut cur);

    if let Ok(s) = std::str::from_utf8(data) {
        let t = s.chars().take(256).collect::<String>();
        let _ = BitcoinAddress::decode(&t);
    }

    let _ = mainnet_genesis();
    let _ = testnet_genesis();
    let _ = regtest_genesis();

    let _ = time::current_timestamp();

    let _ = NetworkParameters::for_version(ProtocolVersion::BitcoinV1);
    let _ = EconomicParameters::for_protocol(ProtocolVersion::BitcoinV1);

    if let Ok(ctx) = ProtocolValidationContext::new(ProtocolVersion::BitcoinV1, 0) {
        let _ = ctx.get_max_size("transaction");
        let _ = ctx.is_feature_enabled("segwit");
    }

    let _ = ProtocolVariant::for_version(ProtocolVersion::BitcoinV1);

    if let Ok(tx) = deserialize_transaction(data) {
        let filter = SpamFilter::with_preset(SpamFilterPreset::Disabled);
        let _ = filter.is_spam(&tx);
    }
});
