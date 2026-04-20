#![no_main]
//! Plan completion harness (generated batch 2).

use blvm_protocol::serialization::transaction::deserialize_transaction;
use blvm_protocol::spam_filter::{SpamFilter, SpamFilterPreset};
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if let Ok(tx) = deserialize_transaction(data) {
        let f = SpamFilter::with_preset(SpamFilterPreset::Disabled);
        let _ = f.is_spam(&tx);
    }
});
