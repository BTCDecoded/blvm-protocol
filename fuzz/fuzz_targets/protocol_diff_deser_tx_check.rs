#![no_main]
//! Plan completion harness (generated batch 2).

use blvm_protocol::serialization::transaction::deserialize_transaction;
use blvm_protocol::transaction::check_transaction;
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if let Ok(tx) = deserialize_transaction(data) {
        let _ = check_transaction(&tx);
    }
});
