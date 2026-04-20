#![no_main]
//! Plan completion harness (generated batch 2).

use blvm_protocol::spam_filter::ScriptType;
use blvm_consensus::types::ByteString;
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let b: ByteString = data.to_vec().into();
    let _ = ScriptType::detect(&b);
});
