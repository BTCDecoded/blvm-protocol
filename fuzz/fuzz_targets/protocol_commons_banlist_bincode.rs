#![no_main]
//! Plan completion harness (generated batch 2).

use blvm_protocol::commons::BanListMessage;
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| { let _ = bincode::deserialize::<BanListMessage>(data); });
