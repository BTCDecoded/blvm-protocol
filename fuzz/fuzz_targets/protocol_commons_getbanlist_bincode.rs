#![no_main]
//! `GetBanListMessage` bincode decode (commons wire).
use blvm_protocol::commons::GetBanListMessage;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = bincode::deserialize::<GetBanListMessage>(data);
});
