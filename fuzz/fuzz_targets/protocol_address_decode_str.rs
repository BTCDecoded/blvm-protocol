#![no_main]
//! Plan completion harness (generated batch 2).

use blvm_protocol::address::BitcoinAddress;
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let t = s.chars().take(512).collect::<String>();
        let _ = BitcoinAddress::decode(&t);
    }
});
