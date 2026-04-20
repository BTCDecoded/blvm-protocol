#![no_main]
//! Plan completion harness (generated batch 2).

use blvm_protocol::service_flags;
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let mut s = u64::from_le_bytes(data.get(0..8).unwrap_or(&[0u8;8]).try_into().unwrap_or([0u8;8]));
    let f = data.get(8).copied().unwrap_or(1) as u64;
    service_flags::set_flag(&mut s, f);
    let _ = service_flags::has_flag(s, f);
    let _ = service_flags::clear_flag(&mut s, f);
});
