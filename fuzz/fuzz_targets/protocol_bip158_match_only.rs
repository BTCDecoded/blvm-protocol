#![no_main]
//! BIP158 `match_filter` only (filter query path).
use blvm_protocol::bip158::{match_filter, CompactBlockFilter};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let n = (data.first().copied().unwrap_or(0) as u32) % 4096;
    let f = CompactBlockFilter {
        filter_data: data.to_vec(),
        num_elements: n,
    };
    let script = if data.len() > 64 { &data[..64] } else { data };
    let _ = match_filter(&f, script);
});
