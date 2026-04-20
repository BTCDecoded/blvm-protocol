#![no_main]
//! BIP157 message bincode surfaces + BIP158 filter matching.
use blvm_protocol::bip158::{match_filter, CompactBlockFilter};
use blvm_protocol::node_tcp::{
    CfcheckptMessage, CfheadersMessage, CfilterMessage, GetCfcheckptMessage, GetCfheadersMessage,
    GetCfiltersMessage,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = bincode::deserialize::<GetCfiltersMessage>(data);
    let _ = bincode::deserialize::<CfilterMessage>(data);
    let _ = bincode::deserialize::<GetCfheadersMessage>(data);
    let _ = bincode::deserialize::<CfheadersMessage>(data);
    let _ = bincode::deserialize::<GetCfcheckptMessage>(data);
    let _ = bincode::deserialize::<CfcheckptMessage>(data);

    let n = (data.first().copied().unwrap_or(0) as u32) % 4096;
    let filter = CompactBlockFilter {
        filter_data: data.to_vec(),
        num_elements: n,
    };
    let script = if data.len() > 64 {
        &data[..64]
    } else {
        data
    };
    let _ = match_filter(&filter, script);
});
