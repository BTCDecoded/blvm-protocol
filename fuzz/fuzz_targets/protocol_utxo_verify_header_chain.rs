#![no_main]
//! Plan completion harness (generated batch 2).

use blvm_consensus::types::BlockHeader;
use blvm_protocol::utxo_commitments::verification::verify_header_chain;
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let mut headers = Vec::new();
    for chunk in data.chunks(80) {
        if chunk.len() != 80 { continue; }
        let version = i32::from_le_bytes(chunk[0..4].try_into().unwrap()) as i64;
        let prev: [u8; 32] = chunk[4..36].try_into().unwrap();
        let mr: [u8; 32] = chunk[36..68].try_into().unwrap();
        let ts = u32::from_le_bytes(chunk[68..72].try_into().unwrap()) as u64;
        let bits = u32::from_le_bytes(chunk[72..76].try_into().unwrap()) as u64;
        let nonce = u32::from_le_bytes(chunk[76..80].try_into().unwrap()) as u64;
        headers.push(BlockHeader { version, prev_block_hash: prev, merkle_root: mr, timestamp: ts, bits, nonce });
    }
    if !headers.is_empty() { let _ = verify_header_chain(&headers); }
});
