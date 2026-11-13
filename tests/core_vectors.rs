//! Committed Core SipHash and basic block-filter rows.

use blvm_consensus::block::block_header_hash;
use blvm_protocol::bip152::siphash24;
use blvm_protocol::bip157::hash256_concat;
use blvm_protocol::bip158::build_block_filter;
use blvm_protocol::wire::deserialize_block;

const SIPHASH_PATH: &str = "tests/data/core_vectors/siphash.json";
const FILTER_PATH: &str = "tests/data/core_vectors/blockfilters.json";
const SIPHASH_ROWS: usize = 146;
const SIPHASH13_SKIPPED: usize = 64;
const FILTER_ROWS: usize = 10;

fn hex_u64(text: &str) -> u64 {
    u64::from_str_radix(text, 16).unwrap_or_else(|_| panic!("u64 {text}"))
}

fn display_hash(text: &str) -> [u8; 32] {
    let mut bytes = hex::decode(text).unwrap_or_else(|_| panic!("hash {text}"));
    assert_eq!(bytes.len(), 32, "hash {text}");
    bytes.reverse();
    bytes.try_into().unwrap()
}

#[test]
fn committed_siphash_rows_match_siphash24() {
    let rows: Vec<serde_json::Value> =
        serde_json::from_str(&std::fs::read_to_string(SIPHASH_PATH).expect(SIPHASH_PATH))
            .expect("siphash json");
    let mut executed = 0usize;
    let mut skipped_13 = 0usize;
    for (index, row) in rows.iter().enumerate() {
        let k0 = hex_u64(row["key"][0].as_str().expect("k0"));
        let k1 = hex_u64(row["key"][1].as_str().expect("k1"));
        let mut data = Vec::new();
        for part in row["input"].as_array().expect("input") {
            data.extend(hex::decode(part.as_str().expect("input hex")).expect("input bytes"));
        }
        let expect = hex_u64(row["expected"]["siphash24"].as_str().expect("siphash24"));
        assert_eq!(siphash24(k0, k1, &data), expect, "siphash row {index}");
        executed += 1;
        if !row["expected"]["siphash13uj"].is_null() {
            // SipHash-1-3 is a separate algorithm. This file's SipHash-2-4 column still runs.
            skipped_13 += 1;
        }
    }
    assert_eq!(executed, SIPHASH_ROWS);
    assert_eq!(skipped_13, SIPHASH13_SKIPPED);
}

#[test]
fn committed_blockfilters_match_basic_filter() {
    let rows: Vec<serde_json::Value> =
        serde_json::from_str(&std::fs::read_to_string(FILTER_PATH).expect(FILTER_PATH))
            .expect("blockfilters json");
    let mut executed = 0usize;
    let mut skipped_header = 0usize;
    for (index, row) in rows.iter().enumerate() {
        let row = row.as_array().expect("row");
        if row.len() == 1 {
            skipped_header += 1;
            continue;
        }
        assert!(row.len() >= 7, "short filter row {index}");
        let block_bytes = hex::decode(row[2].as_str().expect("block")).expect("block hex");
        let block =
            deserialize_block(&block_bytes).unwrap_or_else(|err| panic!("row {index}: {err}"));
        let block_hash = block_header_hash(&block.header);
        assert_eq!(
            block_hash,
            display_hash(row[1].as_str().expect("block hash")),
            "row {index} hash"
        );
        let spent: Vec<Vec<u8>> = row[3]
            .as_array()
            .expect("spent")
            .iter()
            .map(|script| hex::decode(script.as_str().expect("script")).expect("script hex"))
            .collect();
        let filter = build_block_filter(&block_hash, &block.transactions, &spent)
            .unwrap_or_else(|err| panic!("row {index}: {err}"));
        assert_eq!(
            hex::encode(filter.filter_data.as_slice()),
            row[5].as_str().expect("filter").to_ascii_lowercase(),
            "row {index} filter"
        );
        let filter_hash = blvm_protocol::bip157::hash256(filter.filter_data.as_slice());
        let header = hash256_concat(
            &filter_hash,
            &display_hash(row[4].as_str().expect("prev header")),
        );
        assert_eq!(
            header,
            display_hash(row[6].as_str().expect("filter header")),
            "row {index} header"
        );
        executed += 1;
    }
    assert_eq!(skipped_header, 1);
    assert_eq!(executed, FILTER_ROWS);
}
