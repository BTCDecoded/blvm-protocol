//! BIP158: Compact Block Filters for Light Client Discovery
//!
//! Specification: https://github.com/bitcoin/bips/blob/master/bip-0158.mediawiki
//!
//! Implements Golomb-Rice Coded Sets (GCS) for efficient block filtering.
//! Allows light clients to determine if a block contains relevant transactions
//! without downloading the entire block.

use crate::Transaction;
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// BIP158 filter parameter: false positive rate (2^(-P))
/// P = 19 means ~1 in 524,288 false positives
pub const BIP158_P: u8 = 19;

/// BIP158 filter parameter: multiplier M = 2^P
pub const BIP158_M: u64 = 1 << BIP158_P; // 2^19 = 524,288

/// Compact block filter (GCS)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactBlockFilter {
    /// Golomb-Rice encoded filter data. Shared with a cached `cfilter` message.
    pub filter_data: Arc<Vec<u8>>,
    /// Number of elements in the filter
    pub num_elements: u32,
}

/// Hash a script to a number in range [0, N*M)
fn hash_to_range(script: &[u8], n: u64, m: u64) -> u64 {
    // Hash script with SHA256
    let mut hasher = Sha256::new();
    hasher.update(script);
    let hash = hasher.finalize();

    // Interpret first 8 bytes as u64 (little-endian)
    let hash_value = u64::from_le_bytes([
        hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
    ]);

    // Map to range [0, N*M)
    hash_value % (n * m)
}

/// Bit writer for Golomb-Rice encoding
struct BitWriter {
    data: Vec<u8>,
    current_byte: u8,
    bit_count: u8,
}

impl BitWriter {
    fn new() -> Self {
        Self {
            data: Vec::new(),
            current_byte: 0,
            bit_count: 0,
        }
    }

    /// Write a single bit
    fn write_bit(&mut self, bit: bool) {
        if bit {
            self.current_byte |= 1u8 << (7 - self.bit_count);
        }
        self.bit_count += 1;

        if self.bit_count == 8 {
            self.data.push(self.current_byte);
            self.current_byte = 0;
            self.bit_count = 0;
        }
    }

    /// Write multiple bits (up to 64)
    fn write_bits(&mut self, value: u64, num_bits: u8) {
        for i in 0..num_bits {
            let bit = ((value >> (num_bits - 1 - i)) & 1) != 0;
            self.write_bit(bit);
        }
    }

    /// Finish writing (flush remaining bits)
    fn finish(mut self) -> Vec<u8> {
        self.align_byte();
        self.data
    }

    /// Flush a partial byte so the next value starts on a byte boundary.
    /// Independent encodings were concatenated this way.
    fn align_byte(&mut self) {
        if self.bit_count > 0 {
            self.data.push(self.current_byte);
            self.current_byte = 0;
            self.bit_count = 0;
        }
    }

    /// BIP158: Encode value x as:
    /// - Write (x / 2^P) in unary (that many 1s, then a 0)
    /// - Write (x mod 2^P) in binary (P bits)
    fn write_golomb_rice(&mut self, value: u64, p: u8) {
        let quotient = value >> p;
        let remainder = value & ((1u64 << p) - 1);
        for _ in 0..quotient {
            self.write_bit(true);
        }
        self.write_bit(false);
        self.write_bits(remainder, p);
    }
}

/// Golomb-Rice encode one value. Tests use this as the separate-encoding oracle.
#[cfg(test)]
fn golomb_rice_encode(value: u64, p: u8) -> Vec<u8> {
    let mut writer = BitWriter::new();
    writer.write_golomb_rice(value, p);
    writer.finish()
}

/// Encode sorted hashed values as Golomb-Rice differences from zero.
/// Each value is byte-aligned, matching concatenation of [`golomb_rice_encode`].
fn encode_sorted_differences(values: &[u64]) -> Vec<u8> {
    let mut writer = BitWriter::new();
    let Some((first, rest)) = values.split_first() else {
        return writer.finish();
    };
    writer.write_golomb_rice(*first, BIP158_P);
    writer.align_byte();
    let mut prev = *first;
    for value in rest {
        writer.write_golomb_rice(value - prev, BIP158_P);
        writer.align_byte();
        prev = *value;
    }
    writer.finish()
}

/// Bit reader for Golomb-Rice decoding
struct BitReader<'a> {
    data: &'a [u8],
    bit_offset: usize,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            bit_offset: 0,
        }
    }

    /// Read a single bit
    fn read_bit(&mut self) -> Option<bool> {
        if self.bit_offset >= self.data.len() * 8 {
            return None;
        }
        let byte_idx = self.bit_offset / 8;
        let bit_idx = self.bit_offset % 8;
        let bit = (self.data[byte_idx] >> (7 - bit_idx)) & 1;
        self.bit_offset += 1;
        Some(bit == 1)
    }

    /// Read P bits as a u64
    fn read_bits(&mut self, p: u8) -> Option<u64> {
        let mut value = 0u64;
        for _ in 0..p {
            if let Some(bit) = self.read_bit() {
                value = (value << 1) | (if bit { 1 } else { 0 });
            } else {
                return None;
            }
        }
        Some(value)
    }
}

/// Golomb-Rice decode a value from stream
///
/// BIP158: Decode value x by:
/// - Read unary-encoded quotient (count 1s until 0)
/// - Read P bits as remainder
/// - Value = quotient * 2^P + remainder
fn golomb_rice_decode(reader: &mut BitReader, p: u8) -> Option<u64> {
    // Read quotient in unary (count 1s until we hit a 0)
    let mut quotient = 0u64;
    loop {
        match reader.read_bit() {
            Some(true) => quotient += 1,
            Some(false) => break,
            None => return None,
        }
    }

    // Read remainder in binary (P bits)
    let remainder = reader.read_bits(p)?;

    // Reconstruct value: quotient * 2^P + remainder
    Some((quotient << p) | remainder)
}

/// Build a compact block filter from transaction data
///
/// BIP158: Filter contains:
/// 1. All spendable output scriptPubKeys in the block
/// 2. All scriptPubKeys from outputs spent by block's inputs
pub fn build_block_filter(
    block_transactions: &[Transaction],
    previous_outpoint_scripts: &[Vec<u8>],
) -> Result<CompactBlockFilter, String> {
    let refs: Vec<&[u8]> = previous_outpoint_scripts
        .iter()
        .map(Vec::as_slice)
        .collect();
    build_block_filter_slices(block_transactions, &refs)
}

/// Same filter as [`build_block_filter`]. The spent scripts are borrowed.
pub fn build_block_filter_slices<'a>(
    block_transactions: &'a [Transaction],
    previous_outpoint_scripts: &[&'a [u8]],
) -> Result<CompactBlockFilter, String> {
    let mut output_scripts = Vec::new();
    for tx in block_transactions {
        for output in &tx.outputs {
            output_scripts.push(output.script_pubkey.as_slice());
        }
    }
    build_block_filter_output_scripts(output_scripts, previous_outpoint_scripts)
}

/// Same filter as [`build_block_filter_slices`], from output scripts already in hand.
///
/// `output_scripts` is reused. Spent scripts are appended to it. Empty scripts are dropped.
pub fn build_block_filter_output_scripts<'a>(
    mut scripts: Vec<&'a [u8]>,
    previous_outpoint_scripts: &[&'a [u8]],
) -> Result<CompactBlockFilter, String> {
    scripts.retain(|script| !script.is_empty());
    scripts.extend(
        previous_outpoint_scripts
            .iter()
            .copied()
            .filter(|script| !script.is_empty()),
    );

    // Unique by script bytes. N for the range hash is this count.
    scripts.sort_unstable();
    scripts.dedup();
    let n = scripts.len() as u64;
    if n == 0 {
        // Empty filter
        return Ok(CompactBlockFilter {
            filter_data: Arc::new(Vec::new()),
            num_elements: 0,
        });
    }

    // Hash each script to range [0, N*M)
    let mut hashed_values: Vec<u64> = scripts
        .iter()
        .map(|script| hash_to_range(script, n, BIP158_M))
        .collect();

    // Sort and remove duplicates
    hashed_values.sort_unstable();
    hashed_values.dedup();

    // Update n after deduplication. The first encoded value is the difference from 0.
    let n_final = hashed_values.len() as u64;
    let filter_data = Arc::new(encode_sorted_differences(&hashed_values));

    Ok(CompactBlockFilter {
        filter_data,
        num_elements: n_final as u32,
    })
}

/// Match a script against a compact block filter
///
/// Returns true if the script (or its hash) is likely in the filter.
/// A filter that does not fully decode returns false.
///
/// Algorithm:
/// 1. Hash the script to get a value in range [0, N*M)
/// 2. Walk the Golomb-Rice differences, rebuilding each hashed value
/// 3. The script matches when its hash is one of those values
pub fn match_filter(filter: &CompactBlockFilter, script: &[u8]) -> bool {
    if filter.num_elements == 0 {
        return false;
    }

    let n = filter.num_elements as u64;
    let script_hash = hash_to_range(script, n, BIP158_M);

    let mut reader = BitReader::new(filter.filter_data.as_slice());
    let mut current_value = 0u64;
    let mut found = false;
    for _ in 0..filter.num_elements {
        let Some(diff) = golomb_rice_decode(&mut reader, BIP158_P) else {
            return false;
        };
        current_value += diff;
        if current_value == script_hash {
            found = true;
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_to_range() {
        let script = b"test script";
        let n = 100;
        let m = BIP158_M;
        let value = hash_to_range(script, n, m);
        assert!(value < n * m);
    }

    #[test]
    fn test_golomb_rice_encode() {
        // Test encoding small value
        let encoded = golomb_rice_encode(0, BIP158_P);
        assert!(!encoded.is_empty());

        let encoded2 = golomb_rice_encode(1, BIP158_P);
        assert!(!encoded2.is_empty());
    }

    #[test]
    fn test_empty_filter() {
        let filter = build_block_filter(&[], &[]).unwrap();
        assert_eq!(filter.num_elements, 0);
        assert!(filter.filter_data.is_empty());
    }

    #[test]
    fn test_joined_golomb_matches_separate_encodings() {
        let values = [0u64, 1, 100, 10_000];
        let mut separate = Vec::new();
        for value in values {
            separate.extend(golomb_rice_encode(value, BIP158_P));
        }
        let mut writer = BitWriter::new();
        for value in values {
            writer.write_golomb_rice(value, BIP158_P);
            writer.align_byte();
        }
        assert_eq!(writer.finish(), separate);
    }

    #[test]
    fn test_golomb_rice_encode_decode_roundtrip() {
        let test_values = vec![0, 1, 2, 10, 100, 1000, 10000];

        for value in test_values {
            let encoded = golomb_rice_encode(value, BIP158_P);
            let mut reader = BitReader::new(&encoded);
            let decoded = golomb_rice_decode(&mut reader, BIP158_P);

            assert_eq!(decoded, Some(value), "Roundtrip failed for value {value}");
        }
    }

    #[test]
    fn test_build_and_match_filter() {
        use crate::{OutPoint, Transaction, TransactionInput, TransactionOutput};

        // Create a test transaction
        let tx = Transaction {
            version: 1,
            inputs: vec![TransactionInput {
                prevout: OutPoint {
                    hash: [0u8; 32],
                    index: 0,
                },
                script_sig: vec![],
                sequence: 0xffffffff,
            }]
            .into(),
            outputs: vec![TransactionOutput {
                value: 1000,
                script_pubkey: vec![blvm_consensus::opcodes::OP_1, blvm_consensus::opcodes::OP_2],
            }]
            .into(),
            lock_time: 0,
        };

        // Build filter
        let filter = build_block_filter(&[tx.clone()], &[]).unwrap();
        assert!(filter.num_elements > 0);

        // Match the script that's in the filter
        let script_in_filter = &tx.outputs[0].script_pubkey;
        assert!(match_filter(&filter, script_in_filter));

        // Match a script that's not in the filter
        let script_not_in_filter = vec![0x53, 0x54]; // OP_3 OP_4
        // Note: May have false positives due to GCS nature, but should generally work
        let _matched = match_filter(&filter, &script_not_in_filter);
        // False positives are possible, so we can't assert false
        // But we can verify the filter works for scripts that are definitely in it

        // One more claimed element than the stream can decode rejects the filter.
        let truncated = CompactBlockFilter {
            filter_data: filter.filter_data.clone(),
            num_elements: filter.num_elements + 1,
        };
        assert!(!match_filter(&truncated, script_in_filter));
    }

    #[test]
    fn test_filter_bytes_ignore_script_order() {
        use crate::{Transaction, TransactionInput, TransactionOutput};

        let tx = |scripts: &[&[u8]]| Transaction {
            version: 1,
            inputs: Vec::<TransactionInput>::new().into(),
            outputs: scripts
                .iter()
                .map(|script| TransactionOutput {
                    value: 1,
                    script_pubkey: script.to_vec(),
                })
                .collect::<Vec<_>>()
                .into(),
            lock_time: 0,
        };
        let first = build_block_filter(&[tx(&[b"\x51\x52", b"\x53\x54"])], &[]).unwrap();
        let second = build_block_filter(&[tx(&[b"\x53\x54", b"\x51\x52"])], &[]).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.num_elements, 2);
    }
}
