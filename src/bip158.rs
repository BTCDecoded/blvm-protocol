//! BIP158: Compact Block Filters for Light Client Discovery
//!
//! Specification: https://github.com/bitcoin/bips/blob/master/bip-0158.mediawiki
//!
//! Implements Golomb-Rice Coded Sets (GCS) for efficient block filtering.
//! Allows light clients to determine if a block contains relevant transactions
//! without downloading the entire block.

use crate::Transaction;
use crate::bip152::siphash24;
use std::sync::Arc;

/// Golomb-Rice parameter P. The false-positive rate is about 1 in 2^P.
pub const BIP158_P: u8 = 19;

/// Range multiplier. F = N * BIP158_M.
pub const BIP158_M: u64 = 784_931;

/// Compact block filter (GCS)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactBlockFilter {
    /// Golomb-Rice encoded filter data. Shared with a cached `cfilter` message.
    pub filter_data: Arc<Vec<u8>>,
    /// Number of elements in the filter
    pub num_elements: u32,
}

fn filter_key(block_hash: &[u8; 32]) -> (u64, u64) {
    let k0 = u64::from_le_bytes(block_hash[0..8].try_into().expect("8"));
    let k1 = u64::from_le_bytes(block_hash[8..16].try_into().expect("8"));
    (k0, k1)
}

/// `(siphash24(k0, k1, script) as u128 * F as u128) >> 64`.
fn map_script(k0: u64, k1: u64, script: &[u8], f: u128) -> u64 {
    let hashed = siphash24(k0, k1, script) as u128;
    ((hashed.saturating_mul(f)) >> 64) as u64
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

/// Golomb-Rice deltas from 0, one bitstream. The partial byte is flushed once.
fn encode_sorted_differences(values: &[u64]) -> Vec<u8> {
    let mut writer = BitWriter::new();
    let mut prev = 0u64;
    for value in values {
        writer.write_golomb_rice(value.saturating_sub(prev), BIP158_P);
        prev = *value;
    }
    writer.finish()
}

fn write_compact_size(n: u64, out: &mut Vec<u8>) {
    if n < 253 {
        out.push(n as u8);
    } else if n <= u16::MAX as u64 {
        out.push(0xfd);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= u32::MAX as u64 {
        out.push(0xfe);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        out.push(0xff);
        out.extend_from_slice(&n.to_le_bytes());
    }
}

fn read_compact_size(data: &[u8]) -> Option<(u64, usize)> {
    let first = *data.first()?;
    match first {
        n @ 0..=252 => Some((n as u64, 1)),
        0xfd => {
            let bytes = data.get(1..3)?;
            Some((u16::from_le_bytes([bytes[0], bytes[1]]) as u64, 3))
        }
        0xfe => {
            let bytes: [u8; 4] = data.get(1..5)?.try_into().ok()?;
            Some((u32::from_le_bytes(bytes) as u64, 5))
        }
        _ => {
            let bytes: [u8; 8] = data.get(1..9)?.try_into().ok()?;
            Some((u64::from_le_bytes(bytes), 9))
        }
    }
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
    block_hash: &[u8; 32],
    block_transactions: &[Transaction],
    previous_outpoint_scripts: &[Vec<u8>],
) -> Result<CompactBlockFilter, String> {
    let refs: Vec<&[u8]> = previous_outpoint_scripts
        .iter()
        .map(Vec::as_slice)
        .collect();
    build_block_filter_slices(block_hash, block_transactions, &refs)
}

/// Same filter as [`build_block_filter`]. The spent scripts are borrowed.
pub fn build_block_filter_slices<'a>(
    block_hash: &[u8; 32],
    block_transactions: &'a [Transaction],
    previous_outpoint_scripts: &[&'a [u8]],
) -> Result<CompactBlockFilter, String> {
    let mut output_scripts = Vec::new();
    for tx in block_transactions {
        for output in &tx.outputs {
            output_scripts.push(output.script_pubkey.as_slice());
        }
    }
    build_block_filter_output_scripts(block_hash, output_scripts, previous_outpoint_scripts)
}

/// Same filter as [`build_block_filter_slices`], from output scripts already in hand.
///
/// `output_scripts` is reused. Spent scripts are appended to it. Empty scripts are dropped.
pub fn build_block_filter_output_scripts<'a>(
    block_hash: &[u8; 32],
    mut scripts: Vec<&'a [u8]>,
    previous_outpoint_scripts: &[&'a [u8]],
) -> Result<CompactBlockFilter, String> {
    scripts.extend(previous_outpoint_scripts.iter().copied());
    scripts.retain(|script| !script.is_empty() && script.first() != Some(&0x6a));
    scripts.sort_unstable();
    scripts.dedup();
    let n = scripts.len() as u64;
    if n == 0 {
        // Compact-size 0. An empty byte string omits N.
        return Ok(CompactBlockFilter {
            filter_data: Arc::new(vec![0]),
            num_elements: 0,
        });
    }

    let (k0, k1) = filter_key(block_hash);
    let f = (n as u128).saturating_mul(BIP158_M as u128);
    let mut hashed_values: Vec<u64> = scripts
        .iter()
        .map(|script| map_script(k0, k1, script, f))
        .collect();
    hashed_values.sort_unstable();

    let mut filter_data = Vec::new();
    write_compact_size(n, &mut filter_data);
    filter_data.extend(encode_sorted_differences(&hashed_values));

    Ok(CompactBlockFilter {
        filter_data: Arc::new(filter_data),
        num_elements: n as u32,
    })
}

/// Match a script against a compact block filter
///
/// Returns true if the script (or its hash) is likely in the filter.
/// A filter that does not fully decode returns false.
///
/// Algorithm:
/// 1. Map the script with the block-hash key and F = N * M
/// 2. Read the compact-size count, then the Golomb-Rice differences
/// 3. The script matches when its mapped value is one of those values
pub fn match_filter(block_hash: &[u8; 32], filter: &CompactBlockFilter, script: &[u8]) -> bool {
    if filter.num_elements == 0 {
        return false;
    }

    let n = filter.num_elements as u64;
    let Some((counted, offset)) = read_compact_size(filter.filter_data.as_slice()) else {
        return false;
    };
    if counted != n {
        return false;
    }
    let (k0, k1) = filter_key(block_hash);
    let f = (n as u128).saturating_mul(BIP158_M as u128);
    let script_hash = map_script(k0, k1, script, f);

    let mut reader = BitReader::new(&filter.filter_data[offset..]);
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

    const BLOCK_HASH: [u8; 32] = [0x11; 32];

    #[test]
    fn one_script_encodes_the_mapped_value_and_ignores_op_return() {
        let script = b"\x51";
        let filter =
            build_block_filter_output_scripts(&BLOCK_HASH, vec![script.as_slice()], &[]).unwrap();
        let (k0, k1) = filter_key(&BLOCK_HASH);
        let mapped = ((siphash24(k0, k1, script) as u128 * 784_931) >> 64) as u64;
        let mut expected = Vec::new();
        write_compact_size(1, &mut expected);
        expected.extend(golomb_rice_encode(mapped, BIP158_P));
        assert_eq!(filter.filter_data.as_slice(), expected.as_slice());
        assert_eq!(filter.num_elements, 1);
        assert!(match_filter(&BLOCK_HASH, &filter, script));

        let with_return = build_block_filter_output_scripts(
            &BLOCK_HASH,
            vec![script.as_slice(), &[0x6a, 0x01]],
            &[],
        )
        .unwrap();
        assert_eq!(with_return.filter_data, filter.filter_data);
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
        let filter = build_block_filter(&BLOCK_HASH, &[], &[]).unwrap();
        assert_eq!(filter.num_elements, 0);
        assert_eq!(filter.filter_data.as_slice(), &[0]);
    }

    #[test]
    fn test_deltas_share_one_bitstream() {
        let values = [0u64, 1, 100, 10_000];
        let mut writer = BitWriter::new();
        let mut prev = 0u64;
        for value in values {
            writer.write_golomb_rice(value - prev, BIP158_P);
            prev = value;
        }
        assert_eq!(writer.finish(), encode_sorted_differences(&values));
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
        let filter = build_block_filter(&BLOCK_HASH, &[tx.clone()], &[]).unwrap();
        assert!(filter.num_elements > 0);

        // Match the script that's in the filter
        let script_in_filter = &tx.outputs[0].script_pubkey;
        assert!(match_filter(&BLOCK_HASH, &filter, script_in_filter));

        // Match a script that's not in the filter
        let script_not_in_filter = vec![0x53, 0x54]; // OP_3 OP_4
        // Note: May have false positives due to GCS nature, but should generally work
        let _matched = match_filter(&BLOCK_HASH, &filter, &script_not_in_filter);
        // False positives are possible, so we can't assert false
        // But we can verify the filter works for scripts that are definitely in it

        // One more claimed element than the stream can decode rejects the filter.
        let truncated = CompactBlockFilter {
            filter_data: filter.filter_data.clone(),
            num_elements: filter.num_elements + 1,
        };
        assert!(!match_filter(&BLOCK_HASH, &truncated, script_in_filter));
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
        let first =
            build_block_filter(&BLOCK_HASH, &[tx(&[b"\x51\x52", b"\x53\x54"])], &[]).unwrap();
        let second =
            build_block_filter(&BLOCK_HASH, &[tx(&[b"\x53\x54", b"\x51\x52"])], &[]).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.num_elements, 2);
    }

    /// Bytes from an independent SipHash-2-4 and one Golomb-Rice bitstream.
    /// Block hash is 32 bytes of `0x11`. `P` is 19 and `F` is `N * 784_931`.
    #[test]
    fn known_filter_bytes_match_an_independent_encoding() {
        let one = build_block_filter_output_scripts(&BLOCK_HASH, vec![b"\x51"], &[]).unwrap();
        let expected = hex_bytes("01719c40");
        assert_eq!(one.filter_data.as_slice(), expected.as_slice());
        assert_eq!(one.num_elements, 1);
        assert!(match_filter(&BLOCK_HASH, &one, b"\x51"));
        assert!(!match_filter(&BLOCK_HASH, &one, b"\x52"));

        let with_return =
            build_block_filter_output_scripts(&BLOCK_HASH, vec![b"\x51", &[0x6a, 0x01]], &[])
                .unwrap();
        assert_eq!(with_return.filter_data.as_slice(), expected.as_slice());

        let duplicated =
            build_block_filter_output_scripts(&BLOCK_HASH, vec![b"\x51", b"\x51"], &[]).unwrap();
        assert_eq!(duplicated.filter_data.as_slice(), expected.as_slice());

        let two =
            build_block_filter_output_scripts(&BLOCK_HASH, vec![b"\x52", b"\x51"], &[]).unwrap();
        assert_eq!(
            two.filter_data.as_slice(),
            hex_bytes("02b19c4999d800").as_slice()
        );
        assert_eq!(two.num_elements, 2);
        assert!(match_filter(&BLOCK_HASH, &two, b"\x51"));
        assert!(match_filter(&BLOCK_HASH, &two, b"\x52"));

        let collided = build_block_filter_output_scripts(
            &BLOCK_HASH,
            vec![&[0x25, 0x01, 0x00], &[0x2e, 0x08, 0x00]],
            &[],
        )
        .unwrap();
        assert_eq!(collided.num_elements, 2);
        assert_eq!(
            collided.filter_data.as_slice(),
            hex_bytes("0207aea00000").as_slice()
        );
        assert!(match_filter(&BLOCK_HASH, &collided, &[0x25, 0x01, 0x00]));
        assert!(match_filter(&BLOCK_HASH, &collided, &[0x2e, 0x08, 0x00]));

        let empty = build_block_filter_output_scripts(&BLOCK_HASH, vec![], &[]).unwrap();
        assert_eq!(empty.filter_data.as_slice(), &[0]);
        assert!(!match_filter(&BLOCK_HASH, &empty, b"\x51"));
        let only_return =
            build_block_filter_output_scripts(&BLOCK_HASH, vec![&[0x6a]], &[]).unwrap();
        assert_eq!(only_return.filter_data.as_slice(), &[0]);

        // Quotient 1. Mapped value 730006 is 1 * 2^19 + 205718.
        let unary =
            build_block_filter_output_scripts(&BLOCK_HASH, vec![&[0x04, 0x00]], &[]).unwrap();
        assert_eq!(
            unary.filter_data.as_slice(),
            hex_bytes("01991cb0").as_slice()
        );
        assert!(match_filter(&BLOCK_HASH, &unary, &[0x04, 0x00]));

        // Eight scripts. Deltas have quotients 2, 1, 0, 2, 3, 0, 0, 0.
        let scripts: [&[u8]; 8] = [
            &[0x01, 0x00, 0x5a],
            &[0x02, 0x00, 0x5a],
            &[0x03, 0x00, 0x5a],
            &[0x04, 0x00, 0x5a],
            &[0x05, 0x00, 0x5a],
            &[0x06, 0x00, 0x5a],
            &[0x07, 0x00, 0x5a],
            &[0x08, 0x00, 0x5a],
        ];
        let wide = build_block_filter_output_scripts(&BLOCK_HASH, scripts.to_vec(), &[]).unwrap();
        assert_eq!(wide.num_elements, 8);
        assert_eq!(
            wide.filter_data.as_slice(),
            hex_bytes("08c09d02f1a544977793c53f77dc52be4722d7e3911d").as_slice()
        );
        for script in scripts {
            assert!(match_filter(&BLOCK_HASH, &wide, script));
        }
    }

    fn hex_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }
}
