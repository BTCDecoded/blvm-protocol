//! BIP152 high-level compact block types (wire / serde).
//!
//! Short-id hashing lives here so protocol reconstruction and the node use one rule.
//! Conversions to/from [`crate::network::CmpctBlockMessage`] live in `network.rs`.

use crate::{BlockHeader, Transaction};
use serde::{Deserialize, Serialize};

/// Short transaction ID (6 bytes / 48 bits) per BIP152.
pub type ShortTxId = [u8; 6];

/// Compact block representation (header + short IDs + prefilled txs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactBlock {
    /// Block header
    pub header: BlockHeader,
    /// Nonce for short ID calculation (64-bit)
    pub nonce: u64,
    /// Short transaction IDs (6 bytes each)
    pub short_ids: Vec<ShortTxId>,
    /// Prefilled transactions: block index, transaction, and witness stacks.
    /// `None` means the transaction has no witness.
    pub prefilled_txs: Vec<(usize, Transaction, Option<Vec<crate::segwit::Witness>>)>,
}

/// SipHash-2-4. BIP152 short ids use the low 6 bytes of this digest.
pub fn siphash24(k0: u64, k1: u64, data: &[u8]) -> u64 {
    use siphasher::sip::SipHasher24;
    use std::hash::Hasher;
    let mut hasher = SipHasher24::new_with_keys(k0, k1);
    hasher.write(data);
    hasher.finish()
}

/// BIP152 short id: SipHash-2-4 of the wtxid, keyed by SHA256(header || nonce).
pub fn short_tx_id(header: &BlockHeader, wtxid: &crate::Hash, nonce: u64) -> ShortTxId {
    use sha2::{Digest, Sha256};
    let mut data = crate::serialization::serialize_block_header(header);
    data.extend_from_slice(&nonce.to_le_bytes());
    let hash = Sha256::digest(&data);
    let k0 = u64::from_le_bytes(hash[0..8].try_into().expect("8"));
    let k1 = u64::from_le_bytes(hash[8..16].try_into().expect("8"));
    let digest = siphash24(k0, k1, wtxid);
    let bytes = digest.to_le_bytes();
    let mut short = [0u8; 6];
    short.copy_from_slice(&bytes[..6]);
    short
}

#[cfg(test)]
mod siphash_vector {
    use super::siphash24;

    #[test]
    fn siphash24_matches_the_reference_vector() {
        let mut key = [0u8; 16];
        for (i, byte) in key.iter_mut().enumerate() {
            *byte = i as u8;
        }
        let k0 = u64::from_le_bytes(key[0..8].try_into().unwrap());
        let k1 = u64::from_le_bytes(key[8..16].try_into().unwrap());
        let msg: Vec<u8> = (0..15).collect();
        assert_eq!(siphash24(k0, k1, &msg), 0xa129_ca61_49be_45e5);
    }
}
