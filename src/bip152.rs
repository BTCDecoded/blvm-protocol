//! BIP152 high-level compact block types (wire / serde).
//!
//! Reconstruction, short-id hashing, and transport negotiation stay in the node.
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
    /// Prefilled transactions (full txs for selected indices)
    pub prefilled_txs: Vec<(usize, Transaction)>,
}
