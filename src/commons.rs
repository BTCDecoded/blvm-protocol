//! Commons-specific protocol extensions
//!
//! This module defines protocol messages specific to Bitcoin Commons,
//! including UTXO commitments, filtered blocks, and ban list sharing.

use crate::{BlockHeader, Hash, Transaction};
use serde::{Deserialize, Serialize};

/// GetUTXOSet message - Request UTXO set at specific height
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetUTXOSetMessage {
    /// Block height for which to request UTXO set
    pub height: u64,
    /// Block hash at requested height (for verification)
    pub block_hash: Hash,
}

/// UTXO commitment structure
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UTXOCommitment {
    pub merkle_root: Hash,
    pub total_supply: u64,
    pub utxo_count: u64,
    pub block_height: u64,
    pub block_hash: Hash,
}

/// UTXOSet message - Response with UTXO set commitment
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UTXOSetMessage {
    /// Request ID (echo from GetUTXOSet for matching)
    pub request_id: u64,
    /// UTXO commitment (Merkle root, supply, count, etc.)
    pub commitment: UTXOCommitment,
    /// UTXO set size hint (for chunking)
    pub utxo_count: u64,
    /// Indicates if this is a complete set or partial chunk
    pub is_complete: bool,
    /// Chunk identifier if partial
    pub chunk_id: Option<u32>,
}

/// FilterPreferences - Configure spam filtering
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilterPreferences {
    /// Filter Ordinals/Inscriptions
    pub filter_ordinals: bool,
    /// Filter dust outputs (default: < 546 satoshis)
    pub filter_dust: bool,
    /// Filter BRC-20 patterns
    pub filter_brc20: bool,
    /// Minimum output value to include (satoshis)
    pub min_output_value: u64,
}

/// SpamSummary - Summary of filtered spam
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpamSummary {
    /// Number of filtered transactions
    pub filtered_count: u32,
    /// Total filtered value (satoshis)
    pub filtered_value: u64,
    /// Filter reasons (bitfield)
    pub filter_reasons: u32,
}

/// GetFilteredBlock message - Request filtered block (spam-filtered)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetFilteredBlockMessage {
    /// Request ID for async request-response matching
    pub request_id: u64,
    /// Block hash to request
    pub block_hash: Hash,
    /// Filter preferences (what spam types to filter)
    pub filter_preferences: FilterPreferences,
    /// Request BIP158 compact block filter in response (optional)
    pub include_bip158_filter: bool,
}

/// FilteredBlock message - Response with filtered transactions
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilteredBlockMessage {
    /// Request ID (echo from GetFilteredBlock for matching)
    pub request_id: u64,
    /// Block header
    pub header: BlockHeader,
    /// UTXO commitment for this block
    pub commitment: UTXOCommitment,
    /// Filtered transactions (only non-spam)
    pub transactions: Vec<Transaction>,
    /// Transaction indices in original block (for verification)
    pub transaction_indices: Vec<u32>,
    /// Summary of filtered spam
    pub spam_summary: SpamSummary,
}

/// GetBanList message - Request ban list from peer
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetBanListMessage {
    /// Request ID for async request-response matching
    pub request_id: u64,
    /// Minimum ban score threshold (optional filter)
    pub min_score: Option<u32>,
}

/// BanEntry - Single ban list entry
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BanEntry {
    /// IP address (IPv6 format, 16 bytes)
    pub ip: [u8; 16],
    /// Ban score (higher = more severe)
    pub score: u32,
    /// Ban reason code
    pub reason: u8,
    /// Timestamp when ban was added
    pub timestamp: u64,
    /// Optional signature (if ban list is signed)
    pub signature: Option<Vec<u8>>,
}

/// BanList message - Response with ban list
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BanListMessage {
    /// Request ID (echo from GetBanList for matching)
    pub request_id: u64,
    /// Ban entries
    pub entries: Vec<BanEntry>,
    /// Optional signature over entire ban list
    pub list_signature: Option<Vec<u8>>,
}

// Governance/Commons Economic Node messages

/// EconomicNodeRegistration message - Register economic node via P2P
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EconomicNodeRegistrationMessage {
    /// Node type: "mining_pool", "exchange", "custodian", "commons_contributor"
    pub node_type: String,
    /// Entity name
    pub entity_name: String,
    /// Public key for veto signals
    pub public_key: String,
    /// Qualification data (JSON with cryptographic proofs)
    pub qualification_data: serde_json::Value,
    /// Unix timestamp
    pub timestamp: i64,
    /// Cryptographic signature of message by entity's private key
    /// Signs: node_type || entity_name || public_key || qualification_data_hash || timestamp
    pub signature: String,
    /// Unique message ID for deduplication (hex-encoded hash)
    pub message_id: String,
}

/// EconomicNodeVeto message - Veto signal via P2P
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EconomicNodeVetoMessage {
    /// Economic node ID (if already registered)
    pub node_id: Option<i32>,
    /// Public key (if not registered yet, used to identify node)
    pub public_key: String,
    /// Pull request ID being vetoed
    pub pr_id: i32,
    /// Signal type: "veto", "support", "abstain"
    pub signal_type: String,
    /// Unix timestamp
    pub timestamp: i64,
    /// Cryptographic signature by node's private key
    /// Signs: node_id || public_key || pr_id || signal_type || timestamp
    pub signature: String,
    /// Unique message ID for deduplication
    pub message_id: String,
}

/// EconomicNodeStatus message - Query/response for node status
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EconomicNodeStatusMessage {
    /// Request ID (for async request-response matching)
    pub request_id: u64,
    /// Node ID or public key to query
    pub node_identifier: String,
    /// Query type: "by_id", "by_public_key"
    pub query_type: String,
    /// Response data (if this is a response)
    pub status: Option<NodeStatusResponse>,
}

/// NodeStatusResponse - Status information for economic node
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeStatusResponse {
    /// Node ID
    pub node_id: i32,
    /// Node type
    pub node_type: String,
    /// Entity name
    pub entity_name: String,
    /// Current status: "active", "pending", "revoked"
    pub status: String,
    /// Current weight
    pub weight: f64,
    /// Registered timestamp
    pub registered_at: i64,
    /// Last verified timestamp
    pub last_verified_at: Option<i64>,
}
