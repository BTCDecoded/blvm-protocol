//! Bitcoin Protocol Engine
//!
//! This crate provides a Bitcoin protocol abstraction layer that enables:
//! - Multiple Bitcoin variants (mainnet, testnet, regtest, educational)
//! - Protocol evolution support (Bitcoin V1, V2, etc.)
//! - Economic model abstraction (PoW, future variants)
//! - Educational and research-friendly interfaces
//!
//! This is Tier 3 of the 5-tier BTCDecoded architecture:
//!
//! 1. Orange Paper (mathematical foundation)
//! 2. blvm-consensus (pure math implementation)
//! 3. blvm-protocol (Bitcoin abstraction) ← THIS CRATE
//! 4. blvm-node (full Bitcoin node)
//! 5. blvm-sdk (ergonomic API)

use serde::{Deserialize, Serialize};

// Re-export commonly used types for convenience
// This allows upper layers (like blvm-node) to depend only on blvm-protocol
pub use blvm_consensus::ConsensusProof;
pub use blvm_consensus::config::NetworkMessageLimits;
pub use blvm_consensus::error::{ConsensusError, Result as ConsensusResult};
pub use blvm_consensus::types::{
    Block, BlockHeader, ByteString, Hash, Integer, Natural, OutPoint, Transaction,
    TransactionInput, TransactionOutput, UTXO, UtxoSet, ValidationResult, Witness,
};

#[cfg(all(feature = "production", feature = "benchmarking"))]
pub use blvm_consensus::config::{reset_assume_valid_height, set_assume_valid_height};
/// Buried deployment heights (Core chainparams) for RPC / tooling without a direct `blvm-consensus` dep.
pub use blvm_consensus::{
    BIP112_CSV_ACTIVATION_MAINNET, BIP112_CSV_ACTIVATION_REGTEST, BIP112_CSV_ACTIVATION_TESTNET,
    GENESIS_BLOCK_HASH_INTERNAL, SEGWIT_ACTIVATION_MAINNET, SEGWIT_ACTIVATION_TESTNET,
    TAPROOT_ACTIVATION_MAINNET, TAPROOT_ACTIVATION_TESTNET,
};

// Re-export smallvec for macro use when production feature is enabled
#[cfg(feature = "production")]
pub use smallvec;
// Re-export lru and rayon for production caches and parallel validation
#[cfg(feature = "production")]
pub use lru;
#[cfg(feature = "production")]
pub use rayon;

/// Forwards to `blvm_consensus::profile_log!` so upper layers avoid naming `blvm-consensus` directly.
/// When the `profile` feature is off on consensus, the inner macro expands to a no-op.
#[macro_export]
macro_rules! profile_log {
    ($($arg:tt)*) => {
        ::blvm_consensus::profile_log!($($arg)*)
    };
}

// Protocol-specific Result type
pub use error::{ProtocolError, Result};

// Re-export commonly used modules
pub mod mempool {
    pub use blvm_consensus::mempool::*;
}
pub mod segwit {
    pub use blvm_consensus::segwit::*;
}
pub mod block {
    pub use blvm_consensus::block::*;

    use crate::types::{BlockHeader, Network};

    /// Forwards to [`BlockValidationContext::from_connect_block_ibd_args`] with no BIP54 activation
    /// override and no boundary timestamps. Does not invent time or headers; pass the same values
    /// you would pass to the underlying constructor.
    #[inline]
    pub fn block_validation_context_for_connect_ibd<H: AsRef<BlockHeader>>(
        recent_headers: Option<&[H]>,
        network_time: u64,
        network: Network,
    ) -> BlockValidationContext {
        BlockValidationContext::from_connect_block_ibd_args(
            recent_headers,
            network_time,
            network,
            None,
            None,
        )
    }
}
pub mod mining {
    pub use blvm_consensus::mining::*;
}
pub mod pow {
    pub use blvm_consensus::pow::*;
}

pub mod witness {
    pub use blvm_consensus::witness::*;
}

pub mod crypto {
    pub use blvm_consensus::crypto::*;
}

pub mod transaction {
    pub use blvm_consensus::transaction::*;
}

/// Script interpreter (consensus). Exposed so benches/node avoid a direct `blvm-consensus` dep where possible.
pub mod script {
    pub use blvm_consensus::script::*;
}

/// Transaction sighash / txid helpers from consensus.
pub mod transaction_hash {
    pub use blvm_consensus::transaction_hash::*;
}

/// Production-only batch hashing, preallocation, and related optimization helpers from consensus.
#[cfg(feature = "production")]
pub mod optimizations {
    pub use blvm_consensus::optimizations::*;
}

/// Consensus constants (`blvm-primitives` / Orange Paper symbols) — same as `blvm_consensus::constants`.
pub mod constants {
    pub use blvm_consensus::constants::*;
}

pub mod bip113 {
    pub use blvm_consensus::bip113::*;
}

pub mod locktime {
    pub use blvm_consensus::locktime::*;
}

pub mod bip_validation {
    pub use blvm_consensus::bip_validation::*;
}

pub mod utxo_overlay {
    pub use blvm_consensus::utxo_overlay::*;
}

pub mod version_bits {
    pub use blvm_consensus::version_bits::*;
}

pub mod activation {
    pub use blvm_consensus::activation::*;
}

/// Consensus runtime configuration from `blvm-consensus` (distinct from this crate's [`config`] module).
pub mod consensus_config {
    pub use blvm_consensus::config::*;
}

#[cfg(feature = "test-utils")]
pub mod test_utils {
    pub use blvm_consensus::test_utils::*;
}

/// Script opcodes (re-exported from consensus / primitives) for callers that should not name `blvm-consensus` directly.
pub use blvm_consensus::opcodes;

pub mod sigop {
    pub use blvm_consensus::sigop::*;
}

#[cfg(feature = "utxo-commitments")]
pub mod utxo_commitments;

// Spam filter is always available (not behind utxo-commitments feature)
pub mod spam_filter;
pub mod serialization {
    pub use blvm_consensus::serialization::*;
}
pub mod commons;
pub mod network;
/// Framed TCP P2P (mainnet magic, command allowlist supplied by the node). Not BIP324 v2 transport.
pub mod node_tcp;

pub use node_tcp::{ProtocolMessage, TcpFramedParser};
pub mod p2p_commands;
pub mod p2p_frame;
pub mod p2p_framing;
pub mod service_flags;
pub mod varint;

// BIP324: v2 encrypted transport
#[cfg(all(
    feature = "bip324",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub mod v2_transport;

// Re-export commonly used types for convenience
pub use commons::{
    BanListMessage,
    // Filtered block types
    FilterPreferences,
    // Commons-only types kept in blvm-protocol for bridge layers
    FilteredBlockMessage,
    GetBanListMessage,
    GetFilteredBlockMessage,
    // UTXO proof types
    GetUTXOProofMessage,
    GetUTXOSetMessage,
    // UTXO commitment protocol types
    UTXOCommitment,
    UTXOProofMessage,
    UTXOSetMessage,
};
pub use config::{
    ProtocolConfig, ProtocolFeaturesConfig, ProtocolValidationConfig, ServiceFlagsConfig,
};
pub use network::{BlockMessage, CompactBlockMessage, TxMessage};
pub use service_flags::{commons as service_flags_commons, standard as service_flags_standard};
// Wire format module - Bitcoin P2P wire protocol serialization
pub mod wire;

#[cfg(test)]
mod bip155_serialization_tests;
pub mod types {
    pub use blvm_consensus::types::*;
}
// Re-export macros from blvm-consensus for convenience
pub use blvm_consensus::tx_inputs;
pub use blvm_consensus::tx_outputs;
pub mod error;

// Re-export feature and economic modules for convenience
pub use economic::EconomicParameters;
pub use features::{ActivationMethod, FeatureActivation, FeatureContext, FeatureRegistry};

pub mod config;
pub mod economic;
pub mod features;
pub mod genesis;
pub mod network_params;
pub mod validation;
pub mod variants;

// Protocol-level BIP implementations
pub mod address; // BIP173/350/351: Bech32/Bech32m address encoding
#[cfg(feature = "ctv")]
pub mod bip119 {
    pub use blvm_consensus::bip119::*;
}
pub mod bip152; // BIP152: Compact block relay (wire types)
pub mod bip157; // BIP157: Client-side block filtering network protocol
pub mod bip158; // BIP158: Compact block filters
pub mod payment; // BIP70: Payment protocol (P2P variant)
pub mod time;

/// Bitcoin Protocol Engine
///
/// Provides protocol abstraction for different Bitcoin variants and evolution.
/// Acts as a bridge between blvm-consensus (pure math) and blvm-node (implementation).
pub struct BitcoinProtocolEngine {
    consensus: ConsensusProof,
    protocol_version: ProtocolVersion,
    network_params: NetworkParameters,
    config: ProtocolConfig,
}

/// Bitcoin protocol versions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtocolVersion {
    /// Current Bitcoin mainnet protocol
    BitcoinV1,
    /// Bitcoin testnet protocol
    Testnet3,
    /// Regression test network protocol
    Regtest,
    /// Signet test network (BIP325 block-solution challenge)
    Signet,
    /// Bitcoin testnet4 (BIP94)
    Testnet4,
}

impl ProtocolVersion {
    /// Map protocol variant to consensus `Network` (blvm-primitives / blvm-consensus).
    pub fn consensus_network(self) -> types::Network {
        match self {
            ProtocolVersion::BitcoinV1 => types::Network::Mainnet,
            ProtocolVersion::Testnet3 => types::Network::Testnet,
            ProtocolVersion::Regtest => types::Network::Regtest,
            ProtocolVersion::Signet => types::Network::Signet,
            ProtocolVersion::Testnet4 => types::Network::Testnet4,
        }
    }
}

/// Network parameters for different Bitcoin variants
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkParameters {
    /// Network magic bytes for P2P protocol
    pub magic_bytes: [u8; 4],
    /// Default P2P port
    pub default_port: u16,
    /// Genesis block for this network
    pub genesis_block: Block,
    /// Maximum proof-of-work target
    pub max_target: u32,
    /// Block subsidy halving interval
    pub halving_interval: u64,
    /// Network name for identification
    pub network_name: String,
    /// Whether this is a test network
    pub is_testnet: bool,
    /// Optional BIP325 signet challenge script override (hex-decoded bytes stored here).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signet_challenge: Option<ByteString>,
}

impl BitcoinProtocolEngine {
    /// Create a new protocol engine for the specified variant with default configuration
    pub fn new(version: ProtocolVersion) -> Result<Self> {
        Self::with_config(version, ProtocolConfig::default())
    }

    /// Create a new protocol engine with custom configuration
    pub fn with_config(version: ProtocolVersion, config: ProtocolConfig) -> Result<Self> {
        let consensus = ConsensusProof::new();
        let network_params = NetworkParameters::for_version(version)?;

        Ok(BitcoinProtocolEngine {
            consensus,
            protocol_version: version,
            network_params,
            config,
        })
    }

    /// Get the protocol configuration
    pub fn get_config(&self) -> &ProtocolConfig {
        &self.config
    }

    /// Get mutable reference to protocol configuration
    pub fn get_config_mut(&mut self) -> &mut ProtocolConfig {
        &mut self.config
    }

    /// Get the current protocol version
    pub fn get_protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    /// Get network parameters for this protocol
    pub fn get_network_params(&self) -> &NetworkParameters {
        &self.network_params
    }

    /// Override the BIP325 signet challenge script (custom signet networks).
    pub fn with_signet_challenge(mut self, script: Option<Vec<u8>>) -> Self {
        self.network_params.signet_challenge = script;
        self
    }

    /// Build consensus [`BlockValidationContext`] including signet challenge from network params.
    pub fn connect_block_validation_context<H: AsRef<BlockHeader>>(
        &self,
        recent_headers: Option<&[H]>,
        network_time: u64,
    ) -> block::BlockValidationContext {
        let mut ctx = block::block_validation_context_for_connect_ibd(
            recent_headers,
            network_time,
            self.protocol_version.consensus_network(),
        );
        ctx.signet_challenge = self.network_params.signet_challenge.clone();
        ctx
    }

    /// Validate a block using this protocol's rules.
    ///
    /// **Deprecated**: this API builds empty witness vectors for every input and passes
    /// `None` for the time context, so:
    ///   - SegWit and Taproot scripts are validated against empty witness stacks (always fail
    ///     on witness-dependent scripts).
    ///   - Time-dependent checks fall back to wall-clock time instead of the median-time-past
    ///     computed from actual block headers.
    ///
    /// Prefer [`validate_and_connect_block`], which accepts explicit witnesses and a
    /// [`validation::ProtocolValidationContext`] with a correct `median_time_past`.
    #[deprecated(
        since = "0.1.0",
        note = "Use validate_and_connect_block with explicit witnesses and a ProtocolValidationContext"
    )]
    pub fn validate_block(
        &self,
        block: &Block,
        utxos: &UtxoSet,
        height: u64,
    ) -> Result<ValidationResult> {
        let network = self.protocol_version.consensus_network();
        // Empty witnesses: SegWit/Taproot inputs will fail witness-dependent checks.
        // This is acceptable here only because callers of this deprecated API either
        // use pre-SegWit blocks or do not need full witness validation.
        let witnesses: Vec<Vec<blvm_consensus::segwit::Witness>> = block
            .transactions
            .iter()
            .map(|tx| tx.inputs.iter().map(|_| Vec::new()).collect())
            .collect();
        // Use current wall-clock as the network time context.  For accurate median-time-past
        // validation, use validate_and_connect_block with an explicit context.
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let time_ctx = blvm_consensus::types::TimeContext {
            network_time: now_secs,
            // Without prior block history we approximate MTP as the current wall clock;
            // callers with a real chain tip should use validate_and_connect_block.
            median_time_past: now_secs,
        };
        let (result, _) = self
            .consensus
            .validate_block_with_time_context(
                block,
                &witnesses,
                utxos.clone(),
                height,
                Some(time_ctx),
                network,
            )
            .map_err(ProtocolError::from)?;
        Ok(result)
    }

    /// Validate a transaction using this protocol's rules
    pub fn validate_transaction(&self, tx: &Transaction) -> Result<ValidationResult> {
        self.consensus
            .validate_transaction(tx)
            .map_err(ProtocolError::from)
    }

    /// Validate block with protocol rules and update UTXO set
    ///
    /// This method combines protocol validation (size limits, feature flags)
    /// with consensus validation and UTXO set updates. This is the recommended
    /// method for node implementations that need both validation and state updates.
    ///
    /// # Arguments
    ///
    /// * `block` - The block to validate and connect
    /// * `witnesses` - Witness data for each transaction in the block
    /// * `utxos` - Current UTXO set (will be cloned, not mutated)
    /// * `height` - Current block height
    /// * `recent_headers` - Optional recent block headers for median time-past calculation (BIP113)
    /// * `context` - Protocol validation context
    ///
    /// # Returns
    ///
    /// Returns `(ValidationResult, UtxoSet)` where:
    /// - `ValidationResult` indicates if the block is valid
    /// - `UtxoSet` is the updated UTXO set after applying the block's transactions
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use blvm_protocol::{BitcoinProtocolEngine, ProtocolVersion};
    /// use blvm_protocol::validation::ProtocolValidationContext;
    /// use blvm_protocol::{Block, UtxoSet};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let engine = BitcoinProtocolEngine::new(ProtocolVersion::BitcoinV1)?;
    /// let context = ProtocolValidationContext::new(ProtocolVersion::BitcoinV1, 0)?;
    /// // Create a test block
    /// let block = Block {
    ///     header: blvm_consensus::BlockHeader {
    ///         version: 1,
    ///         prev_block_hash: [0u8; 32],
    ///         merkle_root: [0u8; 32],
    ///         timestamp: 1231006505,
    ///         bits: 0x1d00ffff,
    ///         nonce: 0,
    ///     },
    ///     transactions: vec![].into_boxed_slice(),
    /// };
    /// let witnesses = vec![];
    /// let utxos = UtxoSet::default();
    ///
    /// let (result, new_utxo_set) = engine.validate_and_connect_block(
    ///     &block,
    ///     &witnesses,
    ///     &utxos,
    ///     0,
    ///     None,
    ///     &context,
    /// )?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn validate_and_connect_block(
        &self,
        block: &Block,
        witnesses: &[Vec<segwit::Witness>], // CRITICAL FIX: Changed from &[Witness] to &[Vec<Witness>]
        // witnesses is now Vec<Vec<Witness>> where each Vec<Witness> is for one transaction
        // and each Witness is for one input
        utxos: &UtxoSet,
        height: u64,
        recent_headers: Option<&[BlockHeader]>,
        context: &validation::ProtocolValidationContext,
    ) -> Result<(ValidationResult, UtxoSet)> {
        self.validate_and_connect_block_with_difficulty(
            block,
            witnesses,
            utxos,
            height,
            recent_headers,
            context,
            None,
        )
    }

    /// [`validate_and_connect_block`] plus the ancestor lookup for required `nBits`.
    ///
    /// `difficulty_ancestor` maps a height to that header's compact bits and timestamp.
    /// `None` leaves the required-work check to the caller.
    #[allow(clippy::too_many_arguments)]
    pub fn validate_and_connect_block_with_difficulty(
        &self,
        block: &Block,
        witnesses: &[Vec<segwit::Witness>],
        utxos: &UtxoSet,
        height: u64,
        recent_headers: Option<&[BlockHeader]>,
        context: &validation::ProtocolValidationContext,
        difficulty_ancestor: Option<block::DifficultyAncestor>,
    ) -> Result<(ValidationResult, UtxoSet)> {
        // First, protocol validation with witnesses for accurate BIP141 weight check.
        let protocol_result = self
            .validate_block_with_protocol_and_witnesses(block, witnesses, utxos, height, context)?;
        if !matches!(protocol_result, ValidationResult::Valid) {
            return Ok((protocol_result, utxos.clone()));
        }

        // Consensus connect: use caller time context (REV-P-22), not wall clock.
        let network_time = if context.network_time > 0 {
            context.network_time
        } else {
            crate::time::current_timestamp()
        };
        let mut consensus_ctx = if context.median_time_past > 0 {
            block::BlockValidationContext::from_time_context_and_network(
                Some(blvm_consensus::types::TimeContext {
                    network_time,
                    median_time_past: context.median_time_past,
                }),
                self.protocol_version.consensus_network(),
                None,
            )
        } else {
            self.connect_block_validation_context(recent_headers, network_time)
        };
        consensus_ctx.signet_challenge = self.network_params.signet_challenge.clone();
        consensus_ctx.difficulty_ancestor = difficulty_ancestor;
        let (result, new_utxo_set, _undo_log) = blvm_consensus::block::connect_block(
            block,
            witnesses,
            utxos.clone(),
            height,
            &consensus_ctx,
        )?;

        Ok((result, new_utxo_set))
    }

    /// Check if this protocol supports a specific feature
    pub fn supports_feature(&self, feature: &str) -> bool {
        match self.protocol_version {
            ProtocolVersion::BitcoinV1 => {
                matches!(feature, "segwit" | "taproot" | "rbf" | "ctv")
            }
            ProtocolVersion::Testnet3 => {
                matches!(feature, "segwit" | "taproot" | "rbf" | "ctv")
            }
            ProtocolVersion::Regtest => {
                matches!(
                    feature,
                    "segwit" | "taproot" | "rbf" | "ctv" | "fast_mining"
                )
            }
            ProtocolVersion::Signet => {
                matches!(feature, "segwit" | "taproot" | "rbf" | "ctv" | "signet")
            }
            ProtocolVersion::Testnet4 => {
                matches!(feature, "segwit" | "taproot" | "rbf" | "ctv")
            }
        }
    }

    /// Check if a feature is active at a specific block height and timestamp
    pub fn is_feature_active(&self, feature: &str, height: u64, timestamp: u64) -> bool {
        let registry = features::FeatureRegistry::for_protocol(self.protocol_version);
        registry.is_feature_active(feature, height, timestamp)
    }

    /// Get economic parameters for this protocol
    pub fn get_economic_parameters(&self) -> economic::EconomicParameters {
        economic::EconomicParameters::for_protocol(self.protocol_version)
    }

    /// Get feature activation registry for this protocol
    pub fn get_feature_registry(&self) -> features::FeatureRegistry {
        features::FeatureRegistry::for_protocol(self.protocol_version)
    }

    /// Create a feature context for a specific block height and timestamp
    /// This consolidates all feature activation checks into a single context
    pub fn feature_context(&self, height: u64, timestamp: u64) -> features::FeatureContext {
        let registry = features::FeatureRegistry::for_protocol(self.protocol_version);
        registry.create_context(height, timestamp)
    }
}

impl NetworkParameters {
    /// Create network parameters for a specific protocol version
    pub fn for_version(version: ProtocolVersion) -> Result<Self> {
        match version {
            ProtocolVersion::BitcoinV1 => Self::mainnet(),
            ProtocolVersion::Testnet3 => Self::testnet(),
            ProtocolVersion::Regtest => Self::regtest(),
            ProtocolVersion::Signet => Self::signet(),
            ProtocolVersion::Testnet4 => Self::testnet4(),
        }
    }

    /// Bitcoin mainnet parameters
    pub fn mainnet() -> Result<Self> {
        Ok(NetworkParameters {
            magic_bytes: [0xf9, 0xbe, 0xb4, 0xd9], // Bitcoin mainnet magic
            default_port: 8333,
            genesis_block: genesis::mainnet_genesis(),
            max_target: 0x1d00ffff,
            halving_interval: blvm_consensus::economic::subsidy_halving_interval(
                blvm_consensus::types::Network::Mainnet,
            ),
            network_name: "mainnet".to_string(),
            is_testnet: false,
            signet_challenge: None,
        })
    }

    /// Bitcoin testnet parameters
    pub fn testnet() -> Result<Self> {
        Ok(NetworkParameters {
            magic_bytes: [0x0b, 0x11, 0x09, 0x07], // Bitcoin testnet magic
            default_port: 18333,
            genesis_block: genesis::testnet_genesis(),
            max_target: 0x1d00ffff,
            halving_interval: blvm_consensus::economic::subsidy_halving_interval(
                blvm_consensus::types::Network::Testnet,
            ),
            network_name: "testnet".to_string(),
            is_testnet: true,
            signet_challenge: None,
        })
    }

    /// Bitcoin regtest parameters
    pub fn regtest() -> Result<Self> {
        Ok(NetworkParameters {
            magic_bytes: [0xfa, 0xbf, 0xb5, 0xda], // Bitcoin regtest magic
            default_port: 18444,
            genesis_block: genesis::regtest_genesis(),
            max_target: 0x207fffff, // Easier difficulty for testing
            halving_interval: blvm_consensus::economic::subsidy_halving_interval(
                blvm_consensus::types::Network::Regtest,
            ),
            network_name: "regtest".to_string(),
            is_testnet: true,
            signet_challenge: None,
        })
    }

    /// Bitcoin signet parameters (BIP325 default signet)
    pub fn signet() -> Result<Self> {
        Ok(NetworkParameters {
            // Default signet: first 4 bytes of SHA256d(challenge), as Bitcoin Core's pchMessageStart.
            magic_bytes: [0x0a, 0x03, 0xcf, 0x40],
            default_port: 38333,
            genesis_block: genesis::signet_genesis(),
            max_target: 0x1e0377ae,
            halving_interval: blvm_consensus::economic::subsidy_halving_interval(
                blvm_consensus::types::Network::Signet,
            ),
            network_name: "signet".to_string(),
            is_testnet: true,
            signet_challenge: None,
        })
    }

    /// Bitcoin testnet4 parameters (BIP94).
    pub fn testnet4() -> Result<Self> {
        Ok(NetworkParameters {
            magic_bytes: [0x1c, 0x16, 0x3f, 0x28],
            default_port: 48333,
            genesis_block: genesis::testnet4_genesis(),
            max_target: 0x1d00ffff,
            halving_interval: blvm_consensus::economic::subsidy_halving_interval(
                blvm_consensus::types::Network::Testnet4,
            ),
            network_name: "testnet4".to_string(),
            is_testnet: true,
            signet_challenge: None,
        })
    }
}

#[cfg(test)]
#[path = "lib_tests.rs"]
mod tests;
